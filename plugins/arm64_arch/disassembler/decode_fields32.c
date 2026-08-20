/* GENERATED FILE */
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "decode.h"

void decode_fields32(enum ENCODING enc, context *ctx, Instruction *instr)
{
	uint32_t insword = instr->insword;
	instr->encoding = enc; /* record current path of decoding */
	switch(enc) {
		case ENC_FMADD_H_FLOATDP3:
		case ENC_FMADD_S_FLOATDP3:
		case ENC_FMADD_D_FLOATDP3:
		case ENC_FMSUB_H_FLOATDP3:
		case ENC_FMSUB_S_FLOATDP3:
		case ENC_FMSUB_D_FLOATDP3:
		case ENC_FNMADD_H_FLOATDP3:
		case ENC_FNMADD_S_FLOATDP3:
		case ENC_FNMADD_D_FLOATDP3:
		case ENC_FNMSUB_H_FLOATDP3:
		case ENC_FNMSUB_S_FLOATDP3:
		case ENC_FNMSUB_D_FLOATDP3:
			// M=x|x|S=x|xxxxx|ftype=xx|o1=x|Rm=xxxxx|o0=x|Ra=xxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->M = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->ftype = (insword>>22)&3;
			ctx->o1 = (insword>>21)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->o0 = (insword>>15)&1;
			ctx->Ra = (insword>>10)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FRINT32X_S_FLOATDP1:
		case ENC_FRINT32X_D_FLOATDP1:
		case ENC_FRINT32Z_S_FLOATDP1:
		case ENC_FRINT32Z_D_FLOATDP1:
		case ENC_FRINT64X_S_FLOATDP1:
		case ENC_FRINT64X_D_FLOATDP1:
		case ENC_FRINT64Z_S_FLOATDP1:
		case ENC_FRINT64Z_D_FLOATDP1:
			// M=x|x|S=x|xxxxx|ftype=xx|xxxxx|op=xx|xxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->M = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->ftype = (insword>>22)&3;
			ctx->op = (insword>>15)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FABS_H_FLOATDP1:
		case ENC_FABS_S_FLOATDP1:
		case ENC_FABS_D_FLOATDP1:
		case ENC_FCVT_SH_FLOATDP1:
		case ENC_FCVT_DH_FLOATDP1:
		case ENC_FCVT_HS_FLOATDP1:
		case ENC_FCVT_DS_FLOATDP1:
		case ENC_FCVT_HD_FLOATDP1:
		case ENC_FCVT_SD_FLOATDP1:
		case ENC_FMOV_H_FLOATDP1:
		case ENC_FMOV_S_FLOATDP1:
		case ENC_FMOV_D_FLOATDP1:
		case ENC_FNEG_H_FLOATDP1:
		case ENC_FNEG_S_FLOATDP1:
		case ENC_FNEG_D_FLOATDP1:
		case ENC_FSQRT_H_FLOATDP1:
		case ENC_FSQRT_S_FLOATDP1:
		case ENC_FSQRT_D_FLOATDP1:
			// M=x|x|S=x|xxxxx|ftype=xx|xxxxx|opc=xx|xxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->M = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->ftype = (insword>>22)&3;
			ctx->opc = (insword>>15)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FRINTA_H_FLOATDP1:
		case ENC_FRINTA_S_FLOATDP1:
		case ENC_FRINTA_D_FLOATDP1:
		case ENC_FRINTI_H_FLOATDP1:
		case ENC_FRINTI_S_FLOATDP1:
		case ENC_FRINTI_D_FLOATDP1:
		case ENC_FRINTM_H_FLOATDP1:
		case ENC_FRINTM_S_FLOATDP1:
		case ENC_FRINTM_D_FLOATDP1:
		case ENC_FRINTN_H_FLOATDP1:
		case ENC_FRINTN_S_FLOATDP1:
		case ENC_FRINTN_D_FLOATDP1:
		case ENC_FRINTP_H_FLOATDP1:
		case ENC_FRINTP_S_FLOATDP1:
		case ENC_FRINTP_D_FLOATDP1:
		case ENC_FRINTX_H_FLOATDP1:
		case ENC_FRINTX_S_FLOATDP1:
		case ENC_FRINTX_D_FLOATDP1:
		case ENC_FRINTZ_H_FLOATDP1:
		case ENC_FRINTZ_S_FLOATDP1:
		case ENC_FRINTZ_D_FLOATDP1:
			// M=x|x|S=x|xxxxx|ftype=xx|xxxx|rmode=xxx|xxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->M = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->ftype = (insword>>22)&3;
			ctx->rmode = (insword>>15)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FCSEL_H_FLOATSEL:
		case ENC_FCSEL_S_FLOATSEL:
		case ENC_FCSEL_D_FLOATSEL:
			// M=x|x|S=x|xxxxx|ftype=xx|x|Rm=xxxxx|cond=xxxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->M = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->ftype = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->cond = (insword>>12)&15;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FCCMPE_H_FLOATCCMP:
		case ENC_FCCMPE_S_FLOATCCMP:
		case ENC_FCCMPE_D_FLOATCCMP:
		case ENC_FCCMP_H_FLOATCCMP:
		case ENC_FCCMP_S_FLOATCCMP:
		case ENC_FCCMP_D_FLOATCCMP:
			// M=x|x|S=x|xxxxx|ftype=xx|x|Rm=xxxxx|cond=xxxx|xx|Rn=xxxxx|op=x|nzcv=xxxx
			ctx->M = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->ftype = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->cond = (insword>>12)&15;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->op = (insword>>4)&1;
			ctx->nzcv = insword&15;
			break;
		case ENC_FCMPE_H_FLOATCMP:
		case ENC_FCMPE_HZ_FLOATCMP:
		case ENC_FCMPE_S_FLOATCMP:
		case ENC_FCMPE_SZ_FLOATCMP:
		case ENC_FCMPE_D_FLOATCMP:
		case ENC_FCMPE_DZ_FLOATCMP:
		case ENC_FCMP_H_FLOATCMP:
		case ENC_FCMP_HZ_FLOATCMP:
		case ENC_FCMP_S_FLOATCMP:
		case ENC_FCMP_SZ_FLOATCMP:
		case ENC_FCMP_D_FLOATCMP:
		case ENC_FCMP_DZ_FLOATCMP:
			// M=x|x|S=x|xxxxx|ftype=xx|x|Rm=xxxxx|op=xx|xxxx|Rn=xxxxx|opc=xx|xxx
			ctx->M = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->ftype = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->op = (insword>>14)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->opc = (insword>>3)&3;
			break;
		case ENC_FMUL_H_FLOATDP2:
		case ENC_FMUL_S_FLOATDP2:
		case ENC_FMUL_D_FLOATDP2:
		case ENC_FNMUL_H_FLOATDP2:
		case ENC_FNMUL_S_FLOATDP2:
		case ENC_FNMUL_D_FLOATDP2:
			// M=x|x|S=x|xxxxx|ftype=xx|x|Rm=xxxxx|op=x|xxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->M = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->ftype = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->op = (insword>>15)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FDIV_H_FLOATDP2:
		case ENC_FDIV_S_FLOATDP2:
		case ENC_FDIV_D_FLOATDP2:
			// M=x|x|S=x|xxxxx|ftype=xx|x|Rm=xxxxx|opcode=xxxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->M = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->ftype = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>12)&15;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FADD_H_FLOATDP2:
		case ENC_FADD_S_FLOATDP2:
		case ENC_FADD_D_FLOATDP2:
		case ENC_FSUB_H_FLOATDP2:
		case ENC_FSUB_S_FLOATDP2:
		case ENC_FSUB_D_FLOATDP2:
			// M=x|x|S=x|xxxxx|ftype=xx|x|Rm=xxxxx|xxx|op=x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->M = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->ftype = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->op = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMAXNM_H_FLOATDP2:
		case ENC_FMAXNM_S_FLOATDP2:
		case ENC_FMAXNM_D_FLOATDP2:
		case ENC_FMAX_H_FLOATDP2:
		case ENC_FMAX_S_FLOATDP2:
		case ENC_FMAX_D_FLOATDP2:
		case ENC_FMINNM_H_FLOATDP2:
		case ENC_FMINNM_S_FLOATDP2:
		case ENC_FMINNM_D_FLOATDP2:
		case ENC_FMIN_H_FLOATDP2:
		case ENC_FMIN_S_FLOATDP2:
		case ENC_FMIN_D_FLOATDP2:
			// M=x|x|S=x|xxxxx|ftype=xx|x|Rm=xxxxx|xx|op=xx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->M = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->ftype = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->op = (insword>>12)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMOV_H_FLOATIMM:
		case ENC_FMOV_S_FLOATIMM:
		case ENC_FMOV_D_FLOATIMM:
			// M=x|x|S=x|xxxxx|ftype=xx|x|imm8=xxxxxxxx|xxx|imm5=xxxxx|Rd=xxxxx
			ctx->M = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->ftype = (insword>>22)&3;
			ctx->imm8 = (insword>>13)&0xff;
			ctx->imm5 = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_BFCVT_BS_FLOATDP1:
			// M=x|x|S=x|x|xxx|x|ftype=xx|x|opcode=xxxxxx|xxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->M = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->ftype = (insword>>22)&3;
			ctx->opcode = (insword>>15)&0x3f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_TBNZ_ONLY_TESTBRANCH:
		case ENC_TBZ_ONLY_TESTBRANCH:
			// b5=x|xx|xxx|x|op=x|b40=xxxxx|imm14=xxxxxxxxxxxxxx|Rt=xxxxx
			ctx->b5 = insword>>31;
			ctx->op = (insword>>24)&1;
			ctx->b40 = (insword>>19)&0x1f;
			ctx->imm14 = (insword>>5)&0x3fff;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_ADR_ONLY_PCRELADDR:
		case ENC_ADRP_ONLY_PCRELADDR:
			// op=x|immlo=xx|xxx|xx|immhi=xxxxxxxxxxxxxxxxxxx|Rd=xxxxx
			ctx->op = insword>>31;
			ctx->immlo = (insword>>29)&3;
			ctx->immhi = (insword>>5)&0x7ffff;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_BL_ONLY_BRANCH_IMM:
		case ENC_B_ONLY_BRANCH_IMM:
			// op=x|xx|xxx|imm26=xxxxxxxxxxxxxxxxxxxxxxxxxx
			ctx->op = insword>>31;
			ctx->imm26 = insword&0x3ffffff;
			break;
		case ENC_LDNP_S_LDSTNAPAIR_OFFS:
		case ENC_LDNP_D_LDSTNAPAIR_OFFS:
		case ENC_LDNP_Q_LDSTNAPAIR_OFFS:
		case ENC_LDNP_32_LDSTNAPAIR_OFFS:
		case ENC_LDNP_64_LDSTNAPAIR_OFFS:
		case ENC_LDP_S_LDSTPAIR_POST:
		case ENC_LDP_D_LDSTPAIR_POST:
		case ENC_LDP_Q_LDSTPAIR_POST:
		case ENC_LDP_S_LDSTPAIR_PRE:
		case ENC_LDP_D_LDSTPAIR_PRE:
		case ENC_LDP_Q_LDSTPAIR_PRE:
		case ENC_LDP_S_LDSTPAIR_OFF:
		case ENC_LDP_D_LDSTPAIR_OFF:
		case ENC_LDP_Q_LDSTPAIR_OFF:
		case ENC_LDP_32_LDSTPAIR_POST:
		case ENC_LDP_64_LDSTPAIR_POST:
		case ENC_LDP_32_LDSTPAIR_PRE:
		case ENC_LDP_64_LDSTPAIR_PRE:
		case ENC_LDP_32_LDSTPAIR_OFF:
		case ENC_LDP_64_LDSTPAIR_OFF:
		case ENC_STNP_S_LDSTNAPAIR_OFFS:
		case ENC_STNP_D_LDSTNAPAIR_OFFS:
		case ENC_STNP_Q_LDSTNAPAIR_OFFS:
		case ENC_STNP_32_LDSTNAPAIR_OFFS:
		case ENC_STNP_64_LDSTNAPAIR_OFFS:
		case ENC_STP_S_LDSTPAIR_POST:
		case ENC_STP_D_LDSTPAIR_POST:
		case ENC_STP_Q_LDSTPAIR_POST:
		case ENC_STP_S_LDSTPAIR_PRE:
		case ENC_STP_D_LDSTPAIR_PRE:
		case ENC_STP_Q_LDSTPAIR_PRE:
		case ENC_STP_S_LDSTPAIR_OFF:
		case ENC_STP_D_LDSTPAIR_OFF:
		case ENC_STP_Q_LDSTPAIR_OFF:
		case ENC_STP_32_LDSTPAIR_POST:
		case ENC_STP_64_LDSTPAIR_POST:
		case ENC_STP_32_LDSTPAIR_PRE:
		case ENC_STP_64_LDSTPAIR_PRE:
		case ENC_STP_32_LDSTPAIR_OFF:
		case ENC_STP_64_LDSTPAIR_OFF:
			// opc=xx|xxx|VR=x|xxx|L=x|imm7=xxxxxxx|Rt2=xxxxx|Rn=xxxxx|Rt=xxxxx
			ctx->opc = insword>>30;
			ctx->VR = (insword>>26)&1;
			ctx->L = (insword>>22)&1;
			ctx->imm7 = (insword>>15)&0x7f;
			ctx->Rt2 = (insword>>10)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_LDR_S_LOADLIT:
		case ENC_LDR_D_LOADLIT:
		case ENC_LDR_Q_LOADLIT:
		case ENC_LDR_32_LOADLIT:
		case ENC_LDR_64_LOADLIT:
			// opc=xx|xxx|VR=x|xx|imm19=xxxxxxxxxxxxxxxxxxx|Rt=xxxxx
			ctx->opc = insword>>30;
			ctx->VR = (insword>>26)&1;
			ctx->imm19 = (insword>>5)&0x7ffff;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_LDPSW_64_LDSTPAIR_POST:
		case ENC_LDPSW_64_LDSTPAIR_PRE:
		case ENC_LDPSW_64_LDSTPAIR_OFF:
		case ENC_LDTNP_Q_LDSTNAPAIR_OFFS:
		case ENC_LDTNP_64_LDSTNAPAIR_OFFS:
		case ENC_LDTP_Q_LDSTPAIR_POST:
		case ENC_LDTP_Q_LDSTPAIR_PRE:
		case ENC_LDTP_Q_LDSTPAIR_OFF:
		case ENC_LDTP_64_LDSTPAIR_POST:
		case ENC_LDTP_64_LDSTPAIR_PRE:
		case ENC_LDTP_64_LDSTPAIR_OFF:
		case ENC_STTNP_Q_LDSTNAPAIR_OFFS:
		case ENC_STTNP_64_LDSTNAPAIR_OFFS:
		case ENC_STTP_Q_LDSTPAIR_POST:
		case ENC_STTP_Q_LDSTPAIR_PRE:
		case ENC_STTP_Q_LDSTPAIR_OFF:
		case ENC_STTP_64_LDSTPAIR_POST:
		case ENC_STTP_64_LDSTPAIR_PRE:
		case ENC_STTP_64_LDSTPAIR_OFF:
			// opc=xx|xx|x|VR=x|x|xx|L=x|imm7=xxxxxxx|Rt2=xxxxx|Rn=xxxxx|Rt=xxxxx
			ctx->opc = insword>>30;
			ctx->VR = (insword>>26)&1;
			ctx->L = (insword>>22)&1;
			ctx->imm7 = (insword>>15)&0x7f;
			ctx->Rt2 = (insword>>10)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_STGP_64_LDSTPAIR_POST:
		case ENC_STGP_64_LDSTPAIR_PRE:
		case ENC_STGP_64_LDSTPAIR_OFF:
			// opc=xx|xx|x|VR=x|x|xx|L=x|simm7=xxxxxxx|Rt2=xxxxx|Rn=xxxxx|Rt=xxxxx
			ctx->opc = insword>>30;
			ctx->VR = (insword>>26)&1;
			ctx->L = (insword>>22)&1;
			ctx->simm7 = (insword>>15)&0x7f;
			ctx->Rt2 = (insword>>10)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_LDRSW_64_LOADLIT:
		case ENC_PRFM_P_LOADLIT:
			// opc=xx|xx|x|VR=x|x|x|imm19=xxxxxxxxxxxxxxxxxxx|Rt=xxxxx
			ctx->opc = insword>>30;
			ctx->VR = (insword>>26)&1;
			ctx->imm19 = (insword>>5)&0x7ffff;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_EXTR_32_EXTRACT:
		case ENC_EXTR_64_EXTRACT:
		case ENC_ROR_EXTR_32_EXTRACT:
		case ENC_ROR_EXTR_64_EXTRACT:
			// sf=x|op21=xx|xxxxxx|N=x|o0=x|Rm=xxxxx|imms=xxxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->op21 = (insword>>29)&3;
			ctx->N = (insword>>22)&1;
			ctx->o0 = (insword>>21)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->imms = (insword>>10)&0x3f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_MADD_32A_DP_3SRC:
		case ENC_MADD_64A_DP_3SRC:
		case ENC_MNEG_MSUB_32A_DP_3SRC:
		case ENC_MNEG_MSUB_64A_DP_3SRC:
		case ENC_MSUB_32A_DP_3SRC:
		case ENC_MSUB_64A_DP_3SRC:
		case ENC_MUL_MADD_32A_DP_3SRC:
		case ENC_MUL_MADD_64A_DP_3SRC:
			// sf=x|op54=xx|xxxxx|op31=xxx|Rm=xxxxx|o0=x|Ra=xxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->op54 = (insword>>29)&3;
			ctx->op31 = (insword>>21)&7;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->o0 = (insword>>15)&1;
			ctx->Ra = (insword>>10)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SMADDL_64WA_DP_3SRC:
		case ENC_SMNEGL_SMSUBL_64WA_DP_3SRC:
		case ENC_SMSUBL_64WA_DP_3SRC:
		case ENC_SMULH_64_DP_3SRC:
		case ENC_SMULL_SMADDL_64WA_DP_3SRC:
		case ENC_UMADDL_64WA_DP_3SRC:
		case ENC_UMNEGL_UMSUBL_64WA_DP_3SRC:
		case ENC_UMSUBL_64WA_DP_3SRC:
		case ENC_UMULH_64_DP_3SRC:
		case ENC_UMULL_UMADDL_64WA_DP_3SRC:
			// sf=x|op54=xx|x|xxx|x|U=x|xx|Rm=xxxxx|o0=x|Ra=xxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->op54 = (insword>>29)&3;
			ctx->U = (insword>>23)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->o0 = (insword>>15)&1;
			ctx->Ra = (insword>>10)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_MADDPT_64A_DP_3SRC:
		case ENC_MSUBPT_64A_DP_3SRC:
			// sf=x|op54=xx|x|xxx|x|op31=xxx|Rm=xxxxx|o0=x|Ra=xxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->op54 = (insword>>29)&3;
			ctx->op31 = (insword>>21)&7;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->o0 = (insword>>15)&1;
			ctx->Ra = (insword>>10)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_CINC_CSINC_32_CONDSEL:
		case ENC_CINC_CSINC_64_CONDSEL:
		case ENC_CINV_CSINV_32_CONDSEL:
		case ENC_CINV_CSINV_64_CONDSEL:
		case ENC_CNEG_CSNEG_32_CONDSEL:
		case ENC_CNEG_CSNEG_64_CONDSEL:
		case ENC_CSEL_32_CONDSEL:
		case ENC_CSEL_64_CONDSEL:
		case ENC_CSETM_CSINV_32_CONDSEL:
		case ENC_CSETM_CSINV_64_CONDSEL:
		case ENC_CSET_CSINC_32_CONDSEL:
		case ENC_CSET_CSINC_64_CONDSEL:
		case ENC_CSINC_32_CONDSEL:
		case ENC_CSINC_64_CONDSEL:
		case ENC_CSINV_32_CONDSEL:
		case ENC_CSINV_64_CONDSEL:
		case ENC_CSNEG_32_CONDSEL:
		case ENC_CSNEG_64_CONDSEL:
			// sf=x|op=x|S=x|xxxxxxxx|Rm=xxxxx|cond=xxxx|x|o2=x|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->op = (insword>>30)&1;
			ctx->S = (insword>>29)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->cond = (insword>>12)&15;
			ctx->o2 = (insword>>10)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_CCMN_32_CONDCMP_REG:
		case ENC_CCMN_64_CONDCMP_REG:
		case ENC_CCMP_32_CONDCMP_REG:
		case ENC_CCMP_64_CONDCMP_REG:
			// sf=x|op=x|S=x|xxxxxxxx|Rm=xxxxx|cond=xxxx|x|o2=x|Rn=xxxxx|o3=x|nzcv=xxxx
			ctx->sf = insword>>31;
			ctx->op = (insword>>30)&1;
			ctx->S = (insword>>29)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->cond = (insword>>12)&15;
			ctx->o2 = (insword>>10)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->o3 = (insword>>4)&1;
			ctx->nzcv = insword&15;
			break;
		case ENC_ADC_32_ADDSUB_CARRY:
		case ENC_ADC_64_ADDSUB_CARRY:
		case ENC_ADCS_32_ADDSUB_CARRY:
		case ENC_ADCS_64_ADDSUB_CARRY:
		case ENC_NGCS_SBCS_32_ADDSUB_CARRY:
		case ENC_NGCS_SBCS_64_ADDSUB_CARRY:
		case ENC_NGC_SBC_32_ADDSUB_CARRY:
		case ENC_NGC_SBC_64_ADDSUB_CARRY:
		case ENC_SBC_32_ADDSUB_CARRY:
		case ENC_SBC_64_ADDSUB_CARRY:
		case ENC_SBCS_32_ADDSUB_CARRY:
		case ENC_SBCS_64_ADDSUB_CARRY:
			// sf=x|op=x|S=x|xxxxxxxx|Rm=xxxxx|xxxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->op = (insword>>30)&1;
			ctx->S = (insword>>29)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_CCMN_32_CONDCMP_IMM:
		case ENC_CCMN_64_CONDCMP_IMM:
		case ENC_CCMP_32_CONDCMP_IMM:
		case ENC_CCMP_64_CONDCMP_IMM:
			// sf=x|op=x|S=x|xxxxxxxx|imm5=xxxxx|cond=xxxx|x|o2=x|Rn=xxxxx|o3=x|nzcv=xxxx
			ctx->sf = insword>>31;
			ctx->op = (insword>>30)&1;
			ctx->S = (insword>>29)&1;
			ctx->imm5 = (insword>>16)&0x1f;
			ctx->cond = (insword>>12)&15;
			ctx->o2 = (insword>>10)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->o3 = (insword>>4)&1;
			ctx->nzcv = insword&15;
			break;
		case ENC_SETF8_ONLY_SETF:
		case ENC_SETF16_ONLY_SETF:
			// sf=x|op=x|S=x|xxxxxxxx|opcode2=xxxxxx|sz=x|xxxx|Rn=xxxxx|o3=x|mask=xxxx
			ctx->sf = insword>>31;
			ctx->op = (insword>>30)&1;
			ctx->S = (insword>>29)&1;
			ctx->opcode2 = (insword>>15)&0x3f;
			ctx->sz = (insword>>14)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->o3 = (insword>>4)&1;
			ctx->mask = insword&15;
			break;
		case ENC_SMAX_32_MINMAX_IMM:
		case ENC_SMAX_64_MINMAX_IMM:
		case ENC_SMIN_32_MINMAX_IMM:
		case ENC_SMIN_64_MINMAX_IMM:
		case ENC_UMAX_32U_MINMAX_IMM:
		case ENC_UMAX_64U_MINMAX_IMM:
		case ENC_UMIN_32U_MINMAX_IMM:
		case ENC_UMIN_64U_MINMAX_IMM:
			// sf=x|op=x|S=x|xxxxxxx|opc=xxxx|imm8=xxxxxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->op = (insword>>30)&1;
			ctx->S = (insword>>29)&1;
			ctx->opc = (insword>>18)&15;
			ctx->imm8 = (insword>>10)&0xff;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_ADDS_32S_ADDSUB_IMM:
		case ENC_ADDS_64S_ADDSUB_IMM:
		case ENC_ADD_32_ADDSUB_IMM:
		case ENC_ADD_64_ADDSUB_IMM:
		case ENC_CMN_ADDS_32S_ADDSUB_IMM:
		case ENC_CMN_ADDS_64S_ADDSUB_IMM:
		case ENC_CMP_SUBS_32S_ADDSUB_IMM:
		case ENC_CMP_SUBS_64S_ADDSUB_IMM:
		case ENC_MOV_ADD_32_ADDSUB_IMM:
		case ENC_MOV_ADD_64_ADDSUB_IMM:
		case ENC_SUBS_32S_ADDSUB_IMM:
		case ENC_SUBS_64S_ADDSUB_IMM:
		case ENC_SUB_32_ADDSUB_IMM:
		case ENC_SUB_64_ADDSUB_IMM:
			// sf=x|op=x|S=x|xxxxxx|sh=x|imm12=xxxxxxxxxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->op = (insword>>30)&1;
			ctx->S = (insword>>29)&1;
			ctx->sh = (insword>>22)&1;
			ctx->imm12 = (insword>>10)&0xfff;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_ADDS_32S_ADDSUB_EXT:
		case ENC_ADDS_64S_ADDSUB_EXT:
		case ENC_ADD_32_ADDSUB_EXT:
		case ENC_ADD_64_ADDSUB_EXT:
		case ENC_CMN_ADDS_32S_ADDSUB_EXT:
		case ENC_CMN_ADDS_64S_ADDSUB_EXT:
		case ENC_CMP_SUBS_32S_ADDSUB_EXT:
		case ENC_CMP_SUBS_64S_ADDSUB_EXT:
		case ENC_SUBS_32S_ADDSUB_EXT:
		case ENC_SUBS_64S_ADDSUB_EXT:
		case ENC_SUB_32_ADDSUB_EXT:
		case ENC_SUB_64_ADDSUB_EXT:
			// sf=x|op=x|S=x|xxxxx|opt=xx|x|Rm=xxxxx|option=xxx|imm3=xxx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->op = (insword>>30)&1;
			ctx->S = (insword>>29)&1;
			ctx->opt = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->option = (insword>>13)&7;
			ctx->imm3 = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_ADDS_32_ADDSUB_SHIFT:
		case ENC_ADDS_64_ADDSUB_SHIFT:
		case ENC_ADD_32_ADDSUB_SHIFT:
		case ENC_ADD_64_ADDSUB_SHIFT:
		case ENC_CMN_ADDS_32_ADDSUB_SHIFT:
		case ENC_CMN_ADDS_64_ADDSUB_SHIFT:
		case ENC_CMP_SUBS_32_ADDSUB_SHIFT:
		case ENC_CMP_SUBS_64_ADDSUB_SHIFT:
		case ENC_NEGS_SUBS_32_ADDSUB_SHIFT:
		case ENC_NEGS_SUBS_64_ADDSUB_SHIFT:
		case ENC_NEG_SUB_32_ADDSUB_SHIFT:
		case ENC_NEG_SUB_64_ADDSUB_SHIFT:
		case ENC_SUBS_32_ADDSUB_SHIFT:
		case ENC_SUBS_64_ADDSUB_SHIFT:
		case ENC_SUB_32_ADDSUB_SHIFT:
		case ENC_SUB_64_ADDSUB_SHIFT:
			// sf=x|op=x|S=x|xxxxx|shift=xx|x|Rm=xxxxx|imm6=xxxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->op = (insword>>30)&1;
			ctx->S = (insword>>29)&1;
			ctx->shift = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->imm6 = (insword>>10)&0x3f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_ADDG_64_ADDSUB_IMMTAGS:
		case ENC_SUBG_64_ADDSUB_IMMTAGS:
			// sf=x|op=x|S=x|xxx|xxxx|imm6=xxxxxx|op3=xx|imm4=xxxx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->op = (insword>>30)&1;
			ctx->S = (insword>>29)&1;
			ctx->imm6 = (insword>>16)&0x3f;
			ctx->op3 = (insword>>14)&3;
			ctx->imm4 = (insword>>10)&15;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_ADDPT_64_ADDSUB_PT:
		case ENC_SUBPT_64_ADDSUB_PT:
			// sf=x|op=x|S=x|x|xxx|xxxx|Rm=xxxxx|xxx|imm3=xxx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->op = (insword>>30)&1;
			ctx->S = (insword>>29)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->imm3 = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_RMIF_ONLY_RMIF:
			// sf=x|op=x|S=x|x|xxx|xxxx|imm6=xxxxxx|xxxxx|Rn=xxxxx|o2=x|mask=xxxx
			ctx->sf = insword>>31;
			ctx->op = (insword>>30)&1;
			ctx->S = (insword>>29)&1;
			ctx->imm6 = (insword>>15)&0x3f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->o2 = (insword>>4)&1;
			ctx->mask = insword&15;
			break;
		case ENC_ANDS_32S_LOG_IMM:
		case ENC_ANDS_64S_LOG_IMM:
		case ENC_AND_32_LOG_IMM:
		case ENC_AND_64_LOG_IMM:
		case ENC_ASR_SBFM_32M_BITFIELD:
		case ENC_ASR_SBFM_64M_BITFIELD:
		case ENC_BFC_BFM_32M_BITFIELD:
		case ENC_BFC_BFM_64M_BITFIELD:
		case ENC_BFI_BFM_32M_BITFIELD:
		case ENC_BFI_BFM_64M_BITFIELD:
		case ENC_BFM_32M_BITFIELD:
		case ENC_BFM_64M_BITFIELD:
		case ENC_BFXIL_BFM_32M_BITFIELD:
		case ENC_BFXIL_BFM_64M_BITFIELD:
		case ENC_EOR_32_LOG_IMM:
		case ENC_EOR_64_LOG_IMM:
		case ENC_LSL_UBFM_32M_BITFIELD:
		case ENC_LSL_UBFM_64M_BITFIELD:
		case ENC_LSR_UBFM_32M_BITFIELD:
		case ENC_LSR_UBFM_64M_BITFIELD:
		case ENC_MOV_ORR_32_LOG_IMM:
		case ENC_MOV_ORR_64_LOG_IMM:
		case ENC_ORR_32_LOG_IMM:
		case ENC_ORR_64_LOG_IMM:
		case ENC_SBFIZ_SBFM_32M_BITFIELD:
		case ENC_SBFIZ_SBFM_64M_BITFIELD:
		case ENC_SBFM_32M_BITFIELD:
		case ENC_SBFM_64M_BITFIELD:
		case ENC_SBFX_SBFM_32M_BITFIELD:
		case ENC_SBFX_SBFM_64M_BITFIELD:
		case ENC_SXTB_SBFM_32M_BITFIELD:
		case ENC_SXTB_SBFM_64M_BITFIELD:
		case ENC_SXTH_SBFM_32M_BITFIELD:
		case ENC_SXTH_SBFM_64M_BITFIELD:
		case ENC_TST_ANDS_32S_LOG_IMM:
		case ENC_TST_ANDS_64S_LOG_IMM:
		case ENC_UBFIZ_UBFM_32M_BITFIELD:
		case ENC_UBFIZ_UBFM_64M_BITFIELD:
		case ENC_UBFM_32M_BITFIELD:
		case ENC_UBFM_64M_BITFIELD:
		case ENC_UBFX_UBFM_32M_BITFIELD:
		case ENC_UBFX_UBFM_64M_BITFIELD:
			// sf=x|opc=xx|xxxxxx|N=x|immr=xxxxxx|imms=xxxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->opc = (insword>>29)&3;
			ctx->N = (insword>>22)&1;
			ctx->immr = (insword>>16)&0x3f;
			ctx->imms = (insword>>10)&0x3f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_MOVK_32_MOVEWIDE:
		case ENC_MOVK_64_MOVEWIDE:
		case ENC_MOVN_32_MOVEWIDE:
		case ENC_MOVN_64_MOVEWIDE:
		case ENC_MOVZ_32_MOVEWIDE:
		case ENC_MOVZ_64_MOVEWIDE:
		case ENC_MOV_MOVN_32_MOVEWIDE:
		case ENC_MOV_MOVN_64_MOVEWIDE:
		case ENC_MOV_MOVZ_32_MOVEWIDE:
		case ENC_MOV_MOVZ_64_MOVEWIDE:
			// sf=x|opc=xx|xxxxxx|hw=xx|imm16=xxxxxxxxxxxxxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->opc = (insword>>29)&3;
			ctx->hw = (insword>>21)&3;
			ctx->imm16 = (insword>>5)&0xffff;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_ANDS_32_LOG_SHIFT:
		case ENC_ANDS_64_LOG_SHIFT:
		case ENC_AND_32_LOG_SHIFT:
		case ENC_AND_64_LOG_SHIFT:
		case ENC_BICS_32_LOG_SHIFT:
		case ENC_BICS_64_LOG_SHIFT:
		case ENC_BIC_32_LOG_SHIFT:
		case ENC_BIC_64_LOG_SHIFT:
		case ENC_EON_32_LOG_SHIFT:
		case ENC_EON_64_LOG_SHIFT:
		case ENC_EOR_32_LOG_SHIFT:
		case ENC_EOR_64_LOG_SHIFT:
		case ENC_MOV_ORR_32_LOG_SHIFT:
		case ENC_MOV_ORR_64_LOG_SHIFT:
		case ENC_MVN_ORN_32_LOG_SHIFT:
		case ENC_MVN_ORN_64_LOG_SHIFT:
		case ENC_ORN_32_LOG_SHIFT:
		case ENC_ORN_64_LOG_SHIFT:
		case ENC_ORR_32_LOG_SHIFT:
		case ENC_ORR_64_LOG_SHIFT:
		case ENC_TST_ANDS_32_LOG_SHIFT:
		case ENC_TST_ANDS_64_LOG_SHIFT:
			// sf=x|opc=xx|xxxxx|shift=xx|N=x|Rm=xxxxx|imm6=xxxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->opc = (insword>>29)&3;
			ctx->shift = (insword>>22)&3;
			ctx->N = (insword>>21)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->imm6 = (insword>>10)&0x3f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SXTW_SBFM_64M_BITFIELD:
		case ENC_UXTB_UBFM_32M_BITFIELD:
		case ENC_UXTH_UBFM_32M_BITFIELD:
			// sf=x|opc=xx|xxx|xxx|N=x|immr=xxxxxx|imms=xxxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->opc = (insword>>29)&3;
			ctx->N = (insword>>22)&1;
			ctx->immr = (insword>>16)&0x3f;
			ctx->imms = (insword>>10)&0x3f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_CBLE_CBGE_32_REGS:
		case ENC_CBLE_CBGE_64_REGS:
		case ENC_CBLO_CBHI_32_REGS:
		case ENC_CBLO_CBHI_64_REGS:
		case ENC_CBLS_CBHS_32_REGS:
		case ENC_CBLS_CBHS_64_REGS:
		case ENC_CBLT_CBGT_32_REGS:
		case ENC_CBLT_CBGT_64_REGS:
		case ENC_CBGT_32_REGS:
		case ENC_CBGE_32_REGS:
		case ENC_CBHI_32_REGS:
		case ENC_CBHS_32_REGS:
		case ENC_CBEQ_32_REGS:
		case ENC_CBNE_32_REGS:
		case ENC_CBGT_64_REGS:
		case ENC_CBGE_64_REGS:
		case ENC_CBHI_64_REGS:
		case ENC_CBHS_64_REGS:
		case ENC_CBEQ_64_REGS:
		case ENC_CBNE_64_REGS:
			// sf=x|xxxxxxx|cc=xxx|Rm=xxxxx|xx|imm9=xxxxxxxxx|Rt=xxxxx
			ctx->sf = insword>>31;
			ctx->cc = (insword>>21)&7;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->imm9 = (insword>>5)&0x1ff;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_CBGE_CBGT_32_IMM:
		case ENC_CBGE_CBGT_64_IMM:
		case ENC_CBHS_CBHI_32_IMM:
		case ENC_CBHS_CBHI_64_IMM:
		case ENC_CBLE_CBLT_32_IMM:
		case ENC_CBLE_CBLT_64_IMM:
		case ENC_CBLS_CBLO_32_IMM:
		case ENC_CBLS_CBLO_64_IMM:
		case ENC_CBGT_32_IMM:
		case ENC_CBLT_32_IMM:
		case ENC_CBHI_32_IMM:
		case ENC_CBLO_32_IMM:
		case ENC_CBEQ_32_IMM:
		case ENC_CBNE_32_IMM:
		case ENC_CBGT_64_IMM:
		case ENC_CBLT_64_IMM:
		case ENC_CBHI_64_IMM:
		case ENC_CBLO_64_IMM:
		case ENC_CBEQ_64_IMM:
		case ENC_CBNE_64_IMM:
			// sf=x|xxxxxxx|cc=xxx|imm6=xxxxxx|x|imm9=xxxxxxxxx|Rt=xxxxx
			ctx->sf = insword>>31;
			ctx->cc = (insword>>21)&7;
			ctx->imm6 = (insword>>15)&0x3f;
			ctx->imm9 = (insword>>5)&0x1ff;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_CBNZ_32_COMPBRANCH:
		case ENC_CBNZ_64_COMPBRANCH:
		case ENC_CBZ_32_COMPBRANCH:
		case ENC_CBZ_64_COMPBRANCH:
			// sf=x|xxxxxx|op=x|imm19=xxxxxxxxxxxxxxxxxxx|Rt=xxxxx
			ctx->sf = insword>>31;
			ctx->op = (insword>>24)&1;
			ctx->imm19 = (insword>>5)&0x7ffff;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_AUTIASPPC_ONLY_DP_1SRC_IMM:
		case ENC_AUTIBSPPC_ONLY_DP_1SRC_IMM:
			// sf=x|xx|xxx|xxx|opc=xx|imm16=xxxxxxxxxxxxxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->opc = (insword>>21)&3;
			ctx->imm16 = (insword>>5)&0xffff;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SMAX_32_DP_2SRC:
		case ENC_SMAX_64_DP_2SRC:
		case ENC_SMIN_32_DP_2SRC:
		case ENC_SMIN_64_DP_2SRC:
		case ENC_UMAX_32_DP_2SRC:
		case ENC_UMAX_64_DP_2SRC:
		case ENC_UMIN_32_DP_2SRC:
		case ENC_UMIN_64_DP_2SRC:
			// sf=x|x|S=x|xxxxxxxx|Rm=xxxxx|opcode=xxxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>10)&0x3f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SDIV_32_DP_2SRC:
		case ENC_SDIV_64_DP_2SRC:
		case ENC_UDIV_32_DP_2SRC:
		case ENC_UDIV_64_DP_2SRC:
			// sf=x|x|S=x|xxxxxxxx|Rm=xxxxx|xxxxx|o1=x|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->o1 = (insword>>10)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_ASRV_32_DP_2SRC:
		case ENC_ASRV_64_DP_2SRC:
		case ENC_ASR_ASRV_32_DP_2SRC:
		case ENC_ASR_ASRV_64_DP_2SRC:
		case ENC_LSLV_32_DP_2SRC:
		case ENC_LSLV_64_DP_2SRC:
		case ENC_LSL_LSLV_32_DP_2SRC:
		case ENC_LSL_LSLV_64_DP_2SRC:
		case ENC_LSRV_32_DP_2SRC:
		case ENC_LSRV_64_DP_2SRC:
		case ENC_LSR_LSRV_32_DP_2SRC:
		case ENC_LSR_LSRV_64_DP_2SRC:
		case ENC_RORV_32_DP_2SRC:
		case ENC_RORV_64_DP_2SRC:
		case ENC_ROR_RORV_32_DP_2SRC:
		case ENC_ROR_RORV_64_DP_2SRC:
			// sf=x|x|S=x|xxxxxxxx|Rm=xxxxx|xxxx|op2=xx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->op2 = (insword>>10)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_CRC32B_32C_DP_2SRC:
		case ENC_CRC32H_32C_DP_2SRC:
		case ENC_CRC32W_32C_DP_2SRC:
		case ENC_CRC32X_64C_DP_2SRC:
		case ENC_CRC32CB_32C_DP_2SRC:
		case ENC_CRC32CH_32C_DP_2SRC:
		case ENC_CRC32CW_32C_DP_2SRC:
		case ENC_CRC32CX_64C_DP_2SRC:
			// sf=x|x|S=x|xxxxxxxx|Rm=xxxxx|xxx|C=x|sz=xx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->C = (insword>>12)&1;
			ctx->sz = (insword>>10)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_ABS_32_DP_1SRC:
		case ENC_ABS_64_DP_1SRC:
		case ENC_CNT_32_DP_1SRC:
		case ENC_CNT_64_DP_1SRC:
		case ENC_CTZ_32_DP_1SRC:
		case ENC_CTZ_64_DP_1SRC:
		case ENC_RBIT_32_DP_1SRC:
		case ENC_RBIT_64_DP_1SRC:
			// sf=x|x|S=x|xxxxxxxx|opcode2=xxxxx|opcode=xxxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->opcode2 = (insword>>16)&0x1f;
			ctx->opcode = (insword>>10)&0x3f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_XPACD_64Z_DP_1SRC:
		case ENC_XPACI_64Z_DP_1SRC:
			// sf=x|x|S=x|xxxxxxxx|opcode2=xxxxx|xxxxx|D=x|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->opcode2 = (insword>>16)&0x1f;
			ctx->D = (insword>>10)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_CLS_32_DP_1SRC:
		case ENC_CLS_64_DP_1SRC:
		case ENC_CLZ_32_DP_1SRC:
		case ENC_CLZ_64_DP_1SRC:
			// sf=x|x|S=x|xxxxxxxx|opcode2=xxxxx|xxxxx|op=x|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->opcode2 = (insword>>16)&0x1f;
			ctx->op = (insword>>10)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_REV_32_DP_1SRC:
		case ENC_REV_64_DP_1SRC:
		case ENC_REV16_32_DP_1SRC:
		case ENC_REV16_64_DP_1SRC:
			// sf=x|x|S=x|xxxxxxxx|opcode2=xxxxx|xxxx|opc=xx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->opcode2 = (insword>>16)&0x1f;
			ctx->opc = (insword>>10)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_AUTDA_64P_DP_1SRC:
		case ENC_AUTDZA_64Z_DP_1SRC:
		case ENC_AUTDB_64P_DP_1SRC:
		case ENC_AUTDZB_64Z_DP_1SRC:
		case ENC_AUTIA_64P_DP_1SRC:
		case ENC_AUTIZA_64Z_DP_1SRC:
		case ENC_AUTIB_64P_DP_1SRC:
		case ENC_AUTIZB_64Z_DP_1SRC:
		case ENC_PACDA_64P_DP_1SRC:
		case ENC_PACDZA_64Z_DP_1SRC:
		case ENC_PACDB_64P_DP_1SRC:
		case ENC_PACDZB_64Z_DP_1SRC:
		case ENC_PACIA_64P_DP_1SRC:
		case ENC_PACIZA_64Z_DP_1SRC:
		case ENC_PACIB_64P_DP_1SRC:
		case ENC_PACIZB_64Z_DP_1SRC:
			// sf=x|x|S=x|xxxxxxxx|opcode2=xxxxx|xx|Z=x|xxx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->opcode2 = (insword>>16)&0x1f;
			ctx->Z = (insword>>13)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FCVTZS_32H_FLOAT2FIX:
		case ENC_FCVTZS_64H_FLOAT2FIX:
		case ENC_FCVTZS_32S_FLOAT2FIX:
		case ENC_FCVTZS_64S_FLOAT2FIX:
		case ENC_FCVTZS_32D_FLOAT2FIX:
		case ENC_FCVTZS_64D_FLOAT2FIX:
		case ENC_FCVTZU_32H_FLOAT2FIX:
		case ENC_FCVTZU_64H_FLOAT2FIX:
		case ENC_FCVTZU_32S_FLOAT2FIX:
		case ENC_FCVTZU_64S_FLOAT2FIX:
		case ENC_FCVTZU_32D_FLOAT2FIX:
		case ENC_FCVTZU_64D_FLOAT2FIX:
		case ENC_SCVTF_H32_FLOAT2FIX:
		case ENC_SCVTF_H64_FLOAT2FIX:
		case ENC_SCVTF_S32_FLOAT2FIX:
		case ENC_SCVTF_S64_FLOAT2FIX:
		case ENC_SCVTF_D32_FLOAT2FIX:
		case ENC_SCVTF_D64_FLOAT2FIX:
		case ENC_UCVTF_H32_FLOAT2FIX:
		case ENC_UCVTF_H64_FLOAT2FIX:
		case ENC_UCVTF_S32_FLOAT2FIX:
		case ENC_UCVTF_S64_FLOAT2FIX:
		case ENC_UCVTF_D32_FLOAT2FIX:
		case ENC_UCVTF_D64_FLOAT2FIX:
			// sf=x|x|S=x|xxxxx|ftype=xx|x|rmode=xx|opcode=xxx|scale=xxxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->ftype = (insword>>22)&3;
			ctx->rmode = (insword>>19)&3;
			ctx->opcode = (insword>>16)&7;
			ctx->scale = (insword>>10)&0x3f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FCVTAS_32H_FLOAT2INT:
		case ENC_FCVTAS_64H_FLOAT2INT:
		case ENC_FCVTAS_32S_FLOAT2INT:
		case ENC_FCVTAS_64S_FLOAT2INT:
		case ENC_FCVTAS_32D_FLOAT2INT:
		case ENC_FCVTAS_64D_FLOAT2INT:
		case ENC_FCVTAS_SISD_32H:
		case ENC_FCVTAS_SISD_64H:
		case ENC_FCVTAS_SISD_64S:
		case ENC_FCVTAS_SISD_32D:
		case ENC_FCVTAU_32H_FLOAT2INT:
		case ENC_FCVTAU_64H_FLOAT2INT:
		case ENC_FCVTAU_32S_FLOAT2INT:
		case ENC_FCVTAU_64S_FLOAT2INT:
		case ENC_FCVTAU_32D_FLOAT2INT:
		case ENC_FCVTAU_64D_FLOAT2INT:
		case ENC_FCVTAU_SISD_32H:
		case ENC_FCVTAU_SISD_64H:
		case ENC_FCVTAU_SISD_64S:
		case ENC_FCVTAU_SISD_32D:
		case ENC_FCVTMS_32H_FLOAT2INT:
		case ENC_FCVTMS_64H_FLOAT2INT:
		case ENC_FCVTMS_32S_FLOAT2INT:
		case ENC_FCVTMS_64S_FLOAT2INT:
		case ENC_FCVTMS_32D_FLOAT2INT:
		case ENC_FCVTMS_64D_FLOAT2INT:
		case ENC_FCVTMS_SISD_32H:
		case ENC_FCVTMS_SISD_64H:
		case ENC_FCVTMS_SISD_64S:
		case ENC_FCVTMS_SISD_32D:
		case ENC_FCVTMU_32H_FLOAT2INT:
		case ENC_FCVTMU_64H_FLOAT2INT:
		case ENC_FCVTMU_32S_FLOAT2INT:
		case ENC_FCVTMU_64S_FLOAT2INT:
		case ENC_FCVTMU_32D_FLOAT2INT:
		case ENC_FCVTMU_64D_FLOAT2INT:
		case ENC_FCVTMU_SISD_32H:
		case ENC_FCVTMU_SISD_64H:
		case ENC_FCVTMU_SISD_64S:
		case ENC_FCVTMU_SISD_32D:
		case ENC_FCVTNS_32H_FLOAT2INT:
		case ENC_FCVTNS_64H_FLOAT2INT:
		case ENC_FCVTNS_32S_FLOAT2INT:
		case ENC_FCVTNS_64S_FLOAT2INT:
		case ENC_FCVTNS_32D_FLOAT2INT:
		case ENC_FCVTNS_64D_FLOAT2INT:
		case ENC_FCVTNS_SISD_32H:
		case ENC_FCVTNS_SISD_64H:
		case ENC_FCVTNS_SISD_64S:
		case ENC_FCVTNS_SISD_32D:
		case ENC_FCVTNU_32H_FLOAT2INT:
		case ENC_FCVTNU_64H_FLOAT2INT:
		case ENC_FCVTNU_32S_FLOAT2INT:
		case ENC_FCVTNU_64S_FLOAT2INT:
		case ENC_FCVTNU_32D_FLOAT2INT:
		case ENC_FCVTNU_64D_FLOAT2INT:
		case ENC_FCVTNU_SISD_32H:
		case ENC_FCVTNU_SISD_64H:
		case ENC_FCVTNU_SISD_64S:
		case ENC_FCVTNU_SISD_32D:
		case ENC_FCVTPS_32H_FLOAT2INT:
		case ENC_FCVTPS_64H_FLOAT2INT:
		case ENC_FCVTPS_32S_FLOAT2INT:
		case ENC_FCVTPS_64S_FLOAT2INT:
		case ENC_FCVTPS_32D_FLOAT2INT:
		case ENC_FCVTPS_64D_FLOAT2INT:
		case ENC_FCVTPS_SISD_32H:
		case ENC_FCVTPS_SISD_64H:
		case ENC_FCVTPS_SISD_64S:
		case ENC_FCVTPS_SISD_32D:
		case ENC_FCVTPU_32H_FLOAT2INT:
		case ENC_FCVTPU_64H_FLOAT2INT:
		case ENC_FCVTPU_32S_FLOAT2INT:
		case ENC_FCVTPU_64S_FLOAT2INT:
		case ENC_FCVTPU_32D_FLOAT2INT:
		case ENC_FCVTPU_64D_FLOAT2INT:
		case ENC_FCVTPU_SISD_32H:
		case ENC_FCVTPU_SISD_64H:
		case ENC_FCVTPU_SISD_64S:
		case ENC_FCVTPU_SISD_32D:
		case ENC_FCVTZS_32H_FLOAT2INT:
		case ENC_FCVTZS_64H_FLOAT2INT:
		case ENC_FCVTZS_32S_FLOAT2INT:
		case ENC_FCVTZS_64S_FLOAT2INT:
		case ENC_FCVTZS_32D_FLOAT2INT:
		case ENC_FCVTZS_64D_FLOAT2INT:
		case ENC_FCVTZS_SISD_32H:
		case ENC_FCVTZS_SISD_64H:
		case ENC_FCVTZS_SISD_64S:
		case ENC_FCVTZS_SISD_32D:
		case ENC_FCVTZU_32H_FLOAT2INT:
		case ENC_FCVTZU_64H_FLOAT2INT:
		case ENC_FCVTZU_32S_FLOAT2INT:
		case ENC_FCVTZU_64S_FLOAT2INT:
		case ENC_FCVTZU_32D_FLOAT2INT:
		case ENC_FCVTZU_64D_FLOAT2INT:
		case ENC_FCVTZU_SISD_32H:
		case ENC_FCVTZU_SISD_64H:
		case ENC_FCVTZU_SISD_64S:
		case ENC_FCVTZU_SISD_32D:
		case ENC_FMOV_32H_FLOAT2INT:
		case ENC_FMOV_64H_FLOAT2INT:
		case ENC_FMOV_H32_FLOAT2INT:
		case ENC_FMOV_S32_FLOAT2INT:
		case ENC_FMOV_32S_FLOAT2INT:
		case ENC_FMOV_H64_FLOAT2INT:
		case ENC_FMOV_D64_FLOAT2INT:
		case ENC_FMOV_V64I_FLOAT2INT:
		case ENC_FMOV_64D_FLOAT2INT:
		case ENC_FMOV_64VX_FLOAT2INT:
		case ENC_SCVTF_H32_FLOAT2INT:
		case ENC_SCVTF_S32_FLOAT2INT:
		case ENC_SCVTF_D32_FLOAT2INT:
		case ENC_SCVTF_H64_FLOAT2INT:
		case ENC_SCVTF_S64_FLOAT2INT:
		case ENC_SCVTF_D64_FLOAT2INT:
		case ENC_SCVTF_SISD_32H:
		case ENC_SCVTF_SISD_32D:
		case ENC_SCVTF_SISD_64H:
		case ENC_SCVTF_SISD_64S:
		case ENC_UCVTF_H32_FLOAT2INT:
		case ENC_UCVTF_S32_FLOAT2INT:
		case ENC_UCVTF_D32_FLOAT2INT:
		case ENC_UCVTF_H64_FLOAT2INT:
		case ENC_UCVTF_S64_FLOAT2INT:
		case ENC_UCVTF_D64_FLOAT2INT:
		case ENC_UCVTF_SISD_32H:
		case ENC_UCVTF_SISD_32D:
		case ENC_UCVTF_SISD_64H:
		case ENC_UCVTF_SISD_64S:
			// sf=x|x|S=x|xxxxx|ftype=xx|x|rmode=xx|opcode=xxx|xxxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->ftype = (insword>>22)&3;
			ctx->rmode = (insword>>19)&3;
			ctx->opcode = (insword>>16)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_CMPP_SUBPS_64S_DP_2SRC:
		case ENC_GMI_64G_DP_2SRC:
		case ENC_IRG_64I_DP_2SRC:
		case ENC_PACGA_64P_DP_2SRC:
		case ENC_SUBP_64S_DP_2SRC:
		case ENC_SUBPS_64S_DP_2SRC:
			// sf=x|x|S=x|x|xxx|xxxx|Rm=xxxxx|opcode=xxxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>10)&0x3f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_AUTIA171615_64LR_DP_1SRC:
		case ENC_AUTIASPPCR_64LRR_DP_1SRC:
		case ENC_AUTIB171615_64LR_DP_1SRC:
		case ENC_AUTIBSPPCR_64LRR_DP_1SRC:
		case ENC_PACIA171615_64LR_DP_1SRC:
		case ENC_PACIASPPC_64LR_DP_1SRC:
		case ENC_PACIB171615_64LR_DP_1SRC:
		case ENC_PACIBSPPC_64LR_DP_1SRC:
		case ENC_PACNBIASPPC_64LR_DP_1SRC:
		case ENC_PACNBIBSPPC_64LR_DP_1SRC:
			// sf=x|x|S=x|x|xxx|xxxx|opcode2=xxxxx|opcode=xxxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->opcode2 = (insword>>16)&0x1f;
			ctx->opcode = (insword>>10)&0x3f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_REV32_64_DP_1SRC:
		case ENC_REV64_REV_64_DP_1SRC:
			// sf=x|x|S=x|x|xxx|xxxx|opcode2=xxxxx|xxxx|opc=xx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->opcode2 = (insword>>16)&0x1f;
			ctx->opc = (insword>>10)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FJCVTZS_32D_FLOAT2INT:
			// sf=x|x|S=x|x|xxx|x|ftype=xx|x|rmode=xx|opcode=xxx|xxxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->ftype = (insword>>22)&3;
			ctx->rmode = (insword>>19)&3;
			ctx->opcode = (insword>>16)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_LDAPR_32L_LDAPSTL_WRITEBACK:
		case ENC_LDAPR_64L_LDAPSTL_WRITEBACK:
		case ENC_STLR_32S_LDAPSTL_WRITEBACK:
		case ENC_STLR_64S_LDAPSTL_WRITEBACK:
			// size=xx|xxxxxxx|L=x|xxxxxxxxxxxx|Rn=xxxxx|Rt=xxxxx
			ctx->size = insword>>30;
			ctx->L = (insword>>22)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_CAS_C32_COMSWAP:
		case ENC_CASA_C32_COMSWAP:
		case ENC_CASAL_C32_COMSWAP:
		case ENC_CASL_C32_COMSWAP:
		case ENC_CAS_C64_COMSWAP:
		case ENC_CASA_C64_COMSWAP:
		case ENC_CASAL_C64_COMSWAP:
		case ENC_CASL_C64_COMSWAP:
		case ENC_CASB_C32_COMSWAP:
		case ENC_CASAB_C32_COMSWAP:
		case ENC_CASALB_C32_COMSWAP:
		case ENC_CASLB_C32_COMSWAP:
		case ENC_CASH_C32_COMSWAP:
		case ENC_CASAH_C32_COMSWAP:
		case ENC_CASALH_C32_COMSWAP:
		case ENC_CASLH_C32_COMSWAP:
		case ENC_LDAR_LR32_LDSTORD:
		case ENC_LDAR_LR64_LDSTORD:
		case ENC_LDAXR_LR32_LDSTEXCLR:
		case ENC_LDAXR_LR64_LDSTEXCLR:
		case ENC_LDLAR_LR32_LDSTORD:
		case ENC_LDLAR_LR64_LDSTORD:
		case ENC_LDXR_LR32_LDSTEXCLR:
		case ENC_LDXR_LR64_LDSTEXCLR:
		case ENC_STLLR_SL32_LDSTORD:
		case ENC_STLLR_SL64_LDSTORD:
		case ENC_STLR_SL32_LDSTORD:
		case ENC_STLR_SL64_LDSTORD:
		case ENC_STLXR_SR32_LDSTEXCLR:
		case ENC_STLXR_SR64_LDSTEXCLR:
		case ENC_STXR_SR32_LDSTEXCLR:
		case ENC_STXR_SR64_LDSTEXCLR:
			// size=xx|xxxxxxx|L=x|x|Rs=xxxxx|o0=x|Rt2=xxxxx|Rn=xxxxx|Rt=xxxxx
			ctx->size = insword>>30;
			ctx->L = (insword>>22)&1;
			ctx->Rs = (insword>>16)&0x1f;
			ctx->o0 = (insword>>15)&1;
			ctx->Rt2 = (insword>>10)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_LDIAPP_32LE_LDIAPPSTILP:
		case ENC_LDIAPP_32L_LDIAPPSTILP:
		case ENC_LDIAPP_64LS_LDIAPPSTILP:
		case ENC_LDIAPP_64L_LDIAPPSTILP:
		case ENC_STILP_32SE_LDIAPPSTILP:
		case ENC_STILP_32S_LDIAPPSTILP:
		case ENC_STILP_64SS_LDIAPPSTILP:
		case ENC_STILP_64S_LDIAPPSTILP:
			// size=xx|xxxxxxx|L=x|x|Rt2=xxxxx|opc2=xxxx|xx|Rn=xxxxx|Rt=xxxxx
			ctx->size = insword>>30;
			ctx->L = (insword>>22)&1;
			ctx->Rt2 = (insword>>16)&0x1f;
			ctx->opc2 = (insword>>12)&15;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_LDAPURSB_32_LDAPSTL_UNSCALED:
		case ENC_LDAPURSB_64_LDAPSTL_UNSCALED:
		case ENC_LDAPURSH_32_LDAPSTL_UNSCALED:
		case ENC_LDAPURSH_64_LDAPSTL_UNSCALED:
		case ENC_LDAPUR_B_LDAPSTL_SIMD:
		case ENC_LDAPUR_H_LDAPSTL_SIMD:
		case ENC_LDAPUR_S_LDAPSTL_SIMD:
		case ENC_LDAPUR_D_LDAPSTL_SIMD:
		case ENC_LDAPUR_Q_LDAPSTL_SIMD:
		case ENC_LDAPUR_32_LDAPSTL_UNSCALED:
		case ENC_LDAPUR_64_LDAPSTL_UNSCALED:
		case ENC_STLUR_B_LDAPSTL_SIMD:
		case ENC_STLUR_H_LDAPSTL_SIMD:
		case ENC_STLUR_S_LDAPSTL_SIMD:
		case ENC_STLUR_D_LDAPSTL_SIMD:
		case ENC_STLUR_Q_LDAPSTL_SIMD:
		case ENC_STLUR_32_LDAPSTL_UNSCALED:
		case ENC_STLUR_64_LDAPSTL_UNSCALED:
			// size=xx|xxxxxx|opc=xx|x|imm9=xxxxxxxxx|xx|Rn=xxxxx|Rt=xxxxx
			ctx->size = insword>>30;
			ctx->opc = (insword>>22)&3;
			ctx->imm9 = (insword>>12)&0x1ff;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_LDADD_32_MEMOP:
		case ENC_LDADDA_32_MEMOP:
		case ENC_LDADDAL_32_MEMOP:
		case ENC_LDADDL_32_MEMOP:
		case ENC_LDADD_64_MEMOP:
		case ENC_LDADDA_64_MEMOP:
		case ENC_LDADDAL_64_MEMOP:
		case ENC_LDADDL_64_MEMOP:
		case ENC_LDADDB_32_MEMOP:
		case ENC_LDADDAB_32_MEMOP:
		case ENC_LDADDALB_32_MEMOP:
		case ENC_LDADDLB_32_MEMOP:
		case ENC_LDADDH_32_MEMOP:
		case ENC_LDADDAH_32_MEMOP:
		case ENC_LDADDALH_32_MEMOP:
		case ENC_LDADDLH_32_MEMOP:
		case ENC_LDAPR_32L_MEMOP:
		case ENC_LDAPR_64L_MEMOP:
		case ENC_LDBFADD_16:
		case ENC_LDBFADDA_16:
		case ENC_LDBFADDAL_16:
		case ENC_LDBFADDL_16:
		case ENC_LDBFMAX_16:
		case ENC_LDBFMAXA_16:
		case ENC_LDBFMAXAL_16:
		case ENC_LDBFMAXL_16:
		case ENC_LDBFMAXNM_16:
		case ENC_LDBFMAXNMA_16:
		case ENC_LDBFMAXNMAL_16:
		case ENC_LDBFMAXNML_16:
		case ENC_LDBFMIN_16:
		case ENC_LDBFMINA_16:
		case ENC_LDBFMINAL_16:
		case ENC_LDBFMINL_16:
		case ENC_LDBFMINNM_16:
		case ENC_LDBFMINNMA_16:
		case ENC_LDBFMINNMAL_16:
		case ENC_LDBFMINNML_16:
		case ENC_LDCLR_32_MEMOP:
		case ENC_LDCLRA_32_MEMOP:
		case ENC_LDCLRAL_32_MEMOP:
		case ENC_LDCLRL_32_MEMOP:
		case ENC_LDCLR_64_MEMOP:
		case ENC_LDCLRA_64_MEMOP:
		case ENC_LDCLRAL_64_MEMOP:
		case ENC_LDCLRL_64_MEMOP:
		case ENC_LDCLRB_32_MEMOP:
		case ENC_LDCLRAB_32_MEMOP:
		case ENC_LDCLRALB_32_MEMOP:
		case ENC_LDCLRLB_32_MEMOP:
		case ENC_LDCLRH_32_MEMOP:
		case ENC_LDCLRAH_32_MEMOP:
		case ENC_LDCLRALH_32_MEMOP:
		case ENC_LDCLRLH_32_MEMOP:
		case ENC_LDEOR_32_MEMOP:
		case ENC_LDEORA_32_MEMOP:
		case ENC_LDEORAL_32_MEMOP:
		case ENC_LDEORL_32_MEMOP:
		case ENC_LDEOR_64_MEMOP:
		case ENC_LDEORA_64_MEMOP:
		case ENC_LDEORAL_64_MEMOP:
		case ENC_LDEORL_64_MEMOP:
		case ENC_LDEORB_32_MEMOP:
		case ENC_LDEORAB_32_MEMOP:
		case ENC_LDEORALB_32_MEMOP:
		case ENC_LDEORLB_32_MEMOP:
		case ENC_LDEORH_32_MEMOP:
		case ENC_LDEORAH_32_MEMOP:
		case ENC_LDEORALH_32_MEMOP:
		case ENC_LDEORLH_32_MEMOP:
		case ENC_LDFADD_16:
		case ENC_LDFADDA_16:
		case ENC_LDFADDAL_16:
		case ENC_LDFADDL_16:
		case ENC_LDFADD_32:
		case ENC_LDFADDA_32:
		case ENC_LDFADDAL_32:
		case ENC_LDFADDL_32:
		case ENC_LDFADD_64:
		case ENC_LDFADDA_64:
		case ENC_LDFADDAL_64:
		case ENC_LDFADDL_64:
		case ENC_LDFMAX_16:
		case ENC_LDFMAXA_16:
		case ENC_LDFMAXAL_16:
		case ENC_LDFMAXL_16:
		case ENC_LDFMAX_32:
		case ENC_LDFMAXA_32:
		case ENC_LDFMAXAL_32:
		case ENC_LDFMAXL_32:
		case ENC_LDFMAX_64:
		case ENC_LDFMAXA_64:
		case ENC_LDFMAXAL_64:
		case ENC_LDFMAXL_64:
		case ENC_LDFMAXNM_16:
		case ENC_LDFMAXNMA_16:
		case ENC_LDFMAXNMAL_16:
		case ENC_LDFMAXNML_16:
		case ENC_LDFMAXNM_32:
		case ENC_LDFMAXNMA_32:
		case ENC_LDFMAXNMAL_32:
		case ENC_LDFMAXNML_32:
		case ENC_LDFMAXNM_64:
		case ENC_LDFMAXNMA_64:
		case ENC_LDFMAXNMAL_64:
		case ENC_LDFMAXNML_64:
		case ENC_LDFMIN_16:
		case ENC_LDFMINA_16:
		case ENC_LDFMINAL_16:
		case ENC_LDFMINL_16:
		case ENC_LDFMIN_32:
		case ENC_LDFMINA_32:
		case ENC_LDFMINAL_32:
		case ENC_LDFMINL_32:
		case ENC_LDFMIN_64:
		case ENC_LDFMINA_64:
		case ENC_LDFMINAL_64:
		case ENC_LDFMINL_64:
		case ENC_LDFMINNM_16:
		case ENC_LDFMINNMA_16:
		case ENC_LDFMINNMAL_16:
		case ENC_LDFMINNML_16:
		case ENC_LDFMINNM_32:
		case ENC_LDFMINNMA_32:
		case ENC_LDFMINNMAL_32:
		case ENC_LDFMINNML_32:
		case ENC_LDFMINNM_64:
		case ENC_LDFMINNMA_64:
		case ENC_LDFMINNMAL_64:
		case ENC_LDFMINNML_64:
		case ENC_LDSET_32_MEMOP:
		case ENC_LDSETA_32_MEMOP:
		case ENC_LDSETAL_32_MEMOP:
		case ENC_LDSETL_32_MEMOP:
		case ENC_LDSET_64_MEMOP:
		case ENC_LDSETA_64_MEMOP:
		case ENC_LDSETAL_64_MEMOP:
		case ENC_LDSETL_64_MEMOP:
		case ENC_LDSETB_32_MEMOP:
		case ENC_LDSETAB_32_MEMOP:
		case ENC_LDSETALB_32_MEMOP:
		case ENC_LDSETLB_32_MEMOP:
		case ENC_LDSETH_32_MEMOP:
		case ENC_LDSETAH_32_MEMOP:
		case ENC_LDSETALH_32_MEMOP:
		case ENC_LDSETLH_32_MEMOP:
		case ENC_LDSMAX_32_MEMOP:
		case ENC_LDSMAXA_32_MEMOP:
		case ENC_LDSMAXAL_32_MEMOP:
		case ENC_LDSMAXL_32_MEMOP:
		case ENC_LDSMAX_64_MEMOP:
		case ENC_LDSMAXA_64_MEMOP:
		case ENC_LDSMAXAL_64_MEMOP:
		case ENC_LDSMAXL_64_MEMOP:
		case ENC_LDSMAXB_32_MEMOP:
		case ENC_LDSMAXAB_32_MEMOP:
		case ENC_LDSMAXALB_32_MEMOP:
		case ENC_LDSMAXLB_32_MEMOP:
		case ENC_LDSMAXH_32_MEMOP:
		case ENC_LDSMAXAH_32_MEMOP:
		case ENC_LDSMAXALH_32_MEMOP:
		case ENC_LDSMAXLH_32_MEMOP:
		case ENC_LDSMIN_32_MEMOP:
		case ENC_LDSMINA_32_MEMOP:
		case ENC_LDSMINAL_32_MEMOP:
		case ENC_LDSMINL_32_MEMOP:
		case ENC_LDSMIN_64_MEMOP:
		case ENC_LDSMINA_64_MEMOP:
		case ENC_LDSMINAL_64_MEMOP:
		case ENC_LDSMINL_64_MEMOP:
		case ENC_LDSMINB_32_MEMOP:
		case ENC_LDSMINAB_32_MEMOP:
		case ENC_LDSMINALB_32_MEMOP:
		case ENC_LDSMINLB_32_MEMOP:
		case ENC_LDSMINH_32_MEMOP:
		case ENC_LDSMINAH_32_MEMOP:
		case ENC_LDSMINALH_32_MEMOP:
		case ENC_LDSMINLH_32_MEMOP:
		case ENC_LDUMAX_32_MEMOP:
		case ENC_LDUMAXA_32_MEMOP:
		case ENC_LDUMAXAL_32_MEMOP:
		case ENC_LDUMAXL_32_MEMOP:
		case ENC_LDUMAX_64_MEMOP:
		case ENC_LDUMAXA_64_MEMOP:
		case ENC_LDUMAXAL_64_MEMOP:
		case ENC_LDUMAXL_64_MEMOP:
		case ENC_LDUMAXB_32_MEMOP:
		case ENC_LDUMAXAB_32_MEMOP:
		case ENC_LDUMAXALB_32_MEMOP:
		case ENC_LDUMAXLB_32_MEMOP:
		case ENC_LDUMAXH_32_MEMOP:
		case ENC_LDUMAXAH_32_MEMOP:
		case ENC_LDUMAXALH_32_MEMOP:
		case ENC_LDUMAXLH_32_MEMOP:
		case ENC_LDUMIN_32_MEMOP:
		case ENC_LDUMINA_32_MEMOP:
		case ENC_LDUMINAL_32_MEMOP:
		case ENC_LDUMINL_32_MEMOP:
		case ENC_LDUMIN_64_MEMOP:
		case ENC_LDUMINA_64_MEMOP:
		case ENC_LDUMINAL_64_MEMOP:
		case ENC_LDUMINL_64_MEMOP:
		case ENC_LDUMINB_32_MEMOP:
		case ENC_LDUMINAB_32_MEMOP:
		case ENC_LDUMINALB_32_MEMOP:
		case ENC_LDUMINLB_32_MEMOP:
		case ENC_LDUMINH_32_MEMOP:
		case ENC_LDUMINAH_32_MEMOP:
		case ENC_LDUMINALH_32_MEMOP:
		case ENC_LDUMINLH_32_MEMOP:
		case ENC_STADDB_LDADDB_32_MEMOP:
		case ENC_STADDLB_LDADDLB_32_MEMOP:
		case ENC_STADDH_LDADDH_32_MEMOP:
		case ENC_STADDLH_LDADDLH_32_MEMOP:
		case ENC_STADD_LDADD_32_MEMOP:
		case ENC_STADDL_LDADDL_32_MEMOP:
		case ENC_STADD_LDADD_64_MEMOP:
		case ENC_STADDL_LDADDL_64_MEMOP:
		case ENC_STBFADD_16:
		case ENC_STBFADDL_16:
		case ENC_STBFMAX_16:
		case ENC_STBFMAXL_16:
		case ENC_STBFMAXNM_16:
		case ENC_STBFMAXNML_16:
		case ENC_STBFMIN_16:
		case ENC_STBFMINL_16:
		case ENC_STBFMINNM_16:
		case ENC_STBFMINNML_16:
		case ENC_STCLRB_LDCLRB_32_MEMOP:
		case ENC_STCLRLB_LDCLRLB_32_MEMOP:
		case ENC_STCLRH_LDCLRH_32_MEMOP:
		case ENC_STCLRLH_LDCLRLH_32_MEMOP:
		case ENC_STCLR_LDCLR_32_MEMOP:
		case ENC_STCLRL_LDCLRL_32_MEMOP:
		case ENC_STCLR_LDCLR_64_MEMOP:
		case ENC_STCLRL_LDCLRL_64_MEMOP:
		case ENC_STEORB_LDEORB_32_MEMOP:
		case ENC_STEORLB_LDEORLB_32_MEMOP:
		case ENC_STEORH_LDEORH_32_MEMOP:
		case ENC_STEORLH_LDEORLH_32_MEMOP:
		case ENC_STEOR_LDEOR_32_MEMOP:
		case ENC_STEORL_LDEORL_32_MEMOP:
		case ENC_STEOR_LDEOR_64_MEMOP:
		case ENC_STEORL_LDEORL_64_MEMOP:
		case ENC_STFADD_16:
		case ENC_STFADDL_16:
		case ENC_STFADD_32:
		case ENC_STFADDL_32:
		case ENC_STFADD_64:
		case ENC_STFADDL_64:
		case ENC_STFMAX_16:
		case ENC_STFMAXL_16:
		case ENC_STFMAX_32:
		case ENC_STFMAXL_32:
		case ENC_STFMAX_64:
		case ENC_STFMAXL_64:
		case ENC_STFMAXNM_16:
		case ENC_STFMAXNML_16:
		case ENC_STFMAXNM_32:
		case ENC_STFMAXNML_32:
		case ENC_STFMAXNM_64:
		case ENC_STFMAXNML_64:
		case ENC_STFMIN_16:
		case ENC_STFMINL_16:
		case ENC_STFMIN_32:
		case ENC_STFMINL_32:
		case ENC_STFMIN_64:
		case ENC_STFMINL_64:
		case ENC_STFMINNM_16:
		case ENC_STFMINNML_16:
		case ENC_STFMINNM_32:
		case ENC_STFMINNML_32:
		case ENC_STFMINNM_64:
		case ENC_STFMINNML_64:
		case ENC_STSETB_LDSETB_32_MEMOP:
		case ENC_STSETLB_LDSETLB_32_MEMOP:
		case ENC_STSETH_LDSETH_32_MEMOP:
		case ENC_STSETLH_LDSETLH_32_MEMOP:
		case ENC_STSET_LDSET_32_MEMOP:
		case ENC_STSETL_LDSETL_32_MEMOP:
		case ENC_STSET_LDSET_64_MEMOP:
		case ENC_STSETL_LDSETL_64_MEMOP:
		case ENC_STSMAXB_LDSMAXB_32_MEMOP:
		case ENC_STSMAXLB_LDSMAXLB_32_MEMOP:
		case ENC_STSMAXH_LDSMAXH_32_MEMOP:
		case ENC_STSMAXLH_LDSMAXLH_32_MEMOP:
		case ENC_STSMAX_LDSMAX_32_MEMOP:
		case ENC_STSMAXL_LDSMAXL_32_MEMOP:
		case ENC_STSMAX_LDSMAX_64_MEMOP:
		case ENC_STSMAXL_LDSMAXL_64_MEMOP:
		case ENC_STSMINB_LDSMINB_32_MEMOP:
		case ENC_STSMINLB_LDSMINLB_32_MEMOP:
		case ENC_STSMINH_LDSMINH_32_MEMOP:
		case ENC_STSMINLH_LDSMINLH_32_MEMOP:
		case ENC_STSMIN_LDSMIN_32_MEMOP:
		case ENC_STSMINL_LDSMINL_32_MEMOP:
		case ENC_STSMIN_LDSMIN_64_MEMOP:
		case ENC_STSMINL_LDSMINL_64_MEMOP:
		case ENC_STUMAXB_LDUMAXB_32_MEMOP:
		case ENC_STUMAXLB_LDUMAXLB_32_MEMOP:
		case ENC_STUMAXH_LDUMAXH_32_MEMOP:
		case ENC_STUMAXLH_LDUMAXLH_32_MEMOP:
		case ENC_STUMAX_LDUMAX_32_MEMOP:
		case ENC_STUMAXL_LDUMAXL_32_MEMOP:
		case ENC_STUMAX_LDUMAX_64_MEMOP:
		case ENC_STUMAXL_LDUMAXL_64_MEMOP:
		case ENC_STUMINB_LDUMINB_32_MEMOP:
		case ENC_STUMINLB_LDUMINLB_32_MEMOP:
		case ENC_STUMINH_LDUMINH_32_MEMOP:
		case ENC_STUMINLH_LDUMINLH_32_MEMOP:
		case ENC_STUMIN_LDUMIN_32_MEMOP:
		case ENC_STUMINL_LDUMINL_32_MEMOP:
		case ENC_STUMIN_LDUMIN_64_MEMOP:
		case ENC_STUMINL_LDUMINL_64_MEMOP:
		case ENC_SWP_32_MEMOP:
		case ENC_SWPA_32_MEMOP:
		case ENC_SWPAL_32_MEMOP:
		case ENC_SWPL_32_MEMOP:
		case ENC_SWP_64_MEMOP:
		case ENC_SWPA_64_MEMOP:
		case ENC_SWPAL_64_MEMOP:
		case ENC_SWPL_64_MEMOP:
		case ENC_SWPB_32_MEMOP:
		case ENC_SWPAB_32_MEMOP:
		case ENC_SWPALB_32_MEMOP:
		case ENC_SWPLB_32_MEMOP:
		case ENC_SWPH_32_MEMOP:
		case ENC_SWPAH_32_MEMOP:
		case ENC_SWPALH_32_MEMOP:
		case ENC_SWPLH_32_MEMOP:
			// size=xx|xxx|VR=x|xx|A=x|R=x|x|Rs=xxxxx|o3=x|opc=xxx|xx|Rn=xxxxx|Rt=xxxxx
			ctx->size = insword>>30;
			ctx->VR = (insword>>26)&1;
			ctx->A = (insword>>23)&1;
			ctx->R = (insword>>22)&1;
			ctx->Rs = (insword>>16)&0x1f;
			ctx->o3 = (insword>>15)&1;
			ctx->opc = (insword>>12)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_LDRAA_64_LDST_PAC:
		case ENC_LDRAA_64W_LDST_PAC:
		case ENC_LDRAB_64_LDST_PAC:
		case ENC_LDRAB_64W_LDST_PAC:
			// size=xx|xxx|VR=x|xx|M=x|S=x|x|imm9=xxxxxxxxx|W=x|x|Rn=xxxxx|Rt=xxxxx
			ctx->size = insword>>30;
			ctx->VR = (insword>>26)&1;
			ctx->M = (insword>>23)&1;
			ctx->S = (insword>>22)&1;
			ctx->imm9 = (insword>>12)&0x1ff;
			ctx->W = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_LDRSB_32_LDST_POS:
		case ENC_LDRSB_64_LDST_POS:
		case ENC_LDRSH_32_LDST_POS:
		case ENC_LDRSH_64_LDST_POS:
		case ENC_LDR_B_LDST_POS:
		case ENC_LDR_H_LDST_POS:
		case ENC_LDR_S_LDST_POS:
		case ENC_LDR_D_LDST_POS:
		case ENC_LDR_Q_LDST_POS:
		case ENC_LDR_32_LDST_POS:
		case ENC_LDR_64_LDST_POS:
		case ENC_STR_B_LDST_POS:
		case ENC_STR_H_LDST_POS:
		case ENC_STR_S_LDST_POS:
		case ENC_STR_D_LDST_POS:
		case ENC_STR_Q_LDST_POS:
		case ENC_STR_32_LDST_POS:
		case ENC_STR_64_LDST_POS:
			// size=xx|xxx|VR=x|xx|opc=xx|imm12=xxxxxxxxxxxx|Rn=xxxxx|Rt=xxxxx
			ctx->size = insword>>30;
			ctx->VR = (insword>>26)&1;
			ctx->opc = (insword>>22)&3;
			ctx->imm12 = (insword>>10)&0xfff;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_LDRB_32B_LDST_REGOFF:
		case ENC_LDRB_32BL_LDST_REGOFF:
		case ENC_LDRSB_32B_LDST_REGOFF:
		case ENC_LDRSB_32BL_LDST_REGOFF:
		case ENC_LDRSB_64B_LDST_REGOFF:
		case ENC_LDRSB_64BL_LDST_REGOFF:
		case ENC_LDRSH_32_LDST_REGOFF:
		case ENC_LDRSH_64_LDST_REGOFF:
		case ENC_LDR_B_LDST_REGOFF:
		case ENC_LDR_BL_LDST_REGOFF:
		case ENC_LDR_H_LDST_REGOFF:
		case ENC_LDR_S_LDST_REGOFF:
		case ENC_LDR_D_LDST_REGOFF:
		case ENC_LDR_Q_LDST_REGOFF:
		case ENC_LDR_32_LDST_REGOFF:
		case ENC_LDR_64_LDST_REGOFF:
		case ENC_STRB_32B_LDST_REGOFF:
		case ENC_STRB_32BL_LDST_REGOFF:
		case ENC_STR_B_LDST_REGOFF:
		case ENC_STR_BL_LDST_REGOFF:
		case ENC_STR_H_LDST_REGOFF:
		case ENC_STR_S_LDST_REGOFF:
		case ENC_STR_D_LDST_REGOFF:
		case ENC_STR_Q_LDST_REGOFF:
		case ENC_STR_32_LDST_REGOFF:
		case ENC_STR_64_LDST_REGOFF:
			// size=xx|xxx|VR=x|xx|opc=xx|x|Rm=xxxxx|option=xxx|S=x|xx|Rn=xxxxx|Rt=xxxxx
			ctx->size = insword>>30;
			ctx->VR = (insword>>26)&1;
			ctx->opc = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->option = (insword>>13)&7;
			ctx->S = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_LDRSB_32_LDST_IMMPOST:
		case ENC_LDRSB_64_LDST_IMMPOST:
		case ENC_LDRSB_32_LDST_IMMPRE:
		case ENC_LDRSB_64_LDST_IMMPRE:
		case ENC_LDRSH_32_LDST_IMMPOST:
		case ENC_LDRSH_64_LDST_IMMPOST:
		case ENC_LDRSH_32_LDST_IMMPRE:
		case ENC_LDRSH_64_LDST_IMMPRE:
		case ENC_LDR_B_LDST_IMMPOST:
		case ENC_LDR_H_LDST_IMMPOST:
		case ENC_LDR_S_LDST_IMMPOST:
		case ENC_LDR_D_LDST_IMMPOST:
		case ENC_LDR_Q_LDST_IMMPOST:
		case ENC_LDR_B_LDST_IMMPRE:
		case ENC_LDR_H_LDST_IMMPRE:
		case ENC_LDR_S_LDST_IMMPRE:
		case ENC_LDR_D_LDST_IMMPRE:
		case ENC_LDR_Q_LDST_IMMPRE:
		case ENC_LDR_32_LDST_IMMPOST:
		case ENC_LDR_64_LDST_IMMPOST:
		case ENC_LDR_32_LDST_IMMPRE:
		case ENC_LDR_64_LDST_IMMPRE:
		case ENC_LDTR_32_LDST_UNPRIV:
		case ENC_LDTR_64_LDST_UNPRIV:
		case ENC_LDTRSB_32_LDST_UNPRIV:
		case ENC_LDTRSB_64_LDST_UNPRIV:
		case ENC_LDTRSH_32_LDST_UNPRIV:
		case ENC_LDTRSH_64_LDST_UNPRIV:
		case ENC_LDURSB_32_LDST_UNSCALED:
		case ENC_LDURSB_64_LDST_UNSCALED:
		case ENC_LDURSH_32_LDST_UNSCALED:
		case ENC_LDURSH_64_LDST_UNSCALED:
		case ENC_LDUR_B_LDST_UNSCALED:
		case ENC_LDUR_H_LDST_UNSCALED:
		case ENC_LDUR_S_LDST_UNSCALED:
		case ENC_LDUR_D_LDST_UNSCALED:
		case ENC_LDUR_Q_LDST_UNSCALED:
		case ENC_LDUR_32_LDST_UNSCALED:
		case ENC_LDUR_64_LDST_UNSCALED:
		case ENC_STR_B_LDST_IMMPOST:
		case ENC_STR_H_LDST_IMMPOST:
		case ENC_STR_S_LDST_IMMPOST:
		case ENC_STR_D_LDST_IMMPOST:
		case ENC_STR_Q_LDST_IMMPOST:
		case ENC_STR_B_LDST_IMMPRE:
		case ENC_STR_H_LDST_IMMPRE:
		case ENC_STR_S_LDST_IMMPRE:
		case ENC_STR_D_LDST_IMMPRE:
		case ENC_STR_Q_LDST_IMMPRE:
		case ENC_STR_32_LDST_IMMPOST:
		case ENC_STR_64_LDST_IMMPOST:
		case ENC_STR_32_LDST_IMMPRE:
		case ENC_STR_64_LDST_IMMPRE:
		case ENC_STTR_32_LDST_UNPRIV:
		case ENC_STTR_64_LDST_UNPRIV:
		case ENC_STUR_B_LDST_UNSCALED:
		case ENC_STUR_H_LDST_UNSCALED:
		case ENC_STUR_S_LDST_UNSCALED:
		case ENC_STUR_D_LDST_UNSCALED:
		case ENC_STUR_Q_LDST_UNSCALED:
		case ENC_STUR_32_LDST_UNSCALED:
		case ENC_STUR_64_LDST_UNSCALED:
			// size=xx|xxx|VR=x|xx|opc=xx|x|imm9=xxxxxxxxx|xx|Rn=xxxxx|Rt=xxxxx
			ctx->size = insword>>30;
			ctx->VR = (insword>>26)&1;
			ctx->opc = (insword>>22)&3;
			ctx->imm9 = (insword>>12)&0x1ff;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_LD64B_64L_MEMOP:
		case ENC_LDAPRB_32L_MEMOP:
		case ENC_LDAPRH_32L_MEMOP:
		case ENC_ST64B_64L_MEMOP:
		case ENC_ST64BV_64_MEMOP:
		case ENC_ST64BV0_64_MEMOP:
			// size=xx|xx|x|VR=x|x|x|A=x|R=x|x|Rs=xxxxx|o3=x|opc=xxx|xx|Rn=xxxxx|Rt=xxxxx
			ctx->size = insword>>30;
			ctx->VR = (insword>>26)&1;
			ctx->A = (insword>>23)&1;
			ctx->R = (insword>>22)&1;
			ctx->Rs = (insword>>16)&0x1f;
			ctx->o3 = (insword>>15)&1;
			ctx->opc = (insword>>12)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_LDRB_32_LDST_POS:
		case ENC_LDRH_32_LDST_POS:
		case ENC_LDRSW_64_LDST_POS:
		case ENC_PRFM_P_LDST_POS:
		case ENC_STRB_32_LDST_POS:
		case ENC_STRH_32_LDST_POS:
			// size=xx|xx|x|VR=x|x|x|opc=xx|imm12=xxxxxxxxxxxx|Rn=xxxxx|Rt=xxxxx
			ctx->size = insword>>30;
			ctx->VR = (insword>>26)&1;
			ctx->opc = (insword>>22)&3;
			ctx->imm12 = (insword>>10)&0xfff;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_LDRH_32_LDST_REGOFF:
		case ENC_LDRSW_64_LDST_REGOFF:
		case ENC_PRFM_P_LDST_REGOFF:
		case ENC_RPRFM_R_LDST_REGOFF:
		case ENC_STRH_32_LDST_REGOFF:
			// size=xx|xx|x|VR=x|x|x|opc=xx|x|Rm=xxxxx|option=xxx|S=x|xx|Rn=xxxxx|Rt=xxxxx
			ctx->size = insword>>30;
			ctx->VR = (insword>>26)&1;
			ctx->opc = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->option = (insword>>13)&7;
			ctx->S = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_LDRB_32_LDST_IMMPOST:
		case ENC_LDRB_32_LDST_IMMPRE:
		case ENC_LDRH_32_LDST_IMMPOST:
		case ENC_LDRH_32_LDST_IMMPRE:
		case ENC_LDRSW_64_LDST_IMMPOST:
		case ENC_LDRSW_64_LDST_IMMPRE:
		case ENC_LDTRB_32_LDST_UNPRIV:
		case ENC_LDTRH_32_LDST_UNPRIV:
		case ENC_LDTRSW_64_LDST_UNPRIV:
		case ENC_LDURB_32_LDST_UNSCALED:
		case ENC_LDURH_32_LDST_UNSCALED:
		case ENC_LDURSW_64_LDST_UNSCALED:
		case ENC_PRFUM_P_LDST_UNSCALED:
		case ENC_STRB_32_LDST_IMMPOST:
		case ENC_STRB_32_LDST_IMMPRE:
		case ENC_STRH_32_LDST_IMMPOST:
		case ENC_STRH_32_LDST_IMMPRE:
		case ENC_STTRB_32_LDST_UNPRIV:
		case ENC_STTRH_32_LDST_UNPRIV:
		case ENC_STURB_32_LDST_UNSCALED:
		case ENC_STURH_32_LDST_UNSCALED:
			// size=xx|xx|x|VR=x|x|x|opc=xx|x|imm9=xxxxxxxxx|xx|Rn=xxxxx|Rt=xxxxx
			ctx->size = insword>>30;
			ctx->VR = (insword>>26)&1;
			ctx->opc = (insword>>22)&3;
			ctx->imm9 = (insword>>12)&0x1ff;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_LDARB_LR32_LDSTORD:
		case ENC_LDARH_LR32_LDSTORD:
		case ENC_LDAXRB_LR32_LDSTEXCLR:
		case ENC_LDAXRH_LR32_LDSTEXCLR:
		case ENC_LDLARB_LR32_LDSTORD:
		case ENC_LDLARH_LR32_LDSTORD:
		case ENC_LDXRB_LR32_LDSTEXCLR:
		case ENC_LDXRH_LR32_LDSTEXCLR:
		case ENC_STLLRB_SL32_LDSTORD:
		case ENC_STLLRH_SL32_LDSTORD:
		case ENC_STLRB_SL32_LDSTORD:
		case ENC_STLRH_SL32_LDSTORD:
		case ENC_STLXRB_SR32_LDSTEXCLR:
		case ENC_STLXRH_SR32_LDSTEXCLR:
		case ENC_STXRB_SR32_LDSTEXCLR:
		case ENC_STXRH_SR32_LDSTEXCLR:
			// size=xx|xx|x|x|x|xx|L=x|x|Rs=xxxxx|o0=x|Rt2=xxxxx|Rn=xxxxx|Rt=xxxxx
			ctx->size = insword>>30;
			ctx->L = (insword>>22)&1;
			ctx->Rs = (insword>>16)&0x1f;
			ctx->o0 = (insword>>15)&1;
			ctx->Rt2 = (insword>>10)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_LDAPP_64_LDIAPPSTILP:
		case ENC_LDAP_64_LDIAPPSTILP:
		case ENC_STLP_64_LDIAPPSTILP:
			// size=xx|xx|x|x|x|xx|L=x|x|Rt2=xxxxx|opc2=xxxx|xx|Rn=xxxxx|Rt=xxxxx
			ctx->size = insword>>30;
			ctx->L = (insword>>22)&1;
			ctx->Rt2 = (insword>>16)&0x1f;
			ctx->opc2 = (insword>>12)&15;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_LDAPURB_32_LDAPSTL_UNSCALED:
		case ENC_LDAPURH_32_LDAPSTL_UNSCALED:
		case ENC_LDAPURSW_64_LDAPSTL_UNSCALED:
		case ENC_STLURB_32_LDAPSTL_UNSCALED:
		case ENC_STLURH_32_LDAPSTL_UNSCALED:
			// size=xx|xx|x|x|x|x|opc=xx|x|imm9=xxxxxxxxx|xx|Rn=xxxxx|Rt=xxxxx
			ctx->size = insword>>30;
			ctx->opc = (insword>>22)&3;
			ctx->imm9 = (insword>>12)&0x1ff;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_CPYFP_CPY_MEMCMS:
		case ENC_CPYFM_CPY_MEMCMS:
		case ENC_CPYFE_CPY_MEMCMS:
		case ENC_CPYFPN_CPY_MEMCMS:
		case ENC_CPYFMN_CPY_MEMCMS:
		case ENC_CPYFEN_CPY_MEMCMS:
		case ENC_CPYFPRN_CPY_MEMCMS:
		case ENC_CPYFMRN_CPY_MEMCMS:
		case ENC_CPYFERN_CPY_MEMCMS:
		case ENC_CPYFPRT_CPY_MEMCMS:
		case ENC_CPYFMRT_CPY_MEMCMS:
		case ENC_CPYFERT_CPY_MEMCMS:
		case ENC_CPYFPRTN_CPY_MEMCMS:
		case ENC_CPYFMRTN_CPY_MEMCMS:
		case ENC_CPYFERTN_CPY_MEMCMS:
		case ENC_CPYFPRTRN_CPY_MEMCMS:
		case ENC_CPYFMRTRN_CPY_MEMCMS:
		case ENC_CPYFERTRN_CPY_MEMCMS:
		case ENC_CPYFPRTWN_CPY_MEMCMS:
		case ENC_CPYFMRTWN_CPY_MEMCMS:
		case ENC_CPYFERTWN_CPY_MEMCMS:
		case ENC_CPYFPT_CPY_MEMCMS:
		case ENC_CPYFMT_CPY_MEMCMS:
		case ENC_CPYFET_CPY_MEMCMS:
		case ENC_CPYFPTN_CPY_MEMCMS:
		case ENC_CPYFMTN_CPY_MEMCMS:
		case ENC_CPYFETN_CPY_MEMCMS:
		case ENC_CPYFPTRN_CPY_MEMCMS:
		case ENC_CPYFMTRN_CPY_MEMCMS:
		case ENC_CPYFETRN_CPY_MEMCMS:
		case ENC_CPYFPTWN_CPY_MEMCMS:
		case ENC_CPYFMTWN_CPY_MEMCMS:
		case ENC_CPYFETWN_CPY_MEMCMS:
		case ENC_CPYFPWN_CPY_MEMCMS:
		case ENC_CPYFMWN_CPY_MEMCMS:
		case ENC_CPYFEWN_CPY_MEMCMS:
		case ENC_CPYFPWT_CPY_MEMCMS:
		case ENC_CPYFMWT_CPY_MEMCMS:
		case ENC_CPYFEWT_CPY_MEMCMS:
		case ENC_CPYFPWTN_CPY_MEMCMS:
		case ENC_CPYFMWTN_CPY_MEMCMS:
		case ENC_CPYFEWTN_CPY_MEMCMS:
		case ENC_CPYFPWTRN_CPY_MEMCMS:
		case ENC_CPYFMWTRN_CPY_MEMCMS:
		case ENC_CPYFEWTRN_CPY_MEMCMS:
		case ENC_CPYFPWTWN_CPY_MEMCMS:
		case ENC_CPYFMWTWN_CPY_MEMCMS:
		case ENC_CPYFEWTWN_CPY_MEMCMS:
		case ENC_CPYP_CPY_MEMCMS:
		case ENC_CPYM_CPY_MEMCMS:
		case ENC_CPYE_CPY_MEMCMS:
		case ENC_CPYPN_CPY_MEMCMS:
		case ENC_CPYMN_CPY_MEMCMS:
		case ENC_CPYEN_CPY_MEMCMS:
		case ENC_CPYPRN_CPY_MEMCMS:
		case ENC_CPYMRN_CPY_MEMCMS:
		case ENC_CPYERN_CPY_MEMCMS:
		case ENC_CPYPRT_CPY_MEMCMS:
		case ENC_CPYMRT_CPY_MEMCMS:
		case ENC_CPYERT_CPY_MEMCMS:
		case ENC_CPYPRTN_CPY_MEMCMS:
		case ENC_CPYMRTN_CPY_MEMCMS:
		case ENC_CPYERTN_CPY_MEMCMS:
		case ENC_CPYPRTRN_CPY_MEMCMS:
		case ENC_CPYMRTRN_CPY_MEMCMS:
		case ENC_CPYERTRN_CPY_MEMCMS:
		case ENC_CPYPRTWN_CPY_MEMCMS:
		case ENC_CPYMRTWN_CPY_MEMCMS:
		case ENC_CPYERTWN_CPY_MEMCMS:
		case ENC_CPYPT_CPY_MEMCMS:
		case ENC_CPYMT_CPY_MEMCMS:
		case ENC_CPYET_CPY_MEMCMS:
		case ENC_CPYPTN_CPY_MEMCMS:
		case ENC_CPYMTN_CPY_MEMCMS:
		case ENC_CPYETN_CPY_MEMCMS:
		case ENC_CPYPTRN_CPY_MEMCMS:
		case ENC_CPYMTRN_CPY_MEMCMS:
		case ENC_CPYETRN_CPY_MEMCMS:
		case ENC_CPYPTWN_CPY_MEMCMS:
		case ENC_CPYMTWN_CPY_MEMCMS:
		case ENC_CPYETWN_CPY_MEMCMS:
		case ENC_CPYPWN_CPY_MEMCMS:
		case ENC_CPYMWN_CPY_MEMCMS:
		case ENC_CPYEWN_CPY_MEMCMS:
		case ENC_CPYPWT_CPY_MEMCMS:
		case ENC_CPYMWT_CPY_MEMCMS:
		case ENC_CPYEWT_CPY_MEMCMS:
		case ENC_CPYPWTN_CPY_MEMCMS:
		case ENC_CPYMWTN_CPY_MEMCMS:
		case ENC_CPYEWTN_CPY_MEMCMS:
		case ENC_CPYPWTRN_CPY_MEMCMS:
		case ENC_CPYMWTRN_CPY_MEMCMS:
		case ENC_CPYEWTRN_CPY_MEMCMS:
		case ENC_CPYPWTWN_CPY_MEMCMS:
		case ENC_CPYMWTWN_CPY_MEMCMS:
		case ENC_CPYEWTWN_CPY_MEMCMS:
		case ENC_SETGP_SET_MEMCMS:
		case ENC_SETGM_SET_MEMCMS:
		case ENC_SETGE_SET_MEMCMS:
		case ENC_SETGPN_SET_MEMCMS:
		case ENC_SETGMN_SET_MEMCMS:
		case ENC_SETGEN_SET_MEMCMS:
		case ENC_SETGPT_SET_MEMCMS:
		case ENC_SETGMT_SET_MEMCMS:
		case ENC_SETGET_SET_MEMCMS:
		case ENC_SETGPTN_SET_MEMCMS:
		case ENC_SETGMTN_SET_MEMCMS:
		case ENC_SETGETN_SET_MEMCMS:
		case ENC_SETP_SET_MEMCMS:
		case ENC_SETM_SET_MEMCMS:
		case ENC_SETE_SET_MEMCMS:
		case ENC_SETPN_SET_MEMCMS:
		case ENC_SETMN_SET_MEMCMS:
		case ENC_SETEN_SET_MEMCMS:
		case ENC_SETPT_SET_MEMCMS:
		case ENC_SETMT_SET_MEMCMS:
		case ENC_SETET_SET_MEMCMS:
		case ENC_SETPTN_SET_MEMCMS:
		case ENC_SETMTN_SET_MEMCMS:
		case ENC_SETETN_SET_MEMCMS:
			// sz=xx|xxx|o0=x|xx|op1=xx|x|Rs=xxxxx|op2=xxxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->sz = insword>>30;
			ctx->o0 = (insword>>26)&1;
			ctx->op1 = (insword>>22)&3;
			ctx->Rs = (insword>>16)&0x1f;
			ctx->op2 = (insword>>12)&15;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_AUTIA1716_HI_HINTS:
		case ENC_AUTIASP_HI_HINTS:
		case ENC_AUTIAZ_HI_HINTS:
		case ENC_AUTIB1716_HI_HINTS:
		case ENC_AUTIBSP_HI_HINTS:
		case ENC_AUTIBZ_HI_HINTS:
		case ENC_PACIA1716_HI_HINTS:
		case ENC_PACIASP_HI_HINTS:
		case ENC_PACIAZ_HI_HINTS:
		case ENC_PACIB1716_HI_HINTS:
		case ENC_PACIBSP_HI_HINTS:
		case ENC_PACIBZ_HI_HINTS:
			// xxxxxxxxxxxxxxxxxxxx|CRm=xxxx|op2=xxx|xxxxx
			ctx->CRm = (insword>>8)&15;
			ctx->op2 = (insword>>5)&7;
			break;
		case ENC_CBBGT_8_REGS:
		case ENC_CBBGE_8_REGS:
		case ENC_CBBHI_8_REGS:
		case ENC_CBBHS_8_REGS:
		case ENC_CBBEQ_8_REGS:
		case ENC_CBBNE_8_REGS:
		case ENC_CBHGT_16_REGS:
		case ENC_CBHGE_16_REGS:
		case ENC_CBHHI_16_REGS:
		case ENC_CBHHS_16_REGS:
		case ENC_CBHEQ_16_REGS:
		case ENC_CBHNE_16_REGS:
			// xxxxxxxx|cc=xxx|Rm=xxxxx|x|H=x|imm9=xxxxxxxxx|Rt=xxxxx
			ctx->cc = (insword>>21)&7;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->H = (insword>>14)&1;
			ctx->imm9 = (insword>>5)&0x1ff;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_MOV_Z_V__DUP_Z_ZI_:
		case ENC_MOV_Z_ZI__DUP_Z_ZI_:
			// xxxxxxxx|imm2=xx|x|tsz=xxxxx|xxxxxx|Zn=xxxxx|Zd=xxxxx
			ctx->imm2 = (insword>>22)&3;
			ctx->tsz = (insword>>16)&0x1f;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_RETAASPPC_ONLY_MISCBRANCH:
		case ENC_RETABSPPC_ONLY_MISCBRANCH:
			// xxxxxxxx|opc=xxx|imm16=xxxxxxxxxxxxxxxx|op2=xxxxx
			ctx->opc = (insword>>21)&7;
			ctx->imm16 = (insword>>5)&0xffff;
			ctx->op2 = insword&0x1f;
			break;
		case ENC_BLRAA_64P_BRANCH_REG:
		case ENC_BLRAAZ_64_BRANCH_REG:
		case ENC_BLRAB_64P_BRANCH_REG:
		case ENC_BLRABZ_64_BRANCH_REG:
		case ENC_BRAA_64P_BRANCH_REG:
		case ENC_BRAAZ_64_BRANCH_REG:
		case ENC_BRAB_64P_BRANCH_REG:
		case ENC_BRABZ_64_BRANCH_REG:
		case ENC_RETAA_64E_BRANCH_REG:
		case ENC_RETAB_64E_BRANCH_REG:
			// xxxxxxx|Z=x|x|op=xx|op2=xxxxx|xxxx|A=x|M=x|Rn=xxxxx|Rm=xxxxx
			ctx->Z = (insword>>24)&1;
			ctx->op = (insword>>21)&3;
			ctx->op2 = (insword>>16)&0x1f;
			ctx->A = (insword>>11)&1;
			ctx->M = (insword>>10)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rm = insword&0x1f;
			break;
		case ENC_RETAASPPCR_64M_BRANCH_REG:
		case ENC_RETABSPPCR_64M_BRANCH_REG:
			// xxxxxxx|opc=xxxx|op2=xxxxx|xxxxx|M=x|Rn=xxxxx|Rm=xxxxx
			ctx->opc = (insword>>21)&15;
			ctx->op2 = (insword>>16)&0x1f;
			ctx->M = (insword>>10)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rm = insword&0x1f;
			break;
		case ENC_ERETAA_64E_BRANCH_REG:
		case ENC_ERETAB_64E_BRANCH_REG:
			// xxxxxxx|opc=xxxx|op2=xxxxx|xxxx|A=x|M=x|Rn=xxxxx|op4=xxxxx
			ctx->opc = (insword>>21)&15;
			ctx->op2 = (insword>>16)&0x1f;
			ctx->A = (insword>>11)&1;
			ctx->M = (insword>>10)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->op4 = insword&0x1f;
			break;
		case ENC_BCAX_VVV16_CRYPTO4:
		case ENC_EOR3_VVV16_CRYPTO4:
		case ENC_SM3SS1_VVV4_CRYPTO4:
			// xxxx|xxx|xx|Op0=xx|Rm=xxxxx|x|Ra=xxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->Op0 = (insword>>21)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->Ra = (insword>>10)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SHA512SU0_VV2_CRYPTOSHA512_2:
		case ENC_SM4E_VV4_CRYPTOSHA512_2:
			// xxxx|xxx|xx|xxxx|xxxxxxx|opcode=xx|Rn=xxxxx|Rd=xxxxx
			ctx->opcode = (insword>>10)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_XAR_VVV2_CRYPTO3_IMM6:
			// xxxx|xxx|xx|xx|Rm=xxxxx|imm6=xxxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->Rm = (insword>>16)&0x1f;
			ctx->imm6 = (insword>>10)&0x3f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SM3TT1A_VVV4_CRYPTO3_IMM2:
		case ENC_SM3TT1B_VVV4_CRYPTO3_IMM2:
		case ENC_SM3TT2A_VVV4_CRYPTO3_IMM2:
		case ENC_SM3TT2B_VVV_CRYPTO3_IMM2:
			// xxxx|xxx|xx|xx|Rm=xxxxx|xx|imm2=xx|opcode=xx|Rn=xxxxx|Rd=xxxxx
			ctx->Rm = (insword>>16)&0x1f;
			ctx->imm2 = (insword>>12)&3;
			ctx->opcode = (insword>>10)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_RAX1_VVV2_CRYPTOSHA512_3:
		case ENC_SHA512H2_QQV_CRYPTOSHA512_3:
		case ENC_SHA512H_QQV_CRYPTOSHA512_3:
		case ENC_SHA512SU1_VVV2_CRYPTOSHA512_3:
		case ENC_SM3PARTW1_VVV4_CRYPTOSHA512_3:
		case ENC_SM3PARTW2_VVV4_CRYPTOSHA512_3:
		case ENC_SM4EKEY_VVV4_CRYPTOSHA512_3:
			// xxxx|xxx|xx|xx|Rm=xxxxx|x|O=x|xx|opcode=xx|Rn=xxxxx|Rd=xxxxx
			ctx->Rm = (insword>>16)&0x1f;
			ctx->O = (insword>>14)&1;
			ctx->opcode = (insword>>10)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SHA1H_SS_CRYPTOSHA2:
		case ENC_SHA1SU1_VV_CRYPTOSHA2:
		case ENC_SHA256SU0_VV_CRYPTOSHA2:
			// xxxx|xxx|x|size=xx|xxxxx|opcode=xxxxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opcode = (insword>>12)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_AESD_B_CRYPTOAES:
		case ENC_AESE_B_CRYPTOAES:
		case ENC_AESIMC_B_CRYPTOAES:
		case ENC_AESMC_B_CRYPTOAES:
			// xxxx|xxx|x|size=xx|xxxxx|xxxx|D=x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->D = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SHA1C_QSV_CRYPTOSHA3:
		case ENC_SHA1M_QSV_CRYPTOSHA3:
		case ENC_SHA1P_QSV_CRYPTOSHA3:
		case ENC_SHA1SU0_VVV_CRYPTOSHA3:
		case ENC_SHA256SU1_VVV_CRYPTOSHA3:
			// xxxx|xxx|x|size=xx|x|Rm=xxxxx|x|opcode=xxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>12)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SHA256H2_QQV_CRYPTOSHA3:
		case ENC_SHA256H_QQV_CRYPTOSHA3:
			// xxxx|xxx|x|size=xx|x|Rm=xxxxx|x|xx|P=x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->P = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_GCSSTR_64_LDST_GCS:
		case ENC_GCSSTTR_64_LDST_GCS:
			// xxxx|x|x|x|xxxxxxxxxx|opc=xxx|xx|Rn=xxxxx|Rt=xxxxx
			ctx->opc = (insword>>12)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_LDG_64LOFFSET_LDSTTAGS:
		case ENC_LDGM_64BULK_LDSTTAGS:
		case ENC_ST2G_64SPOST_LDSTTAGS:
		case ENC_ST2G_64SPRE_LDSTTAGS:
		case ENC_ST2G_64SOFFSET_LDSTTAGS:
		case ENC_STG_64SPOST_LDSTTAGS:
		case ENC_STG_64SPRE_LDSTTAGS:
		case ENC_STG_64SOFFSET_LDSTTAGS:
		case ENC_STGM_64BULK_LDSTTAGS:
		case ENC_STZ2G_64SPOST_LDSTTAGS:
		case ENC_STZ2G_64SPRE_LDSTTAGS:
		case ENC_STZ2G_64SOFFSET_LDSTTAGS:
		case ENC_STZG_64SPOST_LDSTTAGS:
		case ENC_STZG_64SPRE_LDSTTAGS:
		case ENC_STZG_64SOFFSET_LDSTTAGS:
		case ENC_STZGM_64BULK_LDSTTAGS:
			// xxxx|x|x|x|x|opc=xx|x|imm9=xxxxxxxxx|op2=xx|Rn=xxxxx|Rt=xxxxx
			ctx->opc = (insword>>22)&3;
			ctx->imm9 = (insword>>12)&0x1ff;
			ctx->op2 = (insword>>10)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_LD1B_Z_P_BR_U8:
		case ENC_LD1B_Z_P_BR_U16:
		case ENC_LD1B_Z_P_BR_U32:
		case ENC_LD1B_Z_P_BR_U64:
		case ENC_LD1D_Z_P_BR_U64:
		case ENC_LD1H_Z_P_BR_U16:
		case ENC_LD1H_Z_P_BR_U32:
		case ENC_LD1H_Z_P_BR_U64:
		case ENC_LD1SB_Z_P_BR_S16:
		case ENC_LD1SB_Z_P_BR_S32:
		case ENC_LD1SB_Z_P_BR_S64:
		case ENC_LD1SH_Z_P_BR_S32:
		case ENC_LD1SH_Z_P_BR_S64:
		case ENC_LD1SW_Z_P_BR_S64:
		case ENC_LD1W_Z_P_BR_U32:
		case ENC_LD1W_Z_P_BR_U64:
		case ENC_LDFF1B_Z_P_BR_U8:
		case ENC_LDFF1B_Z_P_BR_U16:
		case ENC_LDFF1B_Z_P_BR_U32:
		case ENC_LDFF1B_Z_P_BR_U64:
		case ENC_LDFF1D_Z_P_BR_U64:
		case ENC_LDFF1H_Z_P_BR_U16:
		case ENC_LDFF1H_Z_P_BR_U32:
		case ENC_LDFF1H_Z_P_BR_U64:
		case ENC_LDFF1SB_Z_P_BR_S16:
		case ENC_LDFF1SB_Z_P_BR_S32:
		case ENC_LDFF1SB_Z_P_BR_S64:
		case ENC_LDFF1SH_Z_P_BR_S32:
		case ENC_LDFF1SH_Z_P_BR_S64:
		case ENC_LDFF1SW_Z_P_BR_S64:
		case ENC_LDFF1W_Z_P_BR_U32:
		case ENC_LDFF1W_Z_P_BR_U64:
			// xxx|xxxx|dtype=xxxx|Rm=xxxxx|xxx|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->dtype = (insword>>21)&15;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_LD1B_Z_P_BI_U8:
		case ENC_LD1B_Z_P_BI_U16:
		case ENC_LD1B_Z_P_BI_U32:
		case ENC_LD1B_Z_P_BI_U64:
		case ENC_LD1D_Z_P_BI_U64:
		case ENC_LD1H_Z_P_BI_U16:
		case ENC_LD1H_Z_P_BI_U32:
		case ENC_LD1H_Z_P_BI_U64:
		case ENC_LD1SB_Z_P_BI_S16:
		case ENC_LD1SB_Z_P_BI_S32:
		case ENC_LD1SB_Z_P_BI_S64:
		case ENC_LD1SH_Z_P_BI_S32:
		case ENC_LD1SH_Z_P_BI_S64:
		case ENC_LD1SW_Z_P_BI_S64:
		case ENC_LD1W_Z_P_BI_U32:
		case ENC_LD1W_Z_P_BI_U64:
		case ENC_LDNF1B_Z_P_BI_U8:
		case ENC_LDNF1B_Z_P_BI_U16:
		case ENC_LDNF1B_Z_P_BI_U32:
		case ENC_LDNF1B_Z_P_BI_U64:
		case ENC_LDNF1D_Z_P_BI_U64:
		case ENC_LDNF1H_Z_P_BI_U16:
		case ENC_LDNF1H_Z_P_BI_U32:
		case ENC_LDNF1H_Z_P_BI_U64:
		case ENC_LDNF1SB_Z_P_BI_S16:
		case ENC_LDNF1SB_Z_P_BI_S32:
		case ENC_LDNF1SB_Z_P_BI_S64:
		case ENC_LDNF1SH_Z_P_BI_S32:
		case ENC_LDNF1SH_Z_P_BI_S64:
		case ENC_LDNF1SW_Z_P_BI_S64:
		case ENC_LDNF1W_Z_P_BI_U32:
		case ENC_LDNF1W_Z_P_BI_U64:
			// xxx|xxxx|dtype=xxxx|x|imm4=xxxx|xxx|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->dtype = (insword>>21)&15;
			ctx->imm4 = (insword>>16)&15;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_LD1D_Z_P_BR_U128:
		case ENC_LD1W_Z_P_BR_U128:
			// xxx|xxxx|dtype=xx|xx|Rm=xxxxx|xxx|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->dtype = (insword>>23)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_LD1D_Z_P_BI_U128:
		case ENC_LD1W_Z_P_BI_U128:
			// xxx|xxxx|dtype=xx|xx|x|imm4=xxxx|xxx|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->dtype = (insword>>23)&3;
			ctx->imm4 = (insword>>16)&15;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_LD1RB_Z_P_BI_U8:
		case ENC_LD1RB_Z_P_BI_U16:
		case ENC_LD1RB_Z_P_BI_U32:
		case ENC_LD1RB_Z_P_BI_U64:
		case ENC_LD1RD_Z_P_BI_U64:
		case ENC_LD1RH_Z_P_BI_U16:
		case ENC_LD1RH_Z_P_BI_U32:
		case ENC_LD1RH_Z_P_BI_U64:
		case ENC_LD1RSB_Z_P_BI_S16:
		case ENC_LD1RSB_Z_P_BI_S32:
		case ENC_LD1RSB_Z_P_BI_S64:
		case ENC_LD1RSH_Z_P_BI_S32:
		case ENC_LD1RSH_Z_P_BI_S64:
		case ENC_LD1RSW_Z_P_BI_S64:
		case ENC_LD1RW_Z_P_BI_U32:
		case ENC_LD1RW_Z_P_BI_U64:
			// xxx|xxxx|dtypeh=xx|x|imm6=xxxxxx|x|dtypel=xx|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->dtypeh = (insword>>23)&3;
			ctx->imm6 = (insword>>16)&0x3f;
			ctx->dtypel = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_LD2B_Z_P_BR_CONTIGUOUS:
		case ENC_LD2D_Z_P_BR_CONTIGUOUS:
		case ENC_LD2H_Z_P_BR_CONTIGUOUS:
		case ENC_LD2W_Z_P_BR_CONTIGUOUS:
		case ENC_LD3B_Z_P_BR_CONTIGUOUS:
		case ENC_LD3D_Z_P_BR_CONTIGUOUS:
		case ENC_LD3H_Z_P_BR_CONTIGUOUS:
		case ENC_LD3W_Z_P_BR_CONTIGUOUS:
		case ENC_LD4B_Z_P_BR_CONTIGUOUS:
		case ENC_LD4D_Z_P_BR_CONTIGUOUS:
		case ENC_LD4H_Z_P_BR_CONTIGUOUS:
		case ENC_LD4W_Z_P_BR_CONTIGUOUS:
		case ENC_ST2B_Z_P_BR_CONTIGUOUS:
		case ENC_ST2D_Z_P_BR_CONTIGUOUS:
		case ENC_ST2H_Z_P_BR_CONTIGUOUS:
		case ENC_ST2W_Z_P_BR_CONTIGUOUS:
		case ENC_ST3B_Z_P_BR_CONTIGUOUS:
		case ENC_ST3D_Z_P_BR_CONTIGUOUS:
		case ENC_ST3H_Z_P_BR_CONTIGUOUS:
		case ENC_ST3W_Z_P_BR_CONTIGUOUS:
		case ENC_ST4B_Z_P_BR_CONTIGUOUS:
		case ENC_ST4D_Z_P_BR_CONTIGUOUS:
		case ENC_ST4H_Z_P_BR_CONTIGUOUS:
		case ENC_ST4W_Z_P_BR_CONTIGUOUS:
			// xxx|xxxx|msz=xx|opc=xx|Rm=xxxxx|xxx|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->msz = (insword>>23)&3;
			ctx->opc = (insword>>21)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_LD2B_Z_P_BI_CONTIGUOUS:
		case ENC_LD2D_Z_P_BI_CONTIGUOUS:
		case ENC_LD2H_Z_P_BI_CONTIGUOUS:
		case ENC_LD2W_Z_P_BI_CONTIGUOUS:
		case ENC_LD3B_Z_P_BI_CONTIGUOUS:
		case ENC_LD3D_Z_P_BI_CONTIGUOUS:
		case ENC_LD3H_Z_P_BI_CONTIGUOUS:
		case ENC_LD3W_Z_P_BI_CONTIGUOUS:
		case ENC_LD4B_Z_P_BI_CONTIGUOUS:
		case ENC_LD4D_Z_P_BI_CONTIGUOUS:
		case ENC_LD4H_Z_P_BI_CONTIGUOUS:
		case ENC_LD4W_Z_P_BI_CONTIGUOUS:
		case ENC_ST1D_Z_P_BI_:
		case ENC_ST1D_Z_P_BI_U128:
		case ENC_ST1W_Z_P_BI_U128:
		case ENC_ST2B_Z_P_BI_CONTIGUOUS:
		case ENC_ST2D_Z_P_BI_CONTIGUOUS:
		case ENC_ST2H_Z_P_BI_CONTIGUOUS:
		case ENC_ST2W_Z_P_BI_CONTIGUOUS:
		case ENC_ST3B_Z_P_BI_CONTIGUOUS:
		case ENC_ST3D_Z_P_BI_CONTIGUOUS:
		case ENC_ST3H_Z_P_BI_CONTIGUOUS:
		case ENC_ST3W_Z_P_BI_CONTIGUOUS:
		case ENC_ST4B_Z_P_BI_CONTIGUOUS:
		case ENC_ST4D_Z_P_BI_CONTIGUOUS:
		case ENC_ST4H_Z_P_BI_CONTIGUOUS:
		case ENC_ST4W_Z_P_BI_CONTIGUOUS:
			// xxx|xxxx|msz=xx|opc=xx|x|imm4=xxxx|xxx|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->msz = (insword>>23)&3;
			ctx->opc = (insword>>21)&3;
			ctx->imm4 = (insword>>16)&15;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_ST1B_Z_P_BI_:
		case ENC_ST1H_Z_P_BI_:
			// xxx|xxxx|msz=xx|size=xx|x|imm4=xxxx|xxx|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->msz = (insword>>23)&3;
			ctx->size = (insword>>21)&3;
			ctx->imm4 = (insword>>16)&15;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_LD1ROB_Z_P_BR_CONTIGUOUS:
		case ENC_LD1ROD_Z_P_BR_CONTIGUOUS:
		case ENC_LD1ROH_Z_P_BR_CONTIGUOUS:
		case ENC_LD1ROW_Z_P_BR_CONTIGUOUS:
		case ENC_LD1RQB_Z_P_BR_CONTIGUOUS:
		case ENC_LD1RQD_Z_P_BR_CONTIGUOUS:
		case ENC_LD1RQH_Z_P_BR_CONTIGUOUS:
		case ENC_LD1RQW_Z_P_BR_CONTIGUOUS:
			// xxx|xxxx|msz=xx|ssz=xx|Rm=xxxxx|xxx|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->msz = (insword>>23)&3;
			ctx->ssz = (insword>>21)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_LD1ROB_Z_P_BI_U8:
		case ENC_LD1ROD_Z_P_BI_U64:
		case ENC_LD1ROH_Z_P_BI_U16:
		case ENC_LD1ROW_Z_P_BI_U32:
		case ENC_LD1RQB_Z_P_BI_U8:
		case ENC_LD1RQD_Z_P_BI_U64:
		case ENC_LD1RQH_Z_P_BI_U16:
		case ENC_LD1RQW_Z_P_BI_U32:
			// xxx|xxxx|msz=xx|ssz=xx|x|imm4=xxxx|xxx|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->msz = (insword>>23)&3;
			ctx->ssz = (insword>>21)&3;
			ctx->imm4 = (insword>>16)&15;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_LD1B_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LD1D_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LD1H_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LD1SB_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LD1SH_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LD1SW_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LD1W_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LDFF1B_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LDFF1D_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LDFF1H_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LDFF1SB_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LDFF1SH_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LDFF1SW_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LDFF1W_Z_P_BZ_D_X32_UNSCALED:
			// xxx|xxxx|msz=xx|xs=x|x|Zm=xxxxx|x|U=x|ff=x|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->msz = (insword>>23)&3;
			ctx->xs = (insword>>22)&1;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->U = (insword>>14)&1;
			ctx->ff = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_LDNT1B_Z_P_BR_CONTIGUOUS:
		case ENC_LDNT1D_Z_P_BR_CONTIGUOUS:
		case ENC_LDNT1H_Z_P_BR_CONTIGUOUS:
		case ENC_LDNT1W_Z_P_BR_CONTIGUOUS:
		case ENC_STNT1B_Z_P_BR_CONTIGUOUS:
		case ENC_STNT1D_Z_P_BR_CONTIGUOUS:
		case ENC_STNT1H_Z_P_BR_CONTIGUOUS:
		case ENC_STNT1W_Z_P_BR_CONTIGUOUS:
			// xxx|xxxx|msz=xx|xx|Rm=xxxxx|xxx|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->msz = (insword>>23)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_PRFB_I_P_BR_S:
		case ENC_PRFD_I_P_BR_S:
		case ENC_PRFH_I_P_BR_S:
		case ENC_PRFW_I_P_BR_S:
			// xxx|xxxx|msz=xx|xx|Rm=xxxxx|xxx|Pg=xxx|Rn=xxxxx|x|prfop=xxxx
			ctx->msz = (insword>>23)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->prfop = insword&15;
			break;
		case ENC_LDNT1B_Z_P_AR_S_X32_UNSCALED:
		case ENC_LDNT1H_Z_P_AR_S_X32_UNSCALED:
		case ENC_LDNT1SB_Z_P_AR_S_X32_UNSCALED:
		case ENC_LDNT1SH_Z_P_AR_S_X32_UNSCALED:
		case ENC_LDNT1W_Z_P_AR_S_X32_UNSCALED:
			// xxx|xxxx|msz=xx|xx|Rm=xxxxx|xx|U=x|Pg=xxx|Zn=xxxxx|Zt=xxxxx
			ctx->msz = (insword>>23)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->U = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_LDNT1B_Z_P_AR_D_64_UNSCALED:
		case ENC_LDNT1D_Z_P_AR_D_64_UNSCALED:
		case ENC_LDNT1H_Z_P_AR_D_64_UNSCALED:
		case ENC_LDNT1SB_Z_P_AR_D_64_UNSCALED:
		case ENC_LDNT1SH_Z_P_AR_D_64_UNSCALED:
		case ENC_LDNT1SW_Z_P_AR_D_64_UNSCALED:
		case ENC_LDNT1W_Z_P_AR_D_64_UNSCALED:
			// xxx|xxxx|msz=xx|xx|Rm=xxxxx|x|U=x|x|Pg=xxx|Zn=xxxxx|Zt=xxxxx
			ctx->msz = (insword>>23)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->U = (insword>>14)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_ST1B_Z_P_BZ_D_64_UNSCALED:
		case ENC_ST1D_Z_P_BZ_D_64_SCALED:
		case ENC_ST1D_Z_P_BZ_D_64_UNSCALED:
		case ENC_ST1H_Z_P_BZ_D_64_SCALED:
		case ENC_ST1H_Z_P_BZ_D_64_UNSCALED:
		case ENC_ST1W_Z_P_BZ_D_64_SCALED:
		case ENC_ST1W_Z_P_BZ_D_64_UNSCALED:
			// xxx|xxxx|msz=xx|xx|Zm=xxxxx|xxx|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->msz = (insword>>23)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_LD1B_Z_P_BZ_D_64_UNSCALED:
		case ENC_LD1D_Z_P_BZ_D_64_UNSCALED:
		case ENC_LD1H_Z_P_BZ_D_64_UNSCALED:
		case ENC_LD1SB_Z_P_BZ_D_64_UNSCALED:
		case ENC_LD1SH_Z_P_BZ_D_64_UNSCALED:
		case ENC_LD1SW_Z_P_BZ_D_64_UNSCALED:
		case ENC_LD1W_Z_P_BZ_D_64_UNSCALED:
		case ENC_LDFF1B_Z_P_BZ_D_64_UNSCALED:
		case ENC_LDFF1D_Z_P_BZ_D_64_UNSCALED:
		case ENC_LDFF1H_Z_P_BZ_D_64_UNSCALED:
		case ENC_LDFF1SB_Z_P_BZ_D_64_UNSCALED:
		case ENC_LDFF1SH_Z_P_BZ_D_64_UNSCALED:
		case ENC_LDFF1SW_Z_P_BZ_D_64_UNSCALED:
		case ENC_LDFF1W_Z_P_BZ_D_64_UNSCALED:
			// xxx|xxxx|msz=xx|xx|Zm=xxxxx|x|U=x|ff=x|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->msz = (insword>>23)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->U = (insword>>14)&1;
			ctx->ff = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_ST1B_Z_P_BZ_D_X32_UNSCALED:
		case ENC_ST1B_Z_P_BZ_S_X32_UNSCALED:
		case ENC_ST1D_Z_P_BZ_D_X32_SCALED:
		case ENC_ST1D_Z_P_BZ_D_X32_UNSCALED:
		case ENC_ST1H_Z_P_BZ_S_X32_SCALED:
		case ENC_ST1H_Z_P_BZ_D_X32_SCALED:
		case ENC_ST1H_Z_P_BZ_D_X32_UNSCALED:
		case ENC_ST1H_Z_P_BZ_S_X32_UNSCALED:
		case ENC_ST1W_Z_P_BZ_S_X32_SCALED:
		case ENC_ST1W_Z_P_BZ_D_X32_SCALED:
		case ENC_ST1W_Z_P_BZ_D_X32_UNSCALED:
		case ENC_ST1W_Z_P_BZ_S_X32_UNSCALED:
			// xxx|xxxx|msz=xx|xx|Zm=xxxxx|x|xs=x|x|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->msz = (insword>>23)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->xs = (insword>>14)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_ST1B_Z_P_AI_S:
		case ENC_ST1B_Z_P_AI_D:
		case ENC_ST1D_Z_P_AI_D:
		case ENC_ST1H_Z_P_AI_S:
		case ENC_ST1H_Z_P_AI_D:
		case ENC_ST1W_Z_P_AI_S:
		case ENC_ST1W_Z_P_AI_D:
			// xxx|xxxx|msz=xx|xx|imm5=xxxxx|xxx|Pg=xxx|Zn=xxxxx|Zt=xxxxx
			ctx->msz = (insword>>23)&3;
			ctx->imm5 = (insword>>16)&0x1f;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_PRFB_I_P_AI_S:
		case ENC_PRFB_I_P_AI_D:
		case ENC_PRFD_I_P_AI_S:
		case ENC_PRFD_I_P_AI_D:
		case ENC_PRFH_I_P_AI_S:
		case ENC_PRFH_I_P_AI_D:
		case ENC_PRFW_I_P_AI_S:
		case ENC_PRFW_I_P_AI_D:
			// xxx|xxxx|msz=xx|xx|imm5=xxxxx|xxx|Pg=xxx|Zn=xxxxx|x|prfop=xxxx
			ctx->msz = (insword>>23)&3;
			ctx->imm5 = (insword>>16)&0x1f;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->prfop = insword&15;
			break;
		case ENC_LD1B_Z_P_AI_S:
		case ENC_LD1B_Z_P_AI_D:
		case ENC_LD1D_Z_P_AI_D:
		case ENC_LD1H_Z_P_AI_S:
		case ENC_LD1H_Z_P_AI_D:
		case ENC_LD1SB_Z_P_AI_S:
		case ENC_LD1SB_Z_P_AI_D:
		case ENC_LD1SH_Z_P_AI_S:
		case ENC_LD1SH_Z_P_AI_D:
		case ENC_LD1SW_Z_P_AI_D:
		case ENC_LD1W_Z_P_AI_S:
		case ENC_LD1W_Z_P_AI_D:
		case ENC_LDFF1B_Z_P_AI_S:
		case ENC_LDFF1B_Z_P_AI_D:
		case ENC_LDFF1D_Z_P_AI_D:
		case ENC_LDFF1H_Z_P_AI_S:
		case ENC_LDFF1H_Z_P_AI_D:
		case ENC_LDFF1SB_Z_P_AI_S:
		case ENC_LDFF1SB_Z_P_AI_D:
		case ENC_LDFF1SH_Z_P_AI_S:
		case ENC_LDFF1SH_Z_P_AI_D:
		case ENC_LDFF1SW_Z_P_AI_D:
		case ENC_LDFF1W_Z_P_AI_S:
		case ENC_LDFF1W_Z_P_AI_D:
			// xxx|xxxx|msz=xx|xx|imm5=xxxxx|x|U=x|ff=x|Pg=xxx|Zn=xxxxx|Zt=xxxxx
			ctx->msz = (insword>>23)&3;
			ctx->imm5 = (insword>>16)&0x1f;
			ctx->U = (insword>>14)&1;
			ctx->ff = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_LDNT1B_Z_P_BI_CONTIGUOUS:
		case ENC_LDNT1D_Z_P_BI_CONTIGUOUS:
		case ENC_LDNT1H_Z_P_BI_CONTIGUOUS:
		case ENC_LDNT1W_Z_P_BI_CONTIGUOUS:
		case ENC_STNT1B_Z_P_BI_CONTIGUOUS:
		case ENC_STNT1D_Z_P_BI_CONTIGUOUS:
		case ENC_STNT1H_Z_P_BI_CONTIGUOUS:
		case ENC_STNT1W_Z_P_BI_CONTIGUOUS:
			// xxx|xxxx|msz=xx|xx|x|imm4=xxxx|xxx|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->msz = (insword>>23)&3;
			ctx->imm4 = (insword>>16)&15;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_ST1W_Z_P_BI_:
			// xxx|xxxx|msz=xx|x|sz=x|x|imm4=xxxx|xxx|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->msz = (insword>>23)&3;
			ctx->sz = (insword>>21)&1;
			ctx->imm4 = (insword>>16)&15;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_STNT1B_Z_P_AR_S_X32_UNSCALED:
		case ENC_STNT1B_Z_P_AR_D_64_UNSCALED:
		case ENC_STNT1D_Z_P_AR_D_64_UNSCALED:
		case ENC_STNT1H_Z_P_AR_S_X32_UNSCALED:
		case ENC_STNT1H_Z_P_AR_D_64_UNSCALED:
		case ENC_STNT1W_Z_P_AR_S_X32_UNSCALED:
		case ENC_STNT1W_Z_P_AR_D_64_UNSCALED:
			// xxx|xxxx|msz=xx|x|x|Rm=xxxxx|xxx|Pg=xxx|Zn=xxxxx|Zt=xxxxx
			ctx->msz = (insword>>23)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_LD2Q_Z_P_BR_CONTIGUOUS:
		case ENC_LD3Q_Z_P_BR_CONTIGUOUS:
		case ENC_LD4Q_Z_P_BR_CONTIGUOUS:
			// xxx|xxxx|num=xx|xx|Rm=xxxxx|xxx|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->num = (insword>>23)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_LD2Q_Z_P_BI_CONTIGUOUS:
		case ENC_LD3Q_Z_P_BI_CONTIGUOUS:
		case ENC_LD4Q_Z_P_BI_CONTIGUOUS:
			// xxx|xxxx|num=xx|xx|x|imm4=xxxx|xxx|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->num = (insword>>23)&3;
			ctx->imm4 = (insword>>16)&15;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_ST1D_Z_P_BR_:
		case ENC_ST1D_Z_P_BR_U128:
		case ENC_ST1W_Z_P_BR_U128:
			// xxx|xxxx|opc=xxx|o2=x|Rm=xxxxx|x|x|x|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->opc = (insword>>22)&7;
			ctx->o2 = (insword>>21)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_ST1W_Z_P_BR_:
			// xxx|xxxx|opc=xxx|sz=x|Rm=xxxxx|x|x|x|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->opc = (insword>>22)&7;
			ctx->sz = (insword>>21)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_LD1B_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LD1D_Z_P_BZ_D_X32_SCALED:
		case ENC_LD1H_Z_P_BZ_D_X32_SCALED:
		case ENC_LD1H_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LD1SB_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LD1SH_Z_P_BZ_D_X32_SCALED:
		case ENC_LD1SH_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LD1SW_Z_P_BZ_D_X32_SCALED:
		case ENC_LD1W_Z_P_BZ_D_X32_SCALED:
		case ENC_LD1W_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LDFF1B_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LDFF1D_Z_P_BZ_D_X32_SCALED:
		case ENC_LDFF1H_Z_P_BZ_D_X32_SCALED:
		case ENC_LDFF1H_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LDFF1SB_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LDFF1SH_Z_P_BZ_D_X32_SCALED:
		case ENC_LDFF1SH_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LDFF1SW_Z_P_BZ_D_X32_SCALED:
		case ENC_LDFF1W_Z_P_BZ_D_X32_SCALED:
		case ENC_LDFF1W_Z_P_BZ_S_X32_UNSCALED:
			// xxx|xxxx|opc=xx|xs=x|x|Zm=xxxxx|x|U=x|ff=x|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->opc = (insword>>23)&3;
			ctx->xs = (insword>>22)&1;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->U = (insword>>14)&1;
			ctx->ff = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_LD1D_Z_P_BZ_D_64_SCALED:
		case ENC_LD1H_Z_P_BZ_D_64_SCALED:
		case ENC_LD1SH_Z_P_BZ_D_64_SCALED:
		case ENC_LD1SW_Z_P_BZ_D_64_SCALED:
		case ENC_LD1W_Z_P_BZ_D_64_SCALED:
		case ENC_LDFF1D_Z_P_BZ_D_64_SCALED:
		case ENC_LDFF1H_Z_P_BZ_D_64_SCALED:
		case ENC_LDFF1SH_Z_P_BZ_D_64_SCALED:
		case ENC_LDFF1SW_Z_P_BZ_D_64_SCALED:
		case ENC_LDFF1W_Z_P_BZ_D_64_SCALED:
			// xxx|xxxx|opc=xx|xx|Zm=xxxxx|x|U=x|ff=x|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->opc = (insword>>23)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->U = (insword>>14)&1;
			ctx->ff = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_SDOT_Z32_ZZZ_:
		case ENC_UDOT_Z32_ZZZ_:
			// xxx|xxxx|xxxx|Zm=xxxxx|xxxxx|U=x|Zn=xxxxx|Zda=xxxxx
			ctx->Zm = (insword>>16)&0x1f;
			ctx->U = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_SDOT_Z32_ZZZI_:
		case ENC_UDOT_Z32_ZZZI_:
			// xxx|xxxx|xxxx|i2=xx|Zm=xxx|xxxxx|U=x|Zn=xxxxx|Zda=xxxxx
			ctx->i2 = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->U = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_STR_Z_BI_:
			// xxx|xxxx|xxx|imm9h=xxxxxx|x|x|x|imm9l=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->imm9h = (insword>>16)&0x3f;
			ctx->imm9l = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_STR_P_BI_:
			// xxx|xxxx|xxx|imm9h=xxxxxx|x|x|x|imm9l=xxx|Rn=xxxxx|x|Pt=xxxx
			ctx->imm9h = (insword>>16)&0x3f;
			ctx->imm9l = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Pt = insword&15;
			break;
		case ENC_ST1Q_Z_P_AR_D_64_UNSCALED:
			// xxx|xxxx|xxx|x|Rm=xxxxx|xxx|Pg=xxx|Zn=xxxxx|Zt=xxxxx
			ctx->Rm = (insword>>16)&0x1f;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_BFMMLA_Z_ZZZ_H:
		case ENC_FMMLA_Z16_ZZ8Z8_:
		case ENC_FMMLA_Z32_ZZ8Z8_:
		case ENC_FMMLA_Z_ZZZ_H:
			// xxx|xxxx|xx|op=x|x|Zm=xxxxx|xxxxxx|Zn=xxxxx|Zda=xxxxx
			ctx->op = (insword>>22)&1;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_ST1B_Z_P_BR_:
		case ENC_ST1H_Z_P_BR_:
			// xxx|xxxx|xx|size=xx|Rm=xxxxx|x|x|x|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->size = (insword>>21)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_LD1H_Z_P_BZ_S_X32_SCALED:
		case ENC_LD1SH_Z_P_BZ_S_X32_SCALED:
		case ENC_LD1W_Z_P_BZ_S_X32_SCALED:
		case ENC_LDFF1H_Z_P_BZ_S_X32_SCALED:
		case ENC_LDFF1SH_Z_P_BZ_S_X32_SCALED:
		case ENC_LDFF1W_Z_P_BZ_S_X32_SCALED:
			// xxx|xxxx|xx|xs=x|x|Zm=xxxxx|x|U=x|ff=x|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->xs = (insword>>22)&1;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->U = (insword>>14)&1;
			ctx->ff = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_PRFB_I_P_BZ_S_X32_SCALED:
		case ENC_PRFB_I_P_BZ_D_X32_SCALED:
		case ENC_PRFD_I_P_BZ_S_X32_SCALED:
		case ENC_PRFD_I_P_BZ_D_X32_SCALED:
		case ENC_PRFH_I_P_BZ_S_X32_SCALED:
		case ENC_PRFH_I_P_BZ_D_X32_SCALED:
		case ENC_PRFW_I_P_BZ_S_X32_SCALED:
		case ENC_PRFW_I_P_BZ_D_X32_SCALED:
			// xxx|xxxx|xx|xs=x|x|Zm=xxxxx|x|msz=xx|Pg=xxx|Rn=xxxxx|x|prfop=xxxx
			ctx->xs = (insword>>22)&1;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->msz = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->prfop = insword&15;
			break;
		case ENC_LD1Q_Z_P_AR_D_64_UNSCALED:
			// xxx|xxxx|xx|xx|Rm=xxxxx|xxx|Pg=xxx|Zn=xxxxx|Zt=xxxxx
			ctx->Rm = (insword>>16)&0x1f;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_PRFB_I_P_BZ_D_64_SCALED:
		case ENC_PRFD_I_P_BZ_D_64_SCALED:
		case ENC_PRFH_I_P_BZ_D_64_SCALED:
		case ENC_PRFW_I_P_BZ_D_64_SCALED:
			// xxx|xxxx|xx|xx|Zm=xxxxx|x|msz=xx|Pg=xxx|Rn=xxxxx|x|prfop=xxxx
			ctx->Zm = (insword>>16)&0x1f;
			ctx->msz = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->prfop = insword&15;
			break;
		case ENC_PRFB_I_P_BI_S:
		case ENC_PRFD_I_P_BI_S:
		case ENC_PRFH_I_P_BI_S:
		case ENC_PRFW_I_P_BI_S:
			// xxx|xxxx|xx|x|imm6=xxxxxx|x|msz=xx|Pg=xxx|Rn=xxxxx|x|prfop=xxxx
			ctx->imm6 = (insword>>16)&0x3f;
			ctx->msz = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->prfop = insword&15;
			break;
		case ENC_LDR_Z_BI_:
			// xxx|xxxx|xx|x|imm9h=xxxxxx|xxx|imm9l=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->imm9h = (insword>>16)&0x3f;
			ctx->imm9l = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_LDR_P_BI_:
			// xxx|xxxx|xx|x|imm9h=xxxxxx|xxx|imm9l=xxx|Rn=xxxxx|x|Pt=xxxx
			ctx->imm9h = (insword>>16)&0x3f;
			ctx->imm9l = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Pt = insword&15;
			break;
		case ENC_TRN1_Z_ZZ_Q:
		case ENC_TRN2_Z_ZZ_Q:
		case ENC_UZP1_Z_ZZ_Q:
		case ENC_UZP2_Z_ZZ_Q:
		case ENC_ZIP2_Z_ZZ_Q:
		case ENC_ZIP1_Z_ZZ_Q:
			// xxx|xxxx|xx|x|x|Zm=xxxxx|xxx|opc=xx|H=x|Zn=xxxxx|Zd=xxxxx
			ctx->Zm = (insword>>16)&0x1f;
			ctx->opc = (insword>>11)&3;
			ctx->H = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_EXT_Z_ZI_DES:
			// xxx|xxxx|xx|x|x|imm8h=xxxxx|xxx|imm8l=xxx|Zm=xxxxx|Zdn=xxxxx
			ctx->imm8h = (insword>>16)&0x1f;
			ctx->imm8l = (insword>>10)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_EXT_Z_ZI_CON:
			// xxx|xxxx|xx|x|x|imm8h=xxxxx|xxx|imm8l=xxx|Zn=xxxxx|Zd=xxxxx
			ctx->imm8h = (insword>>16)&0x1f;
			ctx->imm8l = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_BRKA_P_P_P_:
		case ENC_BRKAS_P_P_P_Z:
		case ENC_BRKB_P_P_P_:
		case ENC_BRKBS_P_P_P_Z:
			// xxx|xxxx|x|B=x|S=x|xx|xxxx|xx|Pg=xxxx|x|Pn=xxxx|M=x|Pd=xxxx
			ctx->B = (insword>>23)&1;
			ctx->S = (insword>>22)&1;
			ctx->Pg = (insword>>10)&15;
			ctx->Pn = (insword>>5)&15;
			ctx->M = (insword>>4)&1;
			ctx->Pd = insword&15;
			break;
		case ENC_FMLALB_Z_Z8Z8Z8I_:
		case ENC_FMLALT_Z_Z8Z8Z8I_:
			// xxx|xxxx|x|T=x|xx|i4h=xx|Zm=xxx|xxxx|i4l=xx|Zn=xxxxx|Zda=xxxxx
			ctx->T = (insword>>23)&1;
			ctx->i4h = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->i4l = (insword>>10)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_FMLALLBB_Z32_Z8Z8Z8I_:
		case ENC_FMLALLBT_Z32_Z8Z8Z8I_:
		case ENC_FMLALLTB_Z32_Z8Z8Z8I_:
		case ENC_FMLALLTT_Z32_Z8Z8Z8I_:
			// xxx|xxxx|x|TT=xx|x|i4h=xx|Zm=xxx|xxxx|i4l=xx|Zn=xxxxx|Zda=xxxxx
			ctx->TT = (insword>>22)&3;
			ctx->i4h = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->i4l = (insword>>10)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_PSEL_P_PPI_:
			// xxx|xxxx|x|i1=x|tszh=x|x|tszl=xxx|Rv=xx|xx|Pn=xxxx|S=x|Pm=xxxx|x|Pd=xxxx
			ctx->i1 = (insword>>23)&1;
			ctx->tszh = (insword>>22)&1;
			ctx->tszl = (insword>>18)&7;
			ctx->Rv = (insword>>16)&3;
			ctx->Pn = (insword>>10)&15;
			ctx->S = (insword>>9)&1;
			ctx->Pm = (insword>>5)&15;
			ctx->Pd = insword&15;
			break;
		case ENC_LUTI4_Z_ZZ_8:
		case ENC_LUTI6_Z_ZZZ_16:
			// xxx|xxxx|x|i1=x|x|x|Zm=xxxxx|xxx|xxx|Zn=xxxxx|Zd=xxxxx
			ctx->i1 = (insword>>23)&1;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_LUTI2_Z_ZZ_8:
			// xxx|xxxx|x|i2=xx|x|Zm=xxxxx|xxx|xxx|Zn=xxxxx|Zd=xxxxx
			ctx->i2 = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_LUTI4_Z_ZZ_2X16:
		case ENC_LUTI4_Z_ZZ_1X16:
			// xxx|xxxx|x|i2=xx|x|Zm=xxxxx|xxx|x|op=x|x|Zn=xxxxx|Zd=xxxxx
			ctx->i2 = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->op = (insword>>11)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_LUTI2_Z_ZZ_16:
			// xxx|xxxx|x|i3h=xx|x|Zm=xxxxx|xxx|i3l=x|xx|Zn=xxxxx|Zd=xxxxx
			ctx->i3h = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->i3l = (insword>>12)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_DUP_Z_ZI_:
			// xxx|xxxx|x|imm2=xx|x|tsz=xxxxx|xxxxxx|Zn=xxxxx|Zd=xxxxx
			ctx->imm2 = (insword>>22)&3;
			ctx->tsz = (insword>>16)&0x1f;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_ST2Q_Z_P_BI_CONTIGUOUS:
		case ENC_ST3Q_Z_P_BI_CONTIGUOUS:
		case ENC_ST4Q_Z_P_BI_CONTIGUOUS:
			// xxx|xxxx|x|num=xx|xx|imm4=xxxx|x|x|x|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->num = (insword>>22)&3;
			ctx->imm4 = (insword>>16)&15;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_ST2Q_Z_P_BR_CONTIGUOUS:
		case ENC_ST3Q_Z_P_BR_CONTIGUOUS:
		case ENC_ST4Q_Z_P_BR_CONTIGUOUS:
			// xxx|xxxx|x|num=xx|x|Rm=xxxxx|x|x|x|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->num = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_AND_P_P_PP_Z:
		case ENC_ANDS_P_P_PP_Z:
		case ENC_BIC_P_P_PP_Z:
		case ENC_BICS_P_P_PP_Z:
		case ENC_EOR_P_P_PP_Z:
		case ENC_EORS_P_P_PP_Z:
		case ENC_MOVZ_P_P_P__AND_P_P_PP_Z:
		case ENC_MOV_P_P__ORR_P_P_PP_Z:
		case ENC_MOVM_P_P_P__SEL_P_P_PP_:
		case ENC_MOVZS_P_P_P__ANDS_P_P_PP_Z:
		case ENC_MOVS_P_P__ORRS_P_P_PP_Z:
		case ENC_NAND_P_P_PP_Z:
		case ENC_NANDS_P_P_PP_Z:
		case ENC_NOR_P_P_PP_Z:
		case ENC_NORS_P_P_PP_Z:
		case ENC_NOT_P_P_P_Z_EOR_P_P_PP_Z:
		case ENC_NOTS_P_P_P_Z_EORS_P_P_PP_Z:
		case ENC_ORN_P_P_PP_Z:
		case ENC_ORNS_P_P_PP_Z:
		case ENC_ORR_P_P_PP_Z:
		case ENC_ORRS_P_P_PP_Z:
		case ENC_SEL_P_P_PP_:
			// xxx|xxxx|x|op=x|S=x|xx|Pm=xxxx|xx|Pg=xxxx|o2=x|Pn=xxxx|o3=x|Pd=xxxx
			ctx->op = (insword>>23)&1;
			ctx->S = (insword>>22)&1;
			ctx->Pm = (insword>>16)&15;
			ctx->Pg = (insword>>10)&15;
			ctx->o2 = (insword>>9)&1;
			ctx->Pn = (insword>>5)&15;
			ctx->o3 = (insword>>4)&1;
			ctx->Pd = insword&15;
			break;
		case ENC_BRKPA_P_P_PP_:
		case ENC_BRKPAS_P_P_PP_:
		case ENC_BRKPB_P_P_PP_:
		case ENC_BRKPBS_P_P_PP_:
			// xxx|xxxx|x|op=x|S=x|xx|Pm=xxxx|xx|Pg=xxxx|x|Pn=xxxx|B=x|Pd=xxxx
			ctx->op = (insword>>23)&1;
			ctx->S = (insword>>22)&1;
			ctx->Pm = (insword>>16)&15;
			ctx->Pg = (insword>>10)&15;
			ctx->Pn = (insword>>5)&15;
			ctx->B = (insword>>4)&1;
			ctx->Pd = insword&15;
			break;
		case ENC_PTEST__P_P_:
			// xxx|xxxx|x|op=x|S=x|xx|xxxx|xx|Pg=xxxx|x|Pn=xxxx|x|opc2=xxxx
			ctx->op = (insword>>23)&1;
			ctx->S = (insword>>22)&1;
			ctx->Pg = (insword>>10)&15;
			ctx->Pn = (insword>>5)&15;
			ctx->opc2 = insword&15;
			break;
		case ENC_RDFFR_P_P_F_:
		case ENC_RDFFRS_P_P_F_:
			// xxx|xxxx|x|op=x|S=x|xx|xxxx|xx|xxx|xx|Pg=xxxx|x|Pd=xxxx
			ctx->op = (insword>>23)&1;
			ctx->S = (insword>>22)&1;
			ctx->Pg = (insword>>5)&15;
			ctx->Pd = insword&15;
			break;
		case ENC_PFIRST_P_P_P_:
			// xxx|xxxx|x|op=x|S=x|xx|xxxx|xx|xxx|xx|Pg=xxxx|x|Pdn=xxxx
			ctx->op = (insword>>23)&1;
			ctx->S = (insword>>22)&1;
			ctx->Pg = (insword>>5)&15;
			ctx->Pdn = insword&15;
			break;
		case ENC_PFALSE_P_:
		case ENC_RDFFR_P_F_:
			// xxx|xxxx|x|op=x|S=x|xx|xxxx|xx|xxx|xx|xxxx|x|Pd=xxxx
			ctx->op = (insword>>23)&1;
			ctx->S = (insword>>22)&1;
			ctx->Pd = insword&15;
			break;
		case ENC_CTERMEQ_RR_:
		case ENC_CTERMNE_RR_:
			// xxx|xxxx|x|op=x|sz=x|x|Rm=xxxxx|xx|xx|xx|Rn=xxxxx|ne=x|xxxx
			ctx->op = (insword>>23)&1;
			ctx->sz = (insword>>22)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->ne = (insword>>4)&1;
			break;
		case ENC_BFCVTNT_Z_P_Z_S2BF:
		case ENC_BFCVTNT_Z_P_Z_S2BFZ:
		case ENC_FCVTLT_Z_P_Z_H2S:
		case ENC_FCVTLT_Z_P_Z_H2SZ:
		case ENC_FCVTLT_Z_P_Z_S2D:
		case ENC_FCVTLT_Z_P_Z_S2DZ:
		case ENC_FCVTNT_Z_P_Z_S2H:
		case ENC_FCVTNT_Z_P_Z_S2HZ:
		case ENC_FCVTNT_Z_P_Z_D2S:
		case ENC_FCVTNT_Z_P_Z_D2SZ:
		case ENC_FCVTXNT_Z_P_Z_D2S:
		case ENC_FCVTXNT_Z_P_Z_D2SZ:
			// xxx|xxxx|x|opc=xx|xxxx|opc2=xx|xxx|Pg=xxx|Zn=xxxxx|Zd=xxxxx
			ctx->opc = (insword>>22)&3;
			ctx->opc2 = (insword>>16)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_BFCVT_Z_P_Z_S2BFZ:
		case ENC_FCVT_Z_P_Z_H2SZ:
		case ENC_FCVT_Z_P_Z_H2DZ:
		case ENC_FCVT_Z_P_Z_S2HZ:
		case ENC_FCVT_Z_P_Z_S2DZ:
		case ENC_FCVT_Z_P_Z_D2HZ:
		case ENC_FCVT_Z_P_Z_D2SZ:
		case ENC_FCVTX_Z_P_Z_D2SZ:
			// xxx|xxxx|x|opc=xx|xxx|xxx|x|opc2=xx|Pg=xxx|Zn=xxxxx|Zd=xxxxx
			ctx->opc = (insword>>22)&3;
			ctx->opc2 = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_FCVTZS_Z_P_Z_FP162HZ:
		case ENC_FCVTZS_Z_P_Z_FP162WZ:
		case ENC_FCVTZS_Z_P_Z_FP162XZ:
		case ENC_FCVTZS_Z_P_Z_S2WZ:
		case ENC_FCVTZS_Z_P_Z_S2XZ:
		case ENC_FCVTZS_Z_P_Z_D2WZ:
		case ENC_FCVTZS_Z_P_Z_D2XZ:
		case ENC_FCVTZU_Z_P_Z_FP162HZ:
		case ENC_FCVTZU_Z_P_Z_FP162WZ:
		case ENC_FCVTZU_Z_P_Z_FP162XZ:
		case ENC_FCVTZU_Z_P_Z_S2WZ:
		case ENC_FCVTZU_Z_P_Z_S2XZ:
		case ENC_FCVTZU_Z_P_Z_D2WZ:
		case ENC_FCVTZU_Z_P_Z_D2XZ:
		case ENC_SCVTF_Z_P_Z_H2FP16Z:
		case ENC_SCVTF_Z_P_Z_W2FP16Z:
		case ENC_SCVTF_Z_P_Z_W2SZ:
		case ENC_SCVTF_Z_P_Z_W2DZ:
		case ENC_SCVTF_Z_P_Z_X2FP16Z:
		case ENC_SCVTF_Z_P_Z_X2SZ:
		case ENC_SCVTF_Z_P_Z_X2DZ:
		case ENC_UCVTF_Z_P_Z_H2FP16Z:
		case ENC_UCVTF_Z_P_Z_W2FP16Z:
		case ENC_UCVTF_Z_P_Z_W2SZ:
		case ENC_UCVTF_Z_P_Z_W2DZ:
		case ENC_UCVTF_Z_P_Z_X2FP16Z:
		case ENC_UCVTF_Z_P_Z_X2SZ:
		case ENC_UCVTF_Z_P_Z_X2DZ:
			// xxx|xxxx|x|opc=xx|xxx|xx|o2=x|x|o3=x|int_U=x|Pg=xxx|Zn=xxxxx|Zd=xxxxx
			ctx->opc = (insword>>22)&3;
			ctx->o2 = (insword>>16)&1;
			ctx->o3 = (insword>>14)&1;
			ctx->int_U = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_FLOGB_Z_P_Z_Z:
			// xxx|xxxx|x|opc=xx|xxx|xx|o2=x|x|size=xx|Pg=xxx|Zn=xxxxx|Zd=xxxxx
			ctx->opc = (insword>>22)&3;
			ctx->o2 = (insword>>16)&1;
			ctx->size = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_FRINT32X_Z_P_Z_Z:
		case ENC_FRINT32Z_Z_P_Z_Z:
		case ENC_FRINT64X_Z_P_Z_Z:
		case ENC_FRINT64Z_Z_P_Z_Z:
			// xxx|xxxx|x|opc=xx|xxx|xx|o2=x|x|sz=x|U=x|Pg=xxx|Zn=xxxxx|Zd=xxxxx
			ctx->opc = (insword>>22)&3;
			ctx->o2 = (insword>>16)&1;
			ctx->sz = (insword>>14)&1;
			ctx->U = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_WRFFR_F_P_:
			// xxx|xxxx|x|opc=xx|xxx|x|xx|xxxx|xxx|Pn=xxxx|xxxxx
			ctx->opc = (insword>>22)&3;
			ctx->Pn = (insword>>5)&15;
			break;
		case ENC_SETFFR_F_:
			// xxx|xxxx|x|opc=xx|xxx|x|xx|xxxx|xxx|xxxx|xxxxx
			ctx->opc = (insword>>22)&3;
			break;
		case ENC_AND_Z_ZI_:
		case ENC_BIC_Z_ZI__AND_Z_ZI_:
		case ENC_EON_Z_ZI__EOR_Z_ZI_:
		case ENC_EOR_Z_ZI_:
		case ENC_ORN_Z_ZI__ORR_Z_ZI_:
		case ENC_ORR_Z_ZI_:
			// xxx|xxxx|x|opc=xx|xx|xx|imm13=xxxxxxxxxxxxx|Zdn=xxxxx
			ctx->opc = (insword>>22)&3;
			ctx->imm13 = (insword>>5)&0x1fff;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_BFMMLA_Z_ZZZ_:
		case ENC_FMMLA_Z32_ZZZ_H:
		case ENC_FMMLA_Z_ZZZ_S:
		case ENC_FMMLA_Z_ZZZ_D:
			// xxx|xxxx|x|opc=xx|x|Zm=xxxxx|xxxxxx|Zn=xxxxx|Zda=xxxxx
			ctx->opc = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_ADR_Z_AZ_D_S32_SCALED:
		case ENC_ADR_Z_AZ_D_U32_SCALED:
			// xxx|xxxx|x|opc=xx|x|Zm=xxxxx|xxxx|msz=xx|Zn=xxxxx|Zd=xxxxx
			ctx->opc = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->msz = (insword>>10)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_MADPT_Z_ZZZ_:
			// xxx|xxxx|x|opc=xx|x|Zm=xxxxx|xxxx|o2=x|x|Za=xxxxx|Zdn=xxxxx
			ctx->opc = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->o2 = (insword>>11)&1;
			ctx->Za = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_MLAPT_Z_ZZZ_:
			// xxx|xxxx|x|opc=xx|x|Zm=xxxxx|xxxx|o2=x|x|Zn=xxxxx|Zda=xxxxx
			ctx->opc = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->o2 = (insword>>11)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_AND_Z_ZZ_:
		case ENC_BIC_Z_ZZ_:
		case ENC_EOR_Z_ZZ_:
		case ENC_MOV_Z_Z__ORR_Z_ZZ_:
		case ENC_ORR_Z_ZZ_:
			// xxx|xxxx|x|opc=xx|x|Zm=xxxxx|xxx|xxx|Zn=xxxxx|Zd=xxxxx
			ctx->opc = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_BCAX_Z_ZZZ_:
		case ENC_BSL1N_Z_ZZZ_:
		case ENC_BSL2N_Z_ZZZ_:
		case ENC_BSL_Z_ZZZ_:
		case ENC_EOR3_Z_ZZZ_:
		case ENC_NBSL_Z_ZZZ_:
			// xxx|xxxx|x|opc=xx|x|Zm=xxxxx|xxx|xx|o2=x|Zk=xxxxx|Zdn=xxxxx
			ctx->opc = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->o2 = (insword>>10)&1;
			ctx->Zk = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_MOVPRFX_Z_Z_:
			// xxx|xxxx|x|opc=xx|x|opc2=xxxxx|xxxx|xx|Zn=xxxxx|Zd=xxxxx
			ctx->opc = (insword>>22)&3;
			ctx->opc2 = (insword>>16)&0x1f;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_BFCVT_Z_P_Z_S2BF:
		case ENC_FCVT_Z_P_Z_H2S:
		case ENC_FCVT_Z_P_Z_H2D:
		case ENC_FCVT_Z_P_Z_S2H:
		case ENC_FCVT_Z_P_Z_S2D:
		case ENC_FCVT_Z_P_Z_D2H:
		case ENC_FCVT_Z_P_Z_D2S:
		case ENC_FCVTX_Z_P_Z_D2S:
			// xxx|xxxx|x|opc=xx|x|xxx|opc2=xx|xxx|Pg=xxx|Zn=xxxxx|Zd=xxxxx
			ctx->opc = (insword>>22)&3;
			ctx->opc2 = (insword>>16)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_PMOV_P_ZI_S:
			// xxx|xxxx|x|opc=xx|x|xx|i2=xx|x|xxxxxx|Zn=xxxxx|x|Pd=xxxx
			ctx->opc = (insword>>22)&3;
			ctx->i2 = (insword>>17)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Pd = insword&15;
			break;
		case ENC_PMOV_Z_PI_S:
			// xxx|xxxx|x|opc=xx|x|xx|i2=xx|x|xxxxxx|x|Pn=xxxx|Zd=xxxxx
			ctx->opc = (insword>>22)&3;
			ctx->i2 = (insword>>17)&3;
			ctx->Pn = (insword>>5)&15;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_FCVTZS_Z_P_Z_FP162H:
		case ENC_FCVTZS_Z_P_Z_FP162W:
		case ENC_FCVTZS_Z_P_Z_FP162X:
		case ENC_FCVTZS_Z_P_Z_S2W:
		case ENC_FCVTZS_Z_P_Z_S2X:
		case ENC_FCVTZS_Z_P_Z_D2W:
		case ENC_FCVTZS_Z_P_Z_D2X:
		case ENC_FCVTZU_Z_P_Z_FP162H:
		case ENC_FCVTZU_Z_P_Z_FP162W:
		case ENC_FCVTZU_Z_P_Z_FP162X:
		case ENC_FCVTZU_Z_P_Z_S2W:
		case ENC_FCVTZU_Z_P_Z_S2X:
		case ENC_FCVTZU_Z_P_Z_D2W:
		case ENC_FCVTZU_Z_P_Z_D2X:
		case ENC_SCVTF_Z_P_Z_H2FP16:
		case ENC_SCVTF_Z_P_Z_W2FP16:
		case ENC_SCVTF_Z_P_Z_W2S:
		case ENC_SCVTF_Z_P_Z_W2D:
		case ENC_SCVTF_Z_P_Z_X2FP16:
		case ENC_SCVTF_Z_P_Z_X2S:
		case ENC_SCVTF_Z_P_Z_X2D:
		case ENC_UCVTF_Z_P_Z_H2FP16:
		case ENC_UCVTF_Z_P_Z_W2FP16:
		case ENC_UCVTF_Z_P_Z_W2S:
		case ENC_UCVTF_Z_P_Z_W2D:
		case ENC_UCVTF_Z_P_Z_X2FP16:
		case ENC_UCVTF_Z_P_Z_X2S:
		case ENC_UCVTF_Z_P_Z_X2D:
			// xxx|xxxx|x|opc=xx|x|xx|opc2=xx|int_U=x|xxx|Pg=xxx|Zn=xxxxx|Zd=xxxxx
			ctx->opc = (insword>>22)&3;
			ctx->opc2 = (insword>>17)&3;
			ctx->int_U = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_PMOV_P_ZI_B:
			// xxx|xxxx|x|opc=xx|x|xx|opc2=xx|x|xxxxxx|Zn=xxxxx|x|Pd=xxxx
			ctx->opc = (insword>>22)&3;
			ctx->opc2 = (insword>>17)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Pd = insword&15;
			break;
		case ENC_PMOV_Z_PI_B:
			// xxx|xxxx|x|opc=xx|x|xx|opc2=xx|x|xxxxxx|x|Pn=xxxx|Zd=xxxxx
			ctx->opc = (insword>>22)&3;
			ctx->opc2 = (insword>>17)&3;
			ctx->Pn = (insword>>5)&15;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_FLOGB_Z_P_Z_M:
			// xxx|xxxx|x|opc=xx|x|xx|size=xx|U=x|xxx|Pg=xxx|Zn=xxxxx|Zd=xxxxx
			ctx->opc = (insword>>22)&3;
			ctx->size = (insword>>17)&3;
			ctx->U = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_PMOV_P_ZI_H:
			// xxx|xxxx|x|opc=xx|x|xx|x|i1=x|x|xxxxxx|Zn=xxxxx|x|Pd=xxxx
			ctx->opc = (insword>>22)&3;
			ctx->i1 = (insword>>17)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Pd = insword&15;
			break;
		case ENC_PMOV_Z_PI_H:
			// xxx|xxxx|x|opc=xx|x|xx|x|i1=x|x|xxxxxx|x|Pn=xxxx|Zd=xxxxx
			ctx->opc = (insword>>22)&3;
			ctx->i1 = (insword>>17)&1;
			ctx->Pn = (insword>>5)&15;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_FRINT32X_Z_P_Z_M:
		case ENC_FRINT32Z_Z_P_Z_M:
		case ENC_FRINT64X_Z_P_Z_M:
		case ENC_FRINT64Z_Z_P_Z_M:
			// xxx|xxxx|x|opc=xx|x|xx|x|sz=x|U=x|xxx|Pg=xxx|Zn=xxxxx|Zd=xxxxx
			ctx->opc = (insword>>22)&3;
			ctx->sz = (insword>>17)&1;
			ctx->U = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_FCADD_Z_P_ZZ_:
			// xxx|xxxx|x|size=xx|xxxxx|rot=x|xxx|Pg=xxx|Zm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->rot = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_FADDP_Z_P_ZZ_:
		case ENC_FMAXNMP_Z_P_ZZ_:
		case ENC_FMAXP_Z_P_ZZ_:
		case ENC_FMINNMP_Z_P_ZZ_:
		case ENC_FMINP_Z_P_ZZ_:
			// xxx|xxxx|x|size=xx|xxx|opc=xxx|xxx|Pg=xxx|Zm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>16)&7;
			ctx->Pg = (insword>>10)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_FADDQV_Z_P_Z_:
		case ENC_FADDV_V_P_Z_:
		case ENC_FMAXNMQV_Z_P_Z_:
		case ENC_FMAXNMV_V_P_Z_:
		case ENC_FMAXQV_Z_P_Z_:
		case ENC_FMAXV_V_P_Z_:
		case ENC_FMINNMQV_Z_P_Z_:
		case ENC_FMINNMV_V_P_Z_:
		case ENC_FMINQV_Z_P_Z_:
		case ENC_FMINV_V_P_Z_:
			// xxx|xxxx|x|size=xx|xxx|opc=xxx|xxx|Pg=xxx|Zn=xxxxx|Vd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>16)&7;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Vd = insword&0x1f;
			break;
		case ENC_CNTP_R_P_P_:
		case ENC_FIRSTP_R_P_P_:
		case ENC_LASTP_R_P_P_:
			// xxx|xxxx|x|size=xx|xxx|opc=xxx|xx|Pg=xxxx|x|Pn=xxxx|Rd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>16)&7;
			ctx->Pg = (insword>>10)&15;
			ctx->Pn = (insword>>5)&15;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_CNTP_R_PN_:
			// xxx|xxxx|x|size=xx|xxx|opc=xxx|xx|xxx|vl=x|x|PNn=xxxx|Rd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>16)&7;
			ctx->vl = (insword>>10)&1;
			ctx->PNn = (insword>>5)&15;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SCVTF_Z_Z_:
		case ENC_SCVTFLT_Z_Z_:
		case ENC_UCVTF_Z_Z_:
		case ENC_UCVTFLT_Z_Z_:
			// xxx|xxxx|x|size=xx|xxx|xxx|xxxx|x|U=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->U = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_FCVTZSN_Z_MZ2_:
		case ENC_FCVTZUN_Z_MZ2_:
			// xxx|xxxx|x|size=xx|xxx|xxx|xxxx|x|U=x|Zn=xxxx|x|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->U = (insword>>10)&1;
			ctx->Zn = (insword>>6)&15;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_FRECPX_Z_P_Z_Z:
		case ENC_FSQRT_Z_P_Z_Z:
			// xxx|xxxx|x|size=xx|xxx|xxx|x|opc=xx|Pg=xxx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_FRECPE_Z_Z_:
		case ENC_FRSQRTE_Z_Z_:
			// xxx|xxxx|x|size=xx|xxx|xx|op=x|xxxx|xx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->op = (insword>>16)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_FRINTX_Z_P_Z_Z:
		case ENC_FRINTI_Z_P_Z_Z:
		case ENC_FRINTA_Z_P_Z_Z:
		case ENC_FRINTN_Z_P_Z_Z:
		case ENC_FRINTZ_Z_P_Z_Z:
		case ENC_FRINTM_Z_P_Z_Z:
		case ENC_FRINTP_Z_P_Z_Z:
			// xxx|xxxx|x|size=xx|xxx|xx|op=x|x|opc2=xx|Pg=xxx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->op = (insword>>16)&1;
			ctx->opc2 = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SQDECP_Z_P_Z_:
		case ENC_SQINCP_Z_P_Z_:
		case ENC_UQDECP_Z_P_Z_:
		case ENC_UQINCP_Z_P_Z_:
			// xxx|xxxx|x|size=xx|xxx|x|D=x|U=x|xxxx|x|opc=xx|Pm=xxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->D = (insword>>17)&1;
			ctx->U = (insword>>16)&1;
			ctx->opc = (insword>>9)&3;
			ctx->Pm = (insword>>5)&15;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_SQDECP_R_P_R_SX:
		case ENC_SQDECP_R_P_R_X:
		case ENC_SQINCP_R_P_R_SX:
		case ENC_SQINCP_R_P_R_X:
		case ENC_UQDECP_R_P_R_UW:
		case ENC_UQDECP_R_P_R_X:
		case ENC_UQINCP_R_P_R_UW:
		case ENC_UQINCP_R_P_R_X:
			// xxx|xxxx|x|size=xx|xxx|x|D=x|U=x|xxxx|x|sf=x|op=x|Pm=xxxx|Rdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->D = (insword>>17)&1;
			ctx->U = (insword>>16)&1;
			ctx->sf = (insword>>10)&1;
			ctx->op = (insword>>9)&1;
			ctx->Pm = (insword>>5)&15;
			ctx->Rdn = insword&0x1f;
			break;
		case ENC_FCMEQ_P_P_Z0_:
		case ENC_FCMGT_P_P_Z0_:
		case ENC_FCMGE_P_P_Z0_:
		case ENC_FCMLT_P_P_Z0_:
		case ENC_FCMLE_P_P_Z0_:
		case ENC_FCMNE_P_P_Z0_:
			// xxx|xxxx|x|size=xx|xxx|x|eq=x|lt=x|xxx|Pg=xxx|Zn=xxxxx|ne=x|Pd=xxxx
			ctx->size = (insword>>22)&3;
			ctx->eq = (insword>>17)&1;
			ctx->lt = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->ne = (insword>>4)&1;
			ctx->Pd = insword&15;
			break;
		case ENC_DECP_R_P_R_:
		case ENC_INCP_R_P_R_:
			// xxx|xxxx|x|size=xx|xxx|x|op=x|D=x|xxxx|x|opc2=xx|Pm=xxxx|Rdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->op = (insword>>17)&1;
			ctx->D = (insword>>16)&1;
			ctx->opc2 = (insword>>9)&3;
			ctx->Pm = (insword>>5)&15;
			ctx->Rdn = insword&0x1f;
			break;
		case ENC_DECP_Z_P_Z_:
		case ENC_INCP_Z_P_Z_:
			// xxx|xxxx|x|size=xx|xxx|x|op=x|D=x|xxxx|x|opc2=xx|Pm=xxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->op = (insword>>17)&1;
			ctx->D = (insword>>16)&1;
			ctx->opc2 = (insword>>9)&3;
			ctx->Pm = (insword>>5)&15;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_FADDA_V_P_Z_:
			// xxx|xxxx|x|size=xx|xxx|x|opc=xx|xxx|Pg=xxx|Zm=xxxxx|Vdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>16)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Vdn = insword&0x1f;
			break;
		case ENC_FCPY_Z_P_I_:
		case ENC_FMOV_Z_P_I__FCPY_Z_P_I_:
			// xxx|xxxx|x|size=xx|xx|Pg=xxxx|xxx|imm8=xxxxxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Pg = (insword>>16)&15;
			ctx->imm8 = (insword>>5)&0xff;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_CPY_Z_O_I_:
		case ENC_CPY_Z_P_I_:
		case ENC_FMOV_Z_P_0__CPY_Z_P_I_:
		case ENC_MOV_Z_O_I__CPY_Z_O_I_:
		case ENC_MOV_Z_P_I__CPY_Z_P_I_:
			// xxx|xxxx|x|size=xx|xx|Pg=xxxx|x|M=x|sh=x|imm8=xxxxxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Pg = (insword>>16)&15;
			ctx->M = (insword>>14)&1;
			ctx->sh = (insword>>13)&1;
			ctx->imm8 = (insword>>5)&0xff;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_PNEXT_P_P_P_:
			// xxx|xxxx|x|size=xx|xx|xxxx|xx|xxx|xx|Pv=xxxx|x|Pdn=xxxx
			ctx->size = (insword>>22)&3;
			ctx->Pv = (insword>>5)&15;
			ctx->Pdn = insword&15;
			break;
		case ENC_PTRUE_P_S_:
		case ENC_PTRUES_P_S_:
			// xxx|xxxx|x|size=xx|xx|xxx|S=x|xx|xxx|x|pattern=xxxxx|x|Pd=xxxx
			ctx->size = (insword>>22)&3;
			ctx->S = (insword>>16)&1;
			ctx->pattern = (insword>>5)&0x1f;
			ctx->Pd = insword&15;
			break;
		case ENC_ABS_Z_P_Z_M:
		case ENC_ABS_Z_P_Z_Z:
		case ENC_CLS_Z_P_Z_M:
		case ENC_CLS_Z_P_Z_Z:
		case ENC_CLZ_Z_P_Z_M:
		case ENC_CLZ_Z_P_Z_Z:
		case ENC_CNOT_Z_P_Z_M:
		case ENC_CNOT_Z_P_Z_Z:
		case ENC_CNT_Z_P_Z_M:
		case ENC_CNT_Z_P_Z_Z:
		case ENC_FABS_Z_P_Z_M:
		case ENC_FABS_Z_P_Z_Z:
		case ENC_FNEG_Z_P_Z_M:
		case ENC_FNEG_Z_P_Z_Z:
		case ENC_NEG_Z_P_Z_M:
		case ENC_NEG_Z_P_Z_Z:
		case ENC_NOT_Z_P_Z_M:
		case ENC_NOT_Z_P_Z_Z:
			// xxx|xxxx|x|size=xx|x|M=x|x|opc=xxx|xxx|Pg=xxx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->M = (insword>>20)&1;
			ctx->opc = (insword>>16)&7;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SXTB_Z_P_Z_M:
		case ENC_SXTB_Z_P_Z_Z:
		case ENC_SXTH_Z_P_Z_M:
		case ENC_SXTH_Z_P_Z_Z:
		case ENC_SXTW_Z_P_Z_M:
		case ENC_SXTW_Z_P_Z_Z:
		case ENC_UXTB_Z_P_Z_M:
		case ENC_UXTB_Z_P_Z_Z:
		case ENC_UXTH_Z_P_Z_M:
		case ENC_UXTH_Z_P_Z_Z:
		case ENC_UXTW_Z_P_Z_M:
		case ENC_UXTW_Z_P_Z_Z:
			// xxx|xxxx|x|size=xx|x|M=x|x|xx|U=x|xxx|Pg=xxx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->M = (insword>>20)&1;
			ctx->U = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_INDEX_Z_RR_:
			// xxx|xxxx|x|size=xx|x|Rm=xxxxx|xxxx|xx|Rn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_INDEX_Z_IR_:
			// xxx|xxxx|x|size=xx|x|Rm=xxxxx|xxxx|xx|imm5=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->imm5 = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_WHILEGE_PN_RR_:
		case ENC_WHILEGT_PN_RR_:
		case ENC_WHILEHI_PN_RR_:
		case ENC_WHILEHS_PN_RR_:
		case ENC_WHILELE_PN_RR_:
		case ENC_WHILELO_PN_RR_:
		case ENC_WHILELS_PN_RR_:
		case ENC_WHILELT_PN_RR_:
			// xxx|xxxx|x|size=xx|x|Rm=xxxxx|xx|vl=x|x|U=x|lt=x|Rn=xxxxx|x|eq=x|PNd=xxx
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->vl = (insword>>13)&1;
			ctx->U = (insword>>11)&1;
			ctx->lt = (insword>>10)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->eq = (insword>>3)&1;
			ctx->PNd = insword&7;
			break;
		case ENC_WHILEGE_PP_RR_:
		case ENC_WHILEGT_PP_RR_:
		case ENC_WHILEHI_PP_RR_:
		case ENC_WHILEHS_PP_RR_:
		case ENC_WHILELE_PP_RR_:
		case ENC_WHILELO_PP_RR_:
		case ENC_WHILELS_PP_RR_:
		case ENC_WHILELT_PP_RR_:
			// xxx|xxxx|x|size=xx|x|Rm=xxxxx|xx|xx|U=x|lt=x|Rn=xxxxx|x|Pd=xxx|eq=x
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->U = (insword>>11)&1;
			ctx->lt = (insword>>10)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Pd = (insword>>1)&7;
			ctx->eq = insword&1;
			break;
		case ENC_WHILERW_P_RR_:
		case ENC_WHILEWR_P_RR_:
			// xxx|xxxx|x|size=xx|x|Rm=xxxxx|xx|xx|xx|Rn=xxxxx|rw=x|Pd=xxxx
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->rw = (insword>>4)&1;
			ctx->Pd = insword&15;
			break;
		case ENC_WHILEGE_P_P_RR_:
		case ENC_WHILEGT_P_P_RR_:
		case ENC_WHILEHI_P_P_RR_:
		case ENC_WHILEHS_P_P_RR_:
		case ENC_WHILELE_P_P_RR_:
		case ENC_WHILELO_P_P_RR_:
		case ENC_WHILELS_P_P_RR_:
		case ENC_WHILELT_P_P_RR_:
			// xxx|xxxx|x|size=xx|x|Rm=xxxxx|xx|x|sf=x|U=x|lt=x|Rn=xxxxx|eq=x|Pd=xxxx
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->sf = (insword>>12)&1;
			ctx->U = (insword>>11)&1;
			ctx->lt = (insword>>10)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->eq = (insword>>4)&1;
			ctx->Pd = insword&15;
			break;
		case ENC_FMAD_Z_P_ZZZ_:
		case ENC_FMSB_Z_P_ZZZ_:
		case ENC_FNMAD_Z_P_ZZZ_:
		case ENC_FNMSB_Z_P_ZZZ_:
			// xxx|xxxx|x|size=xx|x|Za=xxxxx|x|N=x|op=x|Pg=xxx|Zm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Za = (insword>>16)&0x1f;
			ctx->N = (insword>>14)&1;
			ctx->op = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_CMPGT_P_P_ZW_:
		case ENC_CMPGE_P_P_ZW_:
		case ENC_CMPHI_P_P_ZW_:
		case ENC_CMPHS_P_P_ZW_:
		case ENC_CMPLT_P_P_ZW_:
		case ENC_CMPLE_P_P_ZW_:
		case ENC_CMPLO_P_P_ZW_:
		case ENC_CMPLS_P_P_ZW_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|U=x|x|lt=x|Pg=xxx|Zn=xxxxx|ne=x|Pd=xxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->U = (insword>>15)&1;
			ctx->lt = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->ne = (insword>>4)&1;
			ctx->Pd = insword&15;
			break;
		case ENC_FCMEQ_P_P_ZZ_:
		case ENC_FCMGT_P_P_ZZ_:
		case ENC_FCMGE_P_P_ZZ_:
		case ENC_FCMNE_P_P_ZZ_:
		case ENC_FCMLE_P_P_ZZ__FCMGE_P_P_ZZ_:
		case ENC_FCMLT_P_P_ZZ__FCMGT_P_P_ZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|op=x|x|cmph=x|Pg=xxx|Zn=xxxxx|cmpl=x|Pd=xxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->op = (insword>>15)&1;
			ctx->cmph = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->cmpl = (insword>>4)&1;
			ctx->Pd = insword&15;
			break;
		case ENC_CMPEQ_P_P_ZW_:
		case ENC_CMPNE_P_P_ZW_:
		case ENC_CMPEQ_P_P_ZZ_:
		case ENC_CMPGT_P_P_ZZ_:
		case ENC_CMPGE_P_P_ZZ_:
		case ENC_CMPHI_P_P_ZZ_:
		case ENC_CMPHS_P_P_ZZ_:
		case ENC_CMPNE_P_P_ZZ_:
		case ENC_CMPLE_P_P_ZZ__CMPGE_P_P_ZZ_:
		case ENC_CMPLO_P_P_ZZ__CMPHI_P_P_ZZ_:
		case ENC_CMPLS_P_P_ZZ__CMPHS_P_P_ZZ_:
		case ENC_CMPLT_P_P_ZZ__CMPGT_P_P_ZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|op=x|x|o2=x|Pg=xxx|Zn=xxxxx|ne=x|Pd=xxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->op = (insword>>15)&1;
			ctx->o2 = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->ne = (insword>>4)&1;
			ctx->Pd = insword&15;
			break;
		case ENC_FACGT_P_P_ZZ_:
		case ENC_FACGE_P_P_ZZ_:
		case ENC_FACLE_P_P_ZZ__FACGE_P_P_ZZ_:
		case ENC_FACLT_P_P_ZZ__FACGT_P_P_ZZ_:
		case ENC_FCMUO_P_P_ZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|op=x|x|o2=x|Pg=xxx|Zn=xxxxx|o3=x|Pd=xxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->op = (insword>>15)&1;
			ctx->o2 = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->o3 = (insword>>4)&1;
			ctx->Pd = insword&15;
			break;
		case ENC_BFCLAMP_Z_ZZ_:
		case ENC_FCLAMP_Z_ZZ_:
		case ENC_TBL_Z_ZZ_1:
		case ENC_TBXQ_Z_ZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|xxxxxx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SCLAMP_Z_ZZ_:
		case ENC_UCLAMP_Z_ZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|xxxxx|U=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->U = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_TBL_Z_ZZ_2:
		case ENC_TBX_Z_ZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|xxxxx|op=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->op = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SABAL_Z_ZZ_:
		case ENC_UABAL_Z_ZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|xxxx|U=x|x|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->U = (insword>>11)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_FTSSEL_Z_ZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|xxxx|x|op=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->op = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_HISTCNT_Z_P_ZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|xxx|Pg=xxx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_MATCH_P_P_ZZ_:
		case ENC_NMATCH_P_P_ZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|xxx|Pg=xxx|Zn=xxxxx|op=x|Pd=xxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->op = (insword>>4)&1;
			ctx->Pd = insword&15;
			break;
		case ENC_ADD_Z_ZZ_:
		case ENC_ADDPT_Z_ZZ_:
		case ENC_BFADD_Z_ZZ_:
		case ENC_BFMUL_Z_ZZ_:
		case ENC_BFSUB_Z_ZZ_:
		case ENC_FADD_Z_ZZ_:
		case ENC_FMUL_Z_ZZ_:
		case ENC_FRECPS_Z_ZZ_:
		case ENC_FRSQRTS_Z_ZZ_:
		case ENC_FSUB_Z_ZZ_:
		case ENC_FTSMUL_Z_ZZ_:
		case ENC_SUB_Z_ZZ_:
		case ENC_SUBPT_Z_ZZ_:
		case ENC_TBLQ_Z_ZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|xxx|opc=xxx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->opc = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_ADDQP_Z_ZZ_:
		case ENC_ADDSUBP_Z_ZZ_:
		case ENC_HISTSEG_Z_ZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|xxx|xxx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_PMULL_MZ_ZZW_1X2:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|xxx|xxx|Zn=xxxxx|Zd=xxxx|x
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = (insword>>1)&15;
			break;
		case ENC_PMLAL_MZ_ZZZW_1X2:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|xxx|xxx|Zn=xxxxx|Zda=xxxx|x
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = (insword>>1)&15;
			break;
		case ENC_TRN1_Z_ZZ_:
		case ENC_TRN2_Z_ZZ_:
		case ENC_UZP1_Z_ZZ_:
		case ENC_UZP2_Z_ZZ_:
		case ENC_UZPQ1_Z_ZZ_:
		case ENC_UZPQ2_Z_ZZ_:
		case ENC_ZIP2_Z_ZZ_:
		case ENC_ZIP1_Z_ZZ_:
		case ENC_ZIPQ1_Z_ZZ_:
		case ENC_ZIPQ2_Z_ZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|xxx|xx|H=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->H = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SQDMULH_Z_ZZ_:
		case ENC_SQRDMULH_Z_ZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|xxx|xx|R=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->R = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SQADD_Z_ZZ_:
		case ENC_SQSUB_Z_ZZ_:
		case ENC_UQADD_Z_ZZ_:
		case ENC_UQSUB_Z_ZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|xxx|xx|U=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->U = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_RAX1_Z_ZZ_:
		case ENC_SM4EKEY_Z_ZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|xxx|xx|op=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->op = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_LSL_Z_ZW_:
		case ENC_MUL_Z_ZZ_:
		case ENC_PMUL_Z_ZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|xxx|x|opc=xx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->opc = (insword>>10)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_ASR_Z_ZW_:
		case ENC_LSR_Z_ZW_:
		case ENC_SMULH_Z_ZZ_:
		case ENC_UMULH_Z_ZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|xxx|x|x|U=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->U = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_MOV_Z_P_Z__SEL_Z_P_ZZ_:
		case ENC_SEL_Z_P_ZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|xx|Pv=xxxx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Pv = (insword>>10)&15;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SABA_Z_ZZZ_:
		case ENC_UABA_Z_ZZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|xx|xxx|U=x|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->U = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_EORBT_Z_ZZ_:
		case ENC_EORTB_Z_ZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|xx|xxx|tb=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->tb = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SADDLBT_Z_ZZ_:
		case ENC_SSUBLBT_Z_ZZ_:
		case ENC_SSUBLTB_Z_ZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|xx|xx|S=x|tb=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->S = (insword>>11)&1;
			ctx->tb = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SABALB_Z_ZZZ_:
		case ENC_SABALT_Z_ZZZ_:
		case ENC_UABALB_Z_ZZZ_:
		case ENC_UABALT_Z_ZZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|xx|xx|U=x|T=x|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->U = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_BDEP_Z_ZZ_:
		case ENC_BEXT_Z_ZZ_:
		case ENC_BGRP_Z_ZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|xx|xx|opc=xx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->opc = (insword>>10)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_FMLA_Z_P_ZZZ_:
		case ENC_FMLS_Z_P_ZZZ_:
		case ENC_FNMLA_Z_P_ZZZ_:
		case ENC_FNMLS_Z_P_ZZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|x|N=x|op=x|Pg=xxx|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->N = (insword>>14)&1;
			ctx->op = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_FCMLA_Z_P_ZZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|x|rot=xx|Pg=xxx|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->rot = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_USDOT_Z_ZZZ_S:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|x|xxxxx|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_SQDMLALBT_Z_ZZZ_:
		case ENC_SQDMLSLBT_Z_ZZZ_:
		case ENC_SQRDMLAH_Z_ZZZ_:
		case ENC_SQRDMLSH_Z_ZZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|x|xxxx|S=x|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->S = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_SDOT_Z16_ZZZ_H:
		case ENC_SDOT_Z_ZZZ_:
		case ENC_UDOT_Z16_ZZZ_H:
		case ENC_UDOT_Z_ZZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|x|xxxx|U=x|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->U = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_SQDMLALB_Z_ZZZ_:
		case ENC_SQDMLALT_Z_ZZZ_:
		case ENC_SQDMLSLB_Z_ZZZ_:
		case ENC_SQDMLSLT_Z_ZZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|x|xxx|S=x|T=x|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->S = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_CDOT_Z_ZZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|x|xxx|rot=xx|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->rot = (insword>>10)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_ADDHNB_Z_ZZ_:
		case ENC_ADDHNT_Z_ZZ_:
		case ENC_RADDHNB_Z_ZZ_:
		case ENC_RADDHNT_Z_ZZ_:
		case ENC_RSUBHNB_Z_ZZ_:
		case ENC_RSUBHNT_Z_ZZ_:
		case ENC_SUBHNB_Z_ZZ_:
		case ENC_SUBHNT_Z_ZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|x|xx|S=x|R=x|T=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->S = (insword>>12)&1;
			ctx->R = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SADDWB_Z_ZZ_:
		case ENC_SADDWT_Z_ZZ_:
		case ENC_SSUBWB_Z_ZZ_:
		case ENC_SSUBWT_Z_ZZ_:
		case ENC_UADDWB_Z_ZZ_:
		case ENC_UADDWT_Z_ZZ_:
		case ENC_USUBWB_Z_ZZ_:
		case ENC_USUBWT_Z_ZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|x|xx|S=x|U=x|T=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->S = (insword>>12)&1;
			ctx->U = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SMLALB_Z_ZZZ_:
		case ENC_SMLALT_Z_ZZZ_:
		case ENC_SMLSLB_Z_ZZZ_:
		case ENC_SMLSLT_Z_ZZZ_:
		case ENC_UMLALB_Z_ZZZ_:
		case ENC_UMLALT_Z_ZZZ_:
		case ENC_UMLSLB_Z_ZZZ_:
		case ENC_UMLSLT_Z_ZZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|x|xx|S=x|U=x|T=x|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->S = (insword>>12)&1;
			ctx->U = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_PMULLB_Z_ZZ_:
		case ENC_PMULLB_Z_ZZ_Q:
		case ENC_PMULLT_Z_ZZ_:
		case ENC_PMULLT_Z_ZZ_Q:
		case ENC_SMULLB_Z_ZZ_:
		case ENC_SMULLT_Z_ZZ_:
		case ENC_SQDMULLB_Z_ZZ_:
		case ENC_SQDMULLT_Z_ZZ_:
		case ENC_UMULLB_Z_ZZ_:
		case ENC_UMULLT_Z_ZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|x|xx|op=x|U=x|T=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->op = (insword>>12)&1;
			ctx->U = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_CMLA_Z_ZZZ_:
		case ENC_SQRDCMLAH_Z_ZZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|x|xx|op=x|rot=xx|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->op = (insword>>12)&1;
			ctx->rot = (insword>>10)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_MAD_Z_P_ZZZ_:
		case ENC_MSB_Z_P_ZZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|x|x|op=x|Pg=xxx|Za=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->op = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Za = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_BFMLA_Z_P_ZZZ_:
		case ENC_BFMLS_Z_P_ZZZ_:
		case ENC_MLA_Z_P_ZZZ_:
		case ENC_MLS_Z_P_ZZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|x|x|op=x|Pg=xxx|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->op = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_SABDLB_Z_ZZ_:
		case ENC_SABDLT_Z_ZZ_:
		case ENC_SADDLB_Z_ZZ_:
		case ENC_SADDLT_Z_ZZ_:
		case ENC_SSUBLB_Z_ZZ_:
		case ENC_SSUBLT_Z_ZZ_:
		case ENC_UABDLB_Z_ZZ_:
		case ENC_UABDLT_Z_ZZ_:
		case ENC_UADDLB_Z_ZZ_:
		case ENC_UADDLT_Z_ZZ_:
		case ENC_USUBLB_Z_ZZ_:
		case ENC_USUBLT_Z_ZZ_:
			// xxx|xxxx|x|size=xx|x|Zm=xxxxx|x|x|op=x|S=x|U=x|T=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->op = (insword>>13)&1;
			ctx->S = (insword>>12)&1;
			ctx->U = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_MUL_Z_ZZI_D:
			// xxx|xxxx|x|size=xx|x|i1=x|Zm=xxxx|xxxxxx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i1 = (insword>>20)&1;
			ctx->Zm = (insword>>16)&15;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SQDMULH_Z_ZZI_D:
		case ENC_SQRDMULH_Z_ZZI_D:
			// xxx|xxxx|x|size=xx|x|i1=x|Zm=xxxx|xxxxx|R=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i1 = (insword>>20)&1;
			ctx->Zm = (insword>>16)&15;
			ctx->R = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_MLA_Z_ZZZI_D:
		case ENC_MLS_Z_ZZZI_D:
		case ENC_SQRDMLAH_Z_ZZZI_D:
		case ENC_SQRDMLSH_Z_ZZZI_D:
			// xxx|xxxx|x|size=xx|x|i1=x|Zm=xxxx|xxxxx|S=x|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i1 = (insword>>20)&1;
			ctx->Zm = (insword>>16)&15;
			ctx->S = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_SDOT_Z_ZZZI_D:
		case ENC_UDOT_Z_ZZZI_D:
			// xxx|xxxx|x|size=xx|x|i1=x|Zm=xxxx|xxxxx|U=x|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i1 = (insword>>20)&1;
			ctx->Zm = (insword>>16)&15;
			ctx->U = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_FMLA_Z_ZZZI_D:
		case ENC_FMLS_Z_ZZZI_D:
			// xxx|xxxx|x|size=xx|x|i1=x|Zm=xxxx|xxxx|o2=x|op=x|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i1 = (insword>>20)&1;
			ctx->Zm = (insword>>16)&15;
			ctx->o2 = (insword>>11)&1;
			ctx->op = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_FMUL_Z_ZZI_D:
			// xxx|xxxx|x|size=xx|x|i1=x|Zm=xxxx|xxxx|o2=x|x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i1 = (insword>>20)&1;
			ctx->Zm = (insword>>16)&15;
			ctx->o2 = (insword>>11)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_CDOT_Z_ZZZI_D:
		case ENC_CMLA_Z_ZZZI_S:
		case ENC_FCMLA_Z_ZZZI_S:
		case ENC_SQRDCMLAH_Z_ZZZI_S:
			// xxx|xxxx|x|size=xx|x|i1=x|Zm=xxxx|xxxx|rot=xx|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i1 = (insword>>20)&1;
			ctx->Zm = (insword>>16)&15;
			ctx->rot = (insword>>10)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_MUL_Z_ZZI_S:
			// xxx|xxxx|x|size=xx|x|i2=xx|Zm=xxx|xxxxxx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i2 = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SQDMULH_Z_ZZI_S:
		case ENC_SQRDMULH_Z_ZZI_S:
			// xxx|xxxx|x|size=xx|x|i2=xx|Zm=xxx|xxxxx|R=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i2 = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->R = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_MLA_Z_ZZZI_S:
		case ENC_MLS_Z_ZZZI_S:
		case ENC_SQRDMLAH_Z_ZZZI_S:
		case ENC_SQRDMLSH_Z_ZZZI_S:
			// xxx|xxxx|x|size=xx|x|i2=xx|Zm=xxx|xxxxx|S=x|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i2 = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->S = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_SDOT_Z_ZZZI_S:
		case ENC_SUDOT_Z_ZZZI_S:
		case ENC_UDOT_Z_ZZZI_S:
		case ENC_USDOT_Z_ZZZI_S:
			// xxx|xxxx|x|size=xx|x|i2=xx|Zm=xxx|xxxxx|U=x|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i2 = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->U = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_FMLA_Z_ZZZI_S:
		case ENC_FMLS_Z_ZZZI_S:
			// xxx|xxxx|x|size=xx|x|i2=xx|Zm=xxx|xxxx|o2=x|op=x|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i2 = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->o2 = (insword>>11)&1;
			ctx->op = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_FMUL_Z_ZZI_S:
			// xxx|xxxx|x|size=xx|x|i2=xx|Zm=xxx|xxxx|o2=x|x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i2 = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->o2 = (insword>>11)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_CDOT_Z_ZZZI_S:
		case ENC_CMLA_Z_ZZZI_H:
		case ENC_FCMLA_Z_ZZZI_H:
		case ENC_SQRDCMLAH_Z_ZZZI_H:
			// xxx|xxxx|x|size=xx|x|i2=xx|Zm=xxx|xxxx|rot=xx|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i2 = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->rot = (insword>>10)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_AESD_MZ_ZZI_2X1:
		case ENC_AESDIMC_MZ_ZZI_2X1:
		case ENC_AESE_MZ_ZZI_2X1:
		case ENC_AESEMC_MZ_ZZI_2X1:
			// xxx|xxxx|x|size=xx|x|i2=xx|xx|op=x|xxx|xx|o2=x|Zm=xxxxx|Zdn=xxxx|o3=x
			ctx->size = (insword>>22)&3;
			ctx->i2 = (insword>>19)&3;
			ctx->op = (insword>>16)&1;
			ctx->o2 = (insword>>10)&1;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = (insword>>1)&15;
			ctx->o3 = insword&1;
			break;
		case ENC_AESD_MZ_ZZI_4X1:
		case ENC_AESDIMC_MZ_ZZI_4X1:
		case ENC_AESE_MZ_ZZI_4X1:
		case ENC_AESEMC_MZ_ZZI_4X1:
			// xxx|xxxx|x|size=xx|x|i2=xx|xx|op=x|xxx|xx|o2=x|Zm=xxxxx|Zdn=xxx|opc3=xx
			ctx->size = (insword>>22)&3;
			ctx->i2 = (insword>>19)&3;
			ctx->op = (insword>>16)&1;
			ctx->o2 = (insword>>10)&1;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = (insword>>2)&7;
			ctx->opc3 = insword&3;
			break;
		case ENC_SQDMULLB_Z_ZZI_D:
		case ENC_SQDMULLT_Z_ZZI_D:
			// xxx|xxxx|x|size=xx|x|i2h=x|Zm=xxxx|xxxx|i2l=x|T=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i2h = (insword>>20)&1;
			ctx->Zm = (insword>>16)&15;
			ctx->i2l = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SQDMLALB_Z_ZZZI_D:
		case ENC_SQDMLALT_Z_ZZZI_D:
		case ENC_SQDMLSLB_Z_ZZZI_D:
		case ENC_SQDMLSLT_Z_ZZZI_D:
			// xxx|xxxx|x|size=xx|x|i2h=x|Zm=xxxx|xxx|S=x|i2l=x|T=x|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i2h = (insword>>20)&1;
			ctx->Zm = (insword>>16)&15;
			ctx->S = (insword>>12)&1;
			ctx->i2l = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_SMULLB_Z_ZZI_D:
		case ENC_SMULLT_Z_ZZI_D:
		case ENC_UMULLB_Z_ZZI_D:
		case ENC_UMULLT_Z_ZZI_D:
			// xxx|xxxx|x|size=xx|x|i2h=x|Zm=xxxx|xxx|U=x|i2l=x|T=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i2h = (insword>>20)&1;
			ctx->Zm = (insword>>16)&15;
			ctx->U = (insword>>12)&1;
			ctx->i2l = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SMLALB_Z_ZZZI_D:
		case ENC_SMLALT_Z_ZZZI_D:
		case ENC_SMLSLB_Z_ZZZI_D:
		case ENC_SMLSLT_Z_ZZZI_D:
		case ENC_UMLALB_Z_ZZZI_D:
		case ENC_UMLALT_Z_ZZZI_D:
		case ENC_UMLSLB_Z_ZZZI_D:
		case ENC_UMLSLT_Z_ZZZI_D:
			// xxx|xxxx|x|size=xx|x|i2h=x|Zm=xxxx|xx|S=x|U=x|i2l=x|T=x|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i2h = (insword>>20)&1;
			ctx->Zm = (insword>>16)&15;
			ctx->S = (insword>>13)&1;
			ctx->U = (insword>>12)&1;
			ctx->i2l = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_SQDMULLB_Z_ZZI_S:
		case ENC_SQDMULLT_Z_ZZI_S:
			// xxx|xxxx|x|size=xx|x|i3h=xx|Zm=xxx|xxxx|i3l=x|T=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i3h = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->i3l = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SQDMLALB_Z_ZZZI_S:
		case ENC_SQDMLALT_Z_ZZZI_S:
		case ENC_SQDMLSLB_Z_ZZZI_S:
		case ENC_SQDMLSLT_Z_ZZZI_S:
			// xxx|xxxx|x|size=xx|x|i3h=xx|Zm=xxx|xxx|S=x|i3l=x|T=x|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i3h = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->S = (insword>>12)&1;
			ctx->i3l = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_SMULLB_Z_ZZI_S:
		case ENC_SMULLT_Z_ZZI_S:
		case ENC_UMULLB_Z_ZZI_S:
		case ENC_UMULLT_Z_ZZI_S:
			// xxx|xxxx|x|size=xx|x|i3h=xx|Zm=xxx|xxx|U=x|i3l=x|T=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i3h = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->U = (insword>>12)&1;
			ctx->i3l = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SMLALB_Z_ZZZI_S:
		case ENC_SMLALT_Z_ZZZI_S:
		case ENC_SMLSLB_Z_ZZZI_S:
		case ENC_SMLSLT_Z_ZZZI_S:
		case ENC_UMLALB_Z_ZZZI_S:
		case ENC_UMLALT_Z_ZZZI_S:
		case ENC_UMLSLB_Z_ZZZI_S:
		case ENC_UMLSLT_Z_ZZZI_S:
			// xxx|xxxx|x|size=xx|x|i3h=xx|Zm=xxx|xx|S=x|U=x|i3l=x|T=x|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i3h = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->S = (insword>>13)&1;
			ctx->U = (insword>>12)&1;
			ctx->i3l = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_CMPGT_P_P_ZI_:
		case ENC_CMPGE_P_P_ZI_:
		case ENC_CMPLT_P_P_ZI_:
		case ENC_CMPLE_P_P_ZI_:
			// xxx|xxxx|x|size=xx|x|imm5=xxxxx|op=x|x|lt=x|Pg=xxx|Zn=xxxxx|ne=x|Pd=xxxx
			ctx->size = (insword>>22)&3;
			ctx->imm5 = (insword>>16)&0x1f;
			ctx->op = (insword>>15)&1;
			ctx->lt = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->ne = (insword>>4)&1;
			ctx->Pd = insword&15;
			break;
		case ENC_CMPEQ_P_P_ZI_:
		case ENC_CMPNE_P_P_ZI_:
			// xxx|xxxx|x|size=xx|x|imm5=xxxxx|op=x|x|o2=x|Pg=xxx|Zn=xxxxx|ne=x|Pd=xxxx
			ctx->size = (insword>>22)&3;
			ctx->imm5 = (insword>>16)&0x1f;
			ctx->op = (insword>>15)&1;
			ctx->o2 = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->ne = (insword>>4)&1;
			ctx->Pd = insword&15;
			break;
		case ENC_INDEX_Z_RI_:
			// xxx|xxxx|x|size=xx|x|imm5=xxxxx|xxxx|xx|Rn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->imm5 = (insword>>16)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_INDEX_Z_II_:
			// xxx|xxxx|x|size=xx|x|imm5b=xxxxx|xxxx|xx|imm5=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->imm5b = (insword>>16)&0x1f;
			ctx->imm5 = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_CMPHI_P_P_ZI_:
		case ENC_CMPHS_P_P_ZI_:
		case ENC_CMPLO_P_P_ZI_:
		case ENC_CMPLS_P_P_ZI_:
			// xxx|xxxx|x|size=xx|x|imm7=xxxxxxx|lt=x|Pg=xxx|Zn=xxxxx|ne=x|Pd=xxxx
			ctx->size = (insword>>22)&3;
			ctx->imm7 = (insword>>14)&0x7f;
			ctx->lt = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->ne = (insword>>4)&1;
			ctx->Pd = insword&15;
			break;
		case ENC_FEXPA_Z_Z_:
			// xxx|xxxx|x|size=xx|x|opc=xxxxx|xxxx|xx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>16)&0x1f;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SQDECB_R_RS_SX:
		case ENC_SQDECB_R_RS_X:
		case ENC_SQDECD_R_RS_SX:
		case ENC_SQDECD_R_RS_X:
		case ENC_SQDECH_R_RS_SX:
		case ENC_SQDECH_R_RS_X:
		case ENC_SQDECW_R_RS_SX:
		case ENC_SQDECW_R_RS_X:
		case ENC_SQINCB_R_RS_SX:
		case ENC_SQINCB_R_RS_X:
		case ENC_SQINCD_R_RS_SX:
		case ENC_SQINCD_R_RS_X:
		case ENC_SQINCH_R_RS_SX:
		case ENC_SQINCH_R_RS_X:
		case ENC_SQINCW_R_RS_SX:
		case ENC_SQINCW_R_RS_X:
		case ENC_UQDECB_R_RS_UW:
		case ENC_UQDECB_R_RS_X:
		case ENC_UQDECD_R_RS_UW:
		case ENC_UQDECD_R_RS_X:
		case ENC_UQDECH_R_RS_UW:
		case ENC_UQDECH_R_RS_X:
		case ENC_UQDECW_R_RS_UW:
		case ENC_UQDECW_R_RS_X:
		case ENC_UQINCB_R_RS_UW:
		case ENC_UQINCB_R_RS_X:
		case ENC_UQINCD_R_RS_UW:
		case ENC_UQINCD_R_RS_X:
		case ENC_UQINCH_R_RS_UW:
		case ENC_UQINCH_R_RS_X:
		case ENC_UQINCW_R_RS_UW:
		case ENC_UQINCW_R_RS_X:
			// xxx|xxxx|x|size=xx|x|sf=x|imm4=xxxx|xx|xx|D=x|U=x|pattern=xxxxx|Rdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->sf = (insword>>20)&1;
			ctx->imm4 = (insword>>16)&15;
			ctx->D = (insword>>11)&1;
			ctx->U = (insword>>10)&1;
			ctx->pattern = (insword>>5)&0x1f;
			ctx->Rdn = insword&0x1f;
			break;
		case ENC_REV_P_P_:
			// xxx|xxxx|x|size=xx|x|xxxxx|xxx|xxxx|Pn=xxxx|x|Pd=xxxx
			ctx->size = (insword>>22)&3;
			ctx->Pn = (insword>>5)&15;
			ctx->Pd = insword&15;
			break;
		case ENC_PTRUE_PN_I_:
			// xxx|xxxx|x|size=xx|x|xxxxx|xx|xxx|xxxxxx|x|x|PNd=xxx
			ctx->size = (insword>>22)&3;
			ctx->PNd = insword&7;
			break;
		case ENC_PEXT_PP_RR_:
			// xxx|xxxx|x|size=xx|x|xxxxx|xx|xxx|xx|i1=x|PNn=xxx|x|Pd=xxxx
			ctx->size = (insword>>22)&3;
			ctx->i1 = (insword>>8)&1;
			ctx->PNn = (insword>>5)&7;
			ctx->Pd = insword&15;
			break;
		case ENC_PEXT_PN_RR_:
			// xxx|xxxx|x|size=xx|x|xxxxx|xx|xxx|x|imm2=xx|PNn=xxx|x|Pd=xxxx
			ctx->size = (insword>>22)&3;
			ctx->imm2 = (insword>>8)&3;
			ctx->PNn = (insword>>5)&7;
			ctx->Pd = insword&15;
			break;
		case ENC_SADALP_Z_P_Z_:
		case ENC_UADALP_Z_P_Z_:
			// xxx|xxxx|x|size=xx|x|xxxx|U=x|xx|x|Pg=xxx|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->U = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_CADD_Z_ZZ_:
		case ENC_SQCADD_Z_ZZ_:
			// xxx|xxxx|x|size=xx|x|xxxx|op=x|xx|xxx|rot=x|Zm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->op = (insword>>16)&1;
			ctx->rot = (insword>>10)&1;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_MUL_Z_P_ZZ_:
		case ENC_SMULH_Z_P_ZZ_:
		case ENC_UMULH_Z_P_ZZ_:
			// xxx|xxxx|x|size=xx|x|xxx|H=x|U=x|xxx|Pg=xxx|Zm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->H = (insword>>17)&1;
			ctx->U = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_SDIV_Z_P_ZZ_:
		case ENC_SDIVR_Z_P_ZZ_:
		case ENC_UDIV_Z_P_ZZ_:
		case ENC_UDIVR_Z_P_ZZ_:
			// xxx|xxxx|x|size=xx|x|xxx|R=x|U=x|xxx|Pg=xxx|Zm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->R = (insword>>17)&1;
			ctx->U = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_ADDQV_Z_P_Z_:
		case ENC_SADDV_R_P_Z_:
		case ENC_SMAXQV_Z_P_Z_:
		case ENC_SMAXV_R_P_Z_:
		case ENC_SMINQV_Z_P_Z_:
		case ENC_SMINV_R_P_Z_:
		case ENC_UADDV_R_P_Z_:
		case ENC_UMAXQV_Z_P_Z_:
		case ENC_UMAXV_R_P_Z_:
		case ENC_UMINQV_Z_P_Z_:
		case ENC_UMINV_R_P_Z_:
			// xxx|xxxx|x|size=xx|x|xxx|op=x|U=x|xxx|Pg=xxx|Zn=xxxxx|Vd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->op = (insword>>17)&1;
			ctx->U = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Vd = insword&0x1f;
			break;
		case ENC_ANDQV_Z_P_Z_:
		case ENC_ANDV_R_P_Z_:
		case ENC_EORQV_Z_P_Z_:
		case ENC_EORV_R_P_Z_:
		case ENC_ORQV_Z_P_Z_:
		case ENC_ORV_R_P_Z_:
			// xxx|xxxx|x|size=xx|x|xxx|opc=xx|xxx|Pg=xxx|Zn=xxxxx|Vd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>16)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Vd = insword&0x1f;
			break;
		case ENC_FRECPX_Z_P_Z_M:
		case ENC_FSQRT_Z_P_Z_M:
			// xxx|xxxx|x|size=xx|x|xxx|opc=xx|xxx|Pg=xxx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>16)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_AESIMC_Z_Z_:
		case ENC_AESMC_Z_Z_:
			// xxx|xxxx|x|size=xx|x|xxx|xx|xxx|xx|op=x|xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->op = (insword>>10)&1;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_AESD_Z_ZZ_:
		case ENC_AESE_Z_ZZ_:
		case ENC_SM4E_Z_ZZ_:
			// xxx|xxxx|x|size=xx|x|xxx|x|op=x|xxx|xx|o2=x|Zm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->op = (insword>>16)&1;
			ctx->o2 = (insword>>10)&1;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_ASR_Z_P_ZW_:
		case ENC_ASR_Z_P_ZZ_:
		case ENC_ASRR_Z_P_ZZ_:
		case ENC_LSL_Z_P_ZW_:
		case ENC_LSL_Z_P_ZZ_:
		case ENC_LSLR_Z_P_ZZ_:
		case ENC_LSR_Z_P_ZW_:
		case ENC_LSR_Z_P_ZZ_:
		case ENC_LSRR_Z_P_ZZ_:
			// xxx|xxxx|x|size=xx|x|xx|R=x|L=x|U=x|xxx|Pg=xxx|Zm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->R = (insword>>18)&1;
			ctx->L = (insword>>17)&1;
			ctx->U = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_SHADD_Z_P_ZZ_:
		case ENC_SHSUB_Z_P_ZZ_:
		case ENC_SHSUBR_Z_P_ZZ_:
		case ENC_SRHADD_Z_P_ZZ_:
		case ENC_UHADD_Z_P_ZZ_:
		case ENC_UHSUB_Z_P_ZZ_:
		case ENC_UHSUBR_Z_P_ZZ_:
		case ENC_URHADD_Z_P_ZZ_:
			// xxx|xxxx|x|size=xx|x|xx|R=x|S=x|U=x|xx|x|Pg=xxx|Zm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->R = (insword>>18)&1;
			ctx->S = (insword>>17)&1;
			ctx->U = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_FTMAD_Z_ZZI_:
			// xxx|xxxx|x|size=xx|x|xx|imm3=xxx|xxx|xxx|Zm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->imm3 = (insword>>16)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_SQADD_Z_P_ZZ_:
		case ENC_SQSUB_Z_P_ZZ_:
		case ENC_SQSUBR_Z_P_ZZ_:
		case ENC_SUQADD_Z_P_ZZ_:
		case ENC_UQADD_Z_P_ZZ_:
		case ENC_UQSUB_Z_P_ZZ_:
		case ENC_UQSUBR_Z_P_ZZ_:
		case ENC_USQADD_Z_P_ZZ_:
			// xxx|xxxx|x|size=xx|x|xx|op=x|S=x|U=x|xx|x|Pg=xxx|Zm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->op = (insword>>18)&1;
			ctx->S = (insword>>17)&1;
			ctx->U = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_ADD_Z_P_ZZ_:
		case ENC_ADDPT_Z_P_ZZ_:
		case ENC_AND_Z_P_ZZ_:
		case ENC_BIC_Z_P_ZZ_:
		case ENC_EOR_Z_P_ZZ_:
		case ENC_ORR_Z_P_ZZ_:
		case ENC_SUB_Z_P_ZZ_:
		case ENC_SUBPT_Z_P_ZZ_:
		case ENC_SUBR_Z_P_ZZ_:
			// xxx|xxxx|x|size=xx|x|xx|opc=xxx|xxx|Pg=xxx|Zm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>16)&7;
			ctx->Pg = (insword>>10)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_FRINTX_Z_P_Z_M:
		case ENC_FRINTI_Z_P_Z_M:
		case ENC_FRINTA_Z_P_Z_M:
		case ENC_FRINTN_Z_P_Z_M:
		case ENC_FRINTZ_Z_P_Z_M:
		case ENC_FRINTM_Z_P_Z_M:
		case ENC_FRINTP_Z_P_Z_M:
			// xxx|xxxx|x|size=xx|x|xx|opc=xxx|xxx|Pg=xxx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>16)&7;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_FADD_Z_P_ZS_:
		case ENC_FMAX_Z_P_ZS_:
		case ENC_FMAXNM_Z_P_ZS_:
		case ENC_FMIN_Z_P_ZS_:
		case ENC_FMINNM_Z_P_ZS_:
		case ENC_FMUL_Z_P_ZS_:
		case ENC_FSUB_Z_P_ZS_:
		case ENC_FSUBR_Z_P_ZS_:
			// xxx|xxxx|x|size=xx|x|xx|opc=xxx|xxx|Pg=xxx|xxxx|i1=x|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>16)&7;
			ctx->Pg = (insword>>10)&7;
			ctx->i1 = (insword>>5)&1;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_MUL_Z_ZI_:
			// xxx|xxxx|x|size=xx|x|xx|opc=xxx|xx|o2=x|imm8=xxxxxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>16)&7;
			ctx->o2 = (insword>>13)&1;
			ctx->imm8 = (insword>>5)&0xff;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_ADD_Z_ZI_:
		case ENC_SUB_Z_ZI_:
		case ENC_SUBR_Z_ZI_:
			// xxx|xxxx|x|size=xx|x|xx|opc=xxx|xx|sh=x|imm8=xxxxxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>16)&7;
			ctx->sh = (insword>>13)&1;
			ctx->imm8 = (insword>>5)&0xff;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_MOVPRFX_Z_P_Z_:
			// xxx|xxxx|x|size=xx|x|xx|opc=xx|M=x|xxx|Pg=xxx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>17)&3;
			ctx->M = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SABD_Z_P_ZZ_:
		case ENC_SMAX_Z_P_ZZ_:
		case ENC_SMIN_Z_P_ZZ_:
		case ENC_UABD_Z_P_ZZ_:
		case ENC_UMAX_Z_P_ZZ_:
		case ENC_UMIN_Z_P_ZZ_:
			// xxx|xxxx|x|size=xx|x|xx|opc=xx|U=x|xxx|Pg=xxx|Zm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>17)&3;
			ctx->U = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_ADDP_Z_P_ZZ_:
		case ENC_SMAXP_Z_P_ZZ_:
		case ENC_SMINP_Z_P_ZZ_:
		case ENC_SUBP_Z_P_ZZ_:
		case ENC_UMAXP_Z_P_ZZ_:
		case ENC_UMINP_Z_P_ZZ_:
			// xxx|xxxx|x|size=xx|x|xx|opc=xx|U=x|xx|x|Pg=xxx|Zm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>17)&3;
			ctx->U = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_FDUP_Z_I_:
		case ENC_FMOV_Z_I__FDUP_Z_I_:
			// xxx|xxxx|x|size=xx|x|xx|opc=xx|x|xx|o2=x|imm8=xxxxxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>17)&3;
			ctx->o2 = (insword>>13)&1;
			ctx->imm8 = (insword>>5)&0xff;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_DUP_Z_I_:
		case ENC_FMOV_Z_0__DUP_Z_I_:
		case ENC_MOV_Z_I__DUP_Z_I_:
			// xxx|xxxx|x|size=xx|x|xx|opc=xx|x|xx|sh=x|imm8=xxxxxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>17)&3;
			ctx->sh = (insword>>13)&1;
			ctx->imm8 = (insword>>5)&0xff;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_INSR_Z_R_:
			// xxx|xxxx|x|size=xx|x|xx|xxx|xxxxxx|Rm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_DUP_Z_R_:
		case ENC_MOV_Z_R__DUP_Z_R_:
			// xxx|xxxx|x|size=xx|x|xx|xxx|xxxxxx|Rn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_INSR_Z_V_:
			// xxx|xxxx|x|size=xx|x|xx|xxx|xxxxxx|Vm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Vm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_REV_Z_Z_:
			// xxx|xxxx|x|size=xx|x|xx|xxx|xxxxxx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SMAX_Z_ZI_:
		case ENC_SMIN_Z_ZI_:
		case ENC_UMAX_Z_ZI_:
		case ENC_UMIN_Z_ZI_:
			// xxx|xxxx|x|size=xx|x|xx|xx|U=x|xx|o2=x|imm8=xxxxxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->U = (insword>>16)&1;
			ctx->o2 = (insword>>13)&1;
			ctx->imm8 = (insword>>5)&0xff;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_SQADD_Z_ZI_:
		case ENC_SQSUB_Z_ZI_:
		case ENC_UQADD_Z_ZI_:
		case ENC_UQSUB_Z_ZI_:
			// xxx|xxxx|x|size=xx|x|xx|xx|U=x|xx|sh=x|imm8=xxxxxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->U = (insword>>16)&1;
			ctx->sh = (insword>>13)&1;
			ctx->imm8 = (insword>>5)&0xff;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_SUNPKHI_Z_Z_:
		case ENC_SUNPKLO_Z_Z_:
		case ENC_UUNPKHI_Z_Z_:
		case ENC_UUNPKLO_Z_Z_:
			// xxx|xxxx|x|size=xx|x|xx|x|U=x|H=x|xxxxxx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->U = (insword>>17)&1;
			ctx->H = (insword>>16)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_TRN1_P_PP_:
		case ENC_TRN2_P_PP_:
		case ENC_UZP1_P_PP_:
		case ENC_UZP2_P_PP_:
		case ENC_ZIP2_P_PP_:
		case ENC_ZIP1_P_PP_:
			// xxx|xxxx|x|size=xx|x|x|Pm=xxxx|xxx|opc=xx|H=x|x|Pn=xxxx|x|Pd=xxxx
			ctx->size = (insword>>22)&3;
			ctx->Pm = (insword>>16)&15;
			ctx->opc = (insword>>11)&3;
			ctx->H = (insword>>10)&1;
			ctx->Pn = (insword>>5)&15;
			ctx->Pd = insword&15;
			break;
		case ENC_SQRSHL_Z_P_ZZ_:
		case ENC_SQRSHLR_Z_P_ZZ_:
		case ENC_SQSHL_Z_P_ZZ_:
		case ENC_SQSHLR_Z_P_ZZ_:
		case ENC_SRSHL_Z_P_ZZ_:
		case ENC_SRSHLR_Z_P_ZZ_:
		case ENC_UQRSHL_Z_P_ZZ_:
		case ENC_UQRSHLR_Z_P_ZZ_:
		case ENC_UQSHL_Z_P_ZZ_:
		case ENC_UQSHLR_Z_P_ZZ_:
		case ENC_URSHL_Z_P_ZZ_:
		case ENC_URSHLR_Z_P_ZZ_:
			// xxx|xxxx|x|size=xx|x|x|Q=x|R=x|N=x|U=x|xx|x|Pg=xxx|Zm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Q = (insword>>19)&1;
			ctx->R = (insword>>18)&1;
			ctx->N = (insword>>17)&1;
			ctx->U = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_SQABS_Z_P_Z_M:
		case ENC_SQABS_Z_P_Z_Z:
		case ENC_SQNEG_Z_P_Z_M:
		case ENC_SQNEG_Z_P_Z_Z:
		case ENC_URECPE_Z_P_Z_M:
		case ENC_URECPE_Z_P_Z_Z:
		case ENC_URSQRTE_Z_P_Z_M:
		case ENC_URSQRTE_Z_P_Z_Z:
			// xxx|xxxx|x|size=xx|x|x|Q=x|x|Z=x|op=x|xx|x|Pg=xxx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Q = (insword>>19)&1;
			ctx->Z = (insword>>17)&1;
			ctx->op = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_DECB_R_RS_:
		case ENC_DECD_R_RS_:
		case ENC_DECH_R_RS_:
		case ENC_DECW_R_RS_:
		case ENC_INCB_R_RS_:
		case ENC_INCD_R_RS_:
		case ENC_INCH_R_RS_:
		case ENC_INCW_R_RS_:
			// xxx|xxxx|x|size=xx|x|x|imm4=xxxx|xx|xxx|D=x|pattern=xxxxx|Rdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->imm4 = (insword>>16)&15;
			ctx->D = (insword>>10)&1;
			ctx->pattern = (insword>>5)&0x1f;
			ctx->Rdn = insword&0x1f;
			break;
		case ENC_DECD_Z_ZS_:
		case ENC_DECH_Z_ZS_:
		case ENC_DECW_Z_ZS_:
		case ENC_INCD_Z_ZS_:
		case ENC_INCH_Z_ZS_:
		case ENC_INCW_Z_ZS_:
			// xxx|xxxx|x|size=xx|x|x|imm4=xxxx|xx|xxx|D=x|pattern=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->imm4 = (insword>>16)&15;
			ctx->D = (insword>>10)&1;
			ctx->pattern = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_CNTB_R_S_:
		case ENC_CNTD_R_S_:
		case ENC_CNTH_R_S_:
		case ENC_CNTW_R_S_:
			// xxx|xxxx|x|size=xx|x|x|imm4=xxxx|xx|xxx|op=x|pattern=xxxxx|Rd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->imm4 = (insword>>16)&15;
			ctx->op = (insword>>10)&1;
			ctx->pattern = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SQDECD_Z_ZS_:
		case ENC_SQDECH_Z_ZS_:
		case ENC_SQDECW_Z_ZS_:
		case ENC_SQINCD_Z_ZS_:
		case ENC_SQINCH_Z_ZS_:
		case ENC_SQINCW_Z_ZS_:
		case ENC_UQDECD_Z_ZS_:
		case ENC_UQDECH_Z_ZS_:
		case ENC_UQDECW_Z_ZS_:
		case ENC_UQINCD_Z_ZS_:
		case ENC_UQINCH_Z_ZS_:
		case ENC_UQINCW_Z_ZS_:
			// xxx|xxxx|x|size=xx|x|x|imm4=xxxx|xx|xx|D=x|U=x|pattern=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->imm4 = (insword>>16)&15;
			ctx->D = (insword>>11)&1;
			ctx->U = (insword>>10)&1;
			ctx->pattern = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_BFADD_Z_P_ZZ_:
		case ENC_BFMAX_Z_P_ZZ_:
		case ENC_BFMAXNM_Z_P_ZZ_:
		case ENC_BFMIN_Z_P_ZZ_:
		case ENC_BFMINNM_Z_P_ZZ_:
		case ENC_BFMUL_Z_P_ZZ_:
		case ENC_BFSCALE_Z_P_ZZ_:
		case ENC_BFSUB_Z_P_ZZ_:
		case ENC_FABD_Z_P_ZZ_:
		case ENC_FADD_Z_P_ZZ_:
		case ENC_FAMAX_Z_P_ZZ_:
		case ENC_FAMIN_Z_P_ZZ_:
		case ENC_FDIV_Z_P_ZZ_:
		case ENC_FDIVR_Z_P_ZZ_:
		case ENC_FMAX_Z_P_ZZ_:
		case ENC_FMAXNM_Z_P_ZZ_:
		case ENC_FMIN_Z_P_ZZ_:
		case ENC_FMINNM_Z_P_ZZ_:
		case ENC_FMUL_Z_P_ZZ_:
		case ENC_FMULX_Z_P_ZZ_:
		case ENC_FSCALE_Z_P_ZZ_:
		case ENC_FSUB_Z_P_ZZ_:
		case ENC_FSUBR_Z_P_ZZ_:
			// xxx|xxxx|x|size=xx|x|x|opc=xxxx|xxx|Pg=xxx|Zm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>16)&15;
			ctx->Pg = (insword>>10)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_CLASTA_R_P_Z_:
		case ENC_CLASTB_R_P_Z_:
			// xxx|xxxx|x|size=xx|x|x|xxx|B=x|xx|x|Pg=xxx|Zm=xxxxx|Rdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->B = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Rdn = insword&0x1f;
			break;
		case ENC_CLASTA_V_P_Z_:
		case ENC_CLASTB_V_P_Z_:
			// xxx|xxxx|x|size=xx|x|x|xxx|B=x|xx|x|Pg=xxx|Zm=xxxxx|Vdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->B = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Vdn = insword&0x1f;
			break;
		case ENC_CLASTA_Z_P_ZZ_:
		case ENC_CLASTB_Z_P_ZZ_:
			// xxx|xxxx|x|size=xx|x|x|xxx|B=x|xx|x|Pg=xxx|Zm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->B = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_LASTA_R_P_Z_:
		case ENC_LASTB_R_P_Z_:
			// xxx|xxxx|x|size=xx|x|x|xxx|B=x|xx|x|Pg=xxx|Zn=xxxxx|Rd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->B = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_LASTA_V_P_Z_:
		case ENC_LASTB_V_P_Z_:
			// xxx|xxxx|x|size=xx|x|x|xxx|B=x|xx|x|Pg=xxx|Zn=xxxxx|Vd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->B = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Vd = insword&0x1f;
			break;
		case ENC_REVD_Z_P_Z_M:
		case ENC_REVD_Z_P_Z_Z:
			// xxx|xxxx|x|size=xx|x|x|xxx|x|xx|Z=x|Pg=xxx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Z = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_CPY_Z_P_R_:
		case ENC_MOV_Z_P_R__CPY_Z_P_R_:
			// xxx|xxxx|x|size=xx|x|x|xxx|x|xx|x|Pg=xxx|Rn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_CPY_Z_P_V_:
		case ENC_MOV_Z_P_V__CPY_Z_P_V_:
			// xxx|xxxx|x|size=xx|x|x|xxx|x|xx|x|Pg=xxx|Vn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Vn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_EXPAND_Z_P_Z_:
			// xxx|xxxx|x|size=xx|x|x|xxx|x|xx|x|Pg=xxx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SPLICE_Z_P_ZZ_DES:
			// xxx|xxxx|x|size=xx|x|x|xxx|x|xx|x|Pv=xxx|Zm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Pv = (insword>>10)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_SPLICE_Z_P_ZZ_CON:
			// xxx|xxxx|x|size=xx|x|x|xxx|x|xx|x|Pv=xxx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Pv = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_RBIT_Z_P_Z_M:
		case ENC_RBIT_Z_P_Z_Z:
		case ENC_REVB_Z_Z_M:
		case ENC_REVB_Z_Z_Z:
		case ENC_REVH_Z_Z_M:
		case ENC_REVH_Z_Z_Z:
		case ENC_REVW_Z_Z_M:
		case ENC_REVW_Z_Z_Z:
			// xxx|xxxx|x|size=xx|x|x|xx|opc=xx|xx|Z=x|Pg=xxx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>16)&3;
			ctx->Z = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_XAR_Z_ZZI_:
			// xxx|xxxx|x|tszh=xx|x|tszl=xx|imm3=xxx|xxx|xxx|Zm=xxxxx|Zdn=xxxxx
			ctx->tszh = (insword>>22)&3;
			ctx->tszl = (insword>>19)&3;
			ctx->imm3 = (insword>>16)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_LSL_Z_ZI_:
			// xxx|xxxx|x|tszh=xx|x|tszl=xx|imm3=xxx|xxx|x|opc=xx|Zn=xxxxx|Zd=xxxxx
			ctx->tszh = (insword>>22)&3;
			ctx->tszl = (insword>>19)&3;
			ctx->imm3 = (insword>>16)&7;
			ctx->opc = (insword>>10)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_ASR_Z_ZI_:
		case ENC_LSR_Z_ZI_:
			// xxx|xxxx|x|tszh=xx|x|tszl=xx|imm3=xxx|xxx|x|x|U=x|Zn=xxxxx|Zd=xxxxx
			ctx->tszh = (insword>>22)&3;
			ctx->tszl = (insword>>19)&3;
			ctx->imm3 = (insword>>16)&7;
			ctx->U = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SLI_Z_ZZI_:
		case ENC_SRI_Z_ZZI_:
			// xxx|xxxx|x|tszh=xx|x|tszl=xx|imm3=xxx|xx|xxx|op=x|Zn=xxxxx|Zd=xxxxx
			ctx->tszh = (insword>>22)&3;
			ctx->tszl = (insword>>19)&3;
			ctx->imm3 = (insword>>16)&7;
			ctx->op = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SRSRA_Z_ZI_:
		case ENC_SSRA_Z_ZI_:
		case ENC_URSRA_Z_ZI_:
		case ENC_USRA_Z_ZI_:
			// xxx|xxxx|x|tszh=xx|x|tszl=xx|imm3=xxx|xx|xx|R=x|U=x|Zn=xxxxx|Zda=xxxxx
			ctx->tszh = (insword>>22)&3;
			ctx->tszl = (insword>>19)&3;
			ctx->imm3 = (insword>>16)&7;
			ctx->R = (insword>>11)&1;
			ctx->U = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_ASR_Z_P_ZI_:
		case ENC_ASRD_Z_P_ZI_:
		case ENC_LSL_Z_P_ZI_:
		case ENC_LSR_Z_P_ZI_:
		case ENC_SQSHL_Z_P_ZI_:
		case ENC_SQSHLU_Z_P_ZI_:
		case ENC_SRSHR_Z_P_ZI_:
		case ENC_UQSHL_Z_P_ZI_:
		case ENC_URSHR_Z_P_ZI_:
			// xxx|xxxx|x|tszh=xx|x|x|opc=xx|L=x|U=x|xxx|Pg=xxx|tszl=xx|imm3=xxx|Zdn=xxxxx
			ctx->tszh = (insword>>22)&3;
			ctx->opc = (insword>>18)&3;
			ctx->L = (insword>>17)&1;
			ctx->U = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->tszl = (insword>>8)&3;
			ctx->imm3 = (insword>>5)&7;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_SMMLA_Z_ZZZ_:
		case ENC_UMMLA_Z_ZZZ_:
		case ENC_USMMLA_Z_ZZZ_:
			// xxx|xxxx|x|uns=xx|x|Zm=xxxxx|xx|xxxx|Zn=xxxxx|Zda=xxxxx
			ctx->uns = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_FCVTNB_Z8_MZ2_S2B:
		case ENC_FCVTNT_Z8_MZ2_S2B:
			// xxx|xxxx|x|xx|xxx|xxx|xxxx|T=x|x|Zn=xxxx|x|Zd=xxxxx
			ctx->T = (insword>>11)&1;
			ctx->Zn = (insword>>6)&15;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_BFCVTN_Z8_MZ2_BF2B:
		case ENC_FCVTN_Z8_MZ2_H2B:
			// xxx|xxxx|x|xx|xxx|xxx|xxxx|opc=xx|Zn=xxxx|x|Zd=xxxxx
			ctx->opc = (insword>>10)&3;
			ctx->Zn = (insword>>6)&15;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_BF1CVT_Z_Z8_B2BF:
		case ENC_BF2CVT_Z_Z8_B2BF:
		case ENC_BF1CVTLT_Z_Z8_B2BF:
		case ENC_BF2CVTLT_Z_Z8_B2BF:
		case ENC_F1CVT_Z_Z8_B2H:
		case ENC_F2CVT_Z_Z8_B2H:
		case ENC_F1CVTLT_Z_Z8_B2H:
		case ENC_F2CVTLT_Z_Z8_B2H:
			// xxx|xxxx|x|xx|xxx|xx|L=x|xxxx|opc=xx|Zn=xxxxx|Zd=xxxxx
			ctx->L = (insword>>16)&1;
			ctx->opc = (insword>>10)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_DUPM_Z_I_:
		case ENC_MOV_Z_M__DUPM_Z_I_:
			// xxx|xxxx|x|xx|xx|xx|imm13=xxxxxxxxxxxxx|Zd=xxxxx
			ctx->imm13 = (insword>>5)&0x1fff;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_DUPQ_Z_ZI_:
			// xxx|xxxx|x|xx|x|i1=x|tsz=xxxx|xxxxxx|Zn=xxxxx|Zd=xxxxx
			ctx->i1 = (insword>>20)&1;
			ctx->tsz = (insword>>16)&15;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_PUNPKHI_P_P_:
		case ENC_PUNPKLO_P_P_:
			// xxx|xxxx|x|xx|x|xxxx|H=x|xxx|xxxx|Pn=xxxx|x|Pd=xxxx
			ctx->H = (insword>>16)&1;
			ctx->Pn = (insword>>5)&15;
			ctx->Pd = insword&15;
			break;
		case ENC_EXTQ_Z_ZI_DES:
			// xxx|xxxx|x|xx|x|x|imm4=xxxx|xxxxxx|Zm=xxxxx|Zdn=xxxxx
			ctx->imm4 = (insword>>16)&15;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_BRKN_P_P_PP_:
		case ENC_BRKNS_P_P_PP_:
			// xxx|xxxx|x|x|S=x|xx|xxxx|xx|Pg=xxxx|x|Pn=xxxx|x|Pdm=xxxx
			ctx->S = (insword>>22)&1;
			ctx->Pg = (insword>>10)&15;
			ctx->Pn = (insword>>5)&15;
			ctx->Pdm = insword&15;
			break;
		case ENC_MUL_Z_ZZI_H:
			// xxx|xxxx|x|x|i3h=x|x|i3l=xx|Zm=xxx|xxxxxx|Zn=xxxxx|Zd=xxxxx
			ctx->i3h = (insword>>22)&1;
			ctx->i3l = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SQDMULH_Z_ZZI_H:
		case ENC_SQRDMULH_Z_ZZI_H:
			// xxx|xxxx|x|x|i3h=x|x|i3l=xx|Zm=xxx|xxxxx|R=x|Zn=xxxxx|Zd=xxxxx
			ctx->i3h = (insword>>22)&1;
			ctx->i3l = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->R = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_MLA_Z_ZZZI_H:
		case ENC_MLS_Z_ZZZI_H:
		case ENC_SQRDMLAH_Z_ZZZI_H:
		case ENC_SQRDMLSH_Z_ZZZI_H:
			// xxx|xxxx|x|x|i3h=x|x|i3l=xx|Zm=xxx|xxxxx|S=x|Zn=xxxxx|Zda=xxxxx
			ctx->i3h = (insword>>22)&1;
			ctx->i3l = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->S = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_SDOT_Z16_ZZZI_H:
		case ENC_UDOT_Z16_ZZZI_H:
			// xxx|xxxx|x|x|i3h=x|x|i3l=xx|Zm=xxx|xxxxx|U=x|Zn=xxxxx|Zda=xxxxx
			ctx->i3h = (insword>>22)&1;
			ctx->i3l = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->U = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_BFMLA_Z_ZZZI_H:
		case ENC_BFMLS_Z_ZZZI_H:
		case ENC_FMLA_Z_ZZZI_H:
		case ENC_FMLS_Z_ZZZI_H:
			// xxx|xxxx|x|x|i3h=x|x|i3l=xx|Zm=xxx|xxxx|o2=x|op=x|Zn=xxxxx|Zda=xxxxx
			ctx->i3h = (insword>>22)&1;
			ctx->i3l = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->o2 = (insword>>11)&1;
			ctx->op = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_BFMUL_Z_ZZI_H:
		case ENC_FMUL_Z_ZZI_H:
			// xxx|xxxx|x|x|i3h=x|x|i3l=xx|Zm=xxx|xxxx|o2=x|x|Zn=xxxxx|Zd=xxxxx
			ctx->i3h = (insword>>22)&1;
			ctx->i3l = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->o2 = (insword>>11)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_PMOV_P_ZI_D:
			// xxx|xxxx|x|x|i3h=x|x|xx|i3l=xx|x|xxxxxx|Zn=xxxxx|x|Pd=xxxx
			ctx->i3h = (insword>>22)&1;
			ctx->i3l = (insword>>17)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Pd = insword&15;
			break;
		case ENC_PMOV_Z_PI_D:
			// xxx|xxxx|x|x|i3h=x|x|xx|i3l=xx|x|xxxxxx|x|Pn=xxxx|Zd=xxxxx
			ctx->i3h = (insword>>22)&1;
			ctx->i3l = (insword>>17)&3;
			ctx->Pn = (insword>>5)&15;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_BFMLALB_Z_ZZZ_:
		case ENC_BFMLALT_Z_ZZZ_:
		case ENC_BFMLSLB_Z_ZZZ_:
		case ENC_BFMLSLT_Z_ZZZ_:
		case ENC_FMLALB_Z_ZZZ_:
		case ENC_FMLALT_Z_ZZZ_:
		case ENC_FMLSLB_Z_ZZZ_:
		case ENC_FMLSLT_Z_ZZZ_:
			// xxx|xxxx|x|x|o2=x|x|Zm=xxxxx|xx|op=x|xx|T=x|Zn=xxxxx|Zda=xxxxx
			ctx->o2 = (insword>>22)&1;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->op = (insword>>13)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_BFMLALB_Z_ZZZI_:
		case ENC_BFMLALT_Z_ZZZI_:
		case ENC_BFMLSLB_Z_ZZZI_:
		case ENC_BFMLSLT_Z_ZZZI_:
		case ENC_FMLALB_Z_ZZZI_S:
		case ENC_FMLALT_Z_ZZZI_S:
		case ENC_FMLSLB_Z_ZZZI_S:
		case ENC_FMLSLT_Z_ZZZI_S:
			// xxx|xxxx|x|x|o2=x|x|i3h=xx|Zm=xxx|xx|op=x|x|i3l=x|T=x|Zn=xxxxx|Zda=xxxxx
			ctx->o2 = (insword>>22)&1;
			ctx->i3h = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->op = (insword>>13)&1;
			ctx->i3l = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_SQSHRN_Z_MZ2_:
		case ENC_SQSHRUN_Z_MZ2_:
		case ENC_UQSHRN_Z_MZ2_:
			// xxx|xxxx|x|x|op0=x|x|tsize=xx|imm3=xxx|x|x|op1=x|U=x|R=x|x|Zn=xxxx|x|Zd=xxxxx
			ctx->op0 = (insword>>22)&1;
			ctx->tsize = (insword>>19)&3;
			ctx->imm3 = (insword>>16)&7;
			ctx->op1 = (insword>>13)&1;
			ctx->U = (insword>>12)&1;
			ctx->R = (insword>>11)&1;
			ctx->Zn = (insword>>6)&15;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SQRSHRN_Z_MZ2_B:
		case ENC_SQRSHRUN_Z_MZ2_B:
		case ENC_UQRSHRN_Z_MZ2_B:
			// xxx|xxxx|x|x|op0=x|x|xx|imm3=xxx|x|x|op1=x|U=x|R=x|x|Zn=xxxx|x|Zd=xxxxx
			ctx->op0 = (insword>>22)&1;
			ctx->imm3 = (insword>>16)&7;
			ctx->op1 = (insword>>13)&1;
			ctx->U = (insword>>12)&1;
			ctx->R = (insword>>11)&1;
			ctx->Zn = (insword>>6)&15;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SQRSHRN_Z_MZ2_:
		case ENC_SQRSHRUN_Z_MZ2_:
		case ENC_UQRSHRN_Z_MZ2_:
			// xxx|xxxx|x|x|op0=x|x|x|imm4=xxxx|x|x|op1=x|U=x|R=x|x|Zn=xxxx|x|Zd=xxxxx
			ctx->op0 = (insword>>22)&1;
			ctx->imm4 = (insword>>16)&15;
			ctx->op1 = (insword>>13)&1;
			ctx->U = (insword>>12)&1;
			ctx->R = (insword>>11)&1;
			ctx->Zn = (insword>>6)&15;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_ADDPL_R_RI_:
		case ENC_ADDSPL_R_RI_:
		case ENC_ADDSVL_R_RI_:
		case ENC_ADDVL_R_RI_:
			// xxx|xxxx|x|x|op=x|x|Rn=xxxxx|xxxx|x|imm6=xxxxxx|Rd=xxxxx
			ctx->op = (insword>>22)&1;
			ctx->Rn = (insword>>16)&0x1f;
			ctx->imm6 = (insword>>5)&0x3f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_BFDOT_Z_ZZZ_:
		case ENC_FDOT_Z32_ZZ8Z8_:
		case ENC_FDOT_Z_ZZ8Z8_:
		case ENC_FDOT_Z_ZZZ_:
			// xxx|xxxx|x|x|op=x|x|Zm=xxxxx|xx|x|xx|o2=x|Zn=xxxxx|Zda=xxxxx
			ctx->op = (insword>>22)&1;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->o2 = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_BFDOT_Z_ZZZI_:
		case ENC_FDOT_Z32_ZZ8Z8I_:
		case ENC_FDOT_Z_ZZZI_:
			// xxx|xxxx|x|x|op=x|x|i2=xx|Zm=xxx|xx|x|x|opc2=xx|Zn=xxxxx|Zda=xxxxx
			ctx->op = (insword>>22)&1;
			ctx->i2 = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->opc2 = (insword>>10)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_FDOT_Z_ZZ8Z8I_:
			// xxx|xxxx|x|x|op=x|x|i3h=xx|Zm=xxx|xx|x|x|i3l=x|x|Zn=xxxxx|Zda=xxxxx
			ctx->op = (insword>>22)&1;
			ctx->i3h = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->i3l = (insword>>11)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_RDSVL_R_I_:
		case ENC_RDVL_R_I_:
			// xxx|xxxx|x|x|op=x|x|opc2=xxxxx|xxxx|x|imm6=xxxxxx|Rd=xxxxx
			ctx->op = (insword>>22)&1;
			ctx->opc2 = (insword>>16)&0x1f;
			ctx->imm6 = (insword>>5)&0x3f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_ADR_Z_AZ_SD_SAME_SCALED:
			// xxx|xxxx|x|x|sz=x|x|Zm=xxxxx|xxxx|msz=xx|Zn=xxxxx|Zd=xxxxx
			ctx->sz = (insword>>22)&1;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->msz = (insword>>10)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_ADCLB_Z_ZZZ_:
		case ENC_ADCLT_Z_ZZZ_:
		case ENC_SBCLB_Z_ZZZ_:
		case ENC_SBCLT_Z_ZZZ_:
			// xxx|xxxx|x|x|sz=x|x|Zm=xxxxx|xx|xxx|T=x|Zn=xxxxx|Zda=xxxxx
			ctx->sz = (insword>>22)&1;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_COMPACT_Z_P_Z_S:
		case ENC_COMPACT_Z_P_Z_:
			// xxx|xxxx|x|x|sz=x|x|x|xxx|x|xx|x|Pg=xxx|Zn=xxxxx|Zd=xxxxx
			ctx->sz = (insword>>22)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SSHLLB_Z_ZI_:
		case ENC_SSHLLT_Z_ZI_:
		case ENC_USHLLB_Z_ZI_:
		case ENC_USHLLT_Z_ZI_:
			// xxx|xxxx|x|x|tszh=x|x|tszl=xx|imm3=xxx|xx|xx|U=x|T=x|Zn=xxxxx|Zd=xxxxx
			ctx->tszh = (insword>>22)&1;
			ctx->tszl = (insword>>19)&3;
			ctx->imm3 = (insword>>16)&7;
			ctx->U = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_RSHRNB_Z_ZI_:
		case ENC_RSHRNT_Z_ZI_:
		case ENC_SHRNB_Z_ZI_:
		case ENC_SHRNT_Z_ZI_:
		case ENC_SQRSHRNB_Z_ZI_:
		case ENC_SQRSHRNT_Z_ZI_:
		case ENC_SQRSHRUNB_Z_ZI_:
		case ENC_SQRSHRUNT_Z_ZI_:
		case ENC_SQSHRNB_Z_ZI_:
		case ENC_SQSHRNT_Z_ZI_:
		case ENC_SQSHRUNB_Z_ZI_:
		case ENC_SQSHRUNT_Z_ZI_:
		case ENC_UQRSHRNB_Z_ZI_:
		case ENC_UQRSHRNT_Z_ZI_:
		case ENC_UQSHRNB_Z_ZI_:
		case ENC_UQSHRNT_Z_ZI_:
			// xxx|xxxx|x|x|tszh=x|x|tszl=xx|imm3=xxx|x|x|op=x|U=x|R=x|T=x|Zn=xxxxx|Zd=xxxxx
			ctx->tszh = (insword>>22)&1;
			ctx->tszl = (insword>>19)&3;
			ctx->imm3 = (insword>>16)&7;
			ctx->op = (insword>>13)&1;
			ctx->U = (insword>>12)&1;
			ctx->R = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SQXTUNB_Z_ZZ_:
		case ENC_SQXTUNT_Z_ZZ_:
			// xxx|xxxx|x|x|tszh=x|x|tszl=xx|xx|x|x|xx|opc=xx|T=x|Zn=xxxxx|Zd=xxxxx
			ctx->tszh = (insword>>22)&1;
			ctx->tszl = (insword>>19)&3;
			ctx->opc = (insword>>11)&3;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SQCVTUN_Z_MZ2_:
			// xxx|xxxx|x|x|tszh=x|x|tszl=xx|xx|x|x|xx|opc=xx|x|Zn=xxxx|x|Zd=xxxxx
			ctx->tszh = (insword>>22)&1;
			ctx->tszl = (insword>>19)&3;
			ctx->opc = (insword>>11)&3;
			ctx->Zn = (insword>>6)&15;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SQXTNB_Z_ZZ_:
		case ENC_SQXTNT_Z_ZZ_:
		case ENC_UQXTNB_Z_ZZ_:
		case ENC_UQXTNT_Z_ZZ_:
			// xxx|xxxx|x|x|tszh=x|x|tszl=xx|xx|x|x|xx|x|U=x|T=x|Zn=xxxxx|Zd=xxxxx
			ctx->tszh = (insword>>22)&1;
			ctx->tszl = (insword>>19)&3;
			ctx->U = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SQCVTN_Z_MZ2_:
		case ENC_UQCVTN_Z_MZ2_:
			// xxx|xxxx|x|x|tszh=x|x|tszl=xx|xx|x|x|xx|x|U=x|x|Zn=xxxx|x|Zd=xxxxx
			ctx->tszh = (insword>>22)&1;
			ctx->tszl = (insword>>19)&3;
			ctx->U = (insword>>11)&1;
			ctx->Zn = (insword>>6)&15;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_FMLALLBB_Z32_Z8Z8Z8_:
		case ENC_FMLALLBT_Z32_Z8Z8Z8_:
		case ENC_FMLALLTB_Z32_Z8Z8Z8_:
		case ENC_FMLALLTT_Z32_Z8Z8Z8_:
			// xxx|xxxx|x|x|xx|Zm=xxxxx|xx|TT=xx|xx|Zn=xxxxx|Zda=xxxxx
			ctx->Zm = (insword>>16)&0x1f;
			ctx->TT = (insword>>12)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_FMLALB_Z_Z8Z8Z8_:
		case ENC_FMLALT_Z_Z8Z8Z8_:
			// xxx|xxxx|x|x|xx|Zm=xxxxx|xx|x|T=x|xx|Zn=xxxxx|Zda=xxxxx
			ctx->Zm = (insword>>16)&0x1f;
			ctx->T = (insword>>12)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_LUTI6_Z_ZZZ_8:
			// xxx|xxxx|x|x|x|x|Zm=xxxxx|xxx|xxx|Zn=xxxxx|Zd=xxxxx
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_WFET_ONLY_SYSTEMINSTRSWITHREG:
		case ENC_WFIT_ONLY_SYSTEMINSTRSWITHREG:
			// xxx|xxx|xxxxxxxxxxxxxx|CRm=xxxx|op2=xxx|Rd=xxxxx
			ctx->CRm = (insword>>8)&15;
			ctx->op2 = (insword>>5)&7;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_CLREX_BN_BARRIERS:
			// xxx|xxx|xxxxxxxxxxxxxx|CRm=xxxx|op2=xxx|Rt=xxxxx
			ctx->CRm = (insword>>8)&15;
			ctx->op2 = (insword>>5)&7;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_BTI_HB_HINTS:
		case ENC_CHKFEAT_HF_HINTS:
		case ENC_CLRBHB_HI_HINTS:
		case ENC_CSDB_HI_HINTS:
		case ENC_DGH_HI_HINTS:
		case ENC_ESB_HI_HINTS:
		case ENC_GCSB_HD_HINTS:
		case ENC_HINT_HM_HINTS:
		case ENC_NOP_HI_HINTS:
		case ENC_PACM_HI_HINTS:
		case ENC_PSB_HC_HINTS:
		case ENC_SEV_HI_HINTS:
		case ENC_SEVL_HI_HINTS:
		case ENC_SHUH_HI_HINTS:
		case ENC_STCPH_HI_HINTS:
		case ENC_STSHH_HI_HINTS:
		case ENC_TSB_HC_HINTS:
		case ENC_WFE_HI_HINTS:
		case ENC_WFI_HI_HINTS:
		case ENC_XPACLRI_HI_HINTS:
		case ENC_YIELD_HI_HINTS:
			// xxx|xxx|xxxxxxxxxxxxxx|CRm=xxxx|op2=xxx|xxxxx
			ctx->CRm = (insword>>8)&15;
			ctx->op2 = (insword>>5)&7;
			break;
		case ENC_DMB_BO_BARRIERS:
		case ENC_DSB_BO_BARRIERS:
		case ENC_ISB_BI_BARRIERS:
		case ENC_PSSBB_DSB_BO_BARRIERS:
		case ENC_SB_ONLY_BARRIERS:
		case ENC_SSBB_DSB_BO_BARRIERS:
			// xxx|xxx|xxxxxxxxxxxxxx|CRm=xxxx|x|opc=xx|Rt=xxxxx
			ctx->CRm = (insword>>8)&15;
			ctx->opc = (insword>>5)&3;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_DSB_BON_BARRIERS:
			// xxx|xxx|xxxxxxxxxxxxxx|imm2=xx|xx|op2=xxx|Rt=xxxxx
			ctx->imm2 = (insword>>10)&3;
			ctx->op2 = (insword>>5)&7;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_AXFLAG_M_PSTATE:
		case ENC_CFINV_M_PSTATE:
		case ENC_MSR_SI_PSTATE:
		case ENC_SMSTART_MSR_SI_PSTATE:
		case ENC_SMSTOP_MSR_SI_PSTATE:
		case ENC_XAFLAG_M_PSTATE:
			// xxx|xxx|xxxxxxx|op1=xxx|xxxx|CRm=xxxx|op2=xxx|Rt=xxxxx
			ctx->op1 = (insword>>16)&7;
			ctx->CRm = (insword>>8)&15;
			ctx->op2 = (insword>>5)&7;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_APAS_SYS_CR_SYSTEMINSTRS:
		case ENC_AT_SYS_CR_SYSTEMINSTRS:
		case ENC_BRB_SYS_CR_SYSTEMINSTRS:
		case ENC_CFP_SYS_CR_SYSTEMINSTRS:
		case ENC_COSP_SYS_CR_SYSTEMINSTRS:
		case ENC_CPP_SYS_CR_SYSTEMINSTRS:
		case ENC_DC_SYS_CR_SYSTEMINSTRS:
		case ENC_DVP_SYS_CR_SYSTEMINSTRS:
		case ENC_GCSPOPCX_SYS_CR_SYSTEMINSTRS:
		case ENC_GCSPOPM_SYSL_RC_SYSTEMINSTRS:
		case ENC_GCSPOPX_SYS_CR_SYSTEMINSTRS:
		case ENC_GCSPUSHM_SYS_CR_SYSTEMINSTRS:
		case ENC_GCSPUSHX_SYS_CR_SYSTEMINSTRS:
		case ENC_GCSSS1_SYS_CR_SYSTEMINSTRS:
		case ENC_GCSSS2_SYSL_RC_SYSTEMINSTRS:
		case ENC_GICR_SYSL_RC_SYSTEMINSTRS:
		case ENC_GIC_SYS_CR_SYSTEMINSTRS:
		case ENC_GSB_SYS_CR_SYSTEMINSTRS:
		case ENC_IC_SYS_CR_SYSTEMINSTRS:
		case ENC_MLBI_SYS_CR_SYSTEMINSTRS:
		case ENC_SYS_CR_SYSTEMINSTRS:
		case ENC_SYSL_RC_SYSTEMINSTRS:
		case ENC_SYSP_CR_SYSPAIRINSTRS:
		case ENC_TLBIP_SYSP_CR_SYSPAIRINSTRS:
		case ENC_TLBI_SYS_CR_SYSTEMINSTRS:
		case ENC_TRCIT_SYS_CR_SYSTEMINSTRS:
			// xxx|xxx|xxxx|L=x|xx|op1=xxx|CRn=xxxx|CRm=xxxx|op2=xxx|Rt=xxxxx
			ctx->L = (insword>>21)&1;
			ctx->op1 = (insword>>16)&7;
			ctx->CRn = (insword>>12)&15;
			ctx->CRm = (insword>>8)&15;
			ctx->op2 = (insword>>5)&7;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_MRRS_RS_SYSTEMMOVEPR:
		case ENC_MRS_RS_SYSTEMMOVE:
		case ENC_MSRR_SR_SYSTEMMOVEPR:
		case ENC_MSR_SR_SYSTEMMOVE:
			// xxx|xxx|xxxx|L=x|x|o0=x|op1=xxx|CRn=xxxx|CRm=xxxx|op2=xxx|Rt=xxxxx
			ctx->L = (insword>>21)&1;
			ctx->o0 = (insword>>19)&1;
			ctx->op1 = (insword>>16)&7;
			ctx->CRn = (insword>>12)&15;
			ctx->CRm = (insword>>8)&15;
			ctx->op2 = (insword>>5)&7;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_CBBLE_CBBGE_8_REGS:
		case ENC_CBBLO_CBBHI_8_REGS:
		case ENC_CBBLS_CBBHS_8_REGS:
		case ENC_CBBLT_CBBGT_8_REGS:
		case ENC_CBHLE_CBHGE_16_REGS:
		case ENC_CBHLO_CBHHI_16_REGS:
		case ENC_CBHLS_CBHHS_16_REGS:
		case ENC_CBHLT_CBHGT_16_REGS:
			// xxx|xxx|xx|cc=xxx|Rm=xxxxx|x|H=x|imm9=xxxxxxxxx|Rt=xxxxx
			ctx->cc = (insword>>21)&7;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->H = (insword>>14)&1;
			ctx->imm9 = (insword>>5)&0x1ff;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_BC_ONLY_CONDBRANCH:
		case ENC_B_ONLY_CONDBRANCH:
			// xxx|xxx|xx|imm19=xxxxxxxxxxxxxxxxxxx|o0=x|cond=xxxx
			ctx->imm19 = (insword>>5)&0x7ffff;
			ctx->o0 = (insword>>4)&1;
			ctx->cond = insword&15;
			break;
		case ENC_BRK_EX_EXCEPTION:
		case ENC_DCPS1_DC_EXCEPTION:
		case ENC_DCPS2_DC_EXCEPTION:
		case ENC_DCPS3_DC_EXCEPTION:
		case ENC_HLT_EX_EXCEPTION:
		case ENC_HVC_EX_EXCEPTION:
		case ENC_SMC_EX_EXCEPTION:
		case ENC_SVC_EX_EXCEPTION:
			// xxx|xxx|xx|opc=xxx|imm16=xxxxxxxxxxxxxxxx|op2=xxx|LL=xx
			ctx->opc = (insword>>21)&7;
			ctx->imm16 = (insword>>5)&0xffff;
			ctx->op2 = (insword>>2)&7;
			ctx->LL = insword&3;
			break;
		case ENC_BLR_64_BRANCH_REG:
		case ENC_BR_64_BRANCH_REG:
		case ENC_RET_64R_BRANCH_REG:
			// xxx|xxx|x|Z=x|x|op=xx|op2=xxxxx|xxxx|A=x|M=x|Rn=xxxxx|Rm=xxxxx
			ctx->Z = (insword>>24)&1;
			ctx->op = (insword>>21)&3;
			ctx->op2 = (insword>>16)&0x1f;
			ctx->A = (insword>>11)&1;
			ctx->M = (insword>>10)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rm = insword&0x1f;
			break;
		case ENC_DRPS_64E_BRANCH_REG:
			// xxx|xxx|x|opc=xxxx|op2=xxxxx|op3=xxxxxx|Rn=xxxxx|op4=xxxxx
			ctx->opc = (insword>>21)&15;
			ctx->op2 = (insword>>16)&0x1f;
			ctx->op3 = (insword>>10)&0x3f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->op4 = insword&0x1f;
			break;
		case ENC_ERET_64E_BRANCH_REG:
			// xxx|xxx|x|opc=xxxx|op2=xxxxx|xxxx|A=x|M=x|Rn=xxxxx|op4=xxxxx
			ctx->opc = (insword>>21)&15;
			ctx->op2 = (insword>>16)&0x1f;
			ctx->A = (insword>>11)&1;
			ctx->M = (insword>>10)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->op4 = insword&0x1f;
			break;
		case ENC_FCVTZS_ASISDSHF_C:
		case ENC_FCVTZU_ASISDSHF_C:
		case ENC_SCVTF_ASISDSHF_C:
		case ENC_SHL_ASISDSHF_R:
		case ENC_SLI_ASISDSHF_R:
		case ENC_SRI_ASISDSHF_R:
		case ENC_UCVTF_ASISDSHF_C:
			// xx|U=x|x|xxx|xx|immh=xxxx|immb=xxx|opcode=xxxxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->immh = (insword>>19)&15;
			ctx->immb = (insword>>16)&7;
			ctx->opcode = (insword>>11)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SQRSHRN_ASISDSHF_N:
		case ENC_SQRSHRUN_ASISDSHF_N:
		case ENC_SQSHRN_ASISDSHF_N:
		case ENC_SQSHRUN_ASISDSHF_N:
		case ENC_UQRSHRN_ASISDSHF_N:
		case ENC_UQSHRN_ASISDSHF_N:
			// xx|U=x|x|xxx|xx|immh=xxxx|immb=xxx|xxxx|op=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->immh = (insword>>19)&15;
			ctx->immb = (insword>>16)&7;
			ctx->op = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SQSHLU_ASISDSHF_R:
		case ENC_SQSHL_ASISDSHF_R:
		case ENC_UQSHL_ASISDSHF_R:
			// xx|U=x|x|xxx|xx|immh=xxxx|immb=xxx|xxx|op=x|x|x|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->immh = (insword>>19)&15;
			ctx->immb = (insword>>16)&7;
			ctx->op = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SRSHR_ASISDSHF_R:
		case ENC_SRSRA_ASISDSHF_R:
		case ENC_SSHR_ASISDSHF_R:
		case ENC_SSRA_ASISDSHF_R:
		case ENC_URSHR_ASISDSHF_R:
		case ENC_URSRA_ASISDSHF_R:
		case ENC_USHR_ASISDSHF_R:
		case ENC_USRA_ASISDSHF_R:
			// xx|U=x|x|xxx|xx|immh=xxxx|immb=xxx|xx|o1=x|o0=x|x|x|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->immh = (insword>>19)&15;
			ctx->immb = (insword>>16)&7;
			ctx->o1 = (insword>>13)&1;
			ctx->o0 = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FACGE_ASISDSAME_ONLY:
		case ENC_FACGT_ASISDSAME_ONLY:
		case ENC_FCMEQ_ASISDSAME_ONLY:
		case ENC_FCMGE_ASISDSAME_ONLY:
		case ENC_FCMGT_ASISDSAME_ONLY:
			// xx|U=x|x|xxx|x|E=x|sz=x|x|Rm=xxxxx|xxxx|ac=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->E = (insword>>23)&1;
			ctx->sz = (insword>>22)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->ac = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FACGE_ASISDSAMEFP16_ONLY:
		case ENC_FACGT_ASISDSAMEFP16_ONLY:
		case ENC_FCMEQ_ASISDSAMEFP16_ONLY:
		case ENC_FCMGE_ASISDSAMEFP16_ONLY:
		case ENC_FCMGT_ASISDSAMEFP16_ONLY:
			// xx|U=x|x|xxx|x|E=x|xx|Rm=xxxxx|xx|xx|ac=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->E = (insword>>23)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->ac = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FCMLT_ASISDMISCFP16_FZ:
		case ENC_FCVTAS_ASISDMISCFP16_R:
		case ENC_FCVTAU_ASISDMISCFP16_R:
		case ENC_FRECPE_ASISDMISCFP16_R:
		case ENC_FRECPX_ASISDMISCFP16_R:
		case ENC_FRSQRTE_ASISDMISCFP16_R:
		case ENC_SCVTF_ASISDMISCFP16_R:
		case ENC_UCVTF_ASISDMISCFP16_R:
			// xx|U=x|x|xxx|x|a=x|xxxx|xx|opcode=xxxxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->a = (insword>>23)&1;
			ctx->opcode = (insword>>12)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FCMEQ_ASISDMISCFP16_FZ:
		case ENC_FCMGE_ASISDMISCFP16_FZ:
		case ENC_FCMGT_ASISDMISCFP16_FZ:
		case ENC_FCMLE_ASISDMISCFP16_FZ:
			// xx|U=x|x|xxx|x|a=x|xxxx|xx|xxxx|op=x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->a = (insword>>23)&1;
			ctx->op = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FABD_ASISDSAMEFP16_ONLY:
		case ENC_FMULX_ASISDSAMEFP16_ONLY:
		case ENC_FRECPS_ASISDSAMEFP16_ONLY:
		case ENC_FRSQRTS_ASISDSAMEFP16_ONLY:
			// xx|U=x|x|xxx|x|a=x|xx|Rm=xxxxx|xx|opcode=xxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->a = (insword>>23)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>11)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMAXNMP_ASISDPAIR_ONLY_H:
		case ENC_FMAXNMP_ASISDPAIR_ONLY_SD:
		case ENC_FMAXP_ASISDPAIR_ONLY_H:
		case ENC_FMAXP_ASISDPAIR_ONLY_SD:
		case ENC_FMINNMP_ASISDPAIR_ONLY_H:
		case ENC_FMINNMP_ASISDPAIR_ONLY_SD:
		case ENC_FMINP_ASISDPAIR_ONLY_H:
		case ENC_FMINP_ASISDPAIR_ONLY_SD:
			// xx|U=x|x|xxx|x|o1=x|sz=x|xxxxx|opcode=xxxxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->o1 = (insword>>23)&1;
			ctx->sz = (insword>>22)&1;
			ctx->opcode = (insword>>12)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FCVTMS_ASISDMISC_R:
		case ENC_FCVTMU_ASISDMISC_R:
		case ENC_FCVTNS_ASISDMISC_R:
		case ENC_FCVTNU_ASISDMISC_R:
		case ENC_FCVTPS_ASISDMISC_R:
		case ENC_FCVTPU_ASISDMISC_R:
		case ENC_FCVTZS_ASISDMISC_R:
		case ENC_FCVTZU_ASISDMISC_R:
			// xx|U=x|x|xxx|x|o2=x|sz=x|xxxxx|xxxx|o1=x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->o2 = (insword>>23)&1;
			ctx->sz = (insword>>22)&1;
			ctx->o1 = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FCVTMS_ASISDMISCFP16_R:
		case ENC_FCVTMU_ASISDMISCFP16_R:
		case ENC_FCVTNS_ASISDMISCFP16_R:
		case ENC_FCVTNU_ASISDMISCFP16_R:
		case ENC_FCVTPS_ASISDMISCFP16_R:
		case ENC_FCVTPU_ASISDMISCFP16_R:
		case ENC_FCVTZS_ASISDMISCFP16_R:
		case ENC_FCVTZU_ASISDMISCFP16_R:
			// xx|U=x|x|xxx|x|o2=x|xxxx|xx|xxxx|o1=x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->o2 = (insword>>23)&1;
			ctx->o1 = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMULX_ASISDELEM_RH_H:
		case ENC_FMUL_ASISDELEM_RH_H:
		case ENC_SQDMULL_ASISDELEM_L:
			// xx|U=x|x|xxx|x|size=xx|L=x|M=x|Rm=xxxx|opcode=xxxx|H=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->L = (insword>>21)&1;
			ctx->M = (insword>>20)&1;
			ctx->Rm = (insword>>16)&15;
			ctx->opcode = (insword>>12)&15;
			ctx->H = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SQDMULH_ASISDELEM_R:
		case ENC_SQRDMULH_ASISDELEM_R:
			// xx|U=x|x|xxx|x|size=xx|L=x|M=x|Rm=xxxx|xxx|op=x|H=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->L = (insword>>21)&1;
			ctx->M = (insword>>20)&1;
			ctx->Rm = (insword>>16)&15;
			ctx->op = (insword>>12)&1;
			ctx->H = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SQRDMLAH_ASISDELEM_R:
		case ENC_SQRDMLSH_ASISDELEM_R:
			// xx|U=x|x|xxx|x|size=xx|L=x|M=x|Rm=xxxx|xx|S=x|x|H=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->L = (insword>>21)&1;
			ctx->M = (insword>>20)&1;
			ctx->Rm = (insword>>16)&15;
			ctx->S = (insword>>13)&1;
			ctx->H = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMLA_ASISDELEM_RH_H:
		case ENC_FMLS_ASISDELEM_RH_H:
		case ENC_SQDMLAL_ASISDELEM_L:
		case ENC_SQDMLSL_ASISDELEM_L:
			// xx|U=x|x|xxx|x|size=xx|L=x|M=x|Rm=xxxx|x|o2=x|xx|H=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->L = (insword>>21)&1;
			ctx->M = (insword>>20)&1;
			ctx->Rm = (insword>>16)&15;
			ctx->o2 = (insword>>14)&1;
			ctx->H = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_ABS_ASISDMISC_R:
		case ENC_ADDP_ASISDPAIR_ONLY:
		case ENC_CMLT_ASISDMISC_Z:
		case ENC_FCVTXN_ASISDMISC_N:
		case ENC_NEG_ASISDMISC_R:
		case ENC_SQABS_ASISDMISC_R:
		case ENC_SQNEG_ASISDMISC_R:
		case ENC_SQXTN_ASISDMISC_N:
		case ENC_SQXTUN_ASISDMISC_N:
		case ENC_SUQADD_ASISDMISC_R:
		case ENC_UQXTN_ASISDMISC_N:
		case ENC_USQADD_ASISDMISC_R:
			// xx|U=x|x|xxx|x|size=xx|xxxxx|opcode=xxxxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->opcode = (insword>>12)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_CMEQ_ASISDMISC_Z:
		case ENC_CMGE_ASISDMISC_Z:
		case ENC_CMGT_ASISDMISC_Z:
		case ENC_CMLE_ASISDMISC_Z:
			// xx|U=x|x|xxx|x|size=xx|xxxxx|xxxx|op=x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->op = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_ADD_ASISDSAME_ONLY:
		case ENC_CMEQ_ASISDSAME_ONLY:
		case ENC_CMTST_ASISDSAME_ONLY:
		case ENC_SQADD_ASISDSAME_ONLY:
		case ENC_SQDMULH_ASISDSAME_ONLY:
		case ENC_SQRDMULH_ASISDSAME_ONLY:
		case ENC_SQSUB_ASISDSAME_ONLY:
		case ENC_SUB_ASISDSAME_ONLY:
		case ENC_UQADD_ASISDSAME_ONLY:
		case ENC_UQSUB_ASISDSAME_ONLY:
			// xx|U=x|x|xxx|x|size=xx|x|Rm=xxxxx|opcode=xxxxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>11)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SQDMULL_ASISDDIFF_ONLY:
			// xx|U=x|x|xxx|x|size=xx|x|Rm=xxxxx|opcode=xxxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>12)&15;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_CMGE_ASISDSAME_ONLY:
		case ENC_CMGT_ASISDSAME_ONLY:
		case ENC_CMHI_ASISDSAME_ONLY:
		case ENC_CMHS_ASISDSAME_ONLY:
			// xx|U=x|x|xxx|x|size=xx|x|Rm=xxxxx|xxxx|eq=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->eq = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SQRSHL_ASISDSAME_ONLY:
		case ENC_SQSHL_ASISDSAME_ONLY:
		case ENC_SRSHL_ASISDSAME_ONLY:
		case ENC_SSHL_ASISDSAME_ONLY:
		case ENC_UQRSHL_ASISDSAME_ONLY:
		case ENC_UQSHL_ASISDSAME_ONLY:
		case ENC_URSHL_ASISDSAME_ONLY:
		case ENC_USHL_ASISDSAME_ONLY:
			// xx|U=x|x|xxx|x|size=xx|x|Rm=xxxxx|xxx|R=x|S=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->R = (insword>>12)&1;
			ctx->S = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SQDMLAL_ASISDDIFF_ONLY:
		case ENC_SQDMLSL_ASISDDIFF_ONLY:
			// xx|U=x|x|xxx|x|size=xx|x|Rm=xxxxx|xx|o1=x|x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->o1 = (insword>>13)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SQRDMLAH_ASISDSAME2_ONLY:
		case ENC_SQRDMLSH_ASISDSAME2_ONLY:
			// xx|U=x|x|xxx|x|size=xx|x|Rm=xxxxx|x|xxx|S=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->S = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMULX_ASISDELEM_R_SD:
		case ENC_FMUL_ASISDELEM_R_SD:
			// xx|U=x|x|xxx|x|x|sz=x|L=x|M=x|Rm=xxxx|opcode=xxxx|H=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->sz = (insword>>22)&1;
			ctx->L = (insword>>21)&1;
			ctx->M = (insword>>20)&1;
			ctx->Rm = (insword>>16)&15;
			ctx->opcode = (insword>>12)&15;
			ctx->H = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMLA_ASISDELEM_R_SD:
		case ENC_FMLS_ASISDELEM_R_SD:
			// xx|U=x|x|xxx|x|x|sz=x|L=x|M=x|Rm=xxxx|x|o2=x|xx|H=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->sz = (insword>>22)&1;
			ctx->L = (insword>>21)&1;
			ctx->M = (insword>>20)&1;
			ctx->Rm = (insword>>16)&15;
			ctx->o2 = (insword>>14)&1;
			ctx->H = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FADDP_ASISDPAIR_ONLY_H:
		case ENC_FADDP_ASISDPAIR_ONLY_SD:
		case ENC_FCMLT_ASISDMISC_FZ:
		case ENC_FCVTAS_ASISDMISC_R:
		case ENC_FCVTAU_ASISDMISC_R:
		case ENC_FRECPE_ASISDMISC_R:
		case ENC_FRECPX_ASISDMISC_R:
		case ENC_FRSQRTE_ASISDMISC_R:
		case ENC_SCVTF_ASISDMISC_R:
		case ENC_UCVTF_ASISDMISC_R:
			// xx|U=x|x|xxx|x|x|sz=x|xxxxx|opcode=xxxxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->sz = (insword>>22)&1;
			ctx->opcode = (insword>>12)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FCMEQ_ASISDMISC_FZ:
		case ENC_FCMGE_ASISDMISC_FZ:
		case ENC_FCMGT_ASISDMISC_FZ:
		case ENC_FCMLE_ASISDMISC_FZ:
			// xx|U=x|x|xxx|x|x|sz=x|xxxxx|xxxx|op=x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->sz = (insword>>22)&1;
			ctx->op = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FABD_ASISDSAME_ONLY:
		case ENC_FMULX_ASISDSAME_ONLY:
		case ENC_FRECPS_ASISDSAME_ONLY:
		case ENC_FRSQRTS_ASISDSAME_ONLY:
			// xx|U=x|x|xxx|x|x|sz=x|x|Rm=xxxxx|opcode=xxxxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->sz = (insword>>22)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>11)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_DUP_ASISDONE_ONLY:
		case ENC_MOV_DUP_ASISDONE_ONLY:
			// xx|op=x|x|xxx|xx|xx|imm5=xxxxx|x|imm4=xxxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->op = (insword>>29)&1;
			ctx->imm5 = (insword>>16)&0x1f;
			ctx->imm4 = (insword>>11)&15;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMLALB_ASIMDELEM_H:
		case ENC_FMLALT_ASIMDELEM_H:
		case ENC_FMLALLBB_ASIMDELEM_J:
		case ENC_FMLALLBT_ASIMDELEM_J:
		case ENC_FMLALLTB_ASIMDELEM_J:
		case ENC_FMLALLTT_ASIMDELEM_J:
			// x|Q=x|U=x|xxxxx|size=xx|L=x|M=x|Rm=xxxx|opcode=xxxx|H=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->L = (insword>>21)&1;
			ctx->M = (insword>>20)&1;
			ctx->Rm = (insword>>16)&15;
			ctx->opcode = (insword>>12)&15;
			ctx->H = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_BF1CVTL_ASIMDMISC_V:
		case ENC_BF2CVTL_ASIMDMISC_V:
		case ENC_F1CVTL_ASIMDMISC_V:
		case ENC_F2CVTL_ASIMDMISC_V:
			// x|Q=x|U=x|xxxxx|size=xx|xxxxx|opcode=xxxxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->opcode = (insword>>12)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMLALB_ASIMDSAME2_J:
		case ENC_FMLALT_ASIMDSAME2_J:
		case ENC_FMLALLBB_ASIMDSAME2_G:
		case ENC_FMLALLBT_ASIMDSAME2_G:
		case ENC_FMLALLTB_ASIMDSAME2_G:
		case ENC_FMLALLTT_ASIMDSAME2_G:
			// x|Q=x|U=x|xxxxx|size=xx|x|Rm=xxxxx|x|opcode=xxxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>11)&15;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FCVTZS_ASIMDSHF_C:
		case ENC_FCVTZU_ASIMDSHF_C:
		case ENC_SCVTF_ASIMDSHF_C:
		case ENC_SHL_ASIMDSHF_R:
		case ENC_SLI_ASIMDSHF_R:
		case ENC_SRI_ASIMDSHF_R:
		case ENC_SSHLL_ASIMDSHF_L:
		case ENC_SXTL_SSHLL_ASIMDSHF_L:
		case ENC_UCVTF_ASIMDSHF_C:
		case ENC_USHLL_ASIMDSHF_L:
		case ENC_UXTL_USHLL_ASIMDSHF_L:
			// x|Q=x|U=x|x|xxx|xx|immh=xxxx|immb=xxx|opcode=xxxxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->immh = (insword>>19)&15;
			ctx->immb = (insword>>16)&7;
			ctx->opcode = (insword>>11)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_RSHRN_ASIMDSHF_N:
		case ENC_SHRN_ASIMDSHF_N:
		case ENC_SQRSHRN_ASIMDSHF_N:
		case ENC_SQRSHRUN_ASIMDSHF_N:
		case ENC_SQSHRN_ASIMDSHF_N:
		case ENC_SQSHRUN_ASIMDSHF_N:
		case ENC_UQRSHRN_ASIMDSHF_N:
		case ENC_UQSHRN_ASIMDSHF_N:
			// x|Q=x|U=x|x|xxx|xx|immh=xxxx|immb=xxx|xxxx|op=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->immh = (insword>>19)&15;
			ctx->immb = (insword>>16)&7;
			ctx->op = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SQSHLU_ASIMDSHF_R:
		case ENC_SQSHL_ASIMDSHF_R:
		case ENC_UQSHL_ASIMDSHF_R:
			// x|Q=x|U=x|x|xxx|xx|immh=xxxx|immb=xxx|xxx|op=x|x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->immh = (insword>>19)&15;
			ctx->immb = (insword>>16)&7;
			ctx->op = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SRSHR_ASIMDSHF_R:
		case ENC_SRSRA_ASIMDSHF_R:
		case ENC_SSHR_ASIMDSHF_R:
		case ENC_SSRA_ASIMDSHF_R:
		case ENC_URSHR_ASIMDSHF_R:
		case ENC_URSRA_ASIMDSHF_R:
		case ENC_USHR_ASIMDSHF_R:
		case ENC_USRA_ASIMDSHF_R:
			// x|Q=x|U=x|x|xxx|xx|immh=xxxx|immb=xxx|xx|o1=x|o0=x|x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->immh = (insword>>19)&15;
			ctx->immb = (insword>>16)&7;
			ctx->o1 = (insword>>13)&1;
			ctx->o0 = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FACGE_ASIMDSAME_ONLY:
		case ENC_FACGT_ASIMDSAME_ONLY:
		case ENC_FCMEQ_ASIMDSAME_ONLY:
		case ENC_FCMGE_ASIMDSAME_ONLY:
		case ENC_FCMGT_ASIMDSAME_ONLY:
			// x|Q=x|U=x|x|xxx|x|E=x|sz=x|x|Rm=xxxxx|xxxx|ac=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->E = (insword>>23)&1;
			ctx->sz = (insword>>22)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->ac = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FACGE_ASIMDSAMEFP16_ONLY:
		case ENC_FACGT_ASIMDSAMEFP16_ONLY:
		case ENC_FCMEQ_ASIMDSAMEFP16_ONLY:
		case ENC_FCMGE_ASIMDSAMEFP16_ONLY:
		case ENC_FCMGT_ASIMDSAMEFP16_ONLY:
			// x|Q=x|U=x|x|xxx|x|E=x|xx|Rm=xxxxx|xx|xx|ac=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->E = (insword>>23)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->ac = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMLAL_ASIMDSAME_F:
		case ENC_FMLAL2_ASIMDSAME_F:
		case ENC_FMLSL_ASIMDSAME_F:
		case ENC_FMLSL2_ASIMDSAME_F:
			// x|Q=x|U=x|x|xxx|x|S=x|sz=x|x|Rm=xxxxx|opcode=xxxxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->S = (insword>>23)&1;
			ctx->sz = (insword>>22)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>11)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SUDOT_ASIMDELEM_D:
		case ENC_USDOT_ASIMDELEM_D:
			// x|Q=x|U=x|x|xxx|x|US=x|x|L=x|M=x|Rm=xxxx|opcode=xxxx|H=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->US = (insword>>23)&1;
			ctx->L = (insword>>21)&1;
			ctx->M = (insword>>20)&1;
			ctx->Rm = (insword>>16)&15;
			ctx->opcode = (insword>>12)&15;
			ctx->H = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FABS_ASIMDMISCFP16_R:
		case ENC_FCMLT_ASIMDMISCFP16_FZ:
		case ENC_FCVTAS_ASIMDMISCFP16_R:
		case ENC_FCVTAU_ASIMDMISCFP16_R:
		case ENC_FNEG_ASIMDMISCFP16_R:
		case ENC_FRECPE_ASIMDMISCFP16_R:
		case ENC_FRSQRTE_ASIMDMISCFP16_R:
		case ENC_FSQRT_ASIMDMISCFP16_R:
		case ENC_SCVTF_ASIMDMISCFP16_R:
		case ENC_UCVTF_ASIMDMISCFP16_R:
			// x|Q=x|U=x|x|xxx|x|a=x|xxxx|xx|opcode=xxxxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->a = (insword>>23)&1;
			ctx->opcode = (insword>>12)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FCMEQ_ASIMDMISCFP16_FZ:
		case ENC_FCMGE_ASIMDMISCFP16_FZ:
		case ENC_FCMGT_ASIMDMISCFP16_FZ:
		case ENC_FCMLE_ASIMDMISCFP16_FZ:
			// x|Q=x|U=x|x|xxx|x|a=x|xxxx|xx|xxxx|op=x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->a = (insword>>23)&1;
			ctx->op = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FABD_ASIMDSAMEFP16_ONLY:
		case ENC_FADDP_ASIMDSAMEFP16_ONLY:
		case ENC_FADD_ASIMDSAMEFP16_ONLY:
		case ENC_FAMAX_ASIMDSAMEFP16_ONLY:
		case ENC_FAMIN_ASIMDSAMEFP16_ONLY:
		case ENC_FDIV_ASIMDSAMEFP16_ONLY:
		case ENC_FMAXNMP_ASIMDSAMEFP16_ONLY:
		case ENC_FMAXNM_ASIMDSAMEFP16_ONLY:
		case ENC_FMINNMP_ASIMDSAMEFP16_ONLY:
		case ENC_FMINNM_ASIMDSAMEFP16_ONLY:
		case ENC_FMLA_ASIMDSAMEFP16_ONLY:
		case ENC_FMLS_ASIMDSAMEFP16_ONLY:
		case ENC_FMULX_ASIMDSAMEFP16_ONLY:
		case ENC_FMUL_ASIMDSAMEFP16_ONLY:
		case ENC_FRECPS_ASIMDSAMEFP16_ONLY:
		case ENC_FRSQRTS_ASIMDSAMEFP16_ONLY:
		case ENC_FSCALE_ASIMDSAMEFP16_ONLY:
		case ENC_FSUB_ASIMDSAMEFP16_ONLY:
			// x|Q=x|U=x|x|xxx|x|a=x|xx|Rm=xxxxx|xx|opcode=xxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->a = (insword>>23)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>11)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMAXNMV_ASIMDALL_ONLY_SD:
		case ENC_FMAXV_ASIMDALL_ONLY_SD:
		case ENC_FMINNMV_ASIMDALL_ONLY_SD:
		case ENC_FMINV_ASIMDALL_ONLY_SD:
			// x|Q=x|U=x|x|xxx|x|o1=x|sz=x|xxxxx|opcode=xxxxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->o1 = (insword>>23)&1;
			ctx->sz = (insword>>22)&1;
			ctx->opcode = (insword>>12)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMAXNMP_ASIMDSAME_ONLY:
		case ENC_FMAXNM_ASIMDSAME_ONLY:
		case ENC_FMAXP_ASIMDSAME_ONLY:
		case ENC_FMAX_ASIMDSAME_ONLY:
		case ENC_FMINNMP_ASIMDSAME_ONLY:
		case ENC_FMINNM_ASIMDSAME_ONLY:
		case ENC_FMINP_ASIMDSAME_ONLY:
		case ENC_FMIN_ASIMDSAME_ONLY:
			// x|Q=x|U=x|x|xxx|x|o1=x|sz=x|x|Rm=xxxxx|opcode=xxxxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->o1 = (insword>>23)&1;
			ctx->sz = (insword>>22)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>11)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMAXP_ASIMDSAMEFP16_ONLY:
		case ENC_FMAX_ASIMDSAMEFP16_ONLY:
		case ENC_FMINP_ASIMDSAMEFP16_ONLY:
		case ENC_FMIN_ASIMDSAMEFP16_ONLY:
			// x|Q=x|U=x|x|xxx|x|o1=x|xx|Rm=xxxxx|xx|opcode=xxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->o1 = (insword>>23)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>11)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMAXNMV_ASIMDALL_ONLY_H:
		case ENC_FMAXV_ASIMDALL_ONLY_H:
		case ENC_FMINNMV_ASIMDALL_ONLY_H:
		case ENC_FMINV_ASIMDALL_ONLY_H:
			// x|Q=x|U=x|x|xxx|x|o1=x|x|xxxxx|opcode=xxxxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->o1 = (insword>>23)&1;
			ctx->opcode = (insword>>12)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FCVTMS_ASIMDMISC_R:
		case ENC_FCVTMU_ASIMDMISC_R:
		case ENC_FCVTNS_ASIMDMISC_R:
		case ENC_FCVTNU_ASIMDMISC_R:
		case ENC_FCVTPS_ASIMDMISC_R:
		case ENC_FCVTPU_ASIMDMISC_R:
		case ENC_FCVTZS_ASIMDMISC_R:
		case ENC_FCVTZU_ASIMDMISC_R:
		case ENC_FRINTA_ASIMDMISC_R:
		case ENC_FRINTI_ASIMDMISC_R:
		case ENC_FRINTM_ASIMDMISC_R:
		case ENC_FRINTN_ASIMDMISC_R:
		case ENC_FRINTP_ASIMDMISC_R:
		case ENC_FRINTX_ASIMDMISC_R:
		case ENC_FRINTZ_ASIMDMISC_R:
			// x|Q=x|U=x|x|xxx|x|o2=x|sz=x|xxxxx|xxxx|o1=x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->o2 = (insword>>23)&1;
			ctx->sz = (insword>>22)&1;
			ctx->o1 = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FCVTMS_ASIMDMISCFP16_R:
		case ENC_FCVTMU_ASIMDMISCFP16_R:
		case ENC_FCVTNS_ASIMDMISCFP16_R:
		case ENC_FCVTNU_ASIMDMISCFP16_R:
		case ENC_FCVTPS_ASIMDMISCFP16_R:
		case ENC_FCVTPU_ASIMDMISCFP16_R:
		case ENC_FCVTZS_ASIMDMISCFP16_R:
		case ENC_FCVTZU_ASIMDMISCFP16_R:
		case ENC_FRINTA_ASIMDMISCFP16_R:
		case ENC_FRINTI_ASIMDMISCFP16_R:
		case ENC_FRINTM_ASIMDMISCFP16_R:
		case ENC_FRINTN_ASIMDMISCFP16_R:
		case ENC_FRINTP_ASIMDMISCFP16_R:
		case ENC_FRINTX_ASIMDMISCFP16_R:
		case ENC_FRINTZ_ASIMDMISCFP16_R:
			// x|Q=x|U=x|x|xxx|x|o2=x|xxxx|xx|xxxx|o1=x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->o2 = (insword>>23)&1;
			ctx->o1 = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMLA_ASIMDSAME_ONLY:
		case ENC_FMLS_ASIMDSAME_ONLY:
			// x|Q=x|U=x|x|xxx|x|op=x|sz=x|x|Rm=xxxxx|opcode=xxxxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->op = (insword>>23)&1;
			ctx->sz = (insword>>22)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>11)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_BIF_ASIMDSAME_ONLY:
		case ENC_BIT_ASIMDSAME_ONLY:
		case ENC_BSL_ASIMDSAME_ONLY:
		case ENC_EOR_ASIMDSAME_ONLY:
			// x|Q=x|U=x|x|xxx|x|opc2=xx|x|Rm=xxxxx|opcode=xxxxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->opc2 = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>11)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_BFDOT_ASIMDELEM_E:
		case ENC_BFMLAL_ASIMDELEM_F:
		case ENC_FDOT_ASIMDELEM_G:
		case ENC_FDOT_ASIMDELEM_D:
		case ENC_FDOT_ASIMDELEM_FP16FP32:
		case ENC_FMULX_ASIMDELEM_RH_H:
		case ENC_FMUL_ASIMDELEM_RH_H:
		case ENC_MUL_ASIMDELEM_R:
		case ENC_SDOT_ASIMDELEM_D:
		case ENC_SMULL_ASIMDELEM_L:
		case ENC_SQDMULL_ASIMDELEM_L:
		case ENC_UDOT_ASIMDELEM_D:
		case ENC_UMULL_ASIMDELEM_L:
			// x|Q=x|U=x|x|xxx|x|size=xx|L=x|M=x|Rm=xxxx|opcode=xxxx|H=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->L = (insword>>21)&1;
			ctx->M = (insword>>20)&1;
			ctx->Rm = (insword>>16)&15;
			ctx->opcode = (insword>>12)&15;
			ctx->H = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SQDMULH_ASIMDELEM_R:
		case ENC_SQRDMULH_ASIMDELEM_R:
			// x|Q=x|U=x|x|xxx|x|size=xx|L=x|M=x|Rm=xxxx|xxx|op=x|H=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->L = (insword>>21)&1;
			ctx->M = (insword>>20)&1;
			ctx->Rm = (insword>>16)&15;
			ctx->op = (insword>>12)&1;
			ctx->H = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SQRDMLAH_ASIMDELEM_R:
		case ENC_SQRDMLSH_ASIMDELEM_R:
			// x|Q=x|U=x|x|xxx|x|size=xx|L=x|M=x|Rm=xxxx|xx|S=x|x|H=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->L = (insword>>21)&1;
			ctx->M = (insword>>20)&1;
			ctx->Rm = (insword>>16)&15;
			ctx->S = (insword>>13)&1;
			ctx->H = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMLA_ASIMDELEM_RH_H:
		case ENC_FMLS_ASIMDELEM_RH_H:
		case ENC_MLA_ASIMDELEM_R:
		case ENC_MLS_ASIMDELEM_R:
		case ENC_SMLAL_ASIMDELEM_L:
		case ENC_SMLSL_ASIMDELEM_L:
		case ENC_SQDMLAL_ASIMDELEM_L:
		case ENC_SQDMLSL_ASIMDELEM_L:
		case ENC_UMLAL_ASIMDELEM_L:
		case ENC_UMLSL_ASIMDELEM_L:
			// x|Q=x|U=x|x|xxx|x|size=xx|L=x|M=x|Rm=xxxx|x|o2=x|xx|H=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->L = (insword>>21)&1;
			ctx->M = (insword>>20)&1;
			ctx->Rm = (insword>>16)&15;
			ctx->o2 = (insword>>14)&1;
			ctx->H = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FCMLA_ADVSIMD_ELT:
			// x|Q=x|U=x|x|xxx|x|size=xx|L=x|M=x|Rm=xxxx|x|rot=xx|x|H=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->L = (insword>>21)&1;
			ctx->M = (insword>>20)&1;
			ctx->Rm = (insword>>16)&15;
			ctx->rot = (insword>>13)&3;
			ctx->H = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SMAXV_ASIMDALL_ONLY:
		case ENC_SMINV_ASIMDALL_ONLY:
		case ENC_UMAXV_ASIMDALL_ONLY:
		case ENC_UMINV_ASIMDALL_ONLY:
			// x|Q=x|U=x|x|xxx|x|size=xx|xxxxx|op=x|xxxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->op = (insword>>16)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_ABS_ASIMDMISC_R:
		case ENC_ADDV_ASIMDALL_ONLY:
		case ENC_BFCVTN_ASIMDMISC_4S:
		case ENC_CLS_ASIMDMISC_R:
		case ENC_CLZ_ASIMDMISC_R:
		case ENC_CMLT_ASIMDMISC_Z:
		case ENC_CNT_ASIMDMISC_R:
		case ENC_FCVTXN_ASIMDMISC_N:
		case ENC_MVN_NOT_ASIMDMISC_R:
		case ENC_NEG_ASIMDMISC_R:
		case ENC_NOT_ASIMDMISC_R:
		case ENC_RBIT_ASIMDMISC_R:
		case ENC_SADDLV_ASIMDALL_ONLY:
		case ENC_SHLL_ASIMDMISC_S:
		case ENC_SQABS_ASIMDMISC_R:
		case ENC_SQNEG_ASIMDMISC_R:
		case ENC_SQXTN_ASIMDMISC_N:
		case ENC_SQXTUN_ASIMDMISC_N:
		case ENC_SUQADD_ASIMDMISC_R:
		case ENC_UADDLV_ASIMDALL_ONLY:
		case ENC_UQXTN_ASIMDMISC_N:
		case ENC_USQADD_ASIMDMISC_R:
		case ENC_XTN_ASIMDMISC_N:
			// x|Q=x|U=x|x|xxx|x|size=xx|xxxxx|opcode=xxxxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->opcode = (insword>>12)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_REV16_ASIMDMISC_R:
		case ENC_REV32_ASIMDMISC_R:
		case ENC_REV64_ASIMDMISC_R:
			// x|Q=x|U=x|x|xxx|x|size=xx|xxxxx|xxxx|o0=x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->o0 = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_CMEQ_ASIMDMISC_Z:
		case ENC_CMGE_ASIMDMISC_Z:
		case ENC_CMGT_ASIMDMISC_Z:
		case ENC_CMLE_ASIMDMISC_Z:
			// x|Q=x|U=x|x|xxx|x|size=xx|xxxxx|xxxx|op=x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->op = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SADALP_ASIMDMISC_P:
		case ENC_SADDLP_ASIMDMISC_P:
		case ENC_UADALP_ASIMDMISC_P:
		case ENC_UADDLP_ASIMDMISC_P:
			// x|Q=x|U=x|x|xxx|x|size=xx|xxxxx|xx|op=x|xx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->op = (insword>>14)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_ADDP_ASIMDSAME_ONLY:
		case ENC_ADD_ASIMDSAME_ONLY:
		case ENC_AND_ASIMDSAME_ONLY:
		case ENC_BIC_ASIMDSAME_ONLY:
		case ENC_CMEQ_ASIMDSAME_ONLY:
		case ENC_CMTST_ASIMDSAME_ONLY:
		case ENC_FAMAX_ASIMDSAME_ONLY:
		case ENC_FAMIN_ASIMDSAME_ONLY:
		case ENC_FSCALE_ASIMDSAME_ONLY:
		case ENC_MLA_ASIMDSAME_ONLY:
		case ENC_MLS_ASIMDSAME_ONLY:
		case ENC_MOV_ORR_ASIMDSAME_ONLY:
		case ENC_MUL_ASIMDSAME_ONLY:
		case ENC_ORN_ASIMDSAME_ONLY:
		case ENC_ORR_ASIMDSAME_ONLY:
		case ENC_PMUL_ASIMDSAME_ONLY:
		case ENC_SHADD_ASIMDSAME_ONLY:
		case ENC_SHSUB_ASIMDSAME_ONLY:
		case ENC_SQADD_ASIMDSAME_ONLY:
		case ENC_SQDMULH_ASIMDSAME_ONLY:
		case ENC_SQRDMULH_ASIMDSAME_ONLY:
		case ENC_SQSUB_ASIMDSAME_ONLY:
		case ENC_SRHADD_ASIMDSAME_ONLY:
		case ENC_SUB_ASIMDSAME_ONLY:
		case ENC_UHADD_ASIMDSAME_ONLY:
		case ENC_UHSUB_ASIMDSAME_ONLY:
		case ENC_UQADD_ASIMDSAME_ONLY:
		case ENC_UQSUB_ASIMDSAME_ONLY:
		case ENC_URHADD_ASIMDSAME_ONLY:
			// x|Q=x|U=x|x|xxx|x|size=xx|x|Rm=xxxxx|opcode=xxxxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>11)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_PMULL_ASIMDDIFF_L:
		case ENC_SMULL_ASIMDDIFF_L:
		case ENC_SQDMULL_ASIMDDIFF_L:
		case ENC_UMULL_ASIMDDIFF_L:
			// x|Q=x|U=x|x|xxx|x|size=xx|x|Rm=xxxxx|opcode=xxxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>12)&15;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SABA_ASIMDSAME_ONLY:
		case ENC_SABD_ASIMDSAME_ONLY:
		case ENC_UABA_ASIMDSAME_ONLY:
		case ENC_UABD_ASIMDSAME_ONLY:
			// x|Q=x|U=x|x|xxx|x|size=xx|x|Rm=xxxxx|xxxx|ac=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->ac = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_CMGE_ASIMDSAME_ONLY:
		case ENC_CMGT_ASIMDSAME_ONLY:
		case ENC_CMHI_ASIMDSAME_ONLY:
		case ENC_CMHS_ASIMDSAME_ONLY:
			// x|Q=x|U=x|x|xxx|x|size=xx|x|Rm=xxxxx|xxxx|eq=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->eq = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SMAXP_ASIMDSAME_ONLY:
		case ENC_SMAX_ASIMDSAME_ONLY:
		case ENC_SMINP_ASIMDSAME_ONLY:
		case ENC_SMIN_ASIMDSAME_ONLY:
		case ENC_UMAXP_ASIMDSAME_ONLY:
		case ENC_UMAX_ASIMDSAME_ONLY:
		case ENC_UMINP_ASIMDSAME_ONLY:
		case ENC_UMIN_ASIMDSAME_ONLY:
			// x|Q=x|U=x|x|xxx|x|size=xx|x|Rm=xxxxx|xxxx|o1=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->o1 = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SQRSHL_ASIMDSAME_ONLY:
		case ENC_SQSHL_ASIMDSAME_ONLY:
		case ENC_SRSHL_ASIMDSAME_ONLY:
		case ENC_SSHL_ASIMDSAME_ONLY:
		case ENC_UQRSHL_ASIMDSAME_ONLY:
		case ENC_UQSHL_ASIMDSAME_ONLY:
		case ENC_URSHL_ASIMDSAME_ONLY:
		case ENC_USHL_ASIMDSAME_ONLY:
			// x|Q=x|U=x|x|xxx|x|size=xx|x|Rm=xxxxx|xxx|R=x|S=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->R = (insword>>12)&1;
			ctx->S = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_ADDHN_ASIMDDIFF_N:
		case ENC_RADDHN_ASIMDDIFF_N:
		case ENC_RSUBHN_ASIMDDIFF_N:
		case ENC_SADDL_ASIMDDIFF_L:
		case ENC_SADDW_ASIMDDIFF_W:
		case ENC_SMLAL_ASIMDDIFF_L:
		case ENC_SMLSL_ASIMDDIFF_L:
		case ENC_SQDMLAL_ASIMDDIFF_L:
		case ENC_SQDMLSL_ASIMDDIFF_L:
		case ENC_SSUBL_ASIMDDIFF_L:
		case ENC_SSUBW_ASIMDDIFF_W:
		case ENC_SUBHN_ASIMDDIFF_N:
		case ENC_UADDL_ASIMDDIFF_L:
		case ENC_UADDW_ASIMDDIFF_W:
		case ENC_UMLAL_ASIMDDIFF_L:
		case ENC_UMLSL_ASIMDDIFF_L:
		case ENC_USUBL_ASIMDDIFF_L:
		case ENC_USUBW_ASIMDDIFF_W:
			// x|Q=x|U=x|x|xxx|x|size=xx|x|Rm=xxxxx|xx|o1=x|x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->o1 = (insword>>13)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SABAL_ASIMDDIFF_L:
		case ENC_SABDL_ASIMDDIFF_L:
		case ENC_UABAL_ASIMDDIFF_L:
		case ENC_UABDL_ASIMDDIFF_L:
			// x|Q=x|U=x|x|xxx|x|size=xx|x|Rm=xxxxx|xx|op=x|x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->op = (insword>>13)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_BFDOT_ASIMDSAME2_D:
		case ENC_BFMLAL_ASIMDSAME2_F_:
		case ENC_BFMMLA_ASIMDSAME2_E:
		case ENC_FCVTN_ASIMDSAME2_D:
		case ENC_FCVTN_ASIMDSAME2_H:
		case ENC_FDOT_ASIMDSAME2_D:
		case ENC_FDOT_ASIMDSAME2_DD:
		case ENC_FDOT_ASIMDSAME2_FP16FP32:
		case ENC_FMMLA_ASIMD_FP8FP16:
		case ENC_FMMLA_ASIMD_FP8FP32:
		case ENC_FMMLA_ASIMD_FP16FP16:
		case ENC_FMMLA_ASIMD_FP16FP32:
		case ENC_SDOT_ASIMDSAME2_D:
		case ENC_UDOT_ASIMDSAME2_D:
		case ENC_USDOT_ASIMDSAME2_D:
			// x|Q=x|U=x|x|xxx|x|size=xx|x|Rm=xxxxx|x|opcode=xxxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>11)&15;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SMMLA_ASIMDSAME2_G:
		case ENC_UMMLA_ASIMDSAME2_G:
		case ENC_USMMLA_ASIMDSAME2_G:
			// x|Q=x|U=x|x|xxx|x|size=xx|x|Rm=xxxxx|x|xxx|B=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->B = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SQRDMLAH_ASIMDSAME2_ONLY:
		case ENC_SQRDMLSH_ASIMDSAME2_ONLY:
			// x|Q=x|U=x|x|xxx|x|size=xx|x|Rm=xxxxx|x|xxx|S=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->S = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FCMLA_ASIMDSAME2_C:
			// x|Q=x|U=x|x|xxx|x|size=xx|x|Rm=xxxxx|x|xx|rot=xx|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->rot = (insword>>11)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FCADD_ASIMDSAME2_C:
			// x|Q=x|U=x|x|xxx|x|size=xx|x|Rm=xxxxx|x|xx|rot=x|x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->rot = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMULX_ASIMDELEM_R_SD:
		case ENC_FMUL_ASIMDELEM_R_SD:
			// x|Q=x|U=x|x|xxx|x|x|sz=x|L=x|M=x|Rm=xxxx|opcode=xxxx|H=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->sz = (insword>>22)&1;
			ctx->L = (insword>>21)&1;
			ctx->M = (insword>>20)&1;
			ctx->Rm = (insword>>16)&15;
			ctx->opcode = (insword>>12)&15;
			ctx->H = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMLAL_ASIMDELEM_LH:
		case ENC_FMLAL2_ASIMDELEM_LH:
		case ENC_FMLSL_ASIMDELEM_LH:
		case ENC_FMLSL2_ASIMDELEM_LH:
			// x|Q=x|U=x|x|xxx|x|x|sz=x|L=x|M=x|Rm=xxxx|x|S=x|xx|H=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->sz = (insword>>22)&1;
			ctx->L = (insword>>21)&1;
			ctx->M = (insword>>20)&1;
			ctx->Rm = (insword>>16)&15;
			ctx->S = (insword>>14)&1;
			ctx->H = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMLA_ASIMDELEM_R_SD:
		case ENC_FMLS_ASIMDELEM_R_SD:
			// x|Q=x|U=x|x|xxx|x|x|sz=x|L=x|M=x|Rm=xxxx|x|o2=x|xx|H=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->sz = (insword>>22)&1;
			ctx->L = (insword>>21)&1;
			ctx->M = (insword>>20)&1;
			ctx->Rm = (insword>>16)&15;
			ctx->o2 = (insword>>14)&1;
			ctx->H = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FABS_ASIMDMISC_R:
		case ENC_FCMLT_ASIMDMISC_FZ:
		case ENC_FCVTAS_ASIMDMISC_R:
		case ENC_FCVTAU_ASIMDMISC_R:
		case ENC_FCVTL_ASIMDMISC_L:
		case ENC_FCVTN_ASIMDMISC_N:
		case ENC_FNEG_ASIMDMISC_R:
		case ENC_FRECPE_ASIMDMISC_R:
		case ENC_FRSQRTE_ASIMDMISC_R:
		case ENC_FSQRT_ASIMDMISC_R:
		case ENC_SCVTF_ASIMDMISC_R:
		case ENC_UCVTF_ASIMDMISC_R:
		case ENC_URECPE_ASIMDMISC_R:
		case ENC_URSQRTE_ASIMDMISC_R:
			// x|Q=x|U=x|x|xxx|x|x|sz=x|xxxxx|opcode=xxxxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->sz = (insword>>22)&1;
			ctx->opcode = (insword>>12)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FCMEQ_ASIMDMISC_FZ:
		case ENC_FCMGE_ASIMDMISC_FZ:
		case ENC_FCMGT_ASIMDMISC_FZ:
		case ENC_FCMLE_ASIMDMISC_FZ:
		case ENC_FRINT32X_ASIMDMISC_R:
		case ENC_FRINT32Z_ASIMDMISC_R:
		case ENC_FRINT64X_ASIMDMISC_R:
		case ENC_FRINT64Z_ASIMDMISC_R:
			// x|Q=x|U=x|x|xxx|x|x|sz=x|xxxxx|xxxx|op=x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->sz = (insword>>22)&1;
			ctx->op = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FABD_ASIMDSAME_ONLY:
		case ENC_FADDP_ASIMDSAME_ONLY:
		case ENC_FADD_ASIMDSAME_ONLY:
		case ENC_FDIV_ASIMDSAME_ONLY:
		case ENC_FMULX_ASIMDSAME_ONLY:
		case ENC_FMUL_ASIMDSAME_ONLY:
		case ENC_FRECPS_ASIMDSAME_ONLY:
		case ENC_FRSQRTS_ASIMDSAME_ONLY:
		case ENC_FSUB_ASIMDSAME_ONLY:
			// x|Q=x|U=x|x|xxx|x|x|sz=x|x|Rm=xxxxx|opcode=xxxxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->sz = (insword>>22)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>11)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_BIC_ASIMDIMM_L_HL:
		case ENC_BIC_ASIMDIMM_L_SL:
		case ENC_FMOV_ASIMDIMM_S_S:
		case ENC_FMOV_ASIMDIMM_D2_D:
		case ENC_MOVI_ASIMDIMM_N_B:
		case ENC_MOVI_ASIMDIMM_L_HL:
		case ENC_MOVI_ASIMDIMM_L_SL:
		case ENC_MOVI_ASIMDIMM_M_SM:
		case ENC_MOVI_ASIMDIMM_D_DS:
		case ENC_MOVI_ASIMDIMM_D2_D:
		case ENC_MVNI_ASIMDIMM_L_HL:
		case ENC_MVNI_ASIMDIMM_L_SL:
		case ENC_MVNI_ASIMDIMM_M_SM:
		case ENC_ORR_ASIMDIMM_L_HL:
		case ENC_ORR_ASIMDIMM_L_SL:
			// x|Q=x|op=x|xxxxxxxxxx|a=x|b=x|c=x|cmode=xxxx|o2=x|x|d=x|e=x|f=x|g=x|h=x|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->op = (insword>>29)&1;
			ctx->a = (insword>>18)&1;
			ctx->b = (insword>>17)&1;
			ctx->c = (insword>>16)&1;
			ctx->cmode = (insword>>12)&15;
			ctx->o2 = (insword>>11)&1;
			ctx->d = (insword>>9)&1;
			ctx->e = (insword>>8)&1;
			ctx->f = (insword>>7)&1;
			ctx->g = (insword>>6)&1;
			ctx->h = (insword>>5)&1;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_MOV_UMOV_ASIMDINS_W_W:
		case ENC_MOV_UMOV_ASIMDINS_X_X:
		case ENC_SMOV_ASIMDINS_W_W:
		case ENC_SMOV_ASIMDINS_X_X:
		case ENC_UMOV_ASIMDINS_W_W:
		case ENC_UMOV_ASIMDINS_X_X:
			// x|Q=x|op=x|xxxxxxxx|imm5=xxxxx|x|imm4=xxxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->op = (insword>>29)&1;
			ctx->imm5 = (insword>>16)&0x1f;
			ctx->imm4 = (insword>>11)&15;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMOV_ASIMDIMM_H_H:
			// x|Q=x|op=x|x|xxx|xx|xxxx|a=x|b=x|c=x|cmode=xxxx|o2=x|x|d=x|e=x|f=x|g=x|h=x|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->op = (insword>>29)&1;
			ctx->a = (insword>>18)&1;
			ctx->b = (insword>>17)&1;
			ctx->c = (insword>>16)&1;
			ctx->cmode = (insword>>12)&15;
			ctx->o2 = (insword>>11)&1;
			ctx->d = (insword>>9)&1;
			ctx->e = (insword>>8)&1;
			ctx->f = (insword>>7)&1;
			ctx->g = (insword>>6)&1;
			ctx->h = (insword>>5)&1;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_DUP_ASIMDINS_DV_V:
		case ENC_DUP_ASIMDINS_DR_R:
		case ENC_INS_ASIMDINS_IV_V:
		case ENC_INS_ASIMDINS_IR_R:
		case ENC_MOV_INS_ASIMDINS_IV_V:
		case ENC_MOV_INS_ASIMDINS_IR_R:
			// x|Q=x|op=x|x|xxx|xx|xx|imm5=xxxxx|x|imm4=xxxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->op = (insword>>29)&1;
			ctx->imm5 = (insword>>16)&0x1f;
			ctx->imm4 = (insword>>11)&15;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_LD1R_ASISDLSOP_R1_I:
		case ENC_LD1R_ASISDLSOP_RX1_R:
		case ENC_LD1_ASISDLSOP_B1_I1B:
		case ENC_LD1_ASISDLSOP_BX1_R1B:
		case ENC_LD1_ASISDLSOP_D1_I1D:
		case ENC_LD1_ASISDLSOP_DX1_R1D:
		case ENC_LD1_ASISDLSOP_H1_I1H:
		case ENC_LD1_ASISDLSOP_HX1_R1H:
		case ENC_LD1_ASISDLSOP_S1_I1S:
		case ENC_LD1_ASISDLSOP_SX1_R1S:
		case ENC_LD2R_ASISDLSOP_R2_I:
		case ENC_LD2R_ASISDLSOP_RX2_R:
		case ENC_LD2_ASISDLSOP_B2_I2B:
		case ENC_LD2_ASISDLSOP_BX2_R2B:
		case ENC_LD2_ASISDLSOP_H2_I2H:
		case ENC_LD2_ASISDLSOP_HX2_R2H:
		case ENC_LD2_ASISDLSOP_S2_I2S:
		case ENC_LD2_ASISDLSOP_SX2_R2S:
		case ENC_LD2_ASISDLSOP_D2_I2D:
		case ENC_LD2_ASISDLSOP_DX2_R2D:
		case ENC_LD3R_ASISDLSOP_R3_I:
		case ENC_LD3R_ASISDLSOP_RX3_R:
		case ENC_LD3_ASISDLSOP_B3_I3B:
		case ENC_LD3_ASISDLSOP_BX3_R3B:
		case ENC_LD3_ASISDLSOP_H3_I3H:
		case ENC_LD3_ASISDLSOP_HX3_R3H:
		case ENC_LD3_ASISDLSOP_S3_I3S:
		case ENC_LD3_ASISDLSOP_SX3_R3S:
		case ENC_LD3_ASISDLSOP_D3_I3D:
		case ENC_LD3_ASISDLSOP_DX3_R3D:
		case ENC_LD4R_ASISDLSOP_R4_I:
		case ENC_LD4R_ASISDLSOP_RX4_R:
		case ENC_LD4_ASISDLSOP_B4_I4B:
		case ENC_LD4_ASISDLSOP_BX4_R4B:
		case ENC_LD4_ASISDLSOP_H4_I4H:
		case ENC_LD4_ASISDLSOP_HX4_R4H:
		case ENC_LD4_ASISDLSOP_S4_I4S:
		case ENC_LD4_ASISDLSOP_SX4_R4S:
		case ENC_LD4_ASISDLSOP_D4_I4D:
		case ENC_LD4_ASISDLSOP_DX4_R4D:
		case ENC_ST1_ASISDLSOP_B1_I1B:
		case ENC_ST1_ASISDLSOP_BX1_R1B:
		case ENC_ST1_ASISDLSOP_H1_I1H:
		case ENC_ST1_ASISDLSOP_HX1_R1H:
		case ENC_ST1_ASISDLSOP_S1_I1S:
		case ENC_ST1_ASISDLSOP_SX1_R1S:
		case ENC_ST1_ASISDLSOP_D1_I1D:
		case ENC_ST1_ASISDLSOP_DX1_R1D:
		case ENC_ST2_ASISDLSOP_B2_I2B:
		case ENC_ST2_ASISDLSOP_BX2_R2B:
		case ENC_ST2_ASISDLSOP_H2_I2H:
		case ENC_ST2_ASISDLSOP_HX2_R2H:
		case ENC_ST2_ASISDLSOP_S2_I2S:
		case ENC_ST2_ASISDLSOP_SX2_R2S:
		case ENC_ST2_ASISDLSOP_D2_I2D:
		case ENC_ST2_ASISDLSOP_DX2_R2D:
		case ENC_ST3_ASISDLSOP_B3_I3B:
		case ENC_ST3_ASISDLSOP_BX3_R3B:
		case ENC_ST3_ASISDLSOP_H3_I3H:
		case ENC_ST3_ASISDLSOP_HX3_R3H:
		case ENC_ST3_ASISDLSOP_S3_I3S:
		case ENC_ST3_ASISDLSOP_SX3_R3S:
		case ENC_ST3_ASISDLSOP_D3_I3D:
		case ENC_ST3_ASISDLSOP_DX3_R3D:
		case ENC_ST4_ASISDLSOP_B4_I4B:
		case ENC_ST4_ASISDLSOP_BX4_R4B:
		case ENC_ST4_ASISDLSOP_H4_I4H:
		case ENC_ST4_ASISDLSOP_HX4_R4H:
		case ENC_ST4_ASISDLSOP_S4_I4S:
		case ENC_ST4_ASISDLSOP_SX4_R4S:
		case ENC_ST4_ASISDLSOP_D4_I4D:
		case ENC_ST4_ASISDLSOP_DX4_R4D:
			// x|Q=x|xxxxxxx|L=x|R=x|Rm=xxxxx|opcode=xxx|S=x|size=xx|Rn=xxxxx|Rt=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->L = (insword>>22)&1;
			ctx->R = (insword>>21)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>13)&7;
			ctx->S = (insword>>12)&1;
			ctx->size = (insword>>10)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_LD1_ASISDLSO_B1_1B:
		case ENC_LD1_ASISDLSO_H1_1H:
		case ENC_LD1_ASISDLSO_S1_1S:
		case ENC_LD1_ASISDLSO_D1_1D:
		case ENC_LD2_ASISDLSO_B2_2B:
		case ENC_LD2_ASISDLSO_H2_2H:
		case ENC_LD2_ASISDLSO_S2_2S:
		case ENC_LD2_ASISDLSO_D2_2D:
		case ENC_LD3_ASISDLSO_B3_3B:
		case ENC_LD3_ASISDLSO_H3_3H:
		case ENC_LD3_ASISDLSO_S3_3S:
		case ENC_LD3_ASISDLSO_D3_3D:
		case ENC_LD4_ASISDLSO_B4_4B:
		case ENC_LD4_ASISDLSO_H4_4H:
		case ENC_LD4_ASISDLSO_S4_4S:
		case ENC_LD4_ASISDLSO_D4_4D:
		case ENC_ST1_ASISDLSO_B1_1B:
		case ENC_ST1_ASISDLSO_H1_1H:
		case ENC_ST1_ASISDLSO_S1_1S:
		case ENC_ST1_ASISDLSO_D1_1D:
		case ENC_ST2_ASISDLSO_B2_2B:
		case ENC_ST2_ASISDLSO_H2_2H:
		case ENC_ST2_ASISDLSO_S2_2S:
		case ENC_ST2_ASISDLSO_D2_2D:
		case ENC_ST3_ASISDLSO_B3_3B:
		case ENC_ST3_ASISDLSO_H3_3H:
		case ENC_ST3_ASISDLSO_S3_3S:
		case ENC_ST3_ASISDLSO_D3_3D:
		case ENC_ST4_ASISDLSO_B4_4B:
		case ENC_ST4_ASISDLSO_H4_4H:
		case ENC_ST4_ASISDLSO_S4_4S:
		case ENC_ST4_ASISDLSO_D4_4D:
			// x|Q=x|xxxxxxx|L=x|R=x|xxxx|o2=x|opcode=xxx|S=x|size=xx|Rn=xxxxx|Rt=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->L = (insword>>22)&1;
			ctx->R = (insword>>21)&1;
			ctx->o2 = (insword>>16)&1;
			ctx->opcode = (insword>>13)&7;
			ctx->S = (insword>>12)&1;
			ctx->size = (insword>>10)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_LD1_ASISDLSE_R1_1V:
		case ENC_LD1_ASISDLSE_R2_2V:
		case ENC_LD1_ASISDLSE_R3_3V:
		case ENC_LD1_ASISDLSE_R4_4V:
		case ENC_ST1_ASISDLSE_R1_1V:
		case ENC_ST1_ASISDLSE_R2_2V:
		case ENC_ST1_ASISDLSE_R3_3V:
		case ENC_ST1_ASISDLSE_R4_4V:
			// x|Q=x|xxxxxxx|L=x|xxxxxx|opcode=xxxx|size=xx|Rn=xxxxx|Rt=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->L = (insword>>22)&1;
			ctx->opcode = (insword>>12)&15;
			ctx->size = (insword>>10)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_LD1_ASISDLSEP_I1_I1:
		case ENC_LD1_ASISDLSEP_R1_R1:
		case ENC_LD1_ASISDLSEP_I2_I2:
		case ENC_LD1_ASISDLSEP_R2_R2:
		case ENC_LD1_ASISDLSEP_I3_I3:
		case ENC_LD1_ASISDLSEP_R3_R3:
		case ENC_LD1_ASISDLSEP_I4_I4:
		case ENC_LD1_ASISDLSEP_R4_R4:
		case ENC_LD2_ASISDLSEP_I2_I:
		case ENC_LD2_ASISDLSEP_R2_R:
		case ENC_LD3_ASISDLSEP_I3_I:
		case ENC_LD3_ASISDLSEP_R3_R:
		case ENC_LD4_ASISDLSEP_I4_I:
		case ENC_LD4_ASISDLSEP_R4_R:
		case ENC_ST1_ASISDLSEP_I1_I1:
		case ENC_ST1_ASISDLSEP_R1_R1:
		case ENC_ST1_ASISDLSEP_I2_I2:
		case ENC_ST1_ASISDLSEP_R2_R2:
		case ENC_ST1_ASISDLSEP_I3_I3:
		case ENC_ST1_ASISDLSEP_R3_R3:
		case ENC_ST1_ASISDLSEP_I4_I4:
		case ENC_ST1_ASISDLSEP_R4_R4:
		case ENC_ST2_ASISDLSEP_I2_I:
		case ENC_ST2_ASISDLSEP_R2_R:
		case ENC_ST3_ASISDLSEP_I3_I:
		case ENC_ST3_ASISDLSEP_R3_R:
		case ENC_ST4_ASISDLSEP_I4_I:
		case ENC_ST4_ASISDLSEP_R4_R:
			// x|Q=x|xxxxxxx|L=x|x|Rm=xxxxx|opcode=xxxx|size=xx|Rn=xxxxx|Rt=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->L = (insword>>22)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>12)&15;
			ctx->size = (insword>>10)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_LUTI2_ASIMDTBL_L5:
		case ENC_LUTI2_ASIMDTBL_L6:
		case ENC_LUTI4_ASIMDTBL_L5:
		case ENC_LUTI4_ASIMDTBL_L7:
		case ENC_TBL_ASIMDTBL_L1_1:
		case ENC_TBL_ASIMDTBL_L2_2:
		case ENC_TBL_ASIMDTBL_L3_3:
		case ENC_TBL_ASIMDTBL_L4_4:
		case ENC_TBX_ASIMDTBL_L1_1:
		case ENC_TBX_ASIMDTBL_L2_2:
		case ENC_TBX_ASIMDTBL_L3_3:
		case ENC_TBX_ASIMDTBL_L4_4:
			// x|Q=x|xxxxxx|op2=xx|x|Rm=xxxxx|x|len=xx|op=x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->op2 = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->len = (insword>>13)&3;
			ctx->op = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_EXT_ASIMDEXT_ONLY:
			// x|Q=x|xx|xxx|x|op2=xx|x|Rm=xxxxx|x|imm4=xxxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->op2 = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->imm4 = (insword>>11)&15;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_TRN1_ASIMDPERM_ONLY:
		case ENC_TRN2_ASIMDPERM_ONLY:
		case ENC_UZP1_ASIMDPERM_ONLY:
		case ENC_UZP2_ASIMDPERM_ONLY:
		case ENC_ZIP1_ASIMDPERM_ONLY:
		case ENC_ZIP2_ASIMDPERM_ONLY:
			// x|Q=x|xx|xxx|x|size=xx|x|Rm=xxxxx|x|op=x|xx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->op = (insword>>14)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_LD1R_ASISDLSO_R1:
		case ENC_LD2R_ASISDLSO_R2:
		case ENC_LD3R_ASISDLSO_R3:
		case ENC_LD4R_ASISDLSO_R4:
		case ENC_LDAP1_ASISDLSO_D1:
		case ENC_STL1_ASISDLSO_D1:
			// x|Q=x|xx|x|x|x|xx|L=x|R=x|xxxx|o2=x|opcode=xxx|S=x|size=xx|Rn=xxxxx|Rt=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->L = (insword>>22)&1;
			ctx->R = (insword>>21)&1;
			ctx->o2 = (insword>>16)&1;
			ctx->opcode = (insword>>13)&7;
			ctx->S = (insword>>12)&1;
			ctx->size = (insword>>10)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_LD2_ASISDLSE_R2:
		case ENC_LD3_ASISDLSE_R3:
		case ENC_LD4_ASISDLSE_R4:
		case ENC_ST2_ASISDLSE_R2:
		case ENC_ST3_ASISDLSE_R3:
		case ENC_ST4_ASISDLSE_R4:
			// x|Q=x|xx|x|x|x|xx|L=x|xxxxxx|opcode=xxxx|size=xx|Rn=xxxxx|Rt=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->L = (insword>>22)&1;
			ctx->opcode = (insword>>12)&15;
			ctx->size = (insword>>10)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_RCWCAS_C64_RCWCOMSWAP:
		case ENC_RCWCASA_C64_RCWCOMSWAP:
		case ENC_RCWCASAL_C64_RCWCOMSWAP:
		case ENC_RCWCASL_C64_RCWCOMSWAP:
		case ENC_RCWCASP_C64_RCWCOMSWAPPR:
		case ENC_RCWCASPA_C64_RCWCOMSWAPPR:
		case ENC_RCWCASPAL_C64_RCWCOMSWAPPR:
		case ENC_RCWCASPL_C64_RCWCOMSWAPPR:
		case ENC_RCWSCAS_C64_RCWCOMSWAP:
		case ENC_RCWSCASA_C64_RCWCOMSWAP:
		case ENC_RCWSCASAL_C64_RCWCOMSWAP:
		case ENC_RCWSCASL_C64_RCWCOMSWAP:
		case ENC_RCWSCASP_C64_RCWCOMSWAPPR:
		case ENC_RCWSCASPA_C64_RCWCOMSWAPPR:
		case ENC_RCWSCASPAL_C64_RCWCOMSWAPPR:
		case ENC_RCWSCASPL_C64_RCWCOMSWAPPR:
			// x|S=x|xxxxxx|A=x|R=x|x|Rs=xxxxx|xxxxxx|Rn=xxxxx|Rt=xxxxx
			ctx->S = (insword>>30)&1;
			ctx->A = (insword>>23)&1;
			ctx->R = (insword>>22)&1;
			ctx->Rs = (insword>>16)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_LDCLRP_128_MEMOP_128:
		case ENC_LDCLRPA_128_MEMOP_128:
		case ENC_LDCLRPAL_128_MEMOP_128:
		case ENC_LDCLRPL_128_MEMOP_128:
		case ENC_LDSETP_128_MEMOP_128:
		case ENC_LDSETPA_128_MEMOP_128:
		case ENC_LDSETPAL_128_MEMOP_128:
		case ENC_LDSETPL_128_MEMOP_128:
		case ENC_RCWCLRP_128_MEMOP_128:
		case ENC_RCWCLRPA_128_MEMOP_128:
		case ENC_RCWCLRPAL_128_MEMOP_128:
		case ENC_RCWCLRPL_128_MEMOP_128:
		case ENC_RCWSCLRP_128_MEMOP_128:
		case ENC_RCWSCLRPA_128_MEMOP_128:
		case ENC_RCWSCLRPAL_128_MEMOP_128:
		case ENC_RCWSCLRPL_128_MEMOP_128:
		case ENC_RCWSETP_128_MEMOP_128:
		case ENC_RCWSETPA_128_MEMOP_128:
		case ENC_RCWSETPAL_128_MEMOP_128:
		case ENC_RCWSETPL_128_MEMOP_128:
		case ENC_RCWSSETP_128_MEMOP_128:
		case ENC_RCWSSETPA_128_MEMOP_128:
		case ENC_RCWSSETPAL_128_MEMOP_128:
		case ENC_RCWSSETPL_128_MEMOP_128:
		case ENC_RCWSSWPP_128_MEMOP_128:
		case ENC_RCWSSWPPA_128_MEMOP_128:
		case ENC_RCWSSWPPAL_128_MEMOP_128:
		case ENC_RCWSSWPPL_128_MEMOP_128:
		case ENC_RCWSWPP_128_MEMOP_128:
		case ENC_RCWSWPPA_128_MEMOP_128:
		case ENC_RCWSWPPAL_128_MEMOP_128:
		case ENC_RCWSWPPL_128_MEMOP_128:
		case ENC_SWPP_128_MEMOP_128:
		case ENC_SWPPA_128_MEMOP_128:
		case ENC_SWPPAL_128_MEMOP_128:
		case ENC_SWPPL_128_MEMOP_128:
			// x|S=x|xxxxxx|A=x|R=x|x|Rt2=xxxxx|o3=x|opc=xxx|xx|Rn=xxxxx|Rt=xxxxx
			ctx->S = (insword>>30)&1;
			ctx->A = (insword>>23)&1;
			ctx->R = (insword>>22)&1;
			ctx->Rt2 = (insword>>16)&0x1f;
			ctx->o3 = (insword>>15)&1;
			ctx->opc = (insword>>12)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_RCWCLR_64_MEMOP:
		case ENC_RCWCLRA_64_MEMOP:
		case ENC_RCWCLRAL_64_MEMOP:
		case ENC_RCWCLRL_64_MEMOP:
		case ENC_RCWSCLR_64_MEMOP:
		case ENC_RCWSCLRA_64_MEMOP:
		case ENC_RCWSCLRAL_64_MEMOP:
		case ENC_RCWSCLRL_64_MEMOP:
		case ENC_RCWSET_64_MEMOP:
		case ENC_RCWSETA_64_MEMOP:
		case ENC_RCWSETAL_64_MEMOP:
		case ENC_RCWSETL_64_MEMOP:
		case ENC_RCWSSET_64_MEMOP:
		case ENC_RCWSSETA_64_MEMOP:
		case ENC_RCWSSETAL_64_MEMOP:
		case ENC_RCWSSETL_64_MEMOP:
		case ENC_RCWSSWP_64_MEMOP:
		case ENC_RCWSSWPA_64_MEMOP:
		case ENC_RCWSSWPAL_64_MEMOP:
		case ENC_RCWSSWPL_64_MEMOP:
		case ENC_RCWSWP_64_MEMOP:
		case ENC_RCWSWPA_64_MEMOP:
		case ENC_RCWSWPAL_64_MEMOP:
		case ENC_RCWSWPL_64_MEMOP:
			// x|S=x|xxx|VR=x|xx|A=x|R=x|x|Rs=xxxxx|o3=x|opc=xxx|xx|Rn=xxxxx|Rt=xxxxx
			ctx->S = (insword>>30)&1;
			ctx->VR = (insword>>26)&1;
			ctx->A = (insword>>23)&1;
			ctx->R = (insword>>22)&1;
			ctx->Rs = (insword>>16)&0x1f;
			ctx->o3 = (insword>>15)&1;
			ctx->opc = (insword>>12)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_CASP_CP32_COMSWAPPR:
		case ENC_CASPA_CP32_COMSWAPPR:
		case ENC_CASPAL_CP32_COMSWAPPR:
		case ENC_CASPL_CP32_COMSWAPPR:
		case ENC_CASP_CP64_COMSWAPPR:
		case ENC_CASPA_CP64_COMSWAPPR:
		case ENC_CASPAL_CP64_COMSWAPPR:
		case ENC_CASPL_CP64_COMSWAPPR:
		case ENC_CASPT_CP64_COMSWAPPR_UNPRIV:
		case ENC_CASPAT_CP64_COMSWAPPR_UNPRIV:
		case ENC_CASPALT_CP64_COMSWAPPR_UNPRIV:
		case ENC_CASPLT_CP64_COMSWAPPR_UNPRIV:
		case ENC_CAST_C64_COMSWAP_UNPRIV:
		case ENC_CASAT_C64_COMSWAP_UNPRIV:
		case ENC_CASALT_C64_COMSWAP_UNPRIV:
		case ENC_CASLT_C64_COMSWAP_UNPRIV:
		case ENC_LDATXR_LR32_LDSTEXCLR_UNPRIV:
		case ENC_LDATXR_LR64_LDSTEXCLR_UNPRIV:
		case ENC_LDAXP_LP32_LDSTEXCLP:
		case ENC_LDAXP_LP64_LDSTEXCLP:
		case ENC_LDTXR_LR32_LDSTEXCLR_UNPRIV:
		case ENC_LDTXR_LR64_LDSTEXCLR_UNPRIV:
		case ENC_LDXP_LP32_LDSTEXCLP:
		case ENC_LDXP_LP64_LDSTEXCLP:
		case ENC_STLTXR_SR32_LDSTEXCLR_UNPRIV:
		case ENC_STLTXR_SR64_LDSTEXCLR_UNPRIV:
		case ENC_STLXP_SP32_LDSTEXCLP:
		case ENC_STLXP_SP64_LDSTEXCLP:
		case ENC_STTXR_SR32_LDSTEXCLR_UNPRIV:
		case ENC_STTXR_SR64_LDSTEXCLR_UNPRIV:
		case ENC_STXP_SP32_LDSTEXCLP:
		case ENC_STXP_SP64_LDSTEXCLP:
			// x|sz=x|xxxxxxx|L=x|x|Rs=xxxxx|o0=x|Rt2=xxxxx|Rn=xxxxx|Rt=xxxxx
			ctx->sz = (insword>>30)&1;
			ctx->L = (insword>>22)&1;
			ctx->Rs = (insword>>16)&0x1f;
			ctx->o0 = (insword>>15)&1;
			ctx->Rt2 = (insword>>10)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_LDTADD_32_MEMOP_UNPRIV:
		case ENC_LDTADDA_32_MEMOP_UNPRIV:
		case ENC_LDTADDAL_32_MEMOP_UNPRIV:
		case ENC_LDTADDL_32_MEMOP_UNPRIV:
		case ENC_LDTADD_64_MEMOP_UNPRIV:
		case ENC_LDTADDA_64_MEMOP_UNPRIV:
		case ENC_LDTADDAL_64_MEMOP_UNPRIV:
		case ENC_LDTADDL_64_MEMOP_UNPRIV:
		case ENC_LDTCLR_32_MEMOP_UNPRIV:
		case ENC_LDTCLRA_32_MEMOP_UNPRIV:
		case ENC_LDTCLRAL_32_MEMOP_UNPRIV:
		case ENC_LDTCLRL_32_MEMOP_UNPRIV:
		case ENC_LDTCLR_64_MEMOP_UNPRIV:
		case ENC_LDTCLRA_64_MEMOP_UNPRIV:
		case ENC_LDTCLRAL_64_MEMOP_UNPRIV:
		case ENC_LDTCLRL_64_MEMOP_UNPRIV:
		case ENC_LDTSET_32_MEMOP_UNPRIV:
		case ENC_LDTSETA_32_MEMOP_UNPRIV:
		case ENC_LDTSETAL_32_MEMOP_UNPRIV:
		case ENC_LDTSETL_32_MEMOP_UNPRIV:
		case ENC_LDTSET_64_MEMOP_UNPRIV:
		case ENC_LDTSETA_64_MEMOP_UNPRIV:
		case ENC_LDTSETAL_64_MEMOP_UNPRIV:
		case ENC_LDTSETL_64_MEMOP_UNPRIV:
		case ENC_STTADD_LDTADD_32_MEMOP_UNPRIV:
		case ENC_STTADDL_LDTADDL_32_MEMOP_UNPRIV:
		case ENC_STTADD_LDTADD_64_MEMOP_UNPRIV:
		case ENC_STTADDL_LDTADDL_64_MEMOP_UNPRIV:
		case ENC_STTCLR_LDTCLR_32_MEMOP_UNPRIV:
		case ENC_STTCLRL_LDTCLRL_32_MEMOP_UNPRIV:
		case ENC_STTCLR_LDTCLR_64_MEMOP_UNPRIV:
		case ENC_STTCLRL_LDTCLRL_64_MEMOP_UNPRIV:
		case ENC_STTSET_LDTSET_32_MEMOP_UNPRIV:
		case ENC_STTSETL_LDTSETL_32_MEMOP_UNPRIV:
		case ENC_STTSET_LDTSET_64_MEMOP_UNPRIV:
		case ENC_STTSETL_LDTSETL_64_MEMOP_UNPRIV:
		case ENC_SWPT_32_MEMOP_UNPRIV:
		case ENC_SWPTA_32_MEMOP_UNPRIV:
		case ENC_SWPTAL_32_MEMOP_UNPRIV:
		case ENC_SWPTL_32_MEMOP_UNPRIV:
		case ENC_SWPT_64_MEMOP_UNPRIV:
		case ENC_SWPTA_64_MEMOP_UNPRIV:
		case ENC_SWPTAL_64_MEMOP_UNPRIV:
		case ENC_SWPTL_64_MEMOP_UNPRIV:
			// x|sz=x|xxxxxx|A=x|R=x|x|Rs=xxxxx|o3=x|opc=xxx|xx|Rn=xxxxx|Rt=xxxxx
			ctx->sz = (insword>>30)&1;
			ctx->A = (insword>>23)&1;
			ctx->R = (insword>>22)&1;
			ctx->Rs = (insword>>16)&0x1f;
			ctx->o3 = (insword>>15)&1;
			ctx->opc = (insword>>12)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_SMOP4A_ZA_ZZ_B1X2:
		case ENC_SMOP4A_ZA_ZZ_B1X1:
		case ENC_SMOP4A_ZA_ZZ_B2X1:
		case ENC_SMOP4A_ZA_ZZ_B2X2:
		case ENC_SMOP4S_ZA_ZZ_B1X2:
		case ENC_SMOP4S_ZA_ZZ_B1X1:
		case ENC_SMOP4S_ZA_ZZ_B2X1:
		case ENC_SMOP4S_ZA_ZZ_B2X2:
		case ENC_SUMOP4A_ZA_ZZ_B1X2:
		case ENC_SUMOP4A_ZA_ZZ_B1X1:
		case ENC_SUMOP4A_ZA_ZZ_B2X1:
		case ENC_SUMOP4A_ZA_ZZ_B2X2:
		case ENC_SUMOP4S_ZA_ZZ_B1X2:
		case ENC_SUMOP4S_ZA_ZZ_B1X1:
		case ENC_SUMOP4S_ZA_ZZ_B2X1:
		case ENC_SUMOP4S_ZA_ZZ_B2X2:
		case ENC_UMOP4A_ZA_ZZ_B1X2:
		case ENC_UMOP4A_ZA_ZZ_B1X1:
		case ENC_UMOP4A_ZA_ZZ_B2X1:
		case ENC_UMOP4A_ZA_ZZ_B2X2:
		case ENC_UMOP4S_ZA_ZZ_B1X2:
		case ENC_UMOP4S_ZA_ZZ_B1X1:
		case ENC_UMOP4S_ZA_ZZ_B2X1:
		case ENC_UMOP4S_ZA_ZZ_B2X2:
		case ENC_USMOP4A_ZA_ZZ_B1X2:
		case ENC_USMOP4A_ZA_ZZ_B1X1:
		case ENC_USMOP4A_ZA_ZZ_B2X1:
		case ENC_USMOP4A_ZA_ZZ_B2X2:
		case ENC_USMOP4S_ZA_ZZ_B1X2:
		case ENC_USMOP4S_ZA_ZZ_B1X1:
		case ENC_USMOP4S_ZA_ZZ_B2X1:
		case ENC_USMOP4S_ZA_ZZ_B2X2:
			// x|xx|xxxx|u0=x|xx|u1=x|M=x|Zm=xxx|x|x|xxxxx|N=x|Zn=xxx|x|S=x|x|x|ZAda=xx
			ctx->u0 = (insword>>24)&1;
			ctx->u1 = (insword>>21)&1;
			ctx->M = (insword>>20)&1;
			ctx->Zm = (insword>>17)&7;
			ctx->N = (insword>>9)&1;
			ctx->Zn = (insword>>6)&7;
			ctx->S = (insword>>4)&1;
			ctx->ZAda = insword&3;
			break;
		case ENC_SMOPA_ZA_PP_ZZ_32:
		case ENC_SMOPS_ZA_PP_ZZ_32:
		case ENC_SUMOPA_ZA_PP_ZZ_32:
		case ENC_SUMOPS_ZA_PP_ZZ_32:
		case ENC_UMOPA_ZA_PP_ZZ_32:
		case ENC_UMOPS_ZA_PP_ZZ_32:
		case ENC_USMOPA_ZA_PP_ZZ_32:
		case ENC_USMOPS_ZA_PP_ZZ_32:
			// x|xx|xxxx|u0=x|xx|u1=x|Zm=xxxxx|Pm=xxx|Pn=xxx|Zn=xxxxx|S=x|x|x|ZAda=xx
			ctx->u0 = (insword>>24)&1;
			ctx->u1 = (insword>>21)&1;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Pm = (insword>>13)&7;
			ctx->Pn = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->S = (insword>>4)&1;
			ctx->ZAda = insword&3;
			break;
		case ENC_STMOPA_ZA_ZZZI_B2X1:
		case ENC_SUTMOPA_ZA_ZZZI_B2X1:
		case ENC_USTMOPA_ZA_ZZZI_B2X1:
		case ENC_UTMOPA_ZA_ZZZI_B2X1:
			// x|xx|xxxx|u0=x|xx|u1=x|Zm=xxxxx|x|x|x|K=x|Zk=xx|Zn=xxxx|i2=xx|x|x|ZAda=xx
			ctx->u0 = (insword>>24)&1;
			ctx->u1 = (insword>>21)&1;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->K = (insword>>12)&1;
			ctx->Zk = (insword>>10)&3;
			ctx->Zn = (insword>>6)&15;
			ctx->i2 = (insword>>4)&3;
			ctx->ZAda = insword&3;
			break;
		case ENC_SMOP4A_ZA32_ZZ_H1X2:
		case ENC_SMOP4A_ZA32_ZZ_H1X1:
		case ENC_SMOP4A_ZA32_ZZ_H2X1:
		case ENC_SMOP4A_ZA32_ZZ_H2X2:
		case ENC_SMOP4S_ZA32_ZZ_H1X2:
		case ENC_SMOP4S_ZA32_ZZ_H1X1:
		case ENC_SMOP4S_ZA32_ZZ_H2X1:
		case ENC_SMOP4S_ZA32_ZZ_H2X2:
		case ENC_UMOP4A_ZA32_ZZ_H1X2:
		case ENC_UMOP4A_ZA32_ZZ_H1X1:
		case ENC_UMOP4A_ZA32_ZZ_H2X1:
		case ENC_UMOP4A_ZA32_ZZ_H2X2:
		case ENC_UMOP4S_ZA32_ZZ_H1X2:
		case ENC_UMOP4S_ZA32_ZZ_H1X1:
		case ENC_UMOP4S_ZA32_ZZ_H2X1:
		case ENC_UMOP4S_ZA32_ZZ_H2X2:
			// x|xx|xxxx|u0=x|xx|x|M=x|Zm=xxx|x|x|xxxxx|N=x|Zn=xxx|x|S=x|x|x|ZAda=xx
			ctx->u0 = (insword>>24)&1;
			ctx->M = (insword>>20)&1;
			ctx->Zm = (insword>>17)&7;
			ctx->N = (insword>>9)&1;
			ctx->Zn = (insword>>6)&7;
			ctx->S = (insword>>4)&1;
			ctx->ZAda = insword&3;
			break;
		case ENC_SMOPA_ZA32_PP_ZZ_16:
		case ENC_SMOPS_ZA32_PP_ZZ_16:
		case ENC_UMOPA_ZA32_PP_ZZ_16:
		case ENC_UMOPS_ZA32_PP_ZZ_16:
			// x|xx|xxxx|u0=x|xx|x|Zm=xxxxx|Pm=xxx|Pn=xxx|Zn=xxxxx|S=x|x|x|ZAda=xx
			ctx->u0 = (insword>>24)&1;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Pm = (insword>>13)&7;
			ctx->Pn = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->S = (insword>>4)&1;
			ctx->ZAda = insword&3;
			break;
		case ENC_STMOPA_ZA32_ZZZI_H2X1:
		case ENC_UTMOPA_ZA32_ZZZI_H2X1:
			// x|xx|xxxx|u0=x|xx|x|Zm=xxxxx|x|x|x|K=x|Zk=xx|Zn=xxxx|i2=xx|x|x|ZAda=xx
			ctx->u0 = (insword>>24)&1;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->K = (insword>>12)&1;
			ctx->Zk = (insword>>10)&3;
			ctx->Zn = (insword>>6)&15;
			ctx->i2 = (insword>>4)&3;
			ctx->ZAda = insword&3;
			break;
		case ENC_UDF_ONLY_PERM_UNDEF:
			// x|xx|xxxx|xxxxxxxxx|imm16=xxxxxxxxxxxxxxxx
			ctx->imm16 = insword&0xffff;
			break;
		case ENC_ZERO_ZA1_RI_2:
		case ENC_ZERO_ZA1_RI_4:
		case ENC_ZERO_ZA2_RI_1:
			// x|xx|xxxx|xxxxxxx|opc=xxx|Rv=xx|xxxxxxxxxx|off3=xxx
			ctx->opc = (insword>>15)&7;
			ctx->Rv = (insword>>13)&3;
			ctx->off3 = insword&7;
			break;
		case ENC_ZERO_ZA4_RI_2:
		case ENC_ZERO_ZA4_RI_4:
			// x|xx|xxxx|xxxxxxx|opc=xxx|Rv=xx|xxxxxxxxxx|xx|o1=x
			ctx->opc = (insword>>15)&7;
			ctx->Rv = (insword>>13)&3;
			ctx->o1 = insword&1;
			break;
		case ENC_ZERO_ZA2_RI_2:
		case ENC_ZERO_ZA2_RI_4:
		case ENC_ZERO_ZA4_RI_1:
			// x|xx|xxxx|xxxxxxx|opc=xxx|Rv=xx|xxxxxxxxxx|x|off2=xx
			ctx->opc = (insword>>15)&7;
			ctx->Rv = (insword>>13)&3;
			ctx->off2 = insword&3;
			break;
		case ENC_ZERO_ZT_I_:
			// x|xx|xxxx|xxxxxxx|xxxxxxxxxxxxxx|opc=xxxx
			ctx->opc = insword&15;
			break;
		case ENC_ZERO_ZA_I_:
			// x|xx|xxxx|xxxxxxx|xxxxxxxxxx|imm8=xxxxxxxx
			ctx->imm8 = insword&0xff;
			break;
		case ENC_MOVT_R_ZT_:
		case ENC_MOVT_ZT_R_:
			// x|xx|xxxx|xxxxxxx|x|xx|off3=xxx|opc=xxxxxxx|Rt=xxxxx
			ctx->off3 = (insword>>12)&7;
			ctx->opc = (insword>>5)&0x7f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_MOVT_ZT_Z_:
			// x|xx|xxxx|xxxxxxx|x|xx|x|off2=xx|opc=xxxxxxx|Zt=xxxxx
			ctx->off2 = (insword>>12)&3;
			ctx->opc = (insword>>5)&0x7f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_LUTI4_MZ4_ZTMZ2_4:
			// x|xx|xxxx|xxxxxx|xxx|xx|size=xx|opc=xx|Zn=xxxx|x|D=x|xx|Zd=xx
			ctx->size = (insword>>12)&3;
			ctx->opc = (insword>>10)&3;
			ctx->Zn = (insword>>6)&15;
			ctx->D = (insword>>4)&1;
			ctx->Zd = insword&3;
			break;
		case ENC_LUTI6_MZ4_ZTMZ3_4:
			// x|xx|xxxx|xxxxxx|xxx|xx|size=xx|opc=xx|Zn=xxx|x|x|D=x|xx|Zd=xx
			ctx->size = (insword>>12)&3;
			ctx->opc = (insword>>10)&3;
			ctx->Zn = (insword>>7)&7;
			ctx->D = (insword>>4)&1;
			ctx->Zd = insword&3;
			break;
		case ENC_LUTI4_MZ4_ZTZ_4:
			// x|xx|xxxx|xxxxxx|xx|i1=x|xx|size=xx|opc2=xx|Zn=xxxxx|D=x|xx|Zd=xx
			ctx->i1 = (insword>>16)&1;
			ctx->size = (insword>>12)&3;
			ctx->opc2 = (insword>>10)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->D = (insword>>4)&1;
			ctx->Zd = insword&3;
			break;
		case ENC_LUTI4_MZ2_ZTZ_8:
			// x|xx|xxxx|xxxxxx|xx|i2=xx|x|size=xx|opc2=xx|Zn=xxxxx|D=x|x|Zd=xxx
			ctx->i2 = (insword>>15)&3;
			ctx->size = (insword>>12)&3;
			ctx->opc2 = (insword>>10)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->D = (insword>>4)&1;
			ctx->Zd = insword&7;
			break;
		case ENC_LUTI2_MZ4_ZTZ_4:
			// x|xx|xxxx|xxxxxx|x|i2=xx|xx|size=xx|opc2=xx|Zn=xxxxx|D=x|xx|Zd=xx
			ctx->i2 = (insword>>16)&3;
			ctx->size = (insword>>12)&3;
			ctx->opc2 = (insword>>10)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->D = (insword>>4)&1;
			ctx->Zd = insword&3;
			break;
		case ENC_LUTI2_MZ2_ZTZ_8:
			// x|xx|xxxx|xxxxxx|x|i3=xxx|x|size=xx|opc2=xx|Zn=xxxxx|D=x|x|Zd=xxx
			ctx->i3 = (insword>>15)&7;
			ctx->size = (insword>>12)&3;
			ctx->opc2 = (insword>>10)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->D = (insword>>4)&1;
			ctx->Zd = insword&7;
			break;
		case ENC_LD1Q_ZA_P_RRR_:
		case ENC_ST1Q_ZA_P_RRR_:
			// x|xx|xxxx|xxxx|Rm=xxxxx|V=x|Rs=xx|Pg=xxx|Rn=xxxxx|x|ZAt=xxxx
			ctx->Rm = (insword>>16)&0x1f;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->ZAt = insword&15;
			break;
		case ENC_LDR_ZA_RI_:
		case ENC_STR_ZA_RI_:
			// x|xx|xxxx|xxx|op=x|xxxxx|x|Rv=xx|xxx|Rn=xxxxx|x|off4=xxxx
			ctx->op = (insword>>21)&1;
			ctx->Rv = (insword>>13)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->off4 = insword&15;
			break;
		case ENC_LDR_ZT_BR_:
		case ENC_STR_ZT_BR_:
			// x|xx|xxxx|xxx|opc=xxxxxx|x|xxxxx|Rn=xxxxx|xxx|opc2=xx
			ctx->opc = (insword>>16)&0x3f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->opc2 = insword&3;
			break;
		case ENC_LUTI6_MZ4_ZMZ2_4:
			// x|xx|xxxx|xx|i1=x|x|Zm=xxxxx|xxxx|xx|Zn=xxxxx|D=x|xx|Zd=xx
			ctx->i1 = (insword>>22)&1;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->D = (insword>>4)&1;
			ctx->Zd = insword&3;
			break;
		case ENC_LUTI6_MZ4_ZMZ2_1:
			// x|xx|xxxx|xx|i1=x|x|Zm=xxxxx|xxxx|xx|Zn=xxxxx|Zd=xxx|xx
			ctx->i1 = (insword>>22)&1;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = (insword>>2)&7;
			break;
		case ENC_SMLALL_ZA_ZZV_1:
		case ENC_SMLSLL_ZA_ZZV_1:
		case ENC_UMLALL_ZA_ZZV_1:
		case ENC_UMLSLL_ZA_ZZV_1:
		case ENC_USMLALL_ZA_ZZV_S:
			// x|xx|xxxx|xx|sz=x|xx|Zm=xxxx|x|Rv=xx|xxx|Zn=xxxxx|U=x|S=x|op=x|off2=xx
			ctx->sz = (insword>>22)&1;
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->U = (insword>>4)&1;
			ctx->S = (insword>>3)&1;
			ctx->op = (insword>>2)&1;
			ctx->off2 = insword&3;
			break;
		case ENC_SMLALL_ZA_ZZV_2X1:
		case ENC_SMLALL_ZA_ZZV_4X1:
		case ENC_SMLSLL_ZA_ZZV_2X1:
		case ENC_SMLSLL_ZA_ZZV_4X1:
		case ENC_SUMLALL_ZA_ZZV_S2X1:
		case ENC_SUMLALL_ZA_ZZV_S4X1:
		case ENC_UMLALL_ZA_ZZV_2X1:
		case ENC_UMLALL_ZA_ZZV_4X1:
		case ENC_UMLSLL_ZA_ZZV_2X1:
		case ENC_UMLSLL_ZA_ZZV_4X1:
		case ENC_USMLALL_ZA_ZZV_S2X1:
		case ENC_USMLALL_ZA_ZZV_S4X1:
			// x|xx|xxxx|xx|sz=x|xx|Zm=xxxx|x|Rv=xx|xxx|Zn=xxxxx|U=x|S=x|op=x|x|o1=x
			ctx->sz = (insword>>22)&1;
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->U = (insword>>4)&1;
			ctx->S = (insword>>3)&1;
			ctx->op = (insword>>2)&1;
			ctx->o1 = insword&1;
			break;
		case ENC_SDOT_ZA_ZZV_2X1:
		case ENC_SDOT_ZA_ZZV_4X1:
		case ENC_UDOT_ZA_ZZV_2X1:
		case ENC_UDOT_ZA_ZZV_4X1:
			// x|xx|xxxx|xx|sz=x|xx|Zm=xxxx|x|Rv=xx|xxx|Zn=xxxxx|U=x|x|off3=xxx
			ctx->sz = (insword>>22)&1;
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->U = (insword>>4)&1;
			ctx->off3 = insword&7;
			break;
		case ENC_ADD_ZA_ZZV_2X1:
		case ENC_ADD_ZA_ZZV_4X1:
		case ENC_BFMLA_ZA_ZZV_2X1_16:
		case ENC_BFMLA_ZA_ZZV_4X1_16:
		case ENC_BFMLS_ZA_ZZV_2X1_16:
		case ENC_BFMLS_ZA_ZZV_4X1_16:
		case ENC_FMLA_ZA_ZZV_2X1:
		case ENC_FMLA_ZA_ZZV_2X1_16:
		case ENC_FMLA_ZA_ZZV_4X1:
		case ENC_FMLA_ZA_ZZV_4X1_16:
		case ENC_FMLS_ZA_ZZV_2X1:
		case ENC_FMLS_ZA_ZZV_2X1_16:
		case ENC_FMLS_ZA_ZZV_4X1:
		case ENC_FMLS_ZA_ZZV_4X1_16:
		case ENC_SUB_ZA_ZZV_2X1:
		case ENC_SUB_ZA_ZZV_4X1:
			// x|xx|xxxx|xx|sz=x|xx|Zm=xxxx|x|Rv=xx|xxx|Zn=xxxxx|x|S=x|off3=xxx
			ctx->sz = (insword>>22)&1;
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->S = (insword>>3)&1;
			ctx->off3 = insword&7;
			break;
		case ENC_BFMLA_ZA_ZZW_2X2_16:
		case ENC_BFMLS_ZA_ZZW_2X2_16:
		case ENC_FMLA_ZA_ZZW_2X2_16:
		case ENC_FMLS_ZA_ZZW_2X2_16:
			// x|xx|xxxx|xx|sz=x|x|Zm=xxxx|xx|Rv=xx|xxx|Zn=xxxx|x|S=x|x|off3=xxx
			ctx->sz = (insword>>22)&1;
			ctx->Zm = (insword>>17)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>6)&15;
			ctx->S = (insword>>4)&1;
			ctx->off3 = insword&7;
			break;
		case ENC_SMLALL_ZA_ZZW_2X2:
		case ENC_SMLSLL_ZA_ZZW_2X2:
		case ENC_UMLALL_ZA_ZZW_2X2:
		case ENC_UMLSLL_ZA_ZZW_2X2:
		case ENC_USMLALL_ZA_ZZW_S2X2:
			// x|xx|xxxx|xx|sz=x|x|Zm=xxxx|xx|Rv=xx|xxx|Zn=xxxx|x|U=x|S=x|op=x|x|o1=x
			ctx->sz = (insword>>22)&1;
			ctx->Zm = (insword>>17)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>6)&15;
			ctx->U = (insword>>4)&1;
			ctx->S = (insword>>3)&1;
			ctx->op = (insword>>2)&1;
			ctx->o1 = insword&1;
			break;
		case ENC_SDOT_ZA_ZZW_2X2:
		case ENC_UDOT_ZA_ZZW_2X2:
			// x|xx|xxxx|xx|sz=x|x|Zm=xxxx|xx|Rv=xx|xxx|Zn=xxxx|x|U=x|x|off3=xxx
			ctx->sz = (insword>>22)&1;
			ctx->Zm = (insword>>17)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>6)&15;
			ctx->U = (insword>>4)&1;
			ctx->off3 = insword&7;
			break;
		case ENC_ADD_ZA_ZZW_2X2:
		case ENC_FMLA_ZA_ZZW_2X2:
		case ENC_FMLS_ZA_ZZW_2X2:
		case ENC_SUB_ZA_ZZW_2X2:
			// x|xx|xxxx|xx|sz=x|x|Zm=xxxx|xx|Rv=xx|xxx|Zn=xxxx|x|x|S=x|off3=xxx
			ctx->sz = (insword>>22)&1;
			ctx->Zm = (insword>>17)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>6)&15;
			ctx->S = (insword>>3)&1;
			ctx->off3 = insword&7;
			break;
		case ENC_BFMLA_ZA_ZZW_4X4_16:
		case ENC_BFMLS_ZA_ZZW_4X4_16:
		case ENC_FMLA_ZA_ZZW_4X4_16:
		case ENC_FMLS_ZA_ZZW_4X4_16:
			// x|xx|xxxx|xx|sz=x|x|Zm=xxx|x|xx|Rv=xx|xxx|Zn=xxx|xx|S=x|x|off3=xxx
			ctx->sz = (insword>>22)&1;
			ctx->Zm = (insword>>18)&7;
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>7)&7;
			ctx->S = (insword>>4)&1;
			ctx->off3 = insword&7;
			break;
		case ENC_SMLALL_ZA_ZZW_4X4:
		case ENC_SMLSLL_ZA_ZZW_4X4:
		case ENC_UMLALL_ZA_ZZW_4X4:
		case ENC_UMLSLL_ZA_ZZW_4X4:
		case ENC_USMLALL_ZA_ZZW_S4X4:
			// x|xx|xxxx|xx|sz=x|x|Zm=xxx|x|xx|Rv=xx|xxx|Zn=xxx|xx|U=x|S=x|op=x|x|o1=x
			ctx->sz = (insword>>22)&1;
			ctx->Zm = (insword>>18)&7;
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>7)&7;
			ctx->U = (insword>>4)&1;
			ctx->S = (insword>>3)&1;
			ctx->op = (insword>>2)&1;
			ctx->o1 = insword&1;
			break;
		case ENC_SDOT_ZA_ZZW_4X4:
		case ENC_UDOT_ZA_ZZW_4X4:
			// x|xx|xxxx|xx|sz=x|x|Zm=xxx|x|xx|Rv=xx|xxx|Zn=xxx|xx|U=x|x|off3=xxx
			ctx->sz = (insword>>22)&1;
			ctx->Zm = (insword>>18)&7;
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>7)&7;
			ctx->U = (insword>>4)&1;
			ctx->off3 = insword&7;
			break;
		case ENC_ADD_ZA_ZZW_4X4:
		case ENC_FMLA_ZA_ZZW_4X4:
		case ENC_FMLS_ZA_ZZW_4X4:
		case ENC_SUB_ZA_ZZW_4X4:
			// x|xx|xxxx|xx|sz=x|x|Zm=xxx|x|xx|Rv=xx|xxx|Zn=xxx|xx|x|S=x|off3=xxx
			ctx->sz = (insword>>22)&1;
			ctx->Zm = (insword>>18)&7;
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>7)&7;
			ctx->S = (insword>>3)&1;
			ctx->off3 = insword&7;
			break;
		case ENC_ADD_ZA_ZW_2X2:
		case ENC_BFADD_ZA_ZW_2X2_16:
		case ENC_BFSUB_ZA_ZW_2X2_16:
		case ENC_FADD_ZA_ZW_2X2:
		case ENC_FADD_ZA_ZW_2X2_16:
		case ENC_FSUB_ZA_ZW_2X2:
		case ENC_FSUB_ZA_ZW_2X2_16:
		case ENC_SUB_ZA_ZW_2X2:
			// x|xx|xxxx|xx|sz=x|x|xx|xx|xx|Rv=xx|xxx|Zm=xxxx|x|x|S=x|off3=xxx
			ctx->sz = (insword>>22)&1;
			ctx->Rv = (insword>>13)&3;
			ctx->Zm = (insword>>6)&15;
			ctx->S = (insword>>3)&1;
			ctx->off3 = insword&7;
			break;
		case ENC_ADD_ZA_ZW_4X4:
		case ENC_BFADD_ZA_ZW_4X4_16:
		case ENC_BFSUB_ZA_ZW_4X4_16:
		case ENC_FADD_ZA_ZW_4X4:
		case ENC_FADD_ZA_ZW_4X4_16:
		case ENC_FSUB_ZA_ZW_4X4:
		case ENC_FSUB_ZA_ZW_4X4_16:
		case ENC_SUB_ZA_ZW_4X4:
			// x|xx|xxxx|xx|sz=x|x|xx|xx|xx|Rv=xx|xxx|Zm=xxx|xx|x|S=x|off3=xxx
			ctx->sz = (insword>>22)&1;
			ctx->Rv = (insword>>13)&3;
			ctx->Zm = (insword>>7)&7;
			ctx->S = (insword>>3)&1;
			ctx->off3 = insword&7;
			break;
		case ENC_LD1B_MZX_P_BI_2X8:
		case ENC_LD1D_MZX_P_BI_2X8:
		case ENC_LD1H_MZX_P_BI_2X8:
		case ENC_LD1W_MZX_P_BI_2X8:
		case ENC_LDNT1B_MZX_P_BI_2X8:
		case ENC_LDNT1D_MZX_P_BI_2X8:
		case ENC_LDNT1H_MZX_P_BI_2X8:
		case ENC_LDNT1W_MZX_P_BI_2X8:
		case ENC_ST1B_MZX_P_BI_2X8:
		case ENC_ST1D_MZX_P_BI_2X8:
		case ENC_ST1H_MZX_P_BI_2X8:
		case ENC_ST1W_MZX_P_BI_2X8:
		case ENC_STNT1B_MZX_P_BI_2X8:
		case ENC_STNT1D_MZX_P_BI_2X8:
		case ENC_STNT1H_MZX_P_BI_2X8:
		case ENC_STNT1W_MZX_P_BI_2X8:
			// x|xx|xxxx|xx|xxx|imm4=xxxx|x|msz=xx|PNg=xxx|Rn=xxxxx|T=x|N=x|Zt=xxx
			ctx->imm4 = (insword>>16)&15;
			ctx->msz = (insword>>13)&3;
			ctx->PNg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->T = (insword>>4)&1;
			ctx->N = (insword>>3)&1;
			ctx->Zt = insword&7;
			break;
		case ENC_LD1B_MZX_P_BI_4X4:
		case ENC_LD1D_MZX_P_BI_4X4:
		case ENC_LD1H_MZX_P_BI_4X4:
		case ENC_LD1W_MZX_P_BI_4X4:
		case ENC_LDNT1B_MZX_P_BI_4X4:
		case ENC_LDNT1D_MZX_P_BI_4X4:
		case ENC_LDNT1H_MZX_P_BI_4X4:
		case ENC_LDNT1W_MZX_P_BI_4X4:
		case ENC_ST1B_MZX_P_BI_4X4:
		case ENC_ST1D_MZX_P_BI_4X4:
		case ENC_ST1H_MZX_P_BI_4X4:
		case ENC_ST1W_MZX_P_BI_4X4:
		case ENC_STNT1B_MZX_P_BI_4X4:
		case ENC_STNT1D_MZX_P_BI_4X4:
		case ENC_STNT1H_MZX_P_BI_4X4:
		case ENC_STNT1W_MZX_P_BI_4X4:
			// x|xx|xxxx|xx|xxx|imm4=xxxx|x|msz=xx|PNg=xxx|Rn=xxxxx|T=x|N=x|x|Zt=xx
			ctx->imm4 = (insword>>16)&15;
			ctx->msz = (insword>>13)&3;
			ctx->PNg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->T = (insword>>4)&1;
			ctx->N = (insword>>3)&1;
			ctx->Zt = insword&3;
			break;
		case ENC_LD1B_MZ_P_BI_2:
		case ENC_LD1D_MZ_P_BI_2:
		case ENC_LD1H_MZ_P_BI_2:
		case ENC_LD1W_MZ_P_BI_2:
		case ENC_LDNT1B_MZ_P_BI_2:
		case ENC_LDNT1D_MZ_P_BI_2:
		case ENC_LDNT1H_MZ_P_BI_2:
		case ENC_LDNT1W_MZ_P_BI_2:
		case ENC_ST1B_MZ_P_BI_2:
		case ENC_ST1D_MZ_P_BI_2:
		case ENC_ST1H_MZ_P_BI_2:
		case ENC_ST1W_MZ_P_BI_2:
		case ENC_STNT1B_MZ_P_BI_2:
		case ENC_STNT1D_MZ_P_BI_2:
		case ENC_STNT1H_MZ_P_BI_2:
		case ENC_STNT1W_MZ_P_BI_2:
			// x|xx|xxxx|xx|xxx|imm4=xxxx|x|msz=xx|PNg=xxx|Rn=xxxxx|Zt=xxxx|N=x
			ctx->imm4 = (insword>>16)&15;
			ctx->msz = (insword>>13)&3;
			ctx->PNg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = (insword>>1)&15;
			ctx->N = insword&1;
			break;
		case ENC_LD1B_MZ_P_BI_4:
		case ENC_LD1D_MZ_P_BI_4:
		case ENC_LD1H_MZ_P_BI_4:
		case ENC_LD1W_MZ_P_BI_4:
		case ENC_LDNT1B_MZ_P_BI_4:
		case ENC_LDNT1D_MZ_P_BI_4:
		case ENC_LDNT1H_MZ_P_BI_4:
		case ENC_LDNT1W_MZ_P_BI_4:
		case ENC_ST1B_MZ_P_BI_4:
		case ENC_ST1D_MZ_P_BI_4:
		case ENC_ST1H_MZ_P_BI_4:
		case ENC_ST1W_MZ_P_BI_4:
		case ENC_STNT1B_MZ_P_BI_4:
		case ENC_STNT1D_MZ_P_BI_4:
		case ENC_STNT1H_MZ_P_BI_4:
		case ENC_STNT1W_MZ_P_BI_4:
			// x|xx|xxxx|xx|xxx|imm4=xxxx|x|msz=xx|PNg=xxx|Rn=xxxxx|Zt=xxx|x|N=x
			ctx->imm4 = (insword>>16)&15;
			ctx->msz = (insword>>13)&3;
			ctx->PNg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = (insword>>2)&7;
			ctx->N = insword&1;
			break;
		case ENC_LD1B_MZX_P_BR_2X8:
		case ENC_LD1D_MZX_P_BR_2X8:
		case ENC_LD1H_MZX_P_BR_2X8:
		case ENC_LD1W_MZX_P_BR_2X8:
		case ENC_LDNT1B_MZX_P_BR_2X8:
		case ENC_LDNT1D_MZX_P_BR_2X8:
		case ENC_LDNT1H_MZX_P_BR_2X8:
		case ENC_LDNT1W_MZX_P_BR_2X8:
		case ENC_ST1B_MZX_P_BR_2X8:
		case ENC_ST1D_MZX_P_BR_2X8:
		case ENC_ST1H_MZX_P_BR_2X8:
		case ENC_ST1W_MZX_P_BR_2X8:
		case ENC_STNT1B_MZX_P_BR_2X8:
		case ENC_STNT1D_MZX_P_BR_2X8:
		case ENC_STNT1H_MZX_P_BR_2X8:
		case ENC_STNT1W_MZX_P_BR_2X8:
			// x|xx|xxxx|xx|xx|Rm=xxxxx|x|msz=xx|PNg=xxx|Rn=xxxxx|T=x|N=x|Zt=xxx
			ctx->Rm = (insword>>16)&0x1f;
			ctx->msz = (insword>>13)&3;
			ctx->PNg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->T = (insword>>4)&1;
			ctx->N = (insword>>3)&1;
			ctx->Zt = insword&7;
			break;
		case ENC_LD1B_MZX_P_BR_4X4:
		case ENC_LD1D_MZX_P_BR_4X4:
		case ENC_LD1H_MZX_P_BR_4X4:
		case ENC_LD1W_MZX_P_BR_4X4:
		case ENC_LDNT1B_MZX_P_BR_4X4:
		case ENC_LDNT1D_MZX_P_BR_4X4:
		case ENC_LDNT1H_MZX_P_BR_4X4:
		case ENC_LDNT1W_MZX_P_BR_4X4:
		case ENC_ST1B_MZX_P_BR_4X4:
		case ENC_ST1D_MZX_P_BR_4X4:
		case ENC_ST1H_MZX_P_BR_4X4:
		case ENC_ST1W_MZX_P_BR_4X4:
		case ENC_STNT1B_MZX_P_BR_4X4:
		case ENC_STNT1D_MZX_P_BR_4X4:
		case ENC_STNT1H_MZX_P_BR_4X4:
		case ENC_STNT1W_MZX_P_BR_4X4:
			// x|xx|xxxx|xx|xx|Rm=xxxxx|x|msz=xx|PNg=xxx|Rn=xxxxx|T=x|N=x|x|Zt=xx
			ctx->Rm = (insword>>16)&0x1f;
			ctx->msz = (insword>>13)&3;
			ctx->PNg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->T = (insword>>4)&1;
			ctx->N = (insword>>3)&1;
			ctx->Zt = insword&3;
			break;
		case ENC_LD1B_MZ_P_BR_2:
		case ENC_LD1D_MZ_P_BR_2:
		case ENC_LD1H_MZ_P_BR_2:
		case ENC_LD1W_MZ_P_BR_2:
		case ENC_LDNT1B_MZ_P_BR_2:
		case ENC_LDNT1D_MZ_P_BR_2:
		case ENC_LDNT1H_MZ_P_BR_2:
		case ENC_LDNT1W_MZ_P_BR_2:
		case ENC_ST1B_MZ_P_BR_2:
		case ENC_ST1D_MZ_P_BR_2:
		case ENC_ST1H_MZ_P_BR_2:
		case ENC_ST1W_MZ_P_BR_2:
		case ENC_STNT1B_MZ_P_BR_2:
		case ENC_STNT1D_MZ_P_BR_2:
		case ENC_STNT1H_MZ_P_BR_2:
		case ENC_STNT1W_MZ_P_BR_2:
			// x|xx|xxxx|xx|xx|Rm=xxxxx|x|msz=xx|PNg=xxx|Rn=xxxxx|Zt=xxxx|N=x
			ctx->Rm = (insword>>16)&0x1f;
			ctx->msz = (insword>>13)&3;
			ctx->PNg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = (insword>>1)&15;
			ctx->N = insword&1;
			break;
		case ENC_LD1B_MZ_P_BR_4:
		case ENC_LD1D_MZ_P_BR_4:
		case ENC_LD1H_MZ_P_BR_4:
		case ENC_LD1W_MZ_P_BR_4:
		case ENC_LDNT1B_MZ_P_BR_4:
		case ENC_LDNT1D_MZ_P_BR_4:
		case ENC_LDNT1H_MZ_P_BR_4:
		case ENC_LDNT1W_MZ_P_BR_4:
		case ENC_ST1B_MZ_P_BR_4:
		case ENC_ST1D_MZ_P_BR_4:
		case ENC_ST1H_MZ_P_BR_4:
		case ENC_ST1W_MZ_P_BR_4:
		case ENC_STNT1B_MZ_P_BR_4:
		case ENC_STNT1D_MZ_P_BR_4:
		case ENC_STNT1H_MZ_P_BR_4:
		case ENC_STNT1W_MZ_P_BR_4:
			// x|xx|xxxx|xx|xx|Rm=xxxxx|x|msz=xx|PNg=xxx|Rn=xxxxx|Zt=xxx|x|N=x
			ctx->Rm = (insword>>16)&0x1f;
			ctx->msz = (insword>>13)&3;
			ctx->PNg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = (insword>>2)&7;
			ctx->N = insword&1;
			break;
		case ENC_LUTI6_Z_ZTZ_:
			// x|xx|xxxx|xx|x|xxx|opc=xxxxx|size=xx|opc2=xx|Zn=xxxxx|Zd=xxxxx
			ctx->opc = (insword>>14)&0x1f;
			ctx->size = (insword>>12)&3;
			ctx->opc2 = (insword>>10)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_LUTI4_MZ4_ZTMZ2_1:
			// x|xx|xxxx|xx|x|xxx|xxxxx|size=xx|opc=xx|Zn=xxxx|x|Zd=xxx|xx
			ctx->size = (insword>>12)&3;
			ctx->opc = (insword>>10)&3;
			ctx->Zn = (insword>>6)&15;
			ctx->Zd = (insword>>2)&7;
			break;
		case ENC_LUTI6_MZ4_ZTMZ3_1:
			// x|xx|xxxx|xx|x|xxx|xxxxx|size=xx|opc=xx|Zn=xxx|x|x|Zd=xxx|xx
			ctx->size = (insword>>12)&3;
			ctx->opc = (insword>>10)&3;
			ctx->Zn = (insword>>7)&7;
			ctx->Zd = (insword>>2)&7;
			break;
		case ENC_LUTI4_MZ4_ZTZ_1:
			// x|xx|xxxx|xx|x|xxx|xx|i1=x|xx|size=xx|opc2=xx|Zn=xxxxx|Zd=xxx|xx
			ctx->i1 = (insword>>16)&1;
			ctx->size = (insword>>12)&3;
			ctx->opc2 = (insword>>10)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = (insword>>2)&7;
			break;
		case ENC_LUTI4_MZ2_ZTZ_1:
			// x|xx|xxxx|xx|x|xxx|xx|i2=xx|x|size=xx|opc2=xx|Zn=xxxxx|Zd=xxxx|x
			ctx->i2 = (insword>>15)&3;
			ctx->size = (insword>>12)&3;
			ctx->opc2 = (insword>>10)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = (insword>>1)&15;
			break;
		case ENC_LUTI4_Z_ZTZ_:
			// x|xx|xxxx|xx|x|xxx|xx|i3=xxx|size=xx|opc2=xx|Zn=xxxxx|Zd=xxxxx
			ctx->i3 = (insword>>14)&7;
			ctx->size = (insword>>12)&3;
			ctx->opc2 = (insword>>10)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_LUTI2_MZ4_ZTZ_1:
			// x|xx|xxxx|xx|x|xxx|x|i2=xx|xx|size=xx|opc2=xx|Zn=xxxxx|Zd=xxx|xx
			ctx->i2 = (insword>>16)&3;
			ctx->size = (insword>>12)&3;
			ctx->opc2 = (insword>>10)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = (insword>>2)&7;
			break;
		case ENC_LUTI2_MZ2_ZTZ_1:
			// x|xx|xxxx|xx|x|xxx|x|i3=xxx|x|size=xx|opc2=xx|Zn=xxxxx|Zd=xxxx|x
			ctx->i3 = (insword>>15)&7;
			ctx->size = (insword>>12)&3;
			ctx->opc2 = (insword>>10)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = (insword>>1)&15;
			break;
		case ENC_LUTI2_Z_ZTZ_:
			// x|xx|xxxx|xx|x|xxx|x|i4=xxxx|size=xx|opc2=xx|Zn=xxxxx|Zd=xxxxx
			ctx->i4 = (insword>>14)&15;
			ctx->size = (insword>>12)&3;
			ctx->opc2 = (insword>>10)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SMLAL_ZA_ZZV_1:
		case ENC_SMLSL_ZA_ZZV_1:
		case ENC_UMLAL_ZA_ZZV_1:
		case ENC_UMLSL_ZA_ZZV_1:
			// x|xx|xxxx|xx|x|xx|Zm=xxxx|x|Rv=xx|xxx|Zn=xxxxx|U=x|S=x|off3=xxx
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->U = (insword>>4)&1;
			ctx->S = (insword>>3)&1;
			ctx->off3 = insword&7;
			break;
		case ENC_SMLAL_ZA_ZZV_2X1:
		case ENC_SMLAL_ZA_ZZV_4X1:
		case ENC_SMLSL_ZA_ZZV_2X1:
		case ENC_SMLSL_ZA_ZZV_4X1:
		case ENC_UMLAL_ZA_ZZV_2X1:
		case ENC_UMLAL_ZA_ZZV_4X1:
		case ENC_UMLSL_ZA_ZZV_2X1:
		case ENC_UMLSL_ZA_ZZV_4X1:
			// x|xx|xxxx|xx|x|xx|Zm=xxxx|x|Rv=xx|xxx|Zn=xxxxx|U=x|S=x|op=x|off2=xx
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->U = (insword>>4)&1;
			ctx->S = (insword>>3)&1;
			ctx->op = (insword>>2)&1;
			ctx->off2 = insword&3;
			break;
		case ENC_SDOT_ZA32_ZZV_2X1:
		case ENC_SDOT_ZA32_ZZV_4X1:
		case ENC_SUDOT_ZA_ZZV_S2X1:
		case ENC_SUDOT_ZA_ZZV_S4X1:
		case ENC_UDOT_ZA32_ZZV_2X1:
		case ENC_UDOT_ZA32_ZZV_4X1:
		case ENC_USDOT_ZA_ZZV_S2X1:
		case ENC_USDOT_ZA_ZZV_S4X1:
			// x|xx|xxxx|xx|x|xx|Zm=xxxx|x|Rv=xx|xxx|Zn=xxxxx|U=x|x|off3=xxx
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->U = (insword>>4)&1;
			ctx->off3 = insword&7;
			break;
		case ENC_BFMLAL_ZA_ZZV_2X1:
		case ENC_BFMLAL_ZA_ZZV_4X1:
		case ENC_BFMLSL_ZA_ZZV_2X1:
		case ENC_BFMLSL_ZA_ZZV_4X1:
		case ENC_FMLAL_ZA_Z8Z8V_2X1:
		case ENC_FMLAL_ZA_Z8Z8V_4X1:
		case ENC_FMLAL_ZA_ZZV_2X1:
		case ENC_FMLAL_ZA_ZZV_4X1:
		case ENC_FMLSL_ZA_ZZV_2X1:
		case ENC_FMLSL_ZA_ZZV_4X1:
			// x|xx|xxxx|xx|x|xx|Zm=xxxx|x|Rv=xx|xxx|Zn=xxxxx|op=x|S=x|o2=x|off2=xx
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->op = (insword>>4)&1;
			ctx->S = (insword>>3)&1;
			ctx->o2 = (insword>>2)&1;
			ctx->off2 = insword&3;
			break;
		case ENC_BFMLAL_ZA_ZZV_1:
		case ENC_BFMLSL_ZA_ZZV_1:
		case ENC_FMLAL_ZA_ZZV_1:
		case ENC_FMLSL_ZA_ZZV_1:
			// x|xx|xxxx|xx|x|xx|Zm=xxxx|x|Rv=xx|xxx|Zn=xxxxx|op=x|S=x|off3=xxx
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->op = (insword>>4)&1;
			ctx->S = (insword>>3)&1;
			ctx->off3 = insword&7;
			break;
		case ENC_BFDOT_ZA_ZZV_2X1:
		case ENC_BFDOT_ZA_ZZV_4X1:
		case ENC_FDOT_ZA32_Z8Z8V_2X1:
		case ENC_FDOT_ZA32_Z8Z8V_4X1:
		case ENC_FDOT_ZA_Z8Z8V_2X1:
		case ENC_FDOT_ZA_Z8Z8V_4X1:
		case ENC_FDOT_ZA_ZZV_2X1:
		case ENC_FDOT_ZA_ZZV_4X1:
			// x|xx|xxxx|xx|x|xx|Zm=xxxx|x|Rv=xx|xxx|Zn=xxxxx|opc=xx|off3=xxx
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->opc = (insword>>3)&3;
			ctx->off3 = insword&7;
			break;
		case ENC_FMLALL_ZA32_Z8Z8V_1:
			// x|xx|xxxx|xx|x|xx|Zm=xxxx|x|Rv=xx|xxx|Zn=xxxxx|xxx|off2=xx
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->off2 = insword&3;
			break;
		case ENC_FMLALL_ZA32_Z8Z8V_2X1:
		case ENC_FMLALL_ZA32_Z8Z8V_4X1:
			// x|xx|xxxx|xx|x|xx|Zm=xxxx|x|Rv=xx|xxx|Zn=xxxxx|xxx|x|o1=x
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->o1 = insword&1;
			break;
		case ENC_FMLAL_ZA_Z8Z8V_1:
			// x|xx|xxxx|xx|x|xx|Zm=xxxx|x|Rv=xx|xxx|Zn=xxxxx|xx|off3=xxx
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->off3 = insword&7;
			break;
		case ENC_BFDOT_ZA_ZZW_2X2:
		case ENC_FDOT_ZA32_Z8Z8W_2X2:
		case ENC_FDOT_ZA_Z8Z8W_2X2:
		case ENC_FDOT_ZA_ZZW_2X2:
			// x|xx|xxxx|xx|x|x|Zm=xxxx|xx|Rv=xx|xxx|Zn=xxxx|opc=xx|x|off3=xxx
			ctx->Zm = (insword>>17)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>6)&15;
			ctx->opc = (insword>>4)&3;
			ctx->off3 = insword&7;
			break;
		case ENC_SMLAL_ZA_ZZW_2X2:
		case ENC_SMLSL_ZA_ZZW_2X2:
		case ENC_UMLAL_ZA_ZZW_2X2:
		case ENC_UMLSL_ZA_ZZW_2X2:
			// x|xx|xxxx|xx|x|x|Zm=xxxx|xx|Rv=xx|xxx|Zn=xxxx|x|U=x|S=x|x|off2=xx
			ctx->Zm = (insword>>17)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>6)&15;
			ctx->U = (insword>>4)&1;
			ctx->S = (insword>>3)&1;
			ctx->off2 = insword&3;
			break;
		case ENC_SDOT_ZA32_ZZW_2X2:
		case ENC_UDOT_ZA32_ZZW_2X2:
			// x|xx|xxxx|xx|x|x|Zm=xxxx|xx|Rv=xx|xxx|Zn=xxxx|x|U=x|x|off3=xxx
			ctx->Zm = (insword>>17)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>6)&15;
			ctx->U = (insword>>4)&1;
			ctx->off3 = insword&7;
			break;
		case ENC_BFMLAL_ZA_ZZW_2X2:
		case ENC_BFMLSL_ZA_ZZW_2X2:
		case ENC_FMLAL_ZA_ZZW_2X2:
		case ENC_FMLSL_ZA_ZZW_2X2:
			// x|xx|xxxx|xx|x|x|Zm=xxxx|xx|Rv=xx|xxx|Zn=xxxx|x|op=x|S=x|x|off2=xx
			ctx->Zm = (insword>>17)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>6)&15;
			ctx->op = (insword>>4)&1;
			ctx->S = (insword>>3)&1;
			ctx->off2 = insword&3;
			break;
		case ENC_FMLAL_ZA_Z8Z8W_2X2:
			// x|xx|xxxx|xx|x|x|Zm=xxxx|xx|Rv=xx|xxx|Zn=xxxx|x|xxx|off2=xx
			ctx->Zm = (insword>>17)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>6)&15;
			ctx->off2 = insword&3;
			break;
		case ENC_FMLALL_ZA32_Z8Z8W_2X2:
			// x|xx|xxxx|xx|x|x|Zm=xxxx|xx|Rv=xx|xxx|Zn=xxxx|x|xxx|x|o1=x
			ctx->Zm = (insword>>17)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>6)&15;
			ctx->o1 = insword&1;
			break;
		case ENC_USDOT_ZA_ZZW_S2X2:
			// x|xx|xxxx|xx|x|x|Zm=xxxx|xx|Rv=xx|xxx|Zn=xxxx|x|xx|off3=xxx
			ctx->Zm = (insword>>17)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>6)&15;
			ctx->off3 = insword&7;
			break;
		case ENC_SMLAL_ZA_ZZW_4X4:
		case ENC_SMLSL_ZA_ZZW_4X4:
		case ENC_UMLAL_ZA_ZZW_4X4:
		case ENC_UMLSL_ZA_ZZW_4X4:
			// x|xx|xxxx|xx|x|x|Zm=xxx|x|xx|Rv=xx|xxx|Zn=xxx|xx|U=x|S=x|x|off2=xx
			ctx->Zm = (insword>>18)&7;
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>7)&7;
			ctx->U = (insword>>4)&1;
			ctx->S = (insword>>3)&1;
			ctx->off2 = insword&3;
			break;
		case ENC_SDOT_ZA32_ZZW_4X4:
		case ENC_UDOT_ZA32_ZZW_4X4:
			// x|xx|xxxx|xx|x|x|Zm=xxx|x|xx|Rv=xx|xxx|Zn=xxx|xx|U=x|x|off3=xxx
			ctx->Zm = (insword>>18)&7;
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>7)&7;
			ctx->U = (insword>>4)&1;
			ctx->off3 = insword&7;
			break;
		case ENC_BFMLAL_ZA_ZZW_4X4:
		case ENC_BFMLSL_ZA_ZZW_4X4:
		case ENC_FMLAL_ZA_ZZW_4X4:
		case ENC_FMLSL_ZA_ZZW_4X4:
			// x|xx|xxxx|xx|x|x|Zm=xxx|x|xx|Rv=xx|xxx|Zn=xxx|xx|op=x|S=x|x|off2=xx
			ctx->Zm = (insword>>18)&7;
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>7)&7;
			ctx->op = (insword>>4)&1;
			ctx->S = (insword>>3)&1;
			ctx->off2 = insword&3;
			break;
		case ENC_FMLAL_ZA_Z8Z8W_4X4:
			// x|xx|xxxx|xx|x|x|Zm=xxx|x|xx|Rv=xx|xxx|Zn=xxx|xx|xxx|off2=xx
			ctx->Zm = (insword>>18)&7;
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>7)&7;
			ctx->off2 = insword&3;
			break;
		case ENC_FMLALL_ZA32_Z8Z8W_4X4:
			// x|xx|xxxx|xx|x|x|Zm=xxx|x|xx|Rv=xx|xxx|Zn=xxx|xx|xxx|x|o1=x
			ctx->Zm = (insword>>18)&7;
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>7)&7;
			ctx->o1 = insword&1;
			break;
		case ENC_USDOT_ZA_ZZW_S4X4:
			// x|xx|xxxx|xx|x|x|Zm=xxx|x|xx|Rv=xx|xxx|Zn=xxx|xx|xx|off3=xxx
			ctx->Zm = (insword>>18)&7;
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>7)&7;
			ctx->off3 = insword&7;
			break;
		case ENC_BFDOT_ZA_ZZW_4X4:
		case ENC_FDOT_ZA32_Z8Z8W_4X4:
		case ENC_FDOT_ZA_Z8Z8W_4X4:
		case ENC_FDOT_ZA_ZZW_4X4:
			// x|xx|xxxx|xx|x|x|Zm=xxx|x|xx|Rv=xx|xxx|Zn=xxx|x|opc=xx|x|off3=xxx
			ctx->Zm = (insword>>18)&7;
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>7)&7;
			ctx->opc = (insword>>4)&3;
			ctx->off3 = insword&7;
			break;
		case ENC_LD1D_ZA_P_RRR_:
		case ENC_ST1D_ZA_P_RRR_:
			// x|xx|xxxx|x|msz=xx|x|Rm=xxxxx|V=x|Rs=xx|Pg=xxx|Rn=xxxxx|x|ZAt=xxx|o1=x
			ctx->msz = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->ZAt = (insword>>1)&7;
			ctx->o1 = insword&1;
			break;
		case ENC_LD1W_ZA_P_RRR_:
		case ENC_ST1W_ZA_P_RRR_:
			// x|xx|xxxx|x|msz=xx|x|Rm=xxxxx|V=x|Rs=xx|Pg=xxx|Rn=xxxxx|x|ZAt=xx|off2=xx
			ctx->msz = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->ZAt = (insword>>2)&3;
			ctx->off2 = insword&3;
			break;
		case ENC_LD1H_ZA_P_RRR_:
		case ENC_ST1H_ZA_P_RRR_:
			// x|xx|xxxx|x|msz=xx|x|Rm=xxxxx|V=x|Rs=xx|Pg=xxx|Rn=xxxxx|x|ZAt=x|off3=xxx
			ctx->msz = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->ZAt = (insword>>3)&1;
			ctx->off3 = insword&7;
			break;
		case ENC_LD1B_ZA_P_RRR_:
		case ENC_ST1B_ZA_P_RRR_:
			// x|xx|xxxx|x|msz=xx|x|Rm=xxxxx|V=x|Rs=xx|Pg=xxx|Rn=xxxxx|x|off4=xxxx
			ctx->msz = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->off4 = insword&15;
			break;
		case ENC_BF1CVT_MZ2_Z8_:
		case ENC_BF2CVT_MZ2_Z8_:
		case ENC_BF1CVTL_MZ2_Z8_:
		case ENC_BF2CVTL_MZ2_Z8_:
		case ENC_F1CVT_MZ2_Z8_:
		case ENC_F2CVT_MZ2_Z8_:
		case ENC_F1CVTL_MZ2_Z8_:
		case ENC_F2CVTL_MZ2_Z8_:
			// x|xx|xxxx|x|opc=xx|x|xxx|xx|xxxxxx|Zn=xxxxx|Zd=xxxx|L=x
			ctx->opc = (insword>>22)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = (insword>>1)&15;
			ctx->L = insword&1;
			break;
		case ENC_MOV_ZA_P_RZ_Q_MOVA_ZA_P_RZ_Q:
		case ENC_MOVA_ZA_P_RZ_Q:
			// x|xx|xxxx|x|size=xx|xxx|x|x|Q=x|V=x|Rs=xx|Pg=xxx|Zn=xxxxx|x|ZAd=xxxx
			ctx->size = (insword>>22)&3;
			ctx->Q = (insword>>16)&1;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->ZAd = insword&15;
			break;
		case ENC_MOV_ZA_P_RZ_D_MOVA_ZA_P_RZ_D:
		case ENC_MOVA_ZA_P_RZ_D:
			// x|xx|xxxx|x|size=xx|xxx|x|x|Q=x|V=x|Rs=xx|Pg=xxx|Zn=xxxxx|x|ZAd=xxx|o1=x
			ctx->size = (insword>>22)&3;
			ctx->Q = (insword>>16)&1;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->ZAd = (insword>>1)&7;
			ctx->o1 = insword&1;
			break;
		case ENC_MOV_ZA_P_RZ_W_MOVA_ZA_P_RZ_W:
		case ENC_MOVA_ZA_P_RZ_W:
			// x|xx|xxxx|x|size=xx|xxx|x|x|Q=x|V=x|Rs=xx|Pg=xxx|Zn=xxxxx|x|ZAd=xx|off2=xx
			ctx->size = (insword>>22)&3;
			ctx->Q = (insword>>16)&1;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->ZAd = (insword>>2)&3;
			ctx->off2 = insword&3;
			break;
		case ENC_MOV_ZA_P_RZ_H_MOVA_ZA_P_RZ_H:
		case ENC_MOVA_ZA_P_RZ_H:
			// x|xx|xxxx|x|size=xx|xxx|x|x|Q=x|V=x|Rs=xx|Pg=xxx|Zn=xxxxx|x|ZAd=x|off3=xxx
			ctx->size = (insword>>22)&3;
			ctx->Q = (insword>>16)&1;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->ZAd = (insword>>3)&1;
			ctx->off3 = insword&7;
			break;
		case ENC_MOV_ZA_P_RZ_B_MOVA_ZA_P_RZ_B:
		case ENC_MOVA_ZA_P_RZ_B:
			// x|xx|xxxx|x|size=xx|xxx|x|x|Q=x|V=x|Rs=xx|Pg=xxx|Zn=xxxxx|x|off4=xxxx
			ctx->size = (insword>>22)&3;
			ctx->Q = (insword>>16)&1;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->off4 = insword&15;
			break;
		case ENC_MOV_Z_P_RZA_Q_MOVA_Z_P_RZA_Q:
		case ENC_MOVA_Z_P_RZA_Q:
			// x|xx|xxxx|x|size=xx|xxx|x|x|Q=x|V=x|Rs=xx|Pg=xxx|x|ZAn=xxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Q = (insword>>16)&1;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->ZAn = (insword>>5)&15;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_MOV_Z_P_RZA_D_MOVA_Z_P_RZA_D:
		case ENC_MOVA_Z_P_RZA_D:
			// x|xx|xxxx|x|size=xx|xxx|x|x|Q=x|V=x|Rs=xx|Pg=xxx|x|ZAn=xxx|o1=x|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Q = (insword>>16)&1;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->ZAn = (insword>>6)&7;
			ctx->o1 = (insword>>5)&1;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_MOV_Z_P_RZA_W_MOVA_Z_P_RZA_W:
		case ENC_MOVA_Z_P_RZA_W:
			// x|xx|xxxx|x|size=xx|xxx|x|x|Q=x|V=x|Rs=xx|Pg=xxx|x|ZAn=xx|off2=xx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Q = (insword>>16)&1;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->ZAn = (insword>>7)&3;
			ctx->off2 = (insword>>5)&3;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_MOV_Z_P_RZA_H_MOVA_Z_P_RZA_H:
		case ENC_MOVA_Z_P_RZA_H:
			// x|xx|xxxx|x|size=xx|xxx|x|x|Q=x|V=x|Rs=xx|Pg=xxx|x|ZAn=x|off3=xxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Q = (insword>>16)&1;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->ZAn = (insword>>8)&1;
			ctx->off3 = (insword>>5)&7;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_MOV_Z_P_RZA_B_MOVA_Z_P_RZA_B:
		case ENC_MOVA_Z_P_RZA_B:
			// x|xx|xxxx|x|size=xx|xxx|x|x|Q=x|V=x|Rs=xx|Pg=xxx|x|off4=xxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Q = (insword>>16)&1;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->off4 = (insword>>5)&15;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_MOVAZ_Z_RZA_Q:
			// x|xx|xxxx|x|size=xx|xxx|x|x|Q=x|V=x|Rs=xx|xxx|x|ZAn=xxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Q = (insword>>16)&1;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->ZAn = (insword>>5)&15;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_MOVAZ_Z_RZA_D:
			// x|xx|xxxx|x|size=xx|xxx|x|x|Q=x|V=x|Rs=xx|xxx|x|ZAn=xxx|o1=x|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Q = (insword>>16)&1;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->ZAn = (insword>>6)&7;
			ctx->o1 = (insword>>5)&1;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_MOVAZ_Z_RZA_W:
			// x|xx|xxxx|x|size=xx|xxx|x|x|Q=x|V=x|Rs=xx|xxx|x|ZAn=xx|off2=xx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Q = (insword>>16)&1;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->ZAn = (insword>>7)&3;
			ctx->off2 = (insword>>5)&3;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_MOVAZ_Z_RZA_H:
			// x|xx|xxxx|x|size=xx|xxx|x|x|Q=x|V=x|Rs=xx|xxx|x|ZAn=x|off3=xxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Q = (insword>>16)&1;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->ZAn = (insword>>8)&1;
			ctx->off3 = (insword>>5)&7;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_MOVAZ_Z_RZA_B:
			// x|xx|xxxx|x|size=xx|xxx|x|x|Q=x|V=x|Rs=xx|xxx|x|off4=xxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Q = (insword>>16)&1;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->off4 = (insword>>5)&15;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_MOV_ZA2_Z_D1_MOVA_ZA2_Z_D1:
		case ENC_MOVA_ZA2_Z_D1:
			// x|xx|xxxx|x|size=xx|xxx|x|x|x|V=x|Rs=xx|xxx|Zn=xxxx|x|x|x|ZAd=xxx
			ctx->size = (insword>>22)&3;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Zn = (insword>>6)&15;
			ctx->ZAd = insword&7;
			break;
		case ENC_MOV_ZA2_Z_W1_MOVA_ZA2_Z_W1:
		case ENC_MOVA_ZA2_Z_W1:
			// x|xx|xxxx|x|size=xx|xxx|x|x|x|V=x|Rs=xx|xxx|Zn=xxxx|x|x|x|ZAd=xx|o1=x
			ctx->size = (insword>>22)&3;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Zn = (insword>>6)&15;
			ctx->ZAd = (insword>>1)&3;
			ctx->o1 = insword&1;
			break;
		case ENC_MOV_ZA2_Z_H1_MOVA_ZA2_Z_H1:
		case ENC_MOVA_ZA2_Z_H1:
			// x|xx|xxxx|x|size=xx|xxx|x|x|x|V=x|Rs=xx|xxx|Zn=xxxx|x|x|x|ZAd=x|off2=xx
			ctx->size = (insword>>22)&3;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Zn = (insword>>6)&15;
			ctx->ZAd = (insword>>2)&1;
			ctx->off2 = insword&3;
			break;
		case ENC_MOV_ZA2_Z_B1_MOVA_ZA2_Z_B1:
		case ENC_MOVA_ZA2_Z_B1:
			// x|xx|xxxx|x|size=xx|xxx|x|x|x|V=x|Rs=xx|xxx|Zn=xxxx|x|x|x|off3=xxx
			ctx->size = (insword>>22)&3;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Zn = (insword>>6)&15;
			ctx->off3 = insword&7;
			break;
		case ENC_MOV_ZA4_Z_D1_MOVA_ZA4_Z_D1:
		case ENC_MOVA_ZA4_Z_D1:
			// x|xx|xxxx|x|size=xx|xxx|x|x|x|V=x|Rs=xx|xxx|Zn=xxx|xx|x|x|ZAd=xxx
			ctx->size = (insword>>22)&3;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Zn = (insword>>7)&7;
			ctx->ZAd = insword&7;
			break;
		case ENC_MOV_ZA4_Z_W1_MOVA_ZA4_Z_W1:
		case ENC_MOVA_ZA4_Z_W1:
			// x|xx|xxxx|x|size=xx|xxx|x|x|x|V=x|Rs=xx|xxx|Zn=xxx|xx|x|x|x|ZAd=xx
			ctx->size = (insword>>22)&3;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Zn = (insword>>7)&7;
			ctx->ZAd = insword&3;
			break;
		case ENC_MOV_ZA4_Z_H1_MOVA_ZA4_Z_H1:
		case ENC_MOVA_ZA4_Z_H1:
			// x|xx|xxxx|x|size=xx|xxx|x|x|x|V=x|Rs=xx|xxx|Zn=xxx|xx|x|x|x|ZAd=x|o1=x
			ctx->size = (insword>>22)&3;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Zn = (insword>>7)&7;
			ctx->ZAd = (insword>>1)&1;
			ctx->o1 = insword&1;
			break;
		case ENC_MOV_ZA4_Z_B1_MOVA_ZA4_Z_B1:
		case ENC_MOVA_ZA4_Z_B1:
			// x|xx|xxxx|x|size=xx|xxx|x|x|x|V=x|Rs=xx|xxx|Zn=xxx|xx|x|x|x|off2=xx
			ctx->size = (insword>>22)&3;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Zn = (insword>>7)&7;
			ctx->off2 = insword&3;
			break;
		case ENC_MOV_MZ2_ZA_D1_MOVA_MZ2_ZA_D1:
		case ENC_MOVA_MZ2_ZA_D1:
		case ENC_MOVAZ_MZ2_ZA_D1:
			// x|xx|xxxx|x|size=xx|xxx|x|x|x|V=x|Rs=xx|xxx|xx|ZAn=xxx|Zd=xxxx|x
			ctx->size = (insword>>22)&3;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->ZAn = (insword>>5)&7;
			ctx->Zd = (insword>>1)&15;
			break;
		case ENC_MOV_MZ4_ZA_D1_MOVA_MZ4_ZA_D1:
		case ENC_MOVA_MZ4_ZA_D1:
		case ENC_MOVAZ_MZ4_ZA_D1:
			// x|xx|xxxx|x|size=xx|xxx|x|x|x|V=x|Rs=xx|xxx|xx|ZAn=xxx|Zd=xxx|xx
			ctx->size = (insword>>22)&3;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->ZAn = (insword>>5)&7;
			ctx->Zd = (insword>>2)&7;
			break;
		case ENC_MOV_MZ2_ZA_W1_MOVA_MZ2_ZA_W1:
		case ENC_MOVA_MZ2_ZA_W1:
		case ENC_MOVAZ_MZ2_ZA_W1:
			// x|xx|xxxx|x|size=xx|xxx|x|x|x|V=x|Rs=xx|xxx|xx|ZAn=xx|o1=x|Zd=xxxx|x
			ctx->size = (insword>>22)&3;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->ZAn = (insword>>6)&3;
			ctx->o1 = (insword>>5)&1;
			ctx->Zd = (insword>>1)&15;
			break;
		case ENC_MOV_MZ2_ZA_H1_MOVA_MZ2_ZA_H1:
		case ENC_MOVA_MZ2_ZA_H1:
		case ENC_MOVAZ_MZ2_ZA_H1:
			// x|xx|xxxx|x|size=xx|xxx|x|x|x|V=x|Rs=xx|xxx|xx|ZAn=x|off2=xx|Zd=xxxx|x
			ctx->size = (insword>>22)&3;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->ZAn = (insword>>7)&1;
			ctx->off2 = (insword>>5)&3;
			ctx->Zd = (insword>>1)&15;
			break;
		case ENC_MOV_MZ2_ZA_B1_MOVA_MZ2_ZA_B1:
		case ENC_MOVA_MZ2_ZA_B1:
		case ENC_MOVAZ_MZ2_ZA_B1:
			// x|xx|xxxx|x|size=xx|xxx|x|x|x|V=x|Rs=xx|xxx|xx|off3=xxx|Zd=xxxx|x
			ctx->size = (insword>>22)&3;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->off3 = (insword>>5)&7;
			ctx->Zd = (insword>>1)&15;
			break;
		case ENC_MOV_MZ4_ZA_W1_MOVA_MZ4_ZA_W1:
		case ENC_MOVA_MZ4_ZA_W1:
		case ENC_MOVAZ_MZ4_ZA_W1:
			// x|xx|xxxx|x|size=xx|xxx|x|x|x|V=x|Rs=xx|xxx|xx|x|ZAn=xx|Zd=xxx|xx
			ctx->size = (insword>>22)&3;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->ZAn = (insword>>5)&3;
			ctx->Zd = (insword>>2)&7;
			break;
		case ENC_MOV_MZ4_ZA_H1_MOVA_MZ4_ZA_H1:
		case ENC_MOVA_MZ4_ZA_H1:
		case ENC_MOVAZ_MZ4_ZA_H1:
			// x|xx|xxxx|x|size=xx|xxx|x|x|x|V=x|Rs=xx|xxx|xx|x|ZAn=x|o1=x|Zd=xxx|xx
			ctx->size = (insword>>22)&3;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->ZAn = (insword>>6)&1;
			ctx->o1 = (insword>>5)&1;
			ctx->Zd = (insword>>2)&7;
			break;
		case ENC_MOV_MZ4_ZA_B1_MOVA_MZ4_ZA_B1:
		case ENC_MOVA_MZ4_ZA_B1:
		case ENC_MOVAZ_MZ4_ZA_B1:
			// x|xx|xxxx|x|size=xx|xxx|x|x|x|V=x|Rs=xx|xxx|xx|x|off2=xx|Zd=xxx|xx
			ctx->size = (insword>>22)&3;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->off2 = (insword>>5)&3;
			ctx->Zd = (insword>>2)&7;
			break;
		case ENC_SRSHL_MZ_ZZV_2X1:
		case ENC_URSHL_MZ_ZZV_2X1:
			// x|xx|xxxx|x|size=xx|xx|Zm=xxxx|xxxxx|x|xx|opc=xxx|Zdn=xxxx|U=x
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&15;
			ctx->opc = (insword>>5)&7;
			ctx->Zdn = (insword>>1)&15;
			ctx->U = insword&1;
			break;
		case ENC_SRSHL_MZ_ZZV_4X1:
		case ENC_URSHL_MZ_ZZV_4X1:
			// x|xx|xxxx|x|size=xx|xx|Zm=xxxx|xxxxx|x|xx|opc=xxx|Zdn=xxx|x|U=x
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&15;
			ctx->opc = (insword>>5)&7;
			ctx->Zdn = (insword>>2)&7;
			ctx->U = insword&1;
			break;
		case ENC_ADD_MZ_ZZV_2X1:
		case ENC_BFSCALE_MZ_ZZV_2X1:
		case ENC_FSCALE_MZ_ZZV_2X1:
		case ENC_SQDMULH_MZ_ZZV_2X1:
			// x|xx|xxxx|x|size=xx|xx|Zm=xxxx|xxxxx|x|xx|xxx|Zdn=xxxx|op=x
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&15;
			ctx->Zdn = (insword>>1)&15;
			ctx->op = insword&1;
			break;
		case ENC_ADD_MZ_ZZV_4X1:
		case ENC_BFSCALE_MZ_ZZV_4X1:
		case ENC_FSCALE_MZ_ZZV_4X1:
		case ENC_SQDMULH_MZ_ZZV_4X1:
			// x|xx|xxxx|x|size=xx|xx|Zm=xxxx|xxxxx|x|xx|xxx|Zdn=xxx|x|op=x
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&15;
			ctx->Zdn = (insword>>2)&7;
			ctx->op = insword&1;
			break;
		case ENC_SMAX_MZ_ZZV_2X1:
		case ENC_SMIN_MZ_ZZV_2X1:
		case ENC_UMAX_MZ_ZZV_2X1:
		case ENC_UMIN_MZ_ZZV_2X1:
			// x|xx|xxxx|x|size=xx|xx|Zm=xxxx|xxxxx|x|xx|xx|op=x|Zdn=xxxx|U=x
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&15;
			ctx->op = (insword>>5)&1;
			ctx->Zdn = (insword>>1)&15;
			ctx->U = insword&1;
			break;
		case ENC_BFMAX_MZ_ZZV_2X1:
		case ENC_BFMAXNM_MZ_ZZV_2X1:
		case ENC_BFMIN_MZ_ZZV_2X1:
		case ENC_BFMINNM_MZ_ZZV_2X1:
		case ENC_FMAX_MZ_ZZV_2X1:
		case ENC_FMAXNM_MZ_ZZV_2X1:
		case ENC_FMIN_MZ_ZZV_2X1:
		case ENC_FMINNM_MZ_ZZV_2X1:
			// x|xx|xxxx|x|size=xx|xx|Zm=xxxx|xxxxx|x|xx|xx|op=x|Zdn=xxxx|o2=x
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&15;
			ctx->op = (insword>>5)&1;
			ctx->Zdn = (insword>>1)&15;
			ctx->o2 = insword&1;
			break;
		case ENC_SMAX_MZ_ZZV_4X1:
		case ENC_SMIN_MZ_ZZV_4X1:
		case ENC_UMAX_MZ_ZZV_4X1:
		case ENC_UMIN_MZ_ZZV_4X1:
			// x|xx|xxxx|x|size=xx|xx|Zm=xxxx|xxxxx|x|xx|xx|op=x|Zdn=xxx|x|U=x
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&15;
			ctx->op = (insword>>5)&1;
			ctx->Zdn = (insword>>2)&7;
			ctx->U = insword&1;
			break;
		case ENC_BFMAX_MZ_ZZV_4X1:
		case ENC_BFMAXNM_MZ_ZZV_4X1:
		case ENC_BFMIN_MZ_ZZV_4X1:
		case ENC_BFMINNM_MZ_ZZV_4X1:
		case ENC_FMAX_MZ_ZZV_4X1:
		case ENC_FMAXNM_MZ_ZZV_4X1:
		case ENC_FMIN_MZ_ZZV_4X1:
		case ENC_FMINNM_MZ_ZZV_4X1:
			// x|xx|xxxx|x|size=xx|xx|Zm=xxxx|xxxxx|x|xx|xx|op=x|Zdn=xxx|x|o2=x
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&15;
			ctx->op = (insword>>5)&1;
			ctx->Zdn = (insword>>2)&7;
			ctx->o2 = insword&1;
			break;
		case ENC_SCLAMP_MZ_ZZ_2:
		case ENC_UCLAMP_MZ_ZZ_2:
			// x|xx|xxxx|x|size=xx|x|Zm=xxxxx|xxx|xxx|Zn=xxxxx|Zd=xxxx|U=x
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = (insword>>1)&15;
			ctx->U = insword&1;
			break;
		case ENC_BFCLAMP_MZ_ZZ_2:
		case ENC_FCLAMP_MZ_ZZ_2:
		case ENC_UZP_MZ_ZZ_2:
		case ENC_ZIP_MZ_ZZ_2:
			// x|xx|xxxx|x|size=xx|x|Zm=xxxxx|xxx|xxx|Zn=xxxxx|Zd=xxxx|op=x
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = (insword>>1)&15;
			ctx->op = insword&1;
			break;
		case ENC_SCLAMP_MZ_ZZ_4:
		case ENC_UCLAMP_MZ_ZZ_4:
			// x|xx|xxxx|x|size=xx|x|Zm=xxxxx|xxx|xxx|Zn=xxxxx|Zd=xxx|x|U=x
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = (insword>>2)&7;
			ctx->U = insword&1;
			break;
		case ENC_BFCLAMP_MZ_ZZ_4:
		case ENC_FCLAMP_MZ_ZZ_4:
			// x|xx|xxxx|x|size=xx|x|Zm=xxxxx|xxx|xxx|Zn=xxxxx|Zd=xxx|x|op=x
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = (insword>>2)&7;
			ctx->op = insword&1;
			break;
		case ENC_SQDMULH_MZ_ZZW_2X2:
			// x|xx|xxxx|x|size=xx|x|Zm=xxxx|xxxxxxx|xxxxx|Zdn=xxxx|op=x
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>17)&15;
			ctx->Zdn = (insword>>1)&15;
			ctx->op = insword&1;
			break;
		case ENC_SMAX_MZ_ZZW_2X2:
		case ENC_SMIN_MZ_ZZW_2X2:
		case ENC_UMAX_MZ_ZZW_2X2:
		case ENC_UMIN_MZ_ZZW_2X2:
			// x|xx|xxxx|x|size=xx|x|Zm=xxxx|xxxxxxx|xxx|opc=xx|Zdn=xxxx|U=x
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>17)&15;
			ctx->opc = (insword>>5)&3;
			ctx->Zdn = (insword>>1)&15;
			ctx->U = insword&1;
			break;
		case ENC_BFMAX_MZ_ZZW_2X2:
		case ENC_BFMAXNM_MZ_ZZW_2X2:
		case ENC_BFMIN_MZ_ZZW_2X2:
		case ENC_BFMINNM_MZ_ZZW_2X2:
		case ENC_BFSCALE_MZ_ZZW_2X2:
		case ENC_FAMAX_MZ_ZZW_2X2:
		case ENC_FAMIN_MZ_ZZW_2X2:
		case ENC_FMAX_MZ_ZZW_2X2:
		case ENC_FMAXNM_MZ_ZZW_2X2:
		case ENC_FMIN_MZ_ZZW_2X2:
		case ENC_FMINNM_MZ_ZZW_2X2:
		case ENC_FSCALE_MZ_ZZW_2X2:
			// x|xx|xxxx|x|size=xx|x|Zm=xxxx|xxxxxxx|xxx|opc=xx|Zdn=xxxx|o2=x
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>17)&15;
			ctx->opc = (insword>>5)&3;
			ctx->Zdn = (insword>>1)&15;
			ctx->o2 = insword&1;
			break;
		case ENC_SRSHL_MZ_ZZW_2X2:
		case ENC_URSHL_MZ_ZZW_2X2:
			// x|xx|xxxx|x|size=xx|x|Zm=xxxx|xxxxxxx|xx|opc=xxx|Zdn=xxxx|U=x
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>17)&15;
			ctx->opc = (insword>>5)&7;
			ctx->Zdn = (insword>>1)&15;
			ctx->U = insword&1;
			break;
		case ENC_BFMUL_MZ_ZZV_2X1:
		case ENC_BFMUL_MZ_ZZW_2X2:
		case ENC_FMUL_MZ_ZZV_2X1:
		case ENC_FMUL_MZ_ZZW_2X2:
			// x|xx|xxxx|x|size=xx|x|Zm=xxxx|x|xxxxxx|Zn=xxxx|x|Zd=xxxx|x
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>17)&15;
			ctx->Zn = (insword>>6)&15;
			ctx->Zd = (insword>>1)&15;
			break;
		case ENC_BFMUL_MZ_ZZV_4X1:
		case ENC_FMUL_MZ_ZZV_4X1:
			// x|xx|xxxx|x|size=xx|x|Zm=xxxx|x|xxxxxx|Zn=xxx|x|x|Zd=xxx|x|x
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>17)&15;
			ctx->Zn = (insword>>7)&7;
			ctx->Zd = (insword>>2)&7;
			break;
		case ENC_SEL_MZ_P_ZZ_2:
			// x|xx|xxxx|x|size=xx|x|Zm=xxxx|x|xxx|PNg=xxx|Zn=xxxx|x|Zd=xxxx|x
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>17)&15;
			ctx->PNg = (insword>>10)&7;
			ctx->Zn = (insword>>6)&15;
			ctx->Zd = (insword>>1)&15;
			break;
		case ENC_SQDMULH_MZ_ZZW_4X4:
			// x|xx|xxxx|x|size=xx|x|Zm=xxx|xxxxxxxx|xxxxx|Zdn=xxx|x|op=x
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>18)&7;
			ctx->Zdn = (insword>>2)&7;
			ctx->op = insword&1;
			break;
		case ENC_SMAX_MZ_ZZW_4X4:
		case ENC_SMIN_MZ_ZZW_4X4:
		case ENC_UMAX_MZ_ZZW_4X4:
		case ENC_UMIN_MZ_ZZW_4X4:
			// x|xx|xxxx|x|size=xx|x|Zm=xxx|xxxxxxxx|xxx|opc=xx|Zdn=xxx|x|U=x
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>18)&7;
			ctx->opc = (insword>>5)&3;
			ctx->Zdn = (insword>>2)&7;
			ctx->U = insword&1;
			break;
		case ENC_BFMAX_MZ_ZZW_4X4:
		case ENC_BFMAXNM_MZ_ZZW_4X4:
		case ENC_BFMIN_MZ_ZZW_4X4:
		case ENC_BFMINNM_MZ_ZZW_4X4:
		case ENC_BFSCALE_MZ_ZZW_4X4:
		case ENC_FAMAX_MZ_ZZW_4X4:
		case ENC_FAMIN_MZ_ZZW_4X4:
		case ENC_FMAX_MZ_ZZW_4X4:
		case ENC_FMAXNM_MZ_ZZW_4X4:
		case ENC_FMIN_MZ_ZZW_4X4:
		case ENC_FMINNM_MZ_ZZW_4X4:
		case ENC_FSCALE_MZ_ZZW_4X4:
			// x|xx|xxxx|x|size=xx|x|Zm=xxx|xxxxxxxx|xxx|opc=xx|Zdn=xxx|x|o2=x
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>18)&7;
			ctx->opc = (insword>>5)&3;
			ctx->Zdn = (insword>>2)&7;
			ctx->o2 = insword&1;
			break;
		case ENC_SRSHL_MZ_ZZW_4X4:
		case ENC_URSHL_MZ_ZZW_4X4:
			// x|xx|xxxx|x|size=xx|x|Zm=xxx|xxxxxxxx|xx|opc=xxx|Zdn=xxx|x|U=x
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>18)&7;
			ctx->opc = (insword>>5)&7;
			ctx->Zdn = (insword>>2)&7;
			ctx->U = insword&1;
			break;
		case ENC_BFMUL_MZ_ZZW_4X4:
		case ENC_FMUL_MZ_ZZW_4X4:
			// x|xx|xxxx|x|size=xx|x|Zm=xxx|xx|xxxxxx|Zn=xxx|x|x|Zd=xxx|x|x
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>18)&7;
			ctx->Zn = (insword>>7)&7;
			ctx->Zd = (insword>>2)&7;
			break;
		case ENC_SEL_MZ_P_ZZ_4:
			// x|xx|xxxx|x|size=xx|x|Zm=xxx|xx|xxx|PNg=xxx|Zn=xxx|xx|Zd=xxx|xx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>18)&7;
			ctx->PNg = (insword>>10)&7;
			ctx->Zn = (insword>>7)&7;
			ctx->Zd = (insword>>2)&7;
			break;
		case ENC_SUNPK_MZ_Z_2:
		case ENC_UUNPK_MZ_Z_2:
			// x|xx|xxxx|x|size=xx|x|xxx|xx|xxxxxx|Zn=xxxxx|Zd=xxxx|U=x
			ctx->size = (insword>>22)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = (insword>>1)&15;
			ctx->U = insword&1;
			break;
		case ENC_SUNPK_MZ_Z_4:
		case ENC_UUNPK_MZ_Z_4:
			// x|xx|xxxx|x|size=xx|x|xxx|xx|xxxxxx|Zn=xxxx|x|Zd=xxx|x|U=x
			ctx->size = (insword>>22)&3;
			ctx->Zn = (insword>>6)&15;
			ctx->Zd = (insword>>2)&7;
			ctx->U = insword&1;
			break;
		case ENC_UZP_MZ_Z_4:
		case ENC_ZIP_MZ_Z_4:
			// x|xx|xxxx|x|size=xx|x|xxx|xx|xxxxxx|Zn=xxx|xx|Zd=xxx|op=x|x
			ctx->size = (insword>>22)&3;
			ctx->Zn = (insword>>7)&7;
			ctx->Zd = (insword>>2)&7;
			ctx->op = (insword>>1)&1;
			break;
		case ENC_FRINTA_MZ_Z_2:
		case ENC_FRINTM_MZ_Z_2:
		case ENC_FRINTN_MZ_Z_2:
		case ENC_FRINTP_MZ_Z_2:
			// x|xx|xxxx|x|size=xx|x|xx|opc=xxx|xxxxxx|Zn=xxxx|x|Zd=xxxx|x
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>16)&7;
			ctx->Zn = (insword>>6)&15;
			ctx->Zd = (insword>>1)&15;
			break;
		case ENC_FRINTA_MZ_Z_4:
		case ENC_FRINTM_MZ_Z_4:
		case ENC_FRINTN_MZ_Z_4:
		case ENC_FRINTP_MZ_Z_4:
			// x|xx|xxxx|x|size=xx|x|xx|opc=xxx|xxxxxx|Zn=xxx|xx|Zd=xxx|xx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>16)&7;
			ctx->Zn = (insword>>7)&7;
			ctx->Zd = (insword>>2)&7;
			break;
		case ENC_SQCVT_Z_MZ4_:
		case ENC_SQCVTN_Z_MZ4_:
		case ENC_SQCVTU_Z_MZ4_:
		case ENC_SQCVTUN_Z_MZ4_:
		case ENC_UQCVT_Z_MZ4_:
		case ENC_UQCVTN_Z_MZ4_:
			// x|xx|xxxx|x|sz=x|op=x|x|xxx|xx|xxxxxx|Zn=xxx|N=x|U=x|Zd=xxxxx
			ctx->sz = (insword>>23)&1;
			ctx->op = (insword>>22)&1;
			ctx->Zn = (insword>>7)&7;
			ctx->N = (insword>>6)&1;
			ctx->U = (insword>>5)&1;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SQRSHR_Z_MZ4_:
		case ENC_SQRSHRN_Z_MZ4_:
		case ENC_SQRSHRU_Z_MZ4_:
		case ENC_SQRSHRUN_Z_MZ4_:
		case ENC_UQRSHR_Z_MZ4_:
		case ENC_UQRSHRN_Z_MZ4_:
			// x|xx|xxxx|x|tsize=xx|x|imm5=xxxxx|xxx|xx|N=x|Zn=xxx|op=x|U=x|Zd=xxxxx
			ctx->tsize = (insword>>22)&3;
			ctx->imm5 = (insword>>16)&0x1f;
			ctx->N = (insword>>10)&1;
			ctx->Zn = (insword>>7)&7;
			ctx->op = (insword>>6)&1;
			ctx->U = (insword>>5)&1;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_MOV_ZA_MZ2_1_MOVA_ZA_MZ2_1:
		case ENC_MOVA_ZA_MZ2_1:
			// x|xx|xxxx|x|xx|xxx|x|x|xx|Rv=xx|xxx|Zn=xxxx|x|x|x|off3=xxx
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>6)&15;
			ctx->off3 = insword&7;
			break;
		case ENC_MOV_ZA_MZ4_1_MOVA_ZA_MZ4_1:
		case ENC_MOVA_ZA_MZ4_1:
			// x|xx|xxxx|x|xx|xxx|x|x|xx|Rv=xx|xxx|Zn=xxx|xx|x|x|off3=xxx
			ctx->Rv = (insword>>13)&3;
			ctx->Zn = (insword>>7)&7;
			ctx->off3 = insword&7;
			break;
		case ENC_MOV_MZ_ZA2_1_MOVA_MZ_ZA2_1:
		case ENC_MOVA_MZ_ZA2_1:
		case ENC_MOVAZ_MZ_ZA2_1:
			// x|xx|xxxx|x|xx|xxx|x|x|xx|Rv=xx|xxx|xx|off3=xxx|Zd=xxxx|x
			ctx->Rv = (insword>>13)&3;
			ctx->off3 = (insword>>5)&7;
			ctx->Zd = (insword>>1)&15;
			break;
		case ENC_MOV_MZ_ZA4_1_MOVA_MZ_ZA4_1:
		case ENC_MOVA_MZ_ZA4_1:
		case ENC_MOVAZ_MZ_ZA4_1:
			// x|xx|xxxx|x|xx|xxx|x|x|xx|Rv=xx|xxx|xx|off3=xxx|Zd=xxx|xx
			ctx->Rv = (insword>>13)&3;
			ctx->off3 = (insword>>5)&7;
			ctx->Zd = (insword>>2)&7;
			break;
		case ENC_SMLAL_ZA_ZZI_1:
		case ENC_SMLSL_ZA_ZZI_1:
		case ENC_UMLAL_ZA_ZZI_1:
		case ENC_UMLSL_ZA_ZZI_1:
			// x|xx|xxxx|x|xx|xx|Zm=xxxx|i3h=x|Rv=xx|x|i3l=xx|Zn=xxxxx|U=x|S=x|off3=xxx
			ctx->Zm = (insword>>16)&15;
			ctx->i3h = (insword>>15)&1;
			ctx->Rv = (insword>>13)&3;
			ctx->i3l = (insword>>10)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->U = (insword>>4)&1;
			ctx->S = (insword>>3)&1;
			ctx->off3 = insword&7;
			break;
		case ENC_SMLALL_ZA_ZZI_D:
		case ENC_SMLSLL_ZA_ZZI_D:
		case ENC_UMLALL_ZA_ZZI_D:
		case ENC_UMLSLL_ZA_ZZI_D:
			// x|xx|xxxx|x|xx|xx|Zm=xxxx|i3h=x|Rv=xx|x|i3l=xx|Zn=xxxxx|U=x|S=x|x|off2=xx
			ctx->Zm = (insword>>16)&15;
			ctx->i3h = (insword>>15)&1;
			ctx->Rv = (insword>>13)&3;
			ctx->i3l = (insword>>10)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->U = (insword>>4)&1;
			ctx->S = (insword>>3)&1;
			ctx->off2 = insword&3;
			break;
		case ENC_BFMLAL_ZA_ZZI_1:
		case ENC_BFMLSL_ZA_ZZI_1:
		case ENC_FMLAL_ZA_ZZI_1:
		case ENC_FMLSL_ZA_ZZI_1:
			// x|xx|xxxx|x|xx|xx|Zm=xxxx|i3h=x|Rv=xx|x|i3l=xx|Zn=xxxxx|op=x|S=x|off3=xxx
			ctx->Zm = (insword>>16)&15;
			ctx->i3h = (insword>>15)&1;
			ctx->Rv = (insword>>13)&3;
			ctx->i3l = (insword>>10)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->op = (insword>>4)&1;
			ctx->S = (insword>>3)&1;
			ctx->off3 = insword&7;
			break;
		case ENC_FMLAL_ZA_Z8Z8I_1:
			// x|xx|xxxx|x|xx|xx|Zm=xxxx|i4A=x|Rv=xx|x|i4B=xx|Zn=xxxxx|x|i4C=x|off3=xxx
			ctx->Zm = (insword>>16)&15;
			ctx->i4A = (insword>>15)&1;
			ctx->Rv = (insword>>13)&3;
			ctx->i4B = (insword>>10)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->i4C = (insword>>3)&1;
			ctx->off3 = insword&7;
			break;
		case ENC_SMLALL_ZA_ZZI_S:
		case ENC_SMLSLL_ZA_ZZI_S:
		case ENC_SUMLALL_ZA_ZZI_S:
		case ENC_UMLALL_ZA_ZZI_S:
		case ENC_UMLSLL_ZA_ZZI_S:
		case ENC_USMLALL_ZA_ZZI_S:
			// x|xx|xxxx|x|xx|xx|Zm=xxxx|i4h=x|Rv=xx|i4l=xxx|Zn=xxxxx|U=x|S=x|op=x|off2=xx
			ctx->Zm = (insword>>16)&15;
			ctx->i4h = (insword>>15)&1;
			ctx->Rv = (insword>>13)&3;
			ctx->i4l = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->U = (insword>>4)&1;
			ctx->S = (insword>>3)&1;
			ctx->op = (insword>>2)&1;
			ctx->off2 = insword&3;
			break;
		case ENC_FMLALL_ZA32_Z8Z8I_1:
			// x|xx|xxxx|x|xx|xx|Zm=xxxx|i4h=x|Rv=xx|i4l=xxx|Zn=xxxxx|xxx|off2=xx
			ctx->Zm = (insword>>16)&15;
			ctx->i4h = (insword>>15)&1;
			ctx->Rv = (insword>>13)&3;
			ctx->i4l = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->off2 = insword&3;
			break;
		case ENC_BFDOT_ZA_ZZI_2XI:
		case ENC_BFVDOT_ZA_ZZI_2XI:
		case ENC_FDOT_ZA32_Z8Z8I_2XI:
		case ENC_FDOT_ZA_ZZI_2XI:
		case ENC_FVDOT_ZA_ZZI_2XI:
			// x|xx|xxxx|x|xx|xx|Zm=xxxx|x|Rv=xx|op=x|i2=xx|Zn=xxxx|opc2=xxx|off3=xxx
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->op = (insword>>12)&1;
			ctx->i2 = (insword>>10)&3;
			ctx->Zn = (insword>>6)&15;
			ctx->opc2 = (insword>>3)&7;
			ctx->off3 = insword&7;
			break;
		case ENC_FMLA_ZA_ZZI_S2XI:
		case ENC_FMLS_ZA_ZZI_S2XI:
			// x|xx|xxxx|x|xx|xx|Zm=xxxx|x|Rv=xx|op=x|i2=xx|Zn=xxxx|x|S=x|x|off3=xxx
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->op = (insword>>12)&1;
			ctx->i2 = (insword>>10)&3;
			ctx->Zn = (insword>>6)&15;
			ctx->S = (insword>>4)&1;
			ctx->off3 = insword&7;
			break;
		case ENC_SDOT_ZA32_ZZI_2XI:
		case ENC_SDOT_ZA_ZZI_S2XI:
		case ENC_SUDOT_ZA_ZZI_S2XI:
		case ENC_SVDOT_ZA32_ZZI_2XI:
		case ENC_UDOT_ZA32_ZZI_2XI:
		case ENC_UDOT_ZA_ZZI_S2XI:
		case ENC_USDOT_ZA_ZZI_S2XI:
		case ENC_UVDOT_ZA32_ZZI_2XI:
			// x|xx|xxxx|x|xx|xx|Zm=xxxx|x|Rv=xx|op=x|i2=xx|Zn=xxxx|x|U=x|x|off3=xxx
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->op = (insword>>12)&1;
			ctx->i2 = (insword>>10)&3;
			ctx->Zn = (insword>>6)&15;
			ctx->U = (insword>>4)&1;
			ctx->off3 = insword&7;
			break;
		case ENC_BFDOT_ZA_ZZI_4XI:
		case ENC_FDOT_ZA32_Z8Z8I_4XI:
		case ENC_FDOT_ZA_ZZI_4XI:
			// x|xx|xxxx|x|xx|xx|Zm=xxxx|x|Rv=xx|op=x|i2=xx|Zn=xxx|x|opc2=xxx|off3=xxx
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->op = (insword>>12)&1;
			ctx->i2 = (insword>>10)&3;
			ctx->Zn = (insword>>7)&7;
			ctx->opc2 = (insword>>3)&7;
			ctx->off3 = insword&7;
			break;
		case ENC_FMLA_ZA_ZZI_S4XI:
		case ENC_FMLS_ZA_ZZI_S4XI:
			// x|xx|xxxx|x|xx|xx|Zm=xxxx|x|Rv=xx|op=x|i2=xx|Zn=xxx|x|x|S=x|x|off3=xxx
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->op = (insword>>12)&1;
			ctx->i2 = (insword>>10)&3;
			ctx->Zn = (insword>>7)&7;
			ctx->S = (insword>>4)&1;
			ctx->off3 = insword&7;
			break;
		case ENC_SDOT_ZA32_ZZI_4XI:
		case ENC_SDOT_ZA_ZZI_S4XI:
		case ENC_SUDOT_ZA_ZZI_S4XI:
		case ENC_SUVDOT_ZA_ZZI_S4XI:
		case ENC_SVDOT_ZA_ZZI_S4XI:
		case ENC_UDOT_ZA32_ZZI_4XI:
		case ENC_UDOT_ZA_ZZI_S4XI:
		case ENC_USDOT_ZA_ZZI_S4XI:
		case ENC_USVDOT_ZA_ZZI_S4XI:
		case ENC_UVDOT_ZA_ZZI_S4XI:
			// x|xx|xxxx|x|xx|xx|Zm=xxxx|x|Rv=xx|op=x|i2=xx|Zn=xxx|x|x|U=x|x|off3=xxx
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->op = (insword>>12)&1;
			ctx->i2 = (insword>>10)&3;
			ctx->Zn = (insword>>7)&7;
			ctx->U = (insword>>4)&1;
			ctx->off3 = insword&7;
			break;
		case ENC_FDOT_ZA_Z8Z8I_2XI:
		case ENC_FVDOT_ZA_Z8Z8I_2XI:
			// x|xx|xxxx|x|xx|xx|Zm=xxxx|x|Rv=xx|op=x|i3h=xx|Zn=xxxx|x|x|i3l=x|off3=xxx
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->op = (insword>>12)&1;
			ctx->i3h = (insword>>10)&3;
			ctx->Zn = (insword>>6)&15;
			ctx->i3l = (insword>>3)&1;
			ctx->off3 = insword&7;
			break;
		case ENC_FMLA_ZA_ZZI_D2XI:
		case ENC_FMLS_ZA_ZZI_D2XI:
			// x|xx|xxxx|x|xx|xx|Zm=xxxx|x|Rv=xx|xx|i1=x|Zn=xxxx|x|S=x|x|off3=xxx
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->i1 = (insword>>10)&1;
			ctx->Zn = (insword>>6)&15;
			ctx->S = (insword>>4)&1;
			ctx->off3 = insword&7;
			break;
		case ENC_SDOT_ZA_ZZI_D2XI:
		case ENC_UDOT_ZA_ZZI_D2XI:
			// x|xx|xxxx|x|xx|xx|Zm=xxxx|x|Rv=xx|xx|i1=x|Zn=xxxx|x|U=x|x|off3=xxx
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->i1 = (insword>>10)&1;
			ctx->Zn = (insword>>6)&15;
			ctx->U = (insword>>4)&1;
			ctx->off3 = insword&7;
			break;
		case ENC_FVDOTB_ZA32_Z8Z8I_2XI:
		case ENC_FVDOTT_ZA32_Z8Z8I_2XI:
			// x|xx|xxxx|x|xx|xx|Zm=xxxx|x|Rv=xx|xx|i2h=x|Zn=xxxx|x|T=x|i2l=x|off3=xxx
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->i2h = (insword>>10)&1;
			ctx->Zn = (insword>>6)&15;
			ctx->T = (insword>>4)&1;
			ctx->i2l = (insword>>3)&1;
			ctx->off3 = insword&7;
			break;
		case ENC_SMLALL_ZA_ZZI_D2XI:
		case ENC_SMLSLL_ZA_ZZI_D2XI:
		case ENC_UMLALL_ZA_ZZI_D2XI:
		case ENC_UMLSLL_ZA_ZZI_D2XI:
			// x|xx|xxxx|x|xx|xx|Zm=xxxx|x|Rv=xx|xx|i3h=x|Zn=xxxx|x|U=x|S=x|i3l=xx|o1=x
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->i3h = (insword>>10)&1;
			ctx->Zn = (insword>>6)&15;
			ctx->U = (insword>>4)&1;
			ctx->S = (insword>>3)&1;
			ctx->i3l = (insword>>1)&3;
			ctx->o1 = insword&1;
			break;
		case ENC_SMLALL_ZA_ZZI_D4XI:
		case ENC_SMLSLL_ZA_ZZI_D4XI:
		case ENC_UMLALL_ZA_ZZI_D4XI:
		case ENC_UMLSLL_ZA_ZZI_D4XI:
			// x|xx|xxxx|x|xx|xx|Zm=xxxx|x|Rv=xx|xx|i3h=x|Zn=xxx|xx|U=x|S=x|i3l=xx|o1=x
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->i3h = (insword>>10)&1;
			ctx->Zn = (insword>>7)&7;
			ctx->U = (insword>>4)&1;
			ctx->S = (insword>>3)&1;
			ctx->i3l = (insword>>1)&3;
			ctx->o1 = insword&1;
			break;
		case ENC_BFMLA_ZA_ZZI_H2XI:
		case ENC_BFMLS_ZA_ZZI_H2XI:
		case ENC_FMLA_ZA_ZZI_H2XI:
		case ENC_FMLS_ZA_ZZI_H2XI:
			// x|xx|xxxx|x|xx|xx|Zm=xxxx|x|Rv=xx|x|i3h=xx|Zn=xxxx|op=x|S=x|i3l=x|off3=xxx
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->i3h = (insword>>10)&3;
			ctx->Zn = (insword>>6)&15;
			ctx->op = (insword>>5)&1;
			ctx->S = (insword>>4)&1;
			ctx->i3l = (insword>>3)&1;
			ctx->off3 = insword&7;
			break;
		case ENC_SMLAL_ZA_ZZI_2XI:
		case ENC_SMLSL_ZA_ZZI_2XI:
		case ENC_UMLAL_ZA_ZZI_2XI:
		case ENC_UMLSL_ZA_ZZI_2XI:
			// x|xx|xxxx|x|xx|xx|Zm=xxxx|x|Rv=xx|x|i3h=xx|Zn=xxxx|x|U=x|S=x|i3l=x|off2=xx
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->i3h = (insword>>10)&3;
			ctx->Zn = (insword>>6)&15;
			ctx->U = (insword>>4)&1;
			ctx->S = (insword>>3)&1;
			ctx->i3l = (insword>>2)&1;
			ctx->off2 = insword&3;
			break;
		case ENC_BFMLAL_ZA_ZZI_2XI:
		case ENC_BFMLSL_ZA_ZZI_2XI:
		case ENC_FMLAL_ZA_ZZI_2XI:
		case ENC_FMLSL_ZA_ZZI_2XI:
			// x|xx|xxxx|x|xx|xx|Zm=xxxx|x|Rv=xx|x|i3h=xx|Zn=xxxx|x|op=x|S=x|i3l=x|off2=xx
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->i3h = (insword>>10)&3;
			ctx->Zn = (insword>>6)&15;
			ctx->op = (insword>>4)&1;
			ctx->S = (insword>>3)&1;
			ctx->i3l = (insword>>2)&1;
			ctx->off2 = insword&3;
			break;
		case ENC_FDOT_ZA_Z8Z8I_4XI:
			// x|xx|xxxx|x|xx|xx|Zm=xxxx|x|Rv=xx|x|i3h=xx|Zn=xxx|xxx|i3l=x|off3=xxx
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->i3h = (insword>>10)&3;
			ctx->Zn = (insword>>7)&7;
			ctx->i3l = (insword>>3)&1;
			ctx->off3 = insword&7;
			break;
		case ENC_SMLAL_ZA_ZZI_4XI:
		case ENC_SMLSL_ZA_ZZI_4XI:
		case ENC_UMLAL_ZA_ZZI_4XI:
		case ENC_UMLSL_ZA_ZZI_4XI:
			// x|xx|xxxx|x|xx|xx|Zm=xxxx|x|Rv=xx|x|i3h=xx|Zn=xxx|xx|U=x|S=x|i3l=x|off2=xx
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->i3h = (insword>>10)&3;
			ctx->Zn = (insword>>7)&7;
			ctx->U = (insword>>4)&1;
			ctx->S = (insword>>3)&1;
			ctx->i3l = (insword>>2)&1;
			ctx->off2 = insword&3;
			break;
		case ENC_BFMLAL_ZA_ZZI_4XI:
		case ENC_BFMLSL_ZA_ZZI_4XI:
		case ENC_FMLAL_ZA_ZZI_4XI:
		case ENC_FMLSL_ZA_ZZI_4XI:
			// x|xx|xxxx|x|xx|xx|Zm=xxxx|x|Rv=xx|x|i3h=xx|Zn=xxx|xx|op=x|S=x|i3l=x|off2=xx
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->i3h = (insword>>10)&3;
			ctx->Zn = (insword>>7)&7;
			ctx->op = (insword>>4)&1;
			ctx->S = (insword>>3)&1;
			ctx->i3l = (insword>>2)&1;
			ctx->off2 = insword&3;
			break;
		case ENC_BFMLA_ZA_ZZI_H4XI:
		case ENC_BFMLS_ZA_ZZI_H4XI:
		case ENC_FMLA_ZA_ZZI_H4XI:
		case ENC_FMLS_ZA_ZZI_H4XI:
			// x|xx|xxxx|x|xx|xx|Zm=xxxx|x|Rv=xx|x|i3h=xx|Zn=xxx|x|op=x|S=x|i3l=x|off3=xxx
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->i3h = (insword>>10)&3;
			ctx->Zn = (insword>>7)&7;
			ctx->op = (insword>>5)&1;
			ctx->S = (insword>>4)&1;
			ctx->i3l = (insword>>3)&1;
			ctx->off3 = insword&7;
			break;
		case ENC_SMLALL_ZA_ZZI_S2XI:
		case ENC_SMLSLL_ZA_ZZI_S2XI:
		case ENC_SUMLALL_ZA_ZZI_S2XI:
		case ENC_UMLALL_ZA_ZZI_S2XI:
		case ENC_UMLSLL_ZA_ZZI_S2XI:
		case ENC_USMLALL_ZA_ZZI_S2XI:
			// x|xx|xxxx|x|xx|xx|Zm=xxxx|x|Rv=xx|x|i4h=xx|Zn=xxxx|op=x|U=x|S=x|i4l=xx|o1=x
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->i4h = (insword>>10)&3;
			ctx->Zn = (insword>>6)&15;
			ctx->op = (insword>>5)&1;
			ctx->U = (insword>>4)&1;
			ctx->S = (insword>>3)&1;
			ctx->i4l = (insword>>1)&3;
			ctx->o1 = insword&1;
			break;
		case ENC_FMLALL_ZA32_Z8Z8I_2XI:
			// x|xx|xxxx|x|xx|xx|Zm=xxxx|x|Rv=xx|x|i4h=xx|Zn=xxxx|x|xx|i4l=xx|o1=x
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->i4h = (insword>>10)&3;
			ctx->Zn = (insword>>6)&15;
			ctx->i4l = (insword>>1)&3;
			ctx->o1 = insword&1;
			break;
		case ENC_FMLAL_ZA_Z8Z8I_2XI:
			// x|xx|xxxx|x|xx|xx|Zm=xxxx|x|Rv=xx|x|i4h=xx|Zn=xxxx|x|x|i4l=xx|off2=xx
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->i4h = (insword>>10)&3;
			ctx->Zn = (insword>>6)&15;
			ctx->i4l = (insword>>2)&3;
			ctx->off2 = insword&3;
			break;
		case ENC_FMLAL_ZA_Z8Z8I_4XI:
			// x|xx|xxxx|x|xx|xx|Zm=xxxx|x|Rv=xx|x|i4h=xx|Zn=xxx|xxx|i4l=xx|off2=xx
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->i4h = (insword>>10)&3;
			ctx->Zn = (insword>>7)&7;
			ctx->i4l = (insword>>2)&3;
			ctx->off2 = insword&3;
			break;
		case ENC_FMLALL_ZA32_Z8Z8I_4XI:
			// x|xx|xxxx|x|xx|xx|Zm=xxxx|x|Rv=xx|x|i4h=xx|Zn=xxx|xxx|x|i4l=xx|o1=x
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->i4h = (insword>>10)&3;
			ctx->Zn = (insword>>7)&7;
			ctx->i4l = (insword>>1)&3;
			ctx->o1 = insword&1;
			break;
		case ENC_SMLALL_ZA_ZZI_S4XI:
		case ENC_SMLSLL_ZA_ZZI_S4XI:
		case ENC_SUMLALL_ZA_ZZI_S4XI:
		case ENC_UMLALL_ZA_ZZI_S4XI:
		case ENC_UMLSLL_ZA_ZZI_S4XI:
		case ENC_USMLALL_ZA_ZZI_S4XI:
			// x|xx|xxxx|x|xx|xx|Zm=xxxx|x|Rv=xx|x|i4h=xx|Zn=xxx|x|op=x|U=x|S=x|i4l=xx|o1=x
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->i4h = (insword>>10)&3;
			ctx->Zn = (insword>>7)&7;
			ctx->op = (insword>>5)&1;
			ctx->U = (insword>>4)&1;
			ctx->S = (insword>>3)&1;
			ctx->i4l = (insword>>1)&3;
			ctx->o1 = insword&1;
			break;
		case ENC_FMLA_ZA_ZZI_D4XI:
		case ENC_FMLS_ZA_ZZI_D4XI:
			// x|xx|xxxx|x|xx|xx|Zm=xxxx|x|Rv=xx|x|op=x|i1=x|Zn=xxx|xx|S=x|x|off3=xxx
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->op = (insword>>11)&1;
			ctx->i1 = (insword>>10)&1;
			ctx->Zn = (insword>>7)&7;
			ctx->S = (insword>>4)&1;
			ctx->off3 = insword&7;
			break;
		case ENC_SDOT_ZA_ZZI_D4XI:
		case ENC_SVDOT_ZA_ZZI_D4XI:
		case ENC_UDOT_ZA_ZZI_D4XI:
		case ENC_UVDOT_ZA_ZZI_D4XI:
			// x|xx|xxxx|x|xx|xx|Zm=xxxx|x|Rv=xx|x|op=x|i1=x|Zn=xxx|xx|U=x|x|off3=xxx
			ctx->Zm = (insword>>16)&15;
			ctx->Rv = (insword>>13)&3;
			ctx->op = (insword>>11)&1;
			ctx->i1 = (insword>>10)&1;
			ctx->Zn = (insword>>7)&7;
			ctx->U = (insword>>4)&1;
			ctx->off3 = insword&7;
			break;
		case ENC_BFMOP4A_ZA32_ZZ_H1X2:
		case ENC_BFMOP4A_ZA32_ZZ_H1X1:
		case ENC_BFMOP4A_ZA32_ZZ_H2X1:
		case ENC_BFMOP4A_ZA32_ZZ_H2X2:
		case ENC_BFMOP4S_ZA32_ZZ_H1X2:
		case ENC_BFMOP4S_ZA32_ZZ_H1X1:
		case ENC_BFMOP4S_ZA32_ZZ_H2X1:
		case ENC_BFMOP4S_ZA32_ZZ_H2X2:
		case ENC_FMOP4A_ZA32_ZZ_H1X2:
		case ENC_FMOP4A_ZA32_ZZ_H1X1:
		case ENC_FMOP4A_ZA32_ZZ_H2X1:
		case ENC_FMOP4A_ZA32_ZZ_H2X2:
		case ENC_FMOP4A_ZA_ZZ_S1X2:
		case ENC_FMOP4A_ZA_ZZ_S1X1:
		case ENC_FMOP4A_ZA_ZZ_S2X1:
		case ENC_FMOP4A_ZA_ZZ_S2X2:
		case ENC_FMOP4S_ZA32_ZZ_H1X2:
		case ENC_FMOP4S_ZA32_ZZ_H1X1:
		case ENC_FMOP4S_ZA32_ZZ_H2X1:
		case ENC_FMOP4S_ZA32_ZZ_H2X2:
		case ENC_FMOP4S_ZA_ZZ_S1X2:
		case ENC_FMOP4S_ZA_ZZ_S1X1:
		case ENC_FMOP4S_ZA_ZZ_S2X1:
		case ENC_FMOP4S_ZA_ZZ_S2X2:
			// x|xx|xxxx|x|xx|x|M=x|Zm=xxx|x|x|xxxxx|N=x|Zn=xxx|x|S=x|x|x|ZAda=xx
			ctx->M = (insword>>20)&1;
			ctx->Zm = (insword>>17)&7;
			ctx->N = (insword>>9)&1;
			ctx->Zn = (insword>>6)&7;
			ctx->S = (insword>>4)&1;
			ctx->ZAda = insword&3;
			break;
		case ENC_BFMOP4A_ZA_ZZ_H1X2:
		case ENC_BFMOP4A_ZA_ZZ_H1X1:
		case ENC_BFMOP4A_ZA_ZZ_H2X1:
		case ENC_BFMOP4A_ZA_ZZ_H2X2:
		case ENC_BFMOP4S_ZA_ZZ_H1X2:
		case ENC_BFMOP4S_ZA_ZZ_H1X1:
		case ENC_BFMOP4S_ZA_ZZ_H2X1:
		case ENC_BFMOP4S_ZA_ZZ_H2X2:
		case ENC_FMOP4A_ZA_ZZ_H1X2:
		case ENC_FMOP4A_ZA_ZZ_H1X1:
		case ENC_FMOP4A_ZA_ZZ_H2X1:
		case ENC_FMOP4A_ZA_ZZ_H2X2:
		case ENC_FMOP4S_ZA_ZZ_H1X2:
		case ENC_FMOP4S_ZA_ZZ_H1X1:
		case ENC_FMOP4S_ZA_ZZ_H2X1:
		case ENC_FMOP4S_ZA_ZZ_H2X2:
			// x|xx|xxxx|x|xx|x|M=x|Zm=xxx|x|x|xxxxx|N=x|Zn=xxx|x|S=x|x|x|x|ZAda=x
			ctx->M = (insword>>20)&1;
			ctx->Zm = (insword>>17)&7;
			ctx->N = (insword>>9)&1;
			ctx->Zn = (insword>>6)&7;
			ctx->S = (insword>>4)&1;
			ctx->ZAda = insword&1;
			break;
		case ENC_FMOP4A_ZA32_Z8Z8_B1X2:
		case ENC_FMOP4A_ZA32_Z8Z8_B1X1:
		case ENC_FMOP4A_ZA32_Z8Z8_B2X1:
		case ENC_FMOP4A_ZA32_Z8Z8_B2X2:
			// x|xx|xxxx|x|xx|x|M=x|Zm=xxx|x|x|xxxxx|N=x|Zn=xxx|x|xx|x|ZAda=xx
			ctx->M = (insword>>20)&1;
			ctx->Zm = (insword>>17)&7;
			ctx->N = (insword>>9)&1;
			ctx->Zn = (insword>>6)&7;
			ctx->ZAda = insword&3;
			break;
		case ENC_FMOP4A_ZA16_Z8Z8_B1X2:
		case ENC_FMOP4A_ZA16_Z8Z8_B1X1:
		case ENC_FMOP4A_ZA16_Z8Z8_B2X1:
		case ENC_FMOP4A_ZA16_Z8Z8_B2X2:
			// x|xx|xxxx|x|xx|x|M=x|Zm=xxx|x|x|xxxxx|N=x|Zn=xxx|x|xx|x|x|ZAda=x
			ctx->M = (insword>>20)&1;
			ctx->Zm = (insword>>17)&7;
			ctx->N = (insword>>9)&1;
			ctx->Zn = (insword>>6)&7;
			ctx->ZAda = insword&1;
			break;
		case ENC_BFMOPA_ZA32_PP_ZZ_:
		case ENC_BFMOPS_ZA32_PP_ZZ_:
		case ENC_BMOPA_ZA_PP_ZZ_32:
		case ENC_BMOPS_ZA_PP_ZZ_32:
		case ENC_FMOPA_ZA32_PP_ZZ_16:
		case ENC_FMOPA_ZA_PP_ZZ_32:
		case ENC_FMOPS_ZA32_PP_ZZ_16:
		case ENC_FMOPS_ZA_PP_ZZ_32:
			// x|xx|xxxx|x|xx|x|Zm=xxxxx|Pm=xxx|Pn=xxx|Zn=xxxxx|S=x|xx|ZAda=xx
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Pm = (insword>>13)&7;
			ctx->Pn = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->S = (insword>>4)&1;
			ctx->ZAda = insword&3;
			break;
		case ENC_BFMOPA_ZA_PP_ZZ_16:
		case ENC_BFMOPS_ZA_PP_ZZ_16:
		case ENC_FMOPA_ZA_PP_ZZ_16:
		case ENC_FMOPS_ZA_PP_ZZ_16:
			// x|xx|xxxx|x|xx|x|Zm=xxxxx|Pm=xxx|Pn=xxx|Zn=xxxxx|S=x|xx|x|ZAda=x
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Pm = (insword>>13)&7;
			ctx->Pn = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->S = (insword>>4)&1;
			ctx->ZAda = insword&1;
			break;
		case ENC_FMOPA_ZA32_PP_Z8Z8_8:
			// x|xx|xxxx|x|xx|x|Zm=xxxxx|Pm=xxx|Pn=xxx|Zn=xxxxx|x|xx|ZAda=xx
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Pm = (insword>>13)&7;
			ctx->Pn = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->ZAda = insword&3;
			break;
		case ENC_FMOPA_ZA16_PP_Z8Z8_8:
			// x|xx|xxxx|x|xx|x|Zm=xxxxx|Pm=xxx|Pn=xxx|Zn=xxxxx|x|xx|x|ZAda=x
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Pm = (insword>>13)&7;
			ctx->Pn = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->ZAda = insword&1;
			break;
		case ENC_UZP_MZ_ZZ_2Q:
		case ENC_ZIP_MZ_ZZ_2Q:
			// x|xx|xxxx|x|xx|x|Zm=xxxxx|xxx|xxx|Zn=xxxxx|Zd=xxxx|op=x
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = (insword>>1)&15;
			ctx->op = insword&1;
			break;
		case ENC_BFTMOPA_ZA32_ZZZI_H2X1:
		case ENC_FTMOPA_ZA32_Z8Z8ZI_B2X1:
		case ENC_FTMOPA_ZA32_ZZZI_H2X1:
		case ENC_FTMOPA_ZA_ZZZI_S2X1:
			// x|xx|xxxx|x|xx|x|Zm=xxxxx|x|x|x|K=x|Zk=xx|Zn=xxxx|i2=xx|x|x|ZAda=xx
			ctx->Zm = (insword>>16)&0x1f;
			ctx->K = (insword>>12)&1;
			ctx->Zk = (insword>>10)&3;
			ctx->Zn = (insword>>6)&15;
			ctx->i2 = (insword>>4)&3;
			ctx->ZAda = insword&3;
			break;
		case ENC_BFTMOPA_ZA_ZZZI_H2X1:
		case ENC_FTMOPA_ZA16_Z8Z8ZI_B2X1:
		case ENC_FTMOPA_ZA_ZZZI_H2X1:
			// x|xx|xxxx|x|xx|x|Zm=xxxxx|x|x|x|K=x|Zk=xx|Zn=xxxx|i2=xx|x|x|x|ZAda=x
			ctx->Zm = (insword>>16)&0x1f;
			ctx->K = (insword>>12)&1;
			ctx->Zk = (insword>>10)&3;
			ctx->Zn = (insword>>6)&15;
			ctx->i2 = (insword>>4)&3;
			ctx->ZAda = insword&1;
			break;
		case ENC_SQRSHR_Z_MZ2_:
		case ENC_SQRSHRU_Z_MZ2_:
		case ENC_UQRSHR_Z_MZ2_:
			// x|xx|xxxx|x|xx|x|op=x|imm4=xxxx|xxx|xxx|Zn=xxxx|U=x|Zd=xxxxx
			ctx->op = (insword>>20)&1;
			ctx->imm4 = (insword>>16)&15;
			ctx->Zn = (insword>>6)&15;
			ctx->U = (insword>>5)&1;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_FCVT_MZ2_Z_:
		case ENC_FCVTL_MZ2_Z_:
			// x|xx|xxxx|x|xx|x|xxx|xx|xxxxxx|Zn=xxxxx|Zd=xxxx|L=x
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = (insword>>1)&15;
			ctx->L = insword&1;
			break;
		case ENC_FCVTZS_MZ_Z_2:
		case ENC_FCVTZU_MZ_Z_2:
		case ENC_SCVTF_MZ_Z_2:
		case ENC_UCVTF_MZ_Z_2:
			// x|xx|xxxx|x|xx|x|xxx|xx|xxxxxx|Zn=xxxx|U=x|Zd=xxxx|x
			ctx->Zn = (insword>>6)&15;
			ctx->U = (insword>>5)&1;
			ctx->Zd = (insword>>1)&15;
			break;
		case ENC_UZP_MZ_Z_4Q:
		case ENC_ZIP_MZ_Z_4Q:
			// x|xx|xxxx|x|xx|x|xxx|xx|xxxxxx|Zn=xxx|xx|Zd=xxx|op=x|x
			ctx->Zn = (insword>>7)&7;
			ctx->Zd = (insword>>2)&7;
			ctx->op = (insword>>1)&1;
			break;
		case ENC_FCVT_Z8_MZ4_:
		case ENC_FCVTN_Z8_MZ4_:
			// x|xx|xxxx|x|xx|x|xxx|xx|xxxxxx|Zn=xxx|x|N=x|Zd=xxxxx
			ctx->Zn = (insword>>7)&7;
			ctx->N = (insword>>5)&1;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_FCVTZS_MZ_Z_4:
		case ENC_FCVTZU_MZ_Z_4:
		case ENC_SCVTF_MZ_Z_4:
		case ENC_UCVTF_MZ_Z_4:
			// x|xx|xxxx|x|xx|x|xxx|xx|xxxxxx|Zn=xxx|x|U=x|Zd=xxx|xx
			ctx->Zn = (insword>>7)&7;
			ctx->U = (insword>>5)&1;
			ctx->Zd = (insword>>2)&7;
			break;
		case ENC_ADDHA_ZA_PP_Z_64:
		case ENC_ADDVA_ZA_PP_Z_64:
			// x|xx|xxxx|x|x|op=x|xxx|xx|V=x|Pm=xxx|Pn=xxx|Zn=xxxxx|x|x|ZAda=xxx
			ctx->op = (insword>>22)&1;
			ctx->V = (insword>>16)&1;
			ctx->Pm = (insword>>13)&7;
			ctx->Pn = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->ZAda = insword&7;
			break;
		case ENC_ADDHA_ZA_PP_Z_32:
		case ENC_ADDVA_ZA_PP_Z_32:
			// x|xx|xxxx|x|x|op=x|xxx|xx|V=x|Pm=xxx|Pn=xxx|Zn=xxxxx|x|x|x|ZAda=xx
			ctx->op = (insword>>22)&1;
			ctx->V = (insword>>16)&1;
			ctx->Pm = (insword>>13)&7;
			ctx->Pn = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->ZAda = insword&3;
			break;
		case ENC_BFCVT_Z_MZ2_:
		case ENC_BFCVTN_Z_MZ2_:
		case ENC_FCVT_Z_MZ2_:
		case ENC_FCVTN_Z_MZ2_:
			// x|xx|xxxx|x|x|op=x|x|xxx|xx|xxxxxx|Zn=xxxx|N=x|Zd=xxxxx
			ctx->op = (insword>>22)&1;
			ctx->Zn = (insword>>6)&15;
			ctx->N = (insword>>5)&1;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SQCVT_Z_MZ2_:
		case ENC_SQCVTU_Z_MZ2_:
		case ENC_UQCVT_Z_MZ2_:
			// x|xx|xxxx|x|x|op=x|x|xxx|xx|xxxxxx|Zn=xxxx|U=x|Zd=xxxxx
			ctx->op = (insword>>22)&1;
			ctx->Zn = (insword>>6)&15;
			ctx->U = (insword>>5)&1;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_BFCVT_Z8_MZ2_:
		case ENC_FCVT_Z8_MZ2_:
			// x|xx|xxxx|x|x|op=x|x|xxx|xx|xxxxxx|Zn=xxxx|x|Zd=xxxxx
			ctx->op = (insword>>22)&1;
			ctx->Zn = (insword>>6)&15;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SMOP4A_ZA_ZZ_H1X2:
		case ENC_SMOP4A_ZA_ZZ_H1X1:
		case ENC_SMOP4A_ZA_ZZ_H2X1:
		case ENC_SMOP4A_ZA_ZZ_H2X2:
		case ENC_SMOP4S_ZA_ZZ_H1X2:
		case ENC_SMOP4S_ZA_ZZ_H1X1:
		case ENC_SMOP4S_ZA_ZZ_H2X1:
		case ENC_SMOP4S_ZA_ZZ_H2X2:
		case ENC_SUMOP4A_ZA_ZZ_H1X2:
		case ENC_SUMOP4A_ZA_ZZ_H1X1:
		case ENC_SUMOP4A_ZA_ZZ_H2X1:
		case ENC_SUMOP4A_ZA_ZZ_H2X2:
		case ENC_SUMOP4S_ZA_ZZ_H1X2:
		case ENC_SUMOP4S_ZA_ZZ_H1X1:
		case ENC_SUMOP4S_ZA_ZZ_H2X1:
		case ENC_SUMOP4S_ZA_ZZ_H2X2:
		case ENC_UMOP4A_ZA_ZZ_H1X2:
		case ENC_UMOP4A_ZA_ZZ_H1X1:
		case ENC_UMOP4A_ZA_ZZ_H2X1:
		case ENC_UMOP4A_ZA_ZZ_H2X2:
		case ENC_UMOP4S_ZA_ZZ_H1X2:
		case ENC_UMOP4S_ZA_ZZ_H1X1:
		case ENC_UMOP4S_ZA_ZZ_H2X1:
		case ENC_UMOP4S_ZA_ZZ_H2X2:
		case ENC_USMOP4A_ZA_ZZ_H1X2:
		case ENC_USMOP4A_ZA_ZZ_H1X1:
		case ENC_USMOP4A_ZA_ZZ_H2X1:
		case ENC_USMOP4A_ZA_ZZ_H2X2:
		case ENC_USMOP4S_ZA_ZZ_H1X2:
		case ENC_USMOP4S_ZA_ZZ_H1X1:
		case ENC_USMOP4S_ZA_ZZ_H2X1:
		case ENC_USMOP4S_ZA_ZZ_H2X2:
			// x|x|x|xxxx|u0=x|xx|u1=x|M=x|Zm=xxx|xxxxxxx|N=x|Zn=xxx|x|S=x|x|ZAda=xxx
			ctx->u0 = (insword>>24)&1;
			ctx->u1 = (insword>>21)&1;
			ctx->M = (insword>>20)&1;
			ctx->Zm = (insword>>17)&7;
			ctx->N = (insword>>9)&1;
			ctx->Zn = (insword>>6)&7;
			ctx->S = (insword>>4)&1;
			ctx->ZAda = insword&7;
			break;
		case ENC_SMOPA_ZA_PP_ZZ_64:
		case ENC_SMOPS_ZA_PP_ZZ_64:
		case ENC_SUMOPA_ZA_PP_ZZ_64:
		case ENC_SUMOPS_ZA_PP_ZZ_64:
		case ENC_UMOPA_ZA_PP_ZZ_64:
		case ENC_UMOPS_ZA_PP_ZZ_64:
		case ENC_USMOPA_ZA_PP_ZZ_64:
		case ENC_USMOPS_ZA_PP_ZZ_64:
			// x|x|x|xxxx|u0=x|xx|u1=x|Zm=xxxxx|Pm=xxx|Pn=xxx|Zn=xxxxx|S=x|x|ZAda=xxx
			ctx->u0 = (insword>>24)&1;
			ctx->u1 = (insword>>21)&1;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Pm = (insword>>13)&7;
			ctx->Pn = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->S = (insword>>4)&1;
			ctx->ZAda = insword&7;
			break;
		case ENC_FMOP4A_ZA_ZZ_D1X2:
		case ENC_FMOP4A_ZA_ZZ_D1X1:
		case ENC_FMOP4A_ZA_ZZ_D2X1:
		case ENC_FMOP4A_ZA_ZZ_D2X2:
		case ENC_FMOP4S_ZA_ZZ_D1X2:
		case ENC_FMOP4S_ZA_ZZ_D1X1:
		case ENC_FMOP4S_ZA_ZZ_D2X1:
		case ENC_FMOP4S_ZA_ZZ_D2X2:
			// x|x|x|xxxx|x|xx|x|M=x|Zm=xxx|xxxxxxx|N=x|Zn=xxx|x|S=x|x|ZAda=xxx
			ctx->M = (insword>>20)&1;
			ctx->Zm = (insword>>17)&7;
			ctx->N = (insword>>9)&1;
			ctx->Zn = (insword>>6)&7;
			ctx->S = (insword>>4)&1;
			ctx->ZAda = insword&7;
			break;
		case ENC_FMOPA_ZA_PP_ZZ_64:
		case ENC_FMOPS_ZA_PP_ZZ_64:
			// x|x|x|xxxx|x|xx|x|Zm=xxxxx|Pm=xxx|Pn=xxx|Zn=xxxxx|S=x|x|ZAda=xxx
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Pm = (insword>>13)&7;
			ctx->Pn = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->S = (insword>>4)&1;
			ctx->ZAda = insword&7;
			break;
		default:
			break;
	}
}
