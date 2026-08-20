/* GENERATED FILE */
#include <stddef.h>
#include <stdbool.h>

#include "operations.h"
#include "encodings_dec.h"
#include "decode.h"
#include "decode2.h"
#include "pcode.h"

int decode_iclass_barriers(context *ctx, Instruction *dec)
{
	uint32_t CRm=(INSWORD>>8)&15, op2=(INSWORD>>5)&7, Rt=INSWORD&0x1f;
	if((CRm&3)==2 && op2==1 && Rt==0x1f && HasXS()) return DSB(ctx, dec); // -> DSB_BOn_barriers
	if((CRm&3)==2 && op2==3 && Rt==0x1f) UNALLOCATED(ENC_UNALLOCATED_823_BARRIERS);
	if((CRm&3)==3 && (op2&5)==1 && Rt==0x1f) UNALLOCATED(ENC_UNALLOCATED_822_BARRIERS);
	if(!op2 && Rt==0x1f) UNALLOCATED(ENC_UNALLOCATED_821_BARRIERS);
	if(op2==2 && Rt==0x1f) return CLREX(ctx, dec); // -> CLREX_BN_barriers
	if(op2==4 && Rt==0x1f) return DSB(ctx, dec); // -> DSB_BO_barriers
	if(op2==5 && Rt==0x1f) return DMB(ctx, dec); // -> DMB_BO_barriers
	if(op2==6 && Rt==0x1f) return ISB(ctx, dec); // -> ISB_BI_barriers
	if(op2==7 && Rt==0x1f && HasSB()) return SB(ctx, dec); // -> SB_only_barriers
	if(!(CRm&2) && (op2&5)==1 && Rt==0x1f) UNALLOCATED(ENC_UNALLOCATED_820_BARRIERS);
	if(Rt!=0x1f) UNALLOCATED(ENC_UNALLOCATED_819_BARRIERS);
	UNMATCHED;
}

int decode_iclass_compbranch(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, op=(INSWORD>>24)&1;
	if(!sf && !op) return CBZ(ctx, dec); // -> CBZ_32_compbranch
	if(!sf && op) return CBNZ(ctx, dec); // -> CBNZ_32_compbranch
	if(sf && !op) return CBZ(ctx, dec); // -> CBZ_64_compbranch
	if(sf && op) return CBNZ(ctx, dec); // -> CBNZ_64_compbranch
	UNMATCHED;
}

int decode_iclass_compbranch_regs2(context *ctx, Instruction *dec)
{
	uint32_t cc=(INSWORD>>21)&7, H=(INSWORD>>14)&1;
	if(!cc && !H && HasCMPBR()) return CBBcc_regs(ctx, dec); // -> CBBGT_8_regs
	if(!cc && H && HasCMPBR()) return CBHcc_regs(ctx, dec); // -> CBHGT_16_regs
	if(cc==1 && !H && HasCMPBR()) return CBBcc_regs(ctx, dec); // -> CBBGE_8_regs
	if(cc==1 && H && HasCMPBR()) return CBHcc_regs(ctx, dec); // -> CBHGE_16_regs
	if(cc==2 && !H && HasCMPBR()) return CBBcc_regs(ctx, dec); // -> CBBHI_8_regs
	if(cc==2 && H && HasCMPBR()) return CBHcc_regs(ctx, dec); // -> CBHHI_16_regs
	if(cc==3 && !H && HasCMPBR()) return CBBcc_regs(ctx, dec); // -> CBBHS_8_regs
	if(cc==3 && H && HasCMPBR()) return CBHcc_regs(ctx, dec); // -> CBHHS_16_regs
	if(cc==6 && !H && HasCMPBR()) return CBBcc_regs(ctx, dec); // -> CBBEQ_8_regs
	if(cc==6 && H && HasCMPBR()) return CBHcc_regs(ctx, dec); // -> CBHEQ_16_regs
	if(cc==7 && !H && HasCMPBR()) return CBBcc_regs(ctx, dec); // -> CBBNE_8_regs
	if(cc==7 && H && HasCMPBR()) return CBHcc_regs(ctx, dec); // -> CBHNE_16_regs
	if((cc&6)==4) UNALLOCATED(ENC_UNALLOCATED_824_COMPBRANCH_REGS2);
	UNMATCHED;
}

int decode_iclass_compbranch_imm(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, cc=(INSWORD>>21)&7;
	if(!sf && !cc && HasCMPBR()) return CBcc_imm(ctx, dec); // -> CBGT_32_imm
	if(!sf && cc==1 && HasCMPBR()) return CBcc_imm(ctx, dec); // -> CBLT_32_imm
	if(!sf && cc==2 && HasCMPBR()) return CBcc_imm(ctx, dec); // -> CBHI_32_imm
	if(!sf && cc==3 && HasCMPBR()) return CBcc_imm(ctx, dec); // -> CBLO_32_imm
	if(!sf && cc==6 && HasCMPBR()) return CBcc_imm(ctx, dec); // -> CBEQ_32_imm
	if(!sf && cc==7 && HasCMPBR()) return CBcc_imm(ctx, dec); // -> CBNE_32_imm
	if(sf && !cc && HasCMPBR()) return CBcc_imm(ctx, dec); // -> CBGT_64_imm
	if(sf && cc==1 && HasCMPBR()) return CBcc_imm(ctx, dec); // -> CBLT_64_imm
	if(sf && cc==2 && HasCMPBR()) return CBcc_imm(ctx, dec); // -> CBHI_64_imm
	if(sf && cc==3 && HasCMPBR()) return CBcc_imm(ctx, dec); // -> CBLO_64_imm
	if(sf && cc==6 && HasCMPBR()) return CBcc_imm(ctx, dec); // -> CBEQ_64_imm
	if(sf && cc==7 && HasCMPBR()) return CBcc_imm(ctx, dec); // -> CBNE_64_imm
	if((cc&6)==4) UNALLOCATED(ENC_UNALLOCATED_825_COMPBRANCH_IMM);
	UNMATCHED;
}

int decode_iclass_compbranch_regs(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, cc=(INSWORD>>21)&7;
	if(!sf && !cc && HasCMPBR()) return CBcc_regs(ctx, dec); // -> CBGT_32_regs
	if(!sf && cc==1 && HasCMPBR()) return CBcc_regs(ctx, dec); // -> CBGE_32_regs
	if(!sf && cc==2 && HasCMPBR()) return CBcc_regs(ctx, dec); // -> CBHI_32_regs
	if(!sf && cc==3 && HasCMPBR()) return CBcc_regs(ctx, dec); // -> CBHS_32_regs
	if(!sf && cc==6 && HasCMPBR()) return CBcc_regs(ctx, dec); // -> CBEQ_32_regs
	if(!sf && cc==7 && HasCMPBR()) return CBcc_regs(ctx, dec); // -> CBNE_32_regs
	if(sf && !cc && HasCMPBR()) return CBcc_regs(ctx, dec); // -> CBGT_64_regs
	if(sf && cc==1 && HasCMPBR()) return CBcc_regs(ctx, dec); // -> CBGE_64_regs
	if(sf && cc==2 && HasCMPBR()) return CBcc_regs(ctx, dec); // -> CBHI_64_regs
	if(sf && cc==3 && HasCMPBR()) return CBcc_regs(ctx, dec); // -> CBHS_64_regs
	if(sf && cc==6 && HasCMPBR()) return CBcc_regs(ctx, dec); // -> CBEQ_64_regs
	if(sf && cc==7 && HasCMPBR()) return CBcc_regs(ctx, dec); // -> CBNE_64_regs
	if((cc&6)==4) UNALLOCATED(ENC_UNALLOCATED_826_COMPBRANCH_REGS);
	UNMATCHED;
}

int decode_iclass_condbranch(context *ctx, Instruction *dec)
{
	uint32_t o0=(INSWORD>>4)&1;
	if(!o0) return B_cond(ctx, dec); // -> B_only_condbranch
	if(o0 && HasHBC()) return BC_cond(ctx, dec); // -> BC_only_condbranch
	UNMATCHED;
}

int decode_iclass_exception(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>21)&7, op2=(INSWORD>>2)&7, LL=INSWORD&3;
	if(!opc && !op2 && !LL) UNALLOCATED(ENC_UNALLOCATED_832_EXCEPTION);
	if(!opc && !op2 && LL==1) return SVC(ctx, dec); // -> SVC_EX_exception
	if(!opc && !op2 && LL==2) return HVC(ctx, dec); // -> HVC_EX_exception
	if(!opc && !op2 && LL==3) return SMC(ctx, dec); // -> SMC_EX_exception
	if(opc==1 && !op2 && !LL) return BRK(ctx, dec); // -> BRK_EX_exception
	if(opc==1 && !op2 && LL) UNALLOCATED(ENC_UNALLOCATED_830_EXCEPTION);
	if(opc==2 && !op2 && !LL) return HLT(ctx, dec); // -> HLT_EX_exception
	if(opc==2 && !op2 && LL) UNALLOCATED(ENC_UNALLOCATED_831_EXCEPTION);
	if(opc==5 && !op2 && !LL) UNALLOCATED(ENC_UNALLOCATED_833_EXCEPTION);
	if(opc==5 && !op2 && LL==1) return DCPS1(ctx, dec); // -> DCPS1_DC_exception
	if(opc==5 && !op2 && LL==2) return DCPS2(ctx, dec); // -> DCPS2_DC_exception
	if(opc==5 && !op2 && LL==3) return DCPS3(ctx, dec); // -> DCPS3_DC_exception
	if((opc&3)==3 && !op2) UNALLOCATED(ENC_UNALLOCATED_829_EXCEPTION);
	if((opc&5)==4 && !op2) UNALLOCATED(ENC_UNALLOCATED_828_EXCEPTION);
	if(op2) UNALLOCATED(ENC_UNALLOCATED_827_EXCEPTION);
	UNMATCHED;
}

int decode_iclass_hints(context *ctx, Instruction *dec)
{
	uint32_t CRm=(INSWORD>>8)&15, op2=(INSWORD>>5)&7;
	if(!CRm && !op2) return NOP(ctx, dec); // -> NOP_HI_hints
	if(!CRm && op2==1) return YIELD(ctx, dec); // -> YIELD_HI_hints
	if(!CRm && op2==2) return WFE(ctx, dec); // -> WFE_HI_hints
	if(!CRm && op2==3) return WFI(ctx, dec); // -> WFI_HI_hints
	if(!CRm && op2==4) return SEV(ctx, dec); // -> SEV_HI_hints
	if(!CRm && op2==5) return SEVL(ctx, dec); // -> SEVL_HI_hints
	if(!CRm && op2==6 && HasDGH()) return DGH(ctx, dec); // -> DGH_HI_hints
	if(!CRm && op2==7 && HasPAuth()) return XPAC(ctx, dec); // -> XPACLRI_HI_hints
	if(CRm==1 && !op2 && HasPAuth()) return PACIA(ctx, dec); // -> PACIA1716_HI_hints
	if(CRm==1 && op2==2 && HasPAuth()) return PACIB(ctx, dec); // -> PACIB1716_HI_hints
	if(CRm==1 && op2==4 && HasPAuth()) return AUTIA(ctx, dec); // -> AUTIA1716_HI_hints
	if(CRm==1 && op2==6 && HasPAuth()) return AUTIB(ctx, dec); // -> AUTIB1716_HI_hints
	if(CRm==2 && !op2 && HasRAS()) return ESB(ctx, dec); // -> ESB_HI_hints
	if(CRm==2 && op2==1 && HasSPE()) return PSB(ctx, dec); // -> PSB_HC_hints
	if(CRm==2 && op2==2 && HasTRF()) return TSB(ctx, dec); // -> TSB_HC_hints
	if(CRm==2 && op2==3 && HasGCS()) return GCSB(ctx, dec); // -> GCSB_HD_hints
	if(CRm==2 && op2==4) return CSDB(ctx, dec); // -> CSDB_HI_hints
	if(CRm==2 && op2==6 && HasCLRBHB()) return CLRBHB(ctx, dec); // -> CLRBHB_HI_hints
	if(CRm==3 && !op2 && HasPAuth()) return PACIA(ctx, dec); // -> PACIAZ_HI_hints
	if(CRm==3 && op2==1 && HasPAuth()) return PACIA(ctx, dec); // -> PACIASP_HI_hints
	if(CRm==3 && op2==2 && HasPAuth()) return PACIB(ctx, dec); // -> PACIBZ_HI_hints
	if(CRm==3 && op2==3 && HasPAuth()) return PACIB(ctx, dec); // -> PACIBSP_HI_hints
	if(CRm==3 && op2==4 && HasPAuth()) return AUTIA(ctx, dec); // -> AUTIAZ_HI_hints
	if(CRm==3 && op2==5 && HasPAuth()) return AUTIA(ctx, dec); // -> AUTIASP_HI_hints
	if(CRm==3 && op2==6 && HasPAuth()) return AUTIB(ctx, dec); // -> AUTIBZ_HI_hints
	if(CRm==3 && op2==7 && HasPAuth()) return AUTIB(ctx, dec); // -> AUTIBSP_HI_hints
	if(CRm==4 && op2==7 && HasPAuth_LR()) return PACM(ctx, dec); // -> PACM_HI_hints
	if(CRm==5 && !op2 && HasCHK()) return CHKFEAT(ctx, dec); // -> CHKFEAT_HF_hints
	if(CRm==6 && op2==4 && HasCMH()) return STCPH(ctx, dec); // -> STCPH_HI_hints
	if(CRm==6 && !(op2&6) && HasPCDPHINT()) return STSHH(ctx, dec); // -> STSHH_HI_hints
	if(CRm==6 && (op2&6)==2 && HasCMH()) return SHUH(ctx, dec); // -> SHUH_HI_hints
	if(CRm==4 && !(op2&1) && HasBTI()) return BTI(ctx, dec); // -> BTI_HB_hints
	if(1) return HINT(ctx, dec); // -> HINT_HM_hints
	UNMATCHED;
}

int decode_iclass_miscbranch(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>21)&7, op2=INSWORD&0x1f;
	if(!opc && op2==0x1f && HasPAuth_LR()) return RETASPPC_imm(ctx, dec); // -> RETAASPPC_only_miscbranch
	if(opc==1 && op2==0x1f && HasPAuth_LR()) return RETASPPC_imm(ctx, dec); // -> RETABSPPC_only_miscbranch
	if(!(opc&6) && op2!=0x1f) UNALLOCATED(ENC_UNALLOCATED_836_MISCBRANCH);
	if((opc&6)==2) UNALLOCATED(ENC_UNALLOCATED_835_MISCBRANCH);
	if((opc&4)==4) UNALLOCATED(ENC_UNALLOCATED_834_MISCBRANCH);
	UNMATCHED;
}

int decode_iclass_pstate(context *ctx, Instruction *dec)
{
	uint32_t op1=(INSWORD>>16)&7, op2=(INSWORD>>5)&7, Rt=INSWORD&0x1f;
	if(!((op1 << 3) | op2) && Rt==0x1f && HasFlagM()) return CFINV(ctx, dec); // -> CFINV_M_pstate
	if(((op1 << 3) | op2)==1 && Rt==0x1f && HasFlagM2()) return XAFLAG(ctx, dec); // -> XAFLAG_M_pstate
	if(((op1 << 3) | op2)==2 && Rt==0x1f && HasFlagM2()) return AXFLAG(ctx, dec); // -> AXFLAG_M_pstate
	if(((op1 << 3) | op2)&0x3e && Rt==0x1f) return MSR_imm(ctx, dec); // -> MSR_SI_pstate
	if(Rt==0x1e) UNALLOCATED(ENC_UNALLOCATED_841_PSTATE);
	if((Rt&0x1e)==0x1c) UNALLOCATED(ENC_UNALLOCATED_840_PSTATE);
	if((Rt&0x1c)==0x18) UNALLOCATED(ENC_UNALLOCATED_839_PSTATE);
	if((Rt&0x18)==0x10) UNALLOCATED(ENC_UNALLOCATED_838_PSTATE);
	if(!(Rt&0x10)) UNALLOCATED(ENC_UNALLOCATED_837_PSTATE);
	UNMATCHED;
}

int decode_iclass_systeminstrs(context *ctx, Instruction *dec)
{
	uint32_t L=(INSWORD>>21)&1;
	if(!L) return SYS(ctx, dec); // -> SYS_CR_systeminstrs
	if(L) return SYSL(ctx, dec); // -> SYSL_RC_systeminstrs
	UNMATCHED;
}

int decode_iclass_systeminstrswithreg(context *ctx, Instruction *dec)
{
	uint32_t CRm=(INSWORD>>8)&15, op2=(INSWORD>>5)&7;
	if(!CRm && !op2 && HasWFxT()) return WFET(ctx, dec); // -> WFET_only_systeminstrswithreg
	if(!CRm && op2==1 && HasWFxT()) return WFIT(ctx, dec); // -> WFIT_only_systeminstrswithreg
	if(!CRm && (op2&6)==2) UNALLOCATED(ENC_UNALLOCATED_844_SYSTEMINSTRSWITHREG);
	if(!CRm && (op2&4)==4) UNALLOCATED(ENC_UNALLOCATED_843_SYSTEMINSTRSWITHREG);
	if(CRm) UNALLOCATED(ENC_UNALLOCATED_842_SYSTEMINSTRSWITHREG);
	UNMATCHED;
}

int decode_iclass_syspairinstrs(context *ctx, Instruction *dec)
{
	uint32_t L=(INSWORD>>21)&1;
	if(!L && HasSYSINSTR128()) return SYSP(ctx, dec); // -> SYSP_CR_syspairinstrs
	if(L) UNALLOCATED(ENC_UNALLOCATED_845_SYSPAIRINSTRS);
	UNMATCHED;
}

int decode_iclass_systemmove(context *ctx, Instruction *dec)
{
	uint32_t L=(INSWORD>>21)&1;
	if(!L) return MSR_reg(ctx, dec); // -> MSR_SR_systemmove
	if(L) return MRS(ctx, dec); // -> MRS_RS_systemmove
	UNMATCHED;
}

int decode_iclass_systemmovepr(context *ctx, Instruction *dec)
{
	uint32_t L=(INSWORD>>21)&1;
	if(!L && HasSYSREG128()) return MSRR(ctx, dec); // -> MSRR_SR_systemmovepr
	if(L && HasSYSREG128()) return MRRS(ctx, dec); // -> MRRS_RS_systemmovepr
	UNMATCHED;
}

int decode_iclass_testbranch(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>24)&1;
	if(!op) return TBZ(ctx, dec); // -> TBZ_only_testbranch
	if(op) return TBNZ(ctx, dec); // -> TBNZ_only_testbranch
	UNMATCHED;
}

int decode_iclass_branch_imm(context *ctx, Instruction *dec)
{
	uint32_t op=INSWORD>>31;
	if(!op) return B_uncond(ctx, dec); // -> B_only_branch_imm
	if(op) return BL(ctx, dec); // -> BL_only_branch_imm
	UNMATCHED;
}

int decode_iclass_branch_reg(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>21)&15, op2=(INSWORD>>16)&0x1f, op3=(INSWORD>>10)&0x3f, Rn=(INSWORD>>5)&0x1f, op4=INSWORD&0x1f;
	if(opc==2 && op2==0x1f && op3==2 && Rn==0x1f && op4==0x1f && HasPAuth()) return RETA(ctx, dec); // -> RETAA_64E_branch_reg
	if(opc==2 && op2==0x1f && op3==2 && Rn==0x1f && op4!=0x1f && HasPAuth_LR()) return RETASPPCR_reg(ctx, dec); // -> RETAASPPCR_64M_branch_reg
	if(opc==2 && op2==0x1f && op3==3 && Rn==0x1f && op4==0x1f && HasPAuth()) return RETA(ctx, dec); // -> RETAB_64E_branch_reg
	if(opc==2 && op2==0x1f && op3==3 && Rn==0x1f && op4!=0x1f && HasPAuth_LR()) return RETASPPCR_reg(ctx, dec); // -> RETABSPPCR_64M_branch_reg
	if(opc==4 && op2==0x1f && !op3 && Rn==0x1f && !op4) return ERET(ctx, dec); // -> ERET_64E_branch_reg
	if(opc==4 && op2==0x1f && op3==2 && Rn==0x1f && op4==0x1f && HasPAuth()) return ERETA(ctx, dec); // -> ERETAA_64E_branch_reg
	if(opc==4 && op2==0x1f && op3==3 && Rn==0x1f && op4==0x1f && HasPAuth()) return ERETA(ctx, dec); // -> ERETAB_64E_branch_reg
	if(opc==5 && op2==0x1f && !op3 && Rn==0x1f && !op4) return DRPS(ctx, dec); // -> DRPS_64E_branch_reg
	if((opc&14)==4 && op2==0x1f && !op3 && Rn==0x1f && op4) UNALLOCATED(ENC_UNALLOCATED_866_BRANCH_REG);
	if(opc==4 && op2==0x1f && (op3&0x3e)==2 && Rn==0x1f && op4==0x1d) UNALLOCATED(ENC_UNALLOCATED_870_BRANCH_REG);
	if(opc==4 && op2==0x1f && (op3&0x3e)==2 && Rn==0x1f && (op4&0x1d)==0x19) UNALLOCATED(ENC_UNALLOCATED_869_BRANCH_REG);
	if(opc==4 && op2==0x1f && (op3&0x3e)==2 && Rn==0x1f && (op4&0x19)==0x11) UNALLOCATED(ENC_UNALLOCATED_868_BRANCH_REG);
	if(opc==4 && op2==0x1f && (op3&0x3e)==2 && Rn==0x1f && (op4&0x11)==1) UNALLOCATED(ENC_UNALLOCATED_867_BRANCH_REG);
	if(!opc && op2==0x1f && !op3 && !op4) return BR(ctx, dec); // -> BR_64_branch_reg
	if(!opc && op2==0x1f && op3==2 && op4==0x1f && HasPAuth()) return BRA(ctx, dec); // -> BRAAZ_64_branch_reg
	if(!opc && op2==0x1f && op3==3 && op4==0x1f && HasPAuth()) return BRA(ctx, dec); // -> BRABZ_64_branch_reg
	if(opc==1 && op2==0x1f && !op3 && !op4) return BLR(ctx, dec); // -> BLR_64_branch_reg
	if(opc==1 && op2==0x1f && !op3 && op4) UNALLOCATED(ENC_UNALLOCATED_862_BRANCH_REG);
	if(opc==1 && op2==0x1f && op3==2 && op4==0x1f && HasPAuth()) return BLRA(ctx, dec); // -> BLRAAZ_64_branch_reg
	if(opc==1 && op2==0x1f && op3==3 && op4==0x1f && HasPAuth()) return BLRA(ctx, dec); // -> BLRABZ_64_branch_reg
	if(opc==2 && op2==0x1f && !op3 && !op4) return RET(ctx, dec); // -> RET_64R_branch_reg
	if(opc==5 && op2==0x1f && (op3&0x3e)==2 && Rn==0x1f && op4&1) UNALLOCATED(ENC_UNALLOCATED_865_BRANCH_REG);
	if(!(opc&13) && op2==0x1f && !op3 && op4) UNALLOCATED(ENC_UNALLOCATED_861_BRANCH_REG);
	if(opc==2 && op2==0x1f && (op3&0x3e)==2 && Rn!=0x1f) UNALLOCATED(ENC_UNALLOCATED_860_BRANCH_REG);
	if((opc&14)==4 && op2==0x1f && op3==1 && Rn==0x1f) UNALLOCATED(ENC_UNALLOCATED_863_BRANCH_REG);
	if((opc&14)==4 && op2==0x1f && (op3&0x3e)==2 && Rn==0x1f && !(op4&1)) UNALLOCATED(ENC_UNALLOCATED_864_BRANCH_REG);
	if(!(opc&14) && op2==0x1f && (op3&0x3e)==2 && op4!=0x1f) UNALLOCATED(ENC_UNALLOCATED_857_BRANCH_REG);
	if((opc&14)==4 && op2==0x1f && !(op3&0x3c) && Rn!=0x1f) UNALLOCATED(ENC_UNALLOCATED_855_BRANCH_REG);
	if(opc==1 && op2==0x1f && op3==1) UNALLOCATED(ENC_UNALLOCATED_859_BRANCH_REG);
	if(opc==8 && op2==0x1f && op3==2 && HasPAuth()) return BRA(ctx, dec); // -> BRAA_64P_branch_reg
	if(opc==8 && op2==0x1f && op3==3 && HasPAuth()) return BRA(ctx, dec); // -> BRAB_64P_branch_reg
	if(opc==9 && op2==0x1f && op3==2 && HasPAuth()) return BLRA(ctx, dec); // -> BLRAA_64P_branch_reg
	if(opc==9 && op2==0x1f && op3==3 && HasPAuth()) return BLRA(ctx, dec); // -> BLRAB_64P_branch_reg
	if(!(opc&13) && op2==0x1f && op3==1) UNALLOCATED(ENC_UNALLOCATED_858_BRANCH_REG);
	if(opc==3 && op2==0x1f && !(op3&0x3c)) UNALLOCATED(ENC_UNALLOCATED_854_BRANCH_REG);
	if((opc&14)==8 && op2==0x1f && !(op3&0x3e)) UNALLOCATED(ENC_UNALLOCATED_856_BRANCH_REG);
	if((opc&14)==6 && op2==0x1f && !(op3&0x3c)) UNALLOCATED(ENC_UNALLOCATED_852_BRANCH_REG);
	if((opc&14)==10 && op2==0x1f && !(op3&0x3c)) UNALLOCATED(ENC_UNALLOCATED_853_BRANCH_REG);
	if((opc&12)==12 && op2==0x1f && !(op3&0x3c)) UNALLOCATED(ENC_UNALLOCATED_851_BRANCH_REG);
	if(op2==0x1f && (op3&0x3c)==4) UNALLOCATED(ENC_UNALLOCATED_850_BRANCH_REG);
	if(op2==0x1f && (op3&0x38)==8) UNALLOCATED(ENC_UNALLOCATED_849_BRANCH_REG);
	if(op2==0x1f && (op3&0x30)==0x10) UNALLOCATED(ENC_UNALLOCATED_848_BRANCH_REG);
	if(op2==0x1f && (op3&0x20)==0x20) UNALLOCATED(ENC_UNALLOCATED_847_BRANCH_REG);
	if(op2!=0x1f) UNALLOCATED(ENC_UNALLOCATED_846_BRANCH_REG);
	UNMATCHED;
}

int decode_iclass_memop_128(context *ctx, Instruction *dec)
{
	uint32_t S=(INSWORD>>30)&1, A=(INSWORD>>23)&1, R=(INSWORD>>22)&1, o3=(INSWORD>>15)&1, opc=(INSWORD>>12)&7;
	if(!S && !A && !R && !o3 && opc==1 && HasLSE128()) return LDCLRP(ctx, dec); // -> LDCLRP_128_memop_128
	if(!S && !A && !R && !o3 && opc==3 && HasLSE128()) return LDSETP(ctx, dec); // -> LDSETP_128_memop_128
	if(!S && !A && !R && o3 && !opc && HasLSE128()) return SWPP(ctx, dec); // -> SWPP_128_memop_128
	if(!S && !A && !R && o3 && opc==1 && HasD128() && HasTHE()) return RCWCLRP(ctx, dec); // -> RCWCLRP_128_memop_128
	if(!S && !A && !R && o3 && opc==2 && HasD128() && HasTHE()) return RCWSWPP(ctx, dec); // -> RCWSWPP_128_memop_128
	if(!S && !A && !R && o3 && opc==3 && HasD128() && HasTHE()) return RCWSETP(ctx, dec); // -> RCWSETP_128_memop_128
	if(!S && !A && R && !o3 && opc==1 && HasLSE128()) return LDCLRP(ctx, dec); // -> LDCLRPL_128_memop_128
	if(!S && !A && R && !o3 && opc==3 && HasLSE128()) return LDSETP(ctx, dec); // -> LDSETPL_128_memop_128
	if(!S && !A && R && o3 && !opc && HasLSE128()) return SWPP(ctx, dec); // -> SWPPL_128_memop_128
	if(!S && !A && R && o3 && opc==1 && HasD128() && HasTHE()) return RCWCLRP(ctx, dec); // -> RCWCLRPL_128_memop_128
	if(!S && !A && R && o3 && opc==2 && HasD128() && HasTHE()) return RCWSWPP(ctx, dec); // -> RCWSWPPL_128_memop_128
	if(!S && !A && R && o3 && opc==3 && HasD128() && HasTHE()) return RCWSETP(ctx, dec); // -> RCWSETPL_128_memop_128
	if(!S && A && !R && !o3 && opc==1 && HasLSE128()) return LDCLRP(ctx, dec); // -> LDCLRPA_128_memop_128
	if(!S && A && !R && !o3 && opc==3 && HasLSE128()) return LDSETP(ctx, dec); // -> LDSETPA_128_memop_128
	if(!S && A && !R && o3 && !opc && HasLSE128()) return SWPP(ctx, dec); // -> SWPPA_128_memop_128
	if(!S && A && !R && o3 && opc==1 && HasD128() && HasTHE()) return RCWCLRP(ctx, dec); // -> RCWCLRPA_128_memop_128
	if(!S && A && !R && o3 && opc==2 && HasD128() && HasTHE()) return RCWSWPP(ctx, dec); // -> RCWSWPPA_128_memop_128
	if(!S && A && !R && o3 && opc==3 && HasD128() && HasTHE()) return RCWSETP(ctx, dec); // -> RCWSETPA_128_memop_128
	if(!S && A && R && !o3 && opc==1 && HasLSE128()) return LDCLRP(ctx, dec); // -> LDCLRPAL_128_memop_128
	if(!S && A && R && !o3 && opc==3 && HasLSE128()) return LDSETP(ctx, dec); // -> LDSETPAL_128_memop_128
	if(!S && A && R && o3 && !opc && HasLSE128()) return SWPP(ctx, dec); // -> SWPPAL_128_memop_128
	if(!S && A && R && o3 && opc==1 && HasD128() && HasTHE()) return RCWCLRP(ctx, dec); // -> RCWCLRPAL_128_memop_128
	if(!S && A && R && o3 && opc==2 && HasD128() && HasTHE()) return RCWSWPP(ctx, dec); // -> RCWSWPPAL_128_memop_128
	if(!S && A && R && o3 && opc==3 && HasD128() && HasTHE()) return RCWSETP(ctx, dec); // -> RCWSETPAL_128_memop_128
	if(S && !A && !R && o3 && opc==1 && HasD128() && HasTHE()) return RCWSCLRP(ctx, dec); // -> RCWSCLRP_128_memop_128
	if(S && !A && !R && o3 && opc==2 && HasD128() && HasTHE()) return RCWSSWPP(ctx, dec); // -> RCWSSWPP_128_memop_128
	if(S && !A && !R && o3 && opc==3 && HasD128() && HasTHE()) return RCWSSETP(ctx, dec); // -> RCWSSETP_128_memop_128
	if(S && !A && R && o3 && opc==1 && HasD128() && HasTHE()) return RCWSCLRP(ctx, dec); // -> RCWSCLRPL_128_memop_128
	if(S && !A && R && o3 && opc==2 && HasD128() && HasTHE()) return RCWSSWPP(ctx, dec); // -> RCWSSWPPL_128_memop_128
	if(S && !A && R && o3 && opc==3 && HasD128() && HasTHE()) return RCWSSETP(ctx, dec); // -> RCWSSETPL_128_memop_128
	if(S && A && !R && o3 && opc==1 && HasD128() && HasTHE()) return RCWSCLRP(ctx, dec); // -> RCWSCLRPA_128_memop_128
	if(S && A && !R && o3 && opc==2 && HasD128() && HasTHE()) return RCWSSWPP(ctx, dec); // -> RCWSSWPPA_128_memop_128
	if(S && A && !R && o3 && opc==3 && HasD128() && HasTHE()) return RCWSSETP(ctx, dec); // -> RCWSSETPA_128_memop_128
	if(S && A && R && o3 && opc==1 && HasD128() && HasTHE()) return RCWSCLRP(ctx, dec); // -> RCWSCLRPAL_128_memop_128
	if(S && A && R && o3 && opc==2 && HasD128() && HasTHE()) return RCWSSWPP(ctx, dec); // -> RCWSSWPPAL_128_memop_128
	if(S && A && R && o3 && opc==3 && HasD128() && HasTHE()) return RCWSSETP(ctx, dec); // -> RCWSSETPAL_128_memop_128
	if(S && o3 && !opc) UNALLOCATED(ENC_UNALLOCATED_874_MEMOP_128);
	if(!S && !o3 && !(opc&5)) UNALLOCATED(ENC_UNALLOCATED_873_MEMOP_128);
	if(S && !o3 && !(opc&4)) UNALLOCATED(ENC_UNALLOCATED_872_MEMOP_128);
	if((opc&4)==4) UNALLOCATED(ENC_UNALLOCATED_871_MEMOP_128);
	UNMATCHED;
}

int decode_iclass_asisdlse(context *ctx, Instruction *dec)
{
	uint32_t L=(INSWORD>>22)&1, opcode=(INSWORD>>12)&15;
	if(!L && !opcode && HasAdvSIMD()) return ST4_advsimd_mult(ctx, dec); // -> ST4_asisdlse_R4
	if(!L && opcode==2 && HasAdvSIMD()) return ST1_advsimd_mult(ctx, dec); // -> ST1_asisdlse_R4_4v
	if(!L && opcode==4 && HasAdvSIMD()) return ST3_advsimd_mult(ctx, dec); // -> ST3_asisdlse_R3
	if(!L && opcode==6 && HasAdvSIMD()) return ST1_advsimd_mult(ctx, dec); // -> ST1_asisdlse_R3_3v
	if(!L && opcode==7 && HasAdvSIMD()) return ST1_advsimd_mult(ctx, dec); // -> ST1_asisdlse_R1_1v
	if(!L && opcode==8 && HasAdvSIMD()) return ST2_advsimd_mult(ctx, dec); // -> ST2_asisdlse_R2
	if(!L && opcode==10 && HasAdvSIMD()) return ST1_advsimd_mult(ctx, dec); // -> ST1_asisdlse_R2_2v
	if(L && !opcode && HasAdvSIMD()) return LD4_advsimd_mult(ctx, dec); // -> LD4_asisdlse_R4
	if(L && opcode==2 && HasAdvSIMD()) return LD1_advsimd_mult(ctx, dec); // -> LD1_asisdlse_R4_4v
	if(L && opcode==4 && HasAdvSIMD()) return LD3_advsimd_mult(ctx, dec); // -> LD3_asisdlse_R3
	if(L && opcode==6 && HasAdvSIMD()) return LD1_advsimd_mult(ctx, dec); // -> LD1_asisdlse_R3_3v
	if(L && opcode==7 && HasAdvSIMD()) return LD1_advsimd_mult(ctx, dec); // -> LD1_asisdlse_R1_1v
	if(L && opcode==8 && HasAdvSIMD()) return LD2_advsimd_mult(ctx, dec); // -> LD2_asisdlse_R2
	if(L && opcode==10 && HasAdvSIMD()) return LD1_advsimd_mult(ctx, dec); // -> LD1_asisdlse_R2_2v
	if(opcode==5) UNALLOCATED(ENC_UNALLOCATED_877_ASISDLSE);
	if((opcode&5)==1) UNALLOCATED(ENC_UNALLOCATED_876_ASISDLSE);
	if((opcode&12)==12) UNALLOCATED(ENC_UNALLOCATED_875_ASISDLSE);
	UNMATCHED;
}

int decode_iclass_asisdlsep(context *ctx, Instruction *dec)
{
	uint32_t L=(INSWORD>>22)&1, Rm=(INSWORD>>16)&0x1f, opcode=(INSWORD>>12)&15;
	if(!L && Rm==0x1f && !opcode && HasAdvSIMD()) return ST4_advsimd_mult(ctx, dec); // -> ST4_asisdlsep_I4_i
	if(!L && Rm==0x1f && opcode==2 && HasAdvSIMD()) return ST1_advsimd_mult(ctx, dec); // -> ST1_asisdlsep_I4_i4
	if(!L && Rm==0x1f && opcode==4 && HasAdvSIMD()) return ST3_advsimd_mult(ctx, dec); // -> ST3_asisdlsep_I3_i
	if(!L && Rm==0x1f && opcode==6 && HasAdvSIMD()) return ST1_advsimd_mult(ctx, dec); // -> ST1_asisdlsep_I3_i3
	if(!L && Rm==0x1f && opcode==7 && HasAdvSIMD()) return ST1_advsimd_mult(ctx, dec); // -> ST1_asisdlsep_I1_i1
	if(!L && Rm==0x1f && opcode==8 && HasAdvSIMD()) return ST2_advsimd_mult(ctx, dec); // -> ST2_asisdlsep_I2_i
	if(!L && Rm==0x1f && opcode==10 && HasAdvSIMD()) return ST1_advsimd_mult(ctx, dec); // -> ST1_asisdlsep_I2_i2
	if(!L && Rm!=0x1f && !opcode && HasAdvSIMD()) return ST4_advsimd_mult(ctx, dec); // -> ST4_asisdlsep_R4_r
	if(!L && Rm!=0x1f && opcode==2 && HasAdvSIMD()) return ST1_advsimd_mult(ctx, dec); // -> ST1_asisdlsep_R4_r4
	if(!L && Rm!=0x1f && opcode==4 && HasAdvSIMD()) return ST3_advsimd_mult(ctx, dec); // -> ST3_asisdlsep_R3_r
	if(!L && Rm!=0x1f && opcode==6 && HasAdvSIMD()) return ST1_advsimd_mult(ctx, dec); // -> ST1_asisdlsep_R3_r3
	if(!L && Rm!=0x1f && opcode==7 && HasAdvSIMD()) return ST1_advsimd_mult(ctx, dec); // -> ST1_asisdlsep_R1_r1
	if(!L && Rm!=0x1f && opcode==8 && HasAdvSIMD()) return ST2_advsimd_mult(ctx, dec); // -> ST2_asisdlsep_R2_r
	if(!L && Rm!=0x1f && opcode==10 && HasAdvSIMD()) return ST1_advsimd_mult(ctx, dec); // -> ST1_asisdlsep_R2_r2
	if(L && Rm==0x1f && !opcode && HasAdvSIMD()) return LD4_advsimd_mult(ctx, dec); // -> LD4_asisdlsep_I4_i
	if(L && Rm==0x1f && opcode==2 && HasAdvSIMD()) return LD1_advsimd_mult(ctx, dec); // -> LD1_asisdlsep_I4_i4
	if(L && Rm==0x1f && opcode==4 && HasAdvSIMD()) return LD3_advsimd_mult(ctx, dec); // -> LD3_asisdlsep_I3_i
	if(L && Rm==0x1f && opcode==6 && HasAdvSIMD()) return LD1_advsimd_mult(ctx, dec); // -> LD1_asisdlsep_I3_i3
	if(L && Rm==0x1f && opcode==7 && HasAdvSIMD()) return LD1_advsimd_mult(ctx, dec); // -> LD1_asisdlsep_I1_i1
	if(L && Rm==0x1f && opcode==8 && HasAdvSIMD()) return LD2_advsimd_mult(ctx, dec); // -> LD2_asisdlsep_I2_i
	if(L && Rm==0x1f && opcode==10 && HasAdvSIMD()) return LD1_advsimd_mult(ctx, dec); // -> LD1_asisdlsep_I2_i2
	if(L && Rm!=0x1f && !opcode && HasAdvSIMD()) return LD4_advsimd_mult(ctx, dec); // -> LD4_asisdlsep_R4_r
	if(L && Rm!=0x1f && opcode==2 && HasAdvSIMD()) return LD1_advsimd_mult(ctx, dec); // -> LD1_asisdlsep_R4_r4
	if(L && Rm!=0x1f && opcode==4 && HasAdvSIMD()) return LD3_advsimd_mult(ctx, dec); // -> LD3_asisdlsep_R3_r
	if(L && Rm!=0x1f && opcode==6 && HasAdvSIMD()) return LD1_advsimd_mult(ctx, dec); // -> LD1_asisdlsep_R3_r3
	if(L && Rm!=0x1f && opcode==7 && HasAdvSIMD()) return LD1_advsimd_mult(ctx, dec); // -> LD1_asisdlsep_R1_r1
	if(L && Rm!=0x1f && opcode==8 && HasAdvSIMD()) return LD2_advsimd_mult(ctx, dec); // -> LD2_asisdlsep_R2_r
	if(L && Rm!=0x1f && opcode==10 && HasAdvSIMD()) return LD1_advsimd_mult(ctx, dec); // -> LD1_asisdlsep_R2_r2
	if(opcode==5) UNALLOCATED(ENC_UNALLOCATED_880_ASISDLSEP);
	if((opcode&5)==1) UNALLOCATED(ENC_UNALLOCATED_879_ASISDLSEP);
	if((opcode&12)==12) UNALLOCATED(ENC_UNALLOCATED_878_ASISDLSEP);
	UNMATCHED;
}

int decode_iclass_asisdlso(context *ctx, Instruction *dec)
{
	uint32_t L=(INSWORD>>22)&1, R=(INSWORD>>21)&1, o2=(INSWORD>>16)&1, opcode=(INSWORD>>13)&7, S=(INSWORD>>12)&1, size=(INSWORD>>10)&3;
	if(!L && !R && !o2 && opcode==4 && !S && size==1 && HasAdvSIMD()) return ST1_advsimd_sngl(ctx, dec); // -> ST1_asisdlso_D1_1d
	if(!L && !R && !o2 && opcode==5 && !S && size==1 && HasAdvSIMD()) return ST3_advsimd_sngl(ctx, dec); // -> ST3_asisdlso_D3_3d
	if(!L && !R && o2 && opcode==4 && !S && size==1 && HasAdvSIMD() && HasLRCPC3()) return STL1_advsimd_sngl(ctx, dec); // -> STL1_asisdlso_D1
	if(!L && R && !o2 && opcode==4 && !S && size==1 && HasAdvSIMD()) return ST2_advsimd_sngl(ctx, dec); // -> ST2_asisdlso_D2_2d
	if(!L && R && !o2 && opcode==5 && !S && size==1 && HasAdvSIMD()) return ST4_advsimd_sngl(ctx, dec); // -> ST4_asisdlso_D4_4d
	if(L && !R && !o2 && opcode==4 && !S && size==1 && HasAdvSIMD()) return LD1_advsimd_sngl(ctx, dec); // -> LD1_asisdlso_D1_1d
	if(L && !R && !o2 && opcode==5 && !S && size==1 && HasAdvSIMD()) return LD3_advsimd_sngl(ctx, dec); // -> LD3_asisdlso_D3_3d
	if(L && !R && o2 && opcode==4 && !S && size==1 && HasAdvSIMD() && HasLRCPC3()) return LDAP1_advsimd_sngl(ctx, dec); // -> LDAP1_asisdlso_D1
	if(L && R && !o2 && opcode==4 && !S && size==1 && HasAdvSIMD()) return LD2_advsimd_sngl(ctx, dec); // -> LD2_asisdlso_D2_2d
	if(L && R && !o2 && opcode==5 && !S && size==1 && HasAdvSIMD()) return LD4_advsimd_sngl(ctx, dec); // -> LD4_asisdlso_D4_4d
	if(!R && o2 && opcode==4 && S && size==1) UNALLOCATED(ENC_UNALLOCATED_889_ASISDLSO);
	if(!L && !R && !o2 && opcode==4 && !size && HasAdvSIMD()) return ST1_advsimd_sngl(ctx, dec); // -> ST1_asisdlso_S1_1s
	if(!L && !R && !o2 && opcode==5 && !size && HasAdvSIMD()) return ST3_advsimd_sngl(ctx, dec); // -> ST3_asisdlso_S3_3s
	if(!L && R && !o2 && opcode==4 && !size && HasAdvSIMD()) return ST2_advsimd_sngl(ctx, dec); // -> ST2_asisdlso_S2_2s
	if(!L && R && !o2 && opcode==5 && !size && HasAdvSIMD()) return ST4_advsimd_sngl(ctx, dec); // -> ST4_asisdlso_S4_4s
	if(L && !R && !o2 && opcode==4 && !size && HasAdvSIMD()) return LD1_advsimd_sngl(ctx, dec); // -> LD1_asisdlso_S1_1s
	if(L && !R && !o2 && opcode==5 && !size && HasAdvSIMD()) return LD3_advsimd_sngl(ctx, dec); // -> LD3_asisdlso_S3_3s
	if(L && R && !o2 && opcode==4 && !size && HasAdvSIMD()) return LD2_advsimd_sngl(ctx, dec); // -> LD2_asisdlso_S2_2s
	if(L && R && !o2 && opcode==5 && !size && HasAdvSIMD()) return LD4_advsimd_sngl(ctx, dec); // -> LD4_asisdlso_S4_4s
	if(!R && o2 && opcode==4 && size!=1) UNALLOCATED(ENC_UNALLOCATED_887_ASISDLSO);
	if(!L && !R && !o2 && opcode==2 && !(size&1) && HasAdvSIMD()) return ST1_advsimd_sngl(ctx, dec); // -> ST1_asisdlso_H1_1h
	if(!L && !R && !o2 && opcode==3 && !(size&1) && HasAdvSIMD()) return ST3_advsimd_sngl(ctx, dec); // -> ST3_asisdlso_H3_3h
	if(!L && R && !o2 && opcode==2 && !(size&1) && HasAdvSIMD()) return ST2_advsimd_sngl(ctx, dec); // -> ST2_asisdlso_H2_2h
	if(!L && R && !o2 && opcode==3 && !(size&1) && HasAdvSIMD()) return ST4_advsimd_sngl(ctx, dec); // -> ST4_asisdlso_H4_4h
	if(L && !R && !o2 && opcode==2 && !(size&1) && HasAdvSIMD()) return LD1_advsimd_sngl(ctx, dec); // -> LD1_asisdlso_H1_1h
	if(L && !R && !o2 && opcode==3 && !(size&1) && HasAdvSIMD()) return LD3_advsimd_sngl(ctx, dec); // -> LD3_asisdlso_H3_3h
	if(L && !R && !o2 && opcode==6 && !S && HasAdvSIMD()) return LD1R_advsimd(ctx, dec); // -> LD1R_asisdlso_R1
	if(L && !R && !o2 && opcode==7 && !S && HasAdvSIMD()) return LD3R_advsimd(ctx, dec); // -> LD3R_asisdlso_R3
	if(L && R && !o2 && opcode==2 && !(size&1) && HasAdvSIMD()) return LD2_advsimd_sngl(ctx, dec); // -> LD2_asisdlso_H2_2h
	if(L && R && !o2 && opcode==3 && !(size&1) && HasAdvSIMD()) return LD4_advsimd_sngl(ctx, dec); // -> LD4_asisdlso_H4_4h
	if(L && R && !o2 && opcode==6 && !S && HasAdvSIMD()) return LD2R_advsimd(ctx, dec); // -> LD2R_asisdlso_R2
	if(L && R && !o2 && opcode==7 && !S && HasAdvSIMD()) return LD4R_advsimd(ctx, dec); // -> LD4R_asisdlso_R4
	if(!o2 && (opcode&6)==4 && S && size==1) UNALLOCATED(ENC_UNALLOCATED_888_ASISDLSO);
	if(!L && !R && !o2 && !opcode && HasAdvSIMD()) return ST1_advsimd_sngl(ctx, dec); // -> ST1_asisdlso_B1_1b
	if(!L && !R && !o2 && opcode==1 && HasAdvSIMD()) return ST3_advsimd_sngl(ctx, dec); // -> ST3_asisdlso_B3_3b
	if(!L && R && !o2 && !opcode && HasAdvSIMD()) return ST2_advsimd_sngl(ctx, dec); // -> ST2_asisdlso_B2_2b
	if(!L && R && !o2 && opcode==1 && HasAdvSIMD()) return ST4_advsimd_sngl(ctx, dec); // -> ST4_asisdlso_B4_4b
	if(L && !R && !o2 && !opcode && HasAdvSIMD()) return LD1_advsimd_sngl(ctx, dec); // -> LD1_asisdlso_B1_1b
	if(L && !R && !o2 && opcode==1 && HasAdvSIMD()) return LD3_advsimd_sngl(ctx, dec); // -> LD3_asisdlso_B3_3b
	if(L && R && !o2 && !opcode && HasAdvSIMD()) return LD2_advsimd_sngl(ctx, dec); // -> LD2_asisdlso_B2_2b
	if(L && R && !o2 && opcode==1 && HasAdvSIMD()) return LD4_advsimd_sngl(ctx, dec); // -> LD4_asisdlso_B4_4b
	if(!R && o2 && opcode!=4) UNALLOCATED(ENC_UNALLOCATED_882_ASISDLSO);
	if(L && !o2 && (opcode&6)==6 && S) UNALLOCATED(ENC_UNALLOCATED_886_ASISDLSO);
	if(!o2 && (opcode&6)==2 && size&1) UNALLOCATED(ENC_UNALLOCATED_884_ASISDLSO);
	if(!o2 && (opcode&6)==4 && (size&2)==2) UNALLOCATED(ENC_UNALLOCATED_885_ASISDLSO);
	if(!L && !o2 && (opcode&6)==6) UNALLOCATED(ENC_UNALLOCATED_883_ASISDLSO);
	if(R && o2) UNALLOCATED(ENC_UNALLOCATED_881_ASISDLSO);
	UNMATCHED;
}

int decode_iclass_asisdlsop(context *ctx, Instruction *dec)
{
	uint32_t L=(INSWORD>>22)&1, R=(INSWORD>>21)&1, Rm=(INSWORD>>16)&0x1f, opcode=(INSWORD>>13)&7, S=(INSWORD>>12)&1, size=(INSWORD>>10)&3;
	if(!L && !R && Rm==0x1f && opcode==4 && !S && size==1 && HasAdvSIMD()) return ST1_advsimd_sngl(ctx, dec); // -> ST1_asisdlsop_D1_i1d
	if(!L && !R && Rm==0x1f && opcode==5 && !S && size==1 && HasAdvSIMD()) return ST3_advsimd_sngl(ctx, dec); // -> ST3_asisdlsop_D3_i3d
	if(!L && !R && Rm!=0x1f && opcode==4 && !S && size==1 && HasAdvSIMD()) return ST1_advsimd_sngl(ctx, dec); // -> ST1_asisdlsop_DX1_r1d
	if(!L && !R && Rm!=0x1f && opcode==5 && !S && size==1 && HasAdvSIMD()) return ST3_advsimd_sngl(ctx, dec); // -> ST3_asisdlsop_DX3_r3d
	if(!L && R && Rm==0x1f && opcode==4 && !S && size==1 && HasAdvSIMD()) return ST2_advsimd_sngl(ctx, dec); // -> ST2_asisdlsop_D2_i2d
	if(!L && R && Rm==0x1f && opcode==5 && !S && size==1 && HasAdvSIMD()) return ST4_advsimd_sngl(ctx, dec); // -> ST4_asisdlsop_D4_i4d
	if(!L && R && Rm!=0x1f && opcode==4 && !S && size==1 && HasAdvSIMD()) return ST2_advsimd_sngl(ctx, dec); // -> ST2_asisdlsop_DX2_r2d
	if(!L && R && Rm!=0x1f && opcode==5 && !S && size==1 && HasAdvSIMD()) return ST4_advsimd_sngl(ctx, dec); // -> ST4_asisdlsop_DX4_r4d
	if(L && !R && Rm==0x1f && opcode==4 && !S && size==1 && HasAdvSIMD()) return LD1_advsimd_sngl(ctx, dec); // -> LD1_asisdlsop_D1_i1d
	if(L && !R && Rm==0x1f && opcode==5 && !S && size==1 && HasAdvSIMD()) return LD3_advsimd_sngl(ctx, dec); // -> LD3_asisdlsop_D3_i3d
	if(L && !R && Rm!=0x1f && opcode==4 && !S && size==1 && HasAdvSIMD()) return LD1_advsimd_sngl(ctx, dec); // -> LD1_asisdlsop_DX1_r1d
	if(L && !R && Rm!=0x1f && opcode==5 && !S && size==1 && HasAdvSIMD()) return LD3_advsimd_sngl(ctx, dec); // -> LD3_asisdlsop_DX3_r3d
	if(L && R && Rm==0x1f && opcode==4 && !S && size==1 && HasAdvSIMD()) return LD2_advsimd_sngl(ctx, dec); // -> LD2_asisdlsop_D2_i2d
	if(L && R && Rm==0x1f && opcode==5 && !S && size==1 && HasAdvSIMD()) return LD4_advsimd_sngl(ctx, dec); // -> LD4_asisdlsop_D4_i4d
	if(L && R && Rm!=0x1f && opcode==4 && !S && size==1 && HasAdvSIMD()) return LD2_advsimd_sngl(ctx, dec); // -> LD2_asisdlsop_DX2_r2d
	if(L && R && Rm!=0x1f && opcode==5 && !S && size==1 && HasAdvSIMD()) return LD4_advsimd_sngl(ctx, dec); // -> LD4_asisdlsop_DX4_r4d
	if(!L && !R && Rm==0x1f && opcode==4 && !size && HasAdvSIMD()) return ST1_advsimd_sngl(ctx, dec); // -> ST1_asisdlsop_S1_i1s
	if(!L && !R && Rm==0x1f && opcode==5 && !size && HasAdvSIMD()) return ST3_advsimd_sngl(ctx, dec); // -> ST3_asisdlsop_S3_i3s
	if(!L && !R && Rm!=0x1f && opcode==4 && !size && HasAdvSIMD()) return ST1_advsimd_sngl(ctx, dec); // -> ST1_asisdlsop_SX1_r1s
	if(!L && !R && Rm!=0x1f && opcode==5 && !size && HasAdvSIMD()) return ST3_advsimd_sngl(ctx, dec); // -> ST3_asisdlsop_SX3_r3s
	if(!L && R && Rm==0x1f && opcode==4 && !size && HasAdvSIMD()) return ST2_advsimd_sngl(ctx, dec); // -> ST2_asisdlsop_S2_i2s
	if(!L && R && Rm==0x1f && opcode==5 && !size && HasAdvSIMD()) return ST4_advsimd_sngl(ctx, dec); // -> ST4_asisdlsop_S4_i4s
	if(!L && R && Rm!=0x1f && opcode==4 && !size && HasAdvSIMD()) return ST2_advsimd_sngl(ctx, dec); // -> ST2_asisdlsop_SX2_r2s
	if(!L && R && Rm!=0x1f && opcode==5 && !size && HasAdvSIMD()) return ST4_advsimd_sngl(ctx, dec); // -> ST4_asisdlsop_SX4_r4s
	if(L && !R && Rm==0x1f && opcode==4 && !size && HasAdvSIMD()) return LD1_advsimd_sngl(ctx, dec); // -> LD1_asisdlsop_S1_i1s
	if(L && !R && Rm==0x1f && opcode==5 && !size && HasAdvSIMD()) return LD3_advsimd_sngl(ctx, dec); // -> LD3_asisdlsop_S3_i3s
	if(L && !R && Rm!=0x1f && opcode==4 && !size && HasAdvSIMD()) return LD1_advsimd_sngl(ctx, dec); // -> LD1_asisdlsop_SX1_r1s
	if(L && !R && Rm!=0x1f && opcode==5 && !size && HasAdvSIMD()) return LD3_advsimd_sngl(ctx, dec); // -> LD3_asisdlsop_SX3_r3s
	if(L && R && Rm==0x1f && opcode==4 && !size && HasAdvSIMD()) return LD2_advsimd_sngl(ctx, dec); // -> LD2_asisdlsop_S2_i2s
	if(L && R && Rm==0x1f && opcode==5 && !size && HasAdvSIMD()) return LD4_advsimd_sngl(ctx, dec); // -> LD4_asisdlsop_S4_i4s
	if(L && R && Rm!=0x1f && opcode==4 && !size && HasAdvSIMD()) return LD2_advsimd_sngl(ctx, dec); // -> LD2_asisdlsop_SX2_r2s
	if(L && R && Rm!=0x1f && opcode==5 && !size && HasAdvSIMD()) return LD4_advsimd_sngl(ctx, dec); // -> LD4_asisdlsop_SX4_r4s
	if(!L && !R && Rm==0x1f && opcode==2 && !(size&1) && HasAdvSIMD()) return ST1_advsimd_sngl(ctx, dec); // -> ST1_asisdlsop_H1_i1h
	if(!L && !R && Rm==0x1f && opcode==3 && !(size&1) && HasAdvSIMD()) return ST3_advsimd_sngl(ctx, dec); // -> ST3_asisdlsop_H3_i3h
	if(!L && !R && Rm!=0x1f && opcode==2 && !(size&1) && HasAdvSIMD()) return ST1_advsimd_sngl(ctx, dec); // -> ST1_asisdlsop_HX1_r1h
	if(!L && !R && Rm!=0x1f && opcode==3 && !(size&1) && HasAdvSIMD()) return ST3_advsimd_sngl(ctx, dec); // -> ST3_asisdlsop_HX3_r3h
	if(!L && R && Rm==0x1f && opcode==2 && !(size&1) && HasAdvSIMD()) return ST2_advsimd_sngl(ctx, dec); // -> ST2_asisdlsop_H2_i2h
	if(!L && R && Rm==0x1f && opcode==3 && !(size&1) && HasAdvSIMD()) return ST4_advsimd_sngl(ctx, dec); // -> ST4_asisdlsop_H4_i4h
	if(!L && R && Rm!=0x1f && opcode==2 && !(size&1) && HasAdvSIMD()) return ST2_advsimd_sngl(ctx, dec); // -> ST2_asisdlsop_HX2_r2h
	if(!L && R && Rm!=0x1f && opcode==3 && !(size&1) && HasAdvSIMD()) return ST4_advsimd_sngl(ctx, dec); // -> ST4_asisdlsop_HX4_r4h
	if(L && !R && Rm==0x1f && opcode==2 && !(size&1) && HasAdvSIMD()) return LD1_advsimd_sngl(ctx, dec); // -> LD1_asisdlsop_H1_i1h
	if(L && !R && Rm==0x1f && opcode==3 && !(size&1) && HasAdvSIMD()) return LD3_advsimd_sngl(ctx, dec); // -> LD3_asisdlsop_H3_i3h
	if(L && !R && Rm==0x1f && opcode==6 && !S && HasAdvSIMD()) return LD1R_advsimd(ctx, dec); // -> LD1R_asisdlsop_R1_i
	if(L && !R && Rm==0x1f && opcode==7 && !S && HasAdvSIMD()) return LD3R_advsimd(ctx, dec); // -> LD3R_asisdlsop_R3_i
	if(L && !R && Rm!=0x1f && opcode==2 && !(size&1) && HasAdvSIMD()) return LD1_advsimd_sngl(ctx, dec); // -> LD1_asisdlsop_HX1_r1h
	if(L && !R && Rm!=0x1f && opcode==3 && !(size&1) && HasAdvSIMD()) return LD3_advsimd_sngl(ctx, dec); // -> LD3_asisdlsop_HX3_r3h
	if(L && !R && Rm!=0x1f && opcode==6 && !S && HasAdvSIMD()) return LD1R_advsimd(ctx, dec); // -> LD1R_asisdlsop_RX1_r
	if(L && !R && Rm!=0x1f && opcode==7 && !S && HasAdvSIMD()) return LD3R_advsimd(ctx, dec); // -> LD3R_asisdlsop_RX3_r
	if(L && R && Rm==0x1f && opcode==2 && !(size&1) && HasAdvSIMD()) return LD2_advsimd_sngl(ctx, dec); // -> LD2_asisdlsop_H2_i2h
	if(L && R && Rm==0x1f && opcode==3 && !(size&1) && HasAdvSIMD()) return LD4_advsimd_sngl(ctx, dec); // -> LD4_asisdlsop_H4_i4h
	if(L && R && Rm==0x1f && opcode==6 && !S && HasAdvSIMD()) return LD2R_advsimd(ctx, dec); // -> LD2R_asisdlsop_R2_i
	if(L && R && Rm==0x1f && opcode==7 && !S && HasAdvSIMD()) return LD4R_advsimd(ctx, dec); // -> LD4R_asisdlsop_R4_i
	if(L && R && Rm!=0x1f && opcode==2 && !(size&1) && HasAdvSIMD()) return LD2_advsimd_sngl(ctx, dec); // -> LD2_asisdlsop_HX2_r2h
	if(L && R && Rm!=0x1f && opcode==3 && !(size&1) && HasAdvSIMD()) return LD4_advsimd_sngl(ctx, dec); // -> LD4_asisdlsop_HX4_r4h
	if(L && R && Rm!=0x1f && opcode==6 && !S && HasAdvSIMD()) return LD2R_advsimd(ctx, dec); // -> LD2R_asisdlsop_RX2_r
	if(L && R && Rm!=0x1f && opcode==7 && !S && HasAdvSIMD()) return LD4R_advsimd(ctx, dec); // -> LD4R_asisdlsop_RX4_r
	if(!L && !R && Rm==0x1f && !opcode && HasAdvSIMD()) return ST1_advsimd_sngl(ctx, dec); // -> ST1_asisdlsop_B1_i1b
	if(!L && !R && Rm==0x1f && opcode==1 && HasAdvSIMD()) return ST3_advsimd_sngl(ctx, dec); // -> ST3_asisdlsop_B3_i3b
	if(!L && !R && Rm!=0x1f && !opcode && HasAdvSIMD()) return ST1_advsimd_sngl(ctx, dec); // -> ST1_asisdlsop_BX1_r1b
	if(!L && !R && Rm!=0x1f && opcode==1 && HasAdvSIMD()) return ST3_advsimd_sngl(ctx, dec); // -> ST3_asisdlsop_BX3_r3b
	if(!L && R && Rm==0x1f && !opcode && HasAdvSIMD()) return ST2_advsimd_sngl(ctx, dec); // -> ST2_asisdlsop_B2_i2b
	if(!L && R && Rm==0x1f && opcode==1 && HasAdvSIMD()) return ST4_advsimd_sngl(ctx, dec); // -> ST4_asisdlsop_B4_i4b
	if(!L && R && Rm!=0x1f && !opcode && HasAdvSIMD()) return ST2_advsimd_sngl(ctx, dec); // -> ST2_asisdlsop_BX2_r2b
	if(!L && R && Rm!=0x1f && opcode==1 && HasAdvSIMD()) return ST4_advsimd_sngl(ctx, dec); // -> ST4_asisdlsop_BX4_r4b
	if(L && !R && Rm==0x1f && !opcode && HasAdvSIMD()) return LD1_advsimd_sngl(ctx, dec); // -> LD1_asisdlsop_B1_i1b
	if(L && !R && Rm==0x1f && opcode==1 && HasAdvSIMD()) return LD3_advsimd_sngl(ctx, dec); // -> LD3_asisdlsop_B3_i3b
	if(L && !R && Rm!=0x1f && !opcode && HasAdvSIMD()) return LD1_advsimd_sngl(ctx, dec); // -> LD1_asisdlsop_BX1_r1b
	if(L && !R && Rm!=0x1f && opcode==1 && HasAdvSIMD()) return LD3_advsimd_sngl(ctx, dec); // -> LD3_asisdlsop_BX3_r3b
	if(L && R && Rm==0x1f && !opcode && HasAdvSIMD()) return LD2_advsimd_sngl(ctx, dec); // -> LD2_asisdlsop_B2_i2b
	if(L && R && Rm==0x1f && opcode==1 && HasAdvSIMD()) return LD4_advsimd_sngl(ctx, dec); // -> LD4_asisdlsop_B4_i4b
	if(L && R && Rm!=0x1f && !opcode && HasAdvSIMD()) return LD2_advsimd_sngl(ctx, dec); // -> LD2_asisdlsop_BX2_r2b
	if(L && R && Rm!=0x1f && opcode==1 && HasAdvSIMD()) return LD4_advsimd_sngl(ctx, dec); // -> LD4_asisdlsop_BX4_r4b
	if((opcode&6)==4 && S && size==1) UNALLOCATED(ENC_UNALLOCATED_894_ASISDLSOP);
	if(L && (opcode&6)==6 && S) UNALLOCATED(ENC_UNALLOCATED_893_ASISDLSOP);
	if((opcode&6)==2 && size&1) UNALLOCATED(ENC_UNALLOCATED_891_ASISDLSOP);
	if((opcode&6)==4 && (size&2)==2) UNALLOCATED(ENC_UNALLOCATED_892_ASISDLSOP);
	if(!L && (opcode&6)==6) UNALLOCATED(ENC_UNALLOCATED_890_ASISDLSOP);
	UNMATCHED;
}

int decode_iclass_memop(context *ctx, Instruction *dec)
{
	uint32_t size=INSWORD>>30, VR=(INSWORD>>26)&1, A=(INSWORD>>23)&1, R=(INSWORD>>22)&1, Rs=(INSWORD>>16)&0x1f, o3=(INSWORD>>15)&1, opc=(INSWORD>>12)&7, Rt=INSWORD&0x1f;
	if(!size && VR && !A && !R && o3 && !opc && Rt==0x1f && HasLSFE()) return STBFADD(ctx, dec); // -> STBFADD_16
	if(!size && VR && !A && !R && o3 && opc==4 && Rt==0x1f && HasLSFE()) return STBFMAX(ctx, dec); // -> STBFMAX_16
	if(!size && VR && !A && !R && o3 && opc==5 && Rt==0x1f && HasLSFE()) return STBFMIN(ctx, dec); // -> STBFMIN_16
	if(!size && VR && !A && !R && o3 && opc==6 && Rt==0x1f && HasLSFE()) return STBFMAXNM(ctx, dec); // -> STBFMAXNM_16
	if(!size && VR && !A && !R && o3 && opc==7 && Rt==0x1f && HasLSFE()) return STBFMINNM(ctx, dec); // -> STBFMINNM_16
	if(!size && VR && !A && R && o3 && !opc && Rt==0x1f && HasLSFE()) return STBFADD(ctx, dec); // -> STBFADDL_16
	if(!size && VR && !A && R && o3 && opc==4 && Rt==0x1f && HasLSFE()) return STBFMAX(ctx, dec); // -> STBFMAXL_16
	if(!size && VR && !A && R && o3 && opc==5 && Rt==0x1f && HasLSFE()) return STBFMIN(ctx, dec); // -> STBFMINL_16
	if(!size && VR && !A && R && o3 && opc==6 && Rt==0x1f && HasLSFE()) return STBFMAXNM(ctx, dec); // -> STBFMAXNML_16
	if(!size && VR && !A && R && o3 && opc==7 && Rt==0x1f && HasLSFE()) return STBFMINNM(ctx, dec); // -> STBFMINNML_16
	if(size==1 && VR && !A && !R && o3 && !opc && Rt==0x1f && HasLSFE()) return STFADD(ctx, dec); // -> STFADD_16
	if(size==1 && VR && !A && !R && o3 && opc==4 && Rt==0x1f && HasLSFE()) return STFMAX(ctx, dec); // -> STFMAX_16
	if(size==1 && VR && !A && !R && o3 && opc==5 && Rt==0x1f && HasLSFE()) return STFMIN(ctx, dec); // -> STFMIN_16
	if(size==1 && VR && !A && !R && o3 && opc==6 && Rt==0x1f && HasLSFE()) return STFMAXNM(ctx, dec); // -> STFMAXNM_16
	if(size==1 && VR && !A && !R && o3 && opc==7 && Rt==0x1f && HasLSFE()) return STFMINNM(ctx, dec); // -> STFMINNM_16
	if(size==1 && VR && !A && R && o3 && !opc && Rt==0x1f && HasLSFE()) return STFADD(ctx, dec); // -> STFADDL_16
	if(size==1 && VR && !A && R && o3 && opc==4 && Rt==0x1f && HasLSFE()) return STFMAX(ctx, dec); // -> STFMAXL_16
	if(size==1 && VR && !A && R && o3 && opc==5 && Rt==0x1f && HasLSFE()) return STFMIN(ctx, dec); // -> STFMINL_16
	if(size==1 && VR && !A && R && o3 && opc==6 && Rt==0x1f && HasLSFE()) return STFMAXNM(ctx, dec); // -> STFMAXNML_16
	if(size==1 && VR && !A && R && o3 && opc==7 && Rt==0x1f && HasLSFE()) return STFMINNM(ctx, dec); // -> STFMINNML_16
	if(size==2 && VR && !A && !R && o3 && !opc && Rt==0x1f && HasLSFE()) return STFADD(ctx, dec); // -> STFADD_32
	if(size==2 && VR && !A && !R && o3 && opc==4 && Rt==0x1f && HasLSFE()) return STFMAX(ctx, dec); // -> STFMAX_32
	if(size==2 && VR && !A && !R && o3 && opc==5 && Rt==0x1f && HasLSFE()) return STFMIN(ctx, dec); // -> STFMIN_32
	if(size==2 && VR && !A && !R && o3 && opc==6 && Rt==0x1f && HasLSFE()) return STFMAXNM(ctx, dec); // -> STFMAXNM_32
	if(size==2 && VR && !A && !R && o3 && opc==7 && Rt==0x1f && HasLSFE()) return STFMINNM(ctx, dec); // -> STFMINNM_32
	if(size==2 && VR && !A && R && o3 && !opc && Rt==0x1f && HasLSFE()) return STFADD(ctx, dec); // -> STFADDL_32
	if(size==2 && VR && !A && R && o3 && opc==4 && Rt==0x1f && HasLSFE()) return STFMAX(ctx, dec); // -> STFMAXL_32
	if(size==2 && VR && !A && R && o3 && opc==5 && Rt==0x1f && HasLSFE()) return STFMIN(ctx, dec); // -> STFMINL_32
	if(size==2 && VR && !A && R && o3 && opc==6 && Rt==0x1f && HasLSFE()) return STFMAXNM(ctx, dec); // -> STFMAXNML_32
	if(size==2 && VR && !A && R && o3 && opc==7 && Rt==0x1f && HasLSFE()) return STFMINNM(ctx, dec); // -> STFMINNML_32
	if(size==3 && !VR && !A && !R && Rs==0x1f && o3 && opc==1 && HasLS64()) return ST64B(ctx, dec); // -> ST64B_64L_memop
	if(size==3 && !VR && !A && !R && Rs==0x1f && o3 && opc==5 && HasLS64()) return LD64B(ctx, dec); // -> LD64B_64L_memop
	if(size==3 && VR && !A && !R && o3 && !opc && Rt==0x1f && HasLSFE()) return STFADD(ctx, dec); // -> STFADD_64
	if(size==3 && VR && !A && !R && o3 && opc==4 && Rt==0x1f && HasLSFE()) return STFMAX(ctx, dec); // -> STFMAX_64
	if(size==3 && VR && !A && !R && o3 && opc==5 && Rt==0x1f && HasLSFE()) return STFMIN(ctx, dec); // -> STFMIN_64
	if(size==3 && VR && !A && !R && o3 && opc==6 && Rt==0x1f && HasLSFE()) return STFMAXNM(ctx, dec); // -> STFMAXNM_64
	if(size==3 && VR && !A && !R && o3 && opc==7 && Rt==0x1f && HasLSFE()) return STFMINNM(ctx, dec); // -> STFMINNM_64
	if(size==3 && VR && !A && R && o3 && !opc && Rt==0x1f && HasLSFE()) return STFADD(ctx, dec); // -> STFADDL_64
	if(size==3 && VR && !A && R && o3 && opc==4 && Rt==0x1f && HasLSFE()) return STFMAX(ctx, dec); // -> STFMAXL_64
	if(size==3 && VR && !A && R && o3 && opc==5 && Rt==0x1f && HasLSFE()) return STFMIN(ctx, dec); // -> STFMINL_64
	if(size==3 && VR && !A && R && o3 && opc==6 && Rt==0x1f && HasLSFE()) return STFMAXNM(ctx, dec); // -> STFMAXNML_64
	if(size==3 && VR && !A && R && o3 && opc==7 && Rt==0x1f && HasLSFE()) return STFMINNM(ctx, dec); // -> STFMINNML_64
	if(size==3 && !VR && !A && !R && Rs!=0x1f && o3 && (opc&3)==1) UNALLOCATED(ENC_UNALLOCATED_912_MEMOP);
	if(VR && !A && o3 && opc==1 && Rt==0x1f) UNALLOCATED(ENC_UNALLOCATED_916_MEMOP);
	if(VR && !A && o3 && (opc&6)==2 && Rt==0x1f) UNALLOCATED(ENC_UNALLOCATED_915_MEMOP);
	if(!size && !VR && !A && !R && !o3 && !opc && HasLSE()) return LDADDB(ctx, dec); // -> LDADDB_32_memop
	if(!size && !VR && !A && !R && !o3 && opc==1 && HasLSE()) return LDCLRB(ctx, dec); // -> LDCLRB_32_memop
	if(!size && !VR && !A && !R && !o3 && opc==2 && HasLSE()) return LDEORB(ctx, dec); // -> LDEORB_32_memop
	if(!size && !VR && !A && !R && !o3 && opc==3 && HasLSE()) return LDSETB(ctx, dec); // -> LDSETB_32_memop
	if(!size && !VR && !A && !R && !o3 && opc==4 && HasLSE()) return LDSMAXB(ctx, dec); // -> LDSMAXB_32_memop
	if(!size && !VR && !A && !R && !o3 && opc==5 && HasLSE()) return LDSMINB(ctx, dec); // -> LDSMINB_32_memop
	if(!size && !VR && !A && !R && !o3 && opc==6 && HasLSE()) return LDUMAXB(ctx, dec); // -> LDUMAXB_32_memop
	if(!size && !VR && !A && !R && !o3 && opc==7 && HasLSE()) return LDUMINB(ctx, dec); // -> LDUMINB_32_memop
	if(!size && !VR && !A && !R && o3 && !opc && HasLSE()) return SWPB(ctx, dec); // -> SWPB_32_memop
	if(!size && !VR && !A && !R && o3 && opc==1 && HasTHE()) return RCWCLR(ctx, dec); // -> RCWCLR_64_memop
	if(!size && !VR && !A && !R && o3 && opc==2 && HasTHE()) return RCWSWP(ctx, dec); // -> RCWSWP_64_memop
	if(!size && !VR && !A && !R && o3 && opc==3 && HasTHE()) return RCWSET(ctx, dec); // -> RCWSET_64_memop
	if(!size && !VR && !A && R && !o3 && !opc && HasLSE()) return LDADDB(ctx, dec); // -> LDADDLB_32_memop
	if(!size && !VR && !A && R && !o3 && opc==1 && HasLSE()) return LDCLRB(ctx, dec); // -> LDCLRLB_32_memop
	if(!size && !VR && !A && R && !o3 && opc==2 && HasLSE()) return LDEORB(ctx, dec); // -> LDEORLB_32_memop
	if(!size && !VR && !A && R && !o3 && opc==3 && HasLSE()) return LDSETB(ctx, dec); // -> LDSETLB_32_memop
	if(!size && !VR && !A && R && !o3 && opc==4 && HasLSE()) return LDSMAXB(ctx, dec); // -> LDSMAXLB_32_memop
	if(!size && !VR && !A && R && !o3 && opc==5 && HasLSE()) return LDSMINB(ctx, dec); // -> LDSMINLB_32_memop
	if(!size && !VR && !A && R && !o3 && opc==6 && HasLSE()) return LDUMAXB(ctx, dec); // -> LDUMAXLB_32_memop
	if(!size && !VR && !A && R && !o3 && opc==7 && HasLSE()) return LDUMINB(ctx, dec); // -> LDUMINLB_32_memop
	if(!size && !VR && !A && R && o3 && !opc && HasLSE()) return SWPB(ctx, dec); // -> SWPLB_32_memop
	if(!size && !VR && !A && R && o3 && opc==1 && HasTHE()) return RCWCLR(ctx, dec); // -> RCWCLRL_64_memop
	if(!size && !VR && !A && R && o3 && opc==2 && HasTHE()) return RCWSWP(ctx, dec); // -> RCWSWPL_64_memop
	if(!size && !VR && !A && R && o3 && opc==3 && HasTHE()) return RCWSET(ctx, dec); // -> RCWSETL_64_memop
	if(!size && !VR && A && !R && !o3 && !opc && HasLSE()) return LDADDB(ctx, dec); // -> LDADDAB_32_memop
	if(!size && !VR && A && !R && !o3 && opc==1 && HasLSE()) return LDCLRB(ctx, dec); // -> LDCLRAB_32_memop
	if(!size && !VR && A && !R && !o3 && opc==2 && HasLSE()) return LDEORB(ctx, dec); // -> LDEORAB_32_memop
	if(!size && !VR && A && !R && !o3 && opc==3 && HasLSE()) return LDSETB(ctx, dec); // -> LDSETAB_32_memop
	if(!size && !VR && A && !R && !o3 && opc==4 && HasLSE()) return LDSMAXB(ctx, dec); // -> LDSMAXAB_32_memop
	if(!size && !VR && A && !R && !o3 && opc==5 && HasLSE()) return LDSMINB(ctx, dec); // -> LDSMINAB_32_memop
	if(!size && !VR && A && !R && !o3 && opc==6 && HasLSE()) return LDUMAXB(ctx, dec); // -> LDUMAXAB_32_memop
	if(!size && !VR && A && !R && !o3 && opc==7 && HasLSE()) return LDUMINB(ctx, dec); // -> LDUMINAB_32_memop
	if(!size && !VR && A && !R && o3 && !opc && HasLSE()) return SWPB(ctx, dec); // -> SWPAB_32_memop
	if(!size && !VR && A && !R && o3 && opc==1 && HasTHE()) return RCWCLR(ctx, dec); // -> RCWCLRA_64_memop
	if(!size && !VR && A && !R && o3 && opc==2 && HasTHE()) return RCWSWP(ctx, dec); // -> RCWSWPA_64_memop
	if(!size && !VR && A && !R && o3 && opc==3 && HasTHE()) return RCWSET(ctx, dec); // -> RCWSETA_64_memop
	if(!size && !VR && A && !R && o3 && opc==4 && HasLRCPC()) return LDAPRB(ctx, dec); // -> LDAPRB_32L_memop
	if(!size && !VR && A && R && !o3 && !opc && HasLSE()) return LDADDB(ctx, dec); // -> LDADDALB_32_memop
	if(!size && !VR && A && R && !o3 && opc==1 && HasLSE()) return LDCLRB(ctx, dec); // -> LDCLRALB_32_memop
	if(!size && !VR && A && R && !o3 && opc==2 && HasLSE()) return LDEORB(ctx, dec); // -> LDEORALB_32_memop
	if(!size && !VR && A && R && !o3 && opc==3 && HasLSE()) return LDSETB(ctx, dec); // -> LDSETALB_32_memop
	if(!size && !VR && A && R && !o3 && opc==4 && HasLSE()) return LDSMAXB(ctx, dec); // -> LDSMAXALB_32_memop
	if(!size && !VR && A && R && !o3 && opc==5 && HasLSE()) return LDSMINB(ctx, dec); // -> LDSMINALB_32_memop
	if(!size && !VR && A && R && !o3 && opc==6 && HasLSE()) return LDUMAXB(ctx, dec); // -> LDUMAXALB_32_memop
	if(!size && !VR && A && R && !o3 && opc==7 && HasLSE()) return LDUMINB(ctx, dec); // -> LDUMINALB_32_memop
	if(!size && !VR && A && R && o3 && !opc && HasLSE()) return SWPB(ctx, dec); // -> SWPALB_32_memop
	if(!size && !VR && A && R && o3 && opc==1 && HasTHE()) return RCWCLR(ctx, dec); // -> RCWCLRAL_64_memop
	if(!size && !VR && A && R && o3 && opc==2 && HasTHE()) return RCWSWP(ctx, dec); // -> RCWSWPAL_64_memop
	if(!size && !VR && A && R && o3 && opc==3 && HasTHE()) return RCWSET(ctx, dec); // -> RCWSETAL_64_memop
	if(!size && VR && !A && !R && !o3 && !opc && HasLSFE()) return LDBFADD(ctx, dec); // -> LDBFADD_16
	if(!size && VR && !A && !R && !o3 && opc==4 && HasLSFE()) return LDBFMAX(ctx, dec); // -> LDBFMAX_16
	if(!size && VR && !A && !R && !o3 && opc==5 && HasLSFE()) return LDBFMIN(ctx, dec); // -> LDBFMIN_16
	if(!size && VR && !A && !R && !o3 && opc==6 && HasLSFE()) return LDBFMAXNM(ctx, dec); // -> LDBFMAXNM_16
	if(!size && VR && !A && !R && !o3 && opc==7 && HasLSFE()) return LDBFMINNM(ctx, dec); // -> LDBFMINNM_16
	if(!size && VR && !A && R && !o3 && !opc && HasLSFE()) return LDBFADD(ctx, dec); // -> LDBFADDL_16
	if(!size && VR && !A && R && !o3 && opc==4 && HasLSFE()) return LDBFMAX(ctx, dec); // -> LDBFMAXL_16
	if(!size && VR && !A && R && !o3 && opc==5 && HasLSFE()) return LDBFMIN(ctx, dec); // -> LDBFMINL_16
	if(!size && VR && !A && R && !o3 && opc==6 && HasLSFE()) return LDBFMAXNM(ctx, dec); // -> LDBFMAXNML_16
	if(!size && VR && !A && R && !o3 && opc==7 && HasLSFE()) return LDBFMINNM(ctx, dec); // -> LDBFMINNML_16
	if(!size && VR && A && !R && !o3 && !opc && HasLSFE()) return LDBFADD(ctx, dec); // -> LDBFADDA_16
	if(!size && VR && A && !R && !o3 && opc==4 && HasLSFE()) return LDBFMAX(ctx, dec); // -> LDBFMAXA_16
	if(!size && VR && A && !R && !o3 && opc==5 && HasLSFE()) return LDBFMIN(ctx, dec); // -> LDBFMINA_16
	if(!size && VR && A && !R && !o3 && opc==6 && HasLSFE()) return LDBFMAXNM(ctx, dec); // -> LDBFMAXNMA_16
	if(!size && VR && A && !R && !o3 && opc==7 && HasLSFE()) return LDBFMINNM(ctx, dec); // -> LDBFMINNMA_16
	if(!size && VR && A && R && !o3 && !opc && HasLSFE()) return LDBFADD(ctx, dec); // -> LDBFADDAL_16
	if(!size && VR && A && R && !o3 && opc==4 && HasLSFE()) return LDBFMAX(ctx, dec); // -> LDBFMAXAL_16
	if(!size && VR && A && R && !o3 && opc==5 && HasLSFE()) return LDBFMIN(ctx, dec); // -> LDBFMINAL_16
	if(!size && VR && A && R && !o3 && opc==6 && HasLSFE()) return LDBFMAXNM(ctx, dec); // -> LDBFMAXNMAL_16
	if(!size && VR && A && R && !o3 && opc==7 && HasLSFE()) return LDBFMINNM(ctx, dec); // -> LDBFMINNMAL_16
	if(size==1 && !VR && !A && !R && !o3 && !opc && HasLSE()) return LDADDH(ctx, dec); // -> LDADDH_32_memop
	if(size==1 && !VR && !A && !R && !o3 && opc==1 && HasLSE()) return LDCLRH(ctx, dec); // -> LDCLRH_32_memop
	if(size==1 && !VR && !A && !R && !o3 && opc==2 && HasLSE()) return LDEORH(ctx, dec); // -> LDEORH_32_memop
	if(size==1 && !VR && !A && !R && !o3 && opc==3 && HasLSE()) return LDSETH(ctx, dec); // -> LDSETH_32_memop
	if(size==1 && !VR && !A && !R && !o3 && opc==4 && HasLSE()) return LDSMAXH(ctx, dec); // -> LDSMAXH_32_memop
	if(size==1 && !VR && !A && !R && !o3 && opc==5 && HasLSE()) return LDSMINH(ctx, dec); // -> LDSMINH_32_memop
	if(size==1 && !VR && !A && !R && !o3 && opc==6 && HasLSE()) return LDUMAXH(ctx, dec); // -> LDUMAXH_32_memop
	if(size==1 && !VR && !A && !R && !o3 && opc==7 && HasLSE()) return LDUMINH(ctx, dec); // -> LDUMINH_32_memop
	if(size==1 && !VR && !A && !R && o3 && !opc && HasLSE()) return SWPH(ctx, dec); // -> SWPH_32_memop
	if(size==1 && !VR && !A && !R && o3 && opc==1 && HasTHE()) return RCWSCLR(ctx, dec); // -> RCWSCLR_64_memop
	if(size==1 && !VR && !A && !R && o3 && opc==2 && HasTHE()) return RCWSSWP(ctx, dec); // -> RCWSSWP_64_memop
	if(size==1 && !VR && !A && !R && o3 && opc==3 && HasTHE()) return RCWSSET(ctx, dec); // -> RCWSSET_64_memop
	if(size==1 && !VR && !A && R && !o3 && !opc && HasLSE()) return LDADDH(ctx, dec); // -> LDADDLH_32_memop
	if(size==1 && !VR && !A && R && !o3 && opc==1 && HasLSE()) return LDCLRH(ctx, dec); // -> LDCLRLH_32_memop
	if(size==1 && !VR && !A && R && !o3 && opc==2 && HasLSE()) return LDEORH(ctx, dec); // -> LDEORLH_32_memop
	if(size==1 && !VR && !A && R && !o3 && opc==3 && HasLSE()) return LDSETH(ctx, dec); // -> LDSETLH_32_memop
	if(size==1 && !VR && !A && R && !o3 && opc==4 && HasLSE()) return LDSMAXH(ctx, dec); // -> LDSMAXLH_32_memop
	if(size==1 && !VR && !A && R && !o3 && opc==5 && HasLSE()) return LDSMINH(ctx, dec); // -> LDSMINLH_32_memop
	if(size==1 && !VR && !A && R && !o3 && opc==6 && HasLSE()) return LDUMAXH(ctx, dec); // -> LDUMAXLH_32_memop
	if(size==1 && !VR && !A && R && !o3 && opc==7 && HasLSE()) return LDUMINH(ctx, dec); // -> LDUMINLH_32_memop
	if(size==1 && !VR && !A && R && o3 && !opc && HasLSE()) return SWPH(ctx, dec); // -> SWPLH_32_memop
	if(size==1 && !VR && !A && R && o3 && opc==1 && HasTHE()) return RCWSCLR(ctx, dec); // -> RCWSCLRL_64_memop
	if(size==1 && !VR && !A && R && o3 && opc==2 && HasTHE()) return RCWSSWP(ctx, dec); // -> RCWSSWPL_64_memop
	if(size==1 && !VR && !A && R && o3 && opc==3 && HasTHE()) return RCWSSET(ctx, dec); // -> RCWSSETL_64_memop
	if(size==1 && !VR && A && !R && !o3 && !opc && HasLSE()) return LDADDH(ctx, dec); // -> LDADDAH_32_memop
	if(size==1 && !VR && A && !R && !o3 && opc==1 && HasLSE()) return LDCLRH(ctx, dec); // -> LDCLRAH_32_memop
	if(size==1 && !VR && A && !R && !o3 && opc==2 && HasLSE()) return LDEORH(ctx, dec); // -> LDEORAH_32_memop
	if(size==1 && !VR && A && !R && !o3 && opc==3 && HasLSE()) return LDSETH(ctx, dec); // -> LDSETAH_32_memop
	if(size==1 && !VR && A && !R && !o3 && opc==4 && HasLSE()) return LDSMAXH(ctx, dec); // -> LDSMAXAH_32_memop
	if(size==1 && !VR && A && !R && !o3 && opc==5 && HasLSE()) return LDSMINH(ctx, dec); // -> LDSMINAH_32_memop
	if(size==1 && !VR && A && !R && !o3 && opc==6 && HasLSE()) return LDUMAXH(ctx, dec); // -> LDUMAXAH_32_memop
	if(size==1 && !VR && A && !R && !o3 && opc==7 && HasLSE()) return LDUMINH(ctx, dec); // -> LDUMINAH_32_memop
	if(size==1 && !VR && A && !R && o3 && !opc && HasLSE()) return SWPH(ctx, dec); // -> SWPAH_32_memop
	if(size==1 && !VR && A && !R && o3 && opc==1 && HasTHE()) return RCWSCLR(ctx, dec); // -> RCWSCLRA_64_memop
	if(size==1 && !VR && A && !R && o3 && opc==2 && HasTHE()) return RCWSSWP(ctx, dec); // -> RCWSSWPA_64_memop
	if(size==1 && !VR && A && !R && o3 && opc==3 && HasTHE()) return RCWSSET(ctx, dec); // -> RCWSSETA_64_memop
	if(size==1 && !VR && A && !R && o3 && opc==4 && HasLRCPC()) return LDAPRH(ctx, dec); // -> LDAPRH_32L_memop
	if(size==1 && !VR && A && R && !o3 && !opc && HasLSE()) return LDADDH(ctx, dec); // -> LDADDALH_32_memop
	if(size==1 && !VR && A && R && !o3 && opc==1 && HasLSE()) return LDCLRH(ctx, dec); // -> LDCLRALH_32_memop
	if(size==1 && !VR && A && R && !o3 && opc==2 && HasLSE()) return LDEORH(ctx, dec); // -> LDEORALH_32_memop
	if(size==1 && !VR && A && R && !o3 && opc==3 && HasLSE()) return LDSETH(ctx, dec); // -> LDSETALH_32_memop
	if(size==1 && !VR && A && R && !o3 && opc==4 && HasLSE()) return LDSMAXH(ctx, dec); // -> LDSMAXALH_32_memop
	if(size==1 && !VR && A && R && !o3 && opc==5 && HasLSE()) return LDSMINH(ctx, dec); // -> LDSMINALH_32_memop
	if(size==1 && !VR && A && R && !o3 && opc==6 && HasLSE()) return LDUMAXH(ctx, dec); // -> LDUMAXALH_32_memop
	if(size==1 && !VR && A && R && !o3 && opc==7 && HasLSE()) return LDUMINH(ctx, dec); // -> LDUMINALH_32_memop
	if(size==1 && !VR && A && R && o3 && !opc && HasLSE()) return SWPH(ctx, dec); // -> SWPALH_32_memop
	if(size==1 && !VR && A && R && o3 && opc==1 && HasTHE()) return RCWSCLR(ctx, dec); // -> RCWSCLRAL_64_memop
	if(size==1 && !VR && A && R && o3 && opc==2 && HasTHE()) return RCWSSWP(ctx, dec); // -> RCWSSWPAL_64_memop
	if(size==1 && !VR && A && R && o3 && opc==3 && HasTHE()) return RCWSSET(ctx, dec); // -> RCWSSETAL_64_memop
	if(size==1 && VR && !A && !R && !o3 && !opc && HasLSFE()) return LDFADD(ctx, dec); // -> LDFADD_16
	if(size==1 && VR && !A && !R && !o3 && opc==4 && HasLSFE()) return LDFMAX(ctx, dec); // -> LDFMAX_16
	if(size==1 && VR && !A && !R && !o3 && opc==5 && HasLSFE()) return LDFMIN(ctx, dec); // -> LDFMIN_16
	if(size==1 && VR && !A && !R && !o3 && opc==6 && HasLSFE()) return LDFMAXNM(ctx, dec); // -> LDFMAXNM_16
	if(size==1 && VR && !A && !R && !o3 && opc==7 && HasLSFE()) return LDFMINNM(ctx, dec); // -> LDFMINNM_16
	if(size==1 && VR && !A && R && !o3 && !opc && HasLSFE()) return LDFADD(ctx, dec); // -> LDFADDL_16
	if(size==1 && VR && !A && R && !o3 && opc==4 && HasLSFE()) return LDFMAX(ctx, dec); // -> LDFMAXL_16
	if(size==1 && VR && !A && R && !o3 && opc==5 && HasLSFE()) return LDFMIN(ctx, dec); // -> LDFMINL_16
	if(size==1 && VR && !A && R && !o3 && opc==6 && HasLSFE()) return LDFMAXNM(ctx, dec); // -> LDFMAXNML_16
	if(size==1 && VR && !A && R && !o3 && opc==7 && HasLSFE()) return LDFMINNM(ctx, dec); // -> LDFMINNML_16
	if(size==1 && VR && A && !R && !o3 && !opc && HasLSFE()) return LDFADD(ctx, dec); // -> LDFADDA_16
	if(size==1 && VR && A && !R && !o3 && opc==4 && HasLSFE()) return LDFMAX(ctx, dec); // -> LDFMAXA_16
	if(size==1 && VR && A && !R && !o3 && opc==5 && HasLSFE()) return LDFMIN(ctx, dec); // -> LDFMINA_16
	if(size==1 && VR && A && !R && !o3 && opc==6 && HasLSFE()) return LDFMAXNM(ctx, dec); // -> LDFMAXNMA_16
	if(size==1 && VR && A && !R && !o3 && opc==7 && HasLSFE()) return LDFMINNM(ctx, dec); // -> LDFMINNMA_16
	if(size==1 && VR && A && R && !o3 && !opc && HasLSFE()) return LDFADD(ctx, dec); // -> LDFADDAL_16
	if(size==1 && VR && A && R && !o3 && opc==4 && HasLSFE()) return LDFMAX(ctx, dec); // -> LDFMAXAL_16
	if(size==1 && VR && A && R && !o3 && opc==5 && HasLSFE()) return LDFMIN(ctx, dec); // -> LDFMINAL_16
	if(size==1 && VR && A && R && !o3 && opc==6 && HasLSFE()) return LDFMAXNM(ctx, dec); // -> LDFMAXNMAL_16
	if(size==1 && VR && A && R && !o3 && opc==7 && HasLSFE()) return LDFMINNM(ctx, dec); // -> LDFMINNMAL_16
	if(size==2 && !VR && !A && !R && !o3 && !opc && HasLSE()) return LDADD(ctx, dec); // -> LDADD_32_memop
	if(size==2 && !VR && !A && !R && !o3 && opc==1 && HasLSE()) return LDCLR(ctx, dec); // -> LDCLR_32_memop
	if(size==2 && !VR && !A && !R && !o3 && opc==2 && HasLSE()) return LDEOR(ctx, dec); // -> LDEOR_32_memop
	if(size==2 && !VR && !A && !R && !o3 && opc==3 && HasLSE()) return LDSET(ctx, dec); // -> LDSET_32_memop
	if(size==2 && !VR && !A && !R && !o3 && opc==4 && HasLSE()) return LDSMAX(ctx, dec); // -> LDSMAX_32_memop
	if(size==2 && !VR && !A && !R && !o3 && opc==5 && HasLSE()) return LDSMIN(ctx, dec); // -> LDSMIN_32_memop
	if(size==2 && !VR && !A && !R && !o3 && opc==6 && HasLSE()) return LDUMAX(ctx, dec); // -> LDUMAX_32_memop
	if(size==2 && !VR && !A && !R && !o3 && opc==7 && HasLSE()) return LDUMIN(ctx, dec); // -> LDUMIN_32_memop
	if(size==2 && !VR && !A && !R && o3 && !opc && HasLSE()) return SWP(ctx, dec); // -> SWP_32_memop
	if(size==2 && !VR && !A && R && !o3 && !opc && HasLSE()) return LDADD(ctx, dec); // -> LDADDL_32_memop
	if(size==2 && !VR && !A && R && !o3 && opc==1 && HasLSE()) return LDCLR(ctx, dec); // -> LDCLRL_32_memop
	if(size==2 && !VR && !A && R && !o3 && opc==2 && HasLSE()) return LDEOR(ctx, dec); // -> LDEORL_32_memop
	if(size==2 && !VR && !A && R && !o3 && opc==3 && HasLSE()) return LDSET(ctx, dec); // -> LDSETL_32_memop
	if(size==2 && !VR && !A && R && !o3 && opc==4 && HasLSE()) return LDSMAX(ctx, dec); // -> LDSMAXL_32_memop
	if(size==2 && !VR && !A && R && !o3 && opc==5 && HasLSE()) return LDSMIN(ctx, dec); // -> LDSMINL_32_memop
	if(size==2 && !VR && !A && R && !o3 && opc==6 && HasLSE()) return LDUMAX(ctx, dec); // -> LDUMAXL_32_memop
	if(size==2 && !VR && !A && R && !o3 && opc==7 && HasLSE()) return LDUMIN(ctx, dec); // -> LDUMINL_32_memop
	if(size==2 && !VR && !A && R && o3 && !opc && HasLSE()) return SWP(ctx, dec); // -> SWPL_32_memop
	if(size==2 && !VR && A && !R && !o3 && !opc && HasLSE()) return LDADD(ctx, dec); // -> LDADDA_32_memop
	if(size==2 && !VR && A && !R && !o3 && opc==1 && HasLSE()) return LDCLR(ctx, dec); // -> LDCLRA_32_memop
	if(size==2 && !VR && A && !R && !o3 && opc==2 && HasLSE()) return LDEOR(ctx, dec); // -> LDEORA_32_memop
	if(size==2 && !VR && A && !R && !o3 && opc==3 && HasLSE()) return LDSET(ctx, dec); // -> LDSETA_32_memop
	if(size==2 && !VR && A && !R && !o3 && opc==4 && HasLSE()) return LDSMAX(ctx, dec); // -> LDSMAXA_32_memop
	if(size==2 && !VR && A && !R && !o3 && opc==5 && HasLSE()) return LDSMIN(ctx, dec); // -> LDSMINA_32_memop
	if(size==2 && !VR && A && !R && !o3 && opc==6 && HasLSE()) return LDUMAX(ctx, dec); // -> LDUMAXA_32_memop
	if(size==2 && !VR && A && !R && !o3 && opc==7 && HasLSE()) return LDUMIN(ctx, dec); // -> LDUMINA_32_memop
	if(size==2 && !VR && A && !R && o3 && !opc && HasLSE()) return SWP(ctx, dec); // -> SWPA_32_memop
	if(size==2 && !VR && A && !R && o3 && opc==4 && HasLRCPC()) return LDAPR(ctx, dec); // -> LDAPR_32L_memop
	if(size==2 && !VR && A && R && !o3 && !opc && HasLSE()) return LDADD(ctx, dec); // -> LDADDAL_32_memop
	if(size==2 && !VR && A && R && !o3 && opc==1 && HasLSE()) return LDCLR(ctx, dec); // -> LDCLRAL_32_memop
	if(size==2 && !VR && A && R && !o3 && opc==2 && HasLSE()) return LDEOR(ctx, dec); // -> LDEORAL_32_memop
	if(size==2 && !VR && A && R && !o3 && opc==3 && HasLSE()) return LDSET(ctx, dec); // -> LDSETAL_32_memop
	if(size==2 && !VR && A && R && !o3 && opc==4 && HasLSE()) return LDSMAX(ctx, dec); // -> LDSMAXAL_32_memop
	if(size==2 && !VR && A && R && !o3 && opc==5 && HasLSE()) return LDSMIN(ctx, dec); // -> LDSMINAL_32_memop
	if(size==2 && !VR && A && R && !o3 && opc==6 && HasLSE()) return LDUMAX(ctx, dec); // -> LDUMAXAL_32_memop
	if(size==2 && !VR && A && R && !o3 && opc==7 && HasLSE()) return LDUMIN(ctx, dec); // -> LDUMINAL_32_memop
	if(size==2 && !VR && A && R && o3 && !opc && HasLSE()) return SWP(ctx, dec); // -> SWPAL_32_memop
	if(size==2 && VR && !A && !R && !o3 && !opc && HasLSFE()) return LDFADD(ctx, dec); // -> LDFADD_32
	if(size==2 && VR && !A && !R && !o3 && opc==4 && HasLSFE()) return LDFMAX(ctx, dec); // -> LDFMAX_32
	if(size==2 && VR && !A && !R && !o3 && opc==5 && HasLSFE()) return LDFMIN(ctx, dec); // -> LDFMIN_32
	if(size==2 && VR && !A && !R && !o3 && opc==6 && HasLSFE()) return LDFMAXNM(ctx, dec); // -> LDFMAXNM_32
	if(size==2 && VR && !A && !R && !o3 && opc==7 && HasLSFE()) return LDFMINNM(ctx, dec); // -> LDFMINNM_32
	if(size==2 && VR && !A && R && !o3 && !opc && HasLSFE()) return LDFADD(ctx, dec); // -> LDFADDL_32
	if(size==2 && VR && !A && R && !o3 && opc==4 && HasLSFE()) return LDFMAX(ctx, dec); // -> LDFMAXL_32
	if(size==2 && VR && !A && R && !o3 && opc==5 && HasLSFE()) return LDFMIN(ctx, dec); // -> LDFMINL_32
	if(size==2 && VR && !A && R && !o3 && opc==6 && HasLSFE()) return LDFMAXNM(ctx, dec); // -> LDFMAXNML_32
	if(size==2 && VR && !A && R && !o3 && opc==7 && HasLSFE()) return LDFMINNM(ctx, dec); // -> LDFMINNML_32
	if(size==2 && VR && A && !R && !o3 && !opc && HasLSFE()) return LDFADD(ctx, dec); // -> LDFADDA_32
	if(size==2 && VR && A && !R && !o3 && opc==4 && HasLSFE()) return LDFMAX(ctx, dec); // -> LDFMAXA_32
	if(size==2 && VR && A && !R && !o3 && opc==5 && HasLSFE()) return LDFMIN(ctx, dec); // -> LDFMINA_32
	if(size==2 && VR && A && !R && !o3 && opc==6 && HasLSFE()) return LDFMAXNM(ctx, dec); // -> LDFMAXNMA_32
	if(size==2 && VR && A && !R && !o3 && opc==7 && HasLSFE()) return LDFMINNM(ctx, dec); // -> LDFMINNMA_32
	if(size==2 && VR && A && R && !o3 && !opc && HasLSFE()) return LDFADD(ctx, dec); // -> LDFADDAL_32
	if(size==2 && VR && A && R && !o3 && opc==4 && HasLSFE()) return LDFMAX(ctx, dec); // -> LDFMAXAL_32
	if(size==2 && VR && A && R && !o3 && opc==5 && HasLSFE()) return LDFMIN(ctx, dec); // -> LDFMINAL_32
	if(size==2 && VR && A && R && !o3 && opc==6 && HasLSFE()) return LDFMAXNM(ctx, dec); // -> LDFMAXNMAL_32
	if(size==2 && VR && A && R && !o3 && opc==7 && HasLSFE()) return LDFMINNM(ctx, dec); // -> LDFMINNMAL_32
	if(size==3 && !VR && !A && !R && !o3 && !opc && HasLSE()) return LDADD(ctx, dec); // -> LDADD_64_memop
	if(size==3 && !VR && !A && !R && !o3 && opc==1 && HasLSE()) return LDCLR(ctx, dec); // -> LDCLR_64_memop
	if(size==3 && !VR && !A && !R && !o3 && opc==2 && HasLSE()) return LDEOR(ctx, dec); // -> LDEOR_64_memop
	if(size==3 && !VR && !A && !R && !o3 && opc==3 && HasLSE()) return LDSET(ctx, dec); // -> LDSET_64_memop
	if(size==3 && !VR && !A && !R && !o3 && opc==4 && HasLSE()) return LDSMAX(ctx, dec); // -> LDSMAX_64_memop
	if(size==3 && !VR && !A && !R && !o3 && opc==5 && HasLSE()) return LDSMIN(ctx, dec); // -> LDSMIN_64_memop
	if(size==3 && !VR && !A && !R && !o3 && opc==6 && HasLSE()) return LDUMAX(ctx, dec); // -> LDUMAX_64_memop
	if(size==3 && !VR && !A && !R && !o3 && opc==7 && HasLSE()) return LDUMIN(ctx, dec); // -> LDUMIN_64_memop
	if(size==3 && !VR && !A && !R && o3 && !opc && HasLSE()) return SWP(ctx, dec); // -> SWP_64_memop
	if(size==3 && !VR && !A && !R && o3 && opc==2 && HasLS64_ACCDATA()) return ST64BV0(ctx, dec); // -> ST64BV0_64_memop
	if(size==3 && !VR && !A && !R && o3 && opc==3 && HasLS64_V()) return ST64BV(ctx, dec); // -> ST64BV_64_memop
	if(size==3 && !VR && !A && R && !o3 && !opc && HasLSE()) return LDADD(ctx, dec); // -> LDADDL_64_memop
	if(size==3 && !VR && !A && R && !o3 && opc==1 && HasLSE()) return LDCLR(ctx, dec); // -> LDCLRL_64_memop
	if(size==3 && !VR && !A && R && !o3 && opc==2 && HasLSE()) return LDEOR(ctx, dec); // -> LDEORL_64_memop
	if(size==3 && !VR && !A && R && !o3 && opc==3 && HasLSE()) return LDSET(ctx, dec); // -> LDSETL_64_memop
	if(size==3 && !VR && !A && R && !o3 && opc==4 && HasLSE()) return LDSMAX(ctx, dec); // -> LDSMAXL_64_memop
	if(size==3 && !VR && !A && R && !o3 && opc==5 && HasLSE()) return LDSMIN(ctx, dec); // -> LDSMINL_64_memop
	if(size==3 && !VR && !A && R && !o3 && opc==6 && HasLSE()) return LDUMAX(ctx, dec); // -> LDUMAXL_64_memop
	if(size==3 && !VR && !A && R && !o3 && opc==7 && HasLSE()) return LDUMIN(ctx, dec); // -> LDUMINL_64_memop
	if(size==3 && !VR && !A && R && o3 && !opc && HasLSE()) return SWP(ctx, dec); // -> SWPL_64_memop
	if(size==3 && !VR && !A && R && o3 && opc==2) UNALLOCATED(ENC_UNALLOCATED_913_MEMOP);
	if(size==3 && !VR && !A && R && o3 && opc==3) UNALLOCATED(ENC_UNALLOCATED_914_MEMOP);
	if(size==3 && !VR && A && !R && !o3 && !opc && HasLSE()) return LDADD(ctx, dec); // -> LDADDA_64_memop
	if(size==3 && !VR && A && !R && !o3 && opc==1 && HasLSE()) return LDCLR(ctx, dec); // -> LDCLRA_64_memop
	if(size==3 && !VR && A && !R && !o3 && opc==2 && HasLSE()) return LDEOR(ctx, dec); // -> LDEORA_64_memop
	if(size==3 && !VR && A && !R && !o3 && opc==3 && HasLSE()) return LDSET(ctx, dec); // -> LDSETA_64_memop
	if(size==3 && !VR && A && !R && !o3 && opc==4 && HasLSE()) return LDSMAX(ctx, dec); // -> LDSMAXA_64_memop
	if(size==3 && !VR && A && !R && !o3 && opc==5 && HasLSE()) return LDSMIN(ctx, dec); // -> LDSMINA_64_memop
	if(size==3 && !VR && A && !R && !o3 && opc==6 && HasLSE()) return LDUMAX(ctx, dec); // -> LDUMAXA_64_memop
	if(size==3 && !VR && A && !R && !o3 && opc==7 && HasLSE()) return LDUMIN(ctx, dec); // -> LDUMINA_64_memop
	if(size==3 && !VR && A && !R && o3 && !opc && HasLSE()) return SWP(ctx, dec); // -> SWPA_64_memop
	if(size==3 && !VR && A && !R && o3 && opc==4 && HasLRCPC()) return LDAPR(ctx, dec); // -> LDAPR_64L_memop
	if(size==3 && !VR && A && R && !o3 && !opc && HasLSE()) return LDADD(ctx, dec); // -> LDADDAL_64_memop
	if(size==3 && !VR && A && R && !o3 && opc==1 && HasLSE()) return LDCLR(ctx, dec); // -> LDCLRAL_64_memop
	if(size==3 && !VR && A && R && !o3 && opc==2 && HasLSE()) return LDEOR(ctx, dec); // -> LDEORAL_64_memop
	if(size==3 && !VR && A && R && !o3 && opc==3 && HasLSE()) return LDSET(ctx, dec); // -> LDSETAL_64_memop
	if(size==3 && !VR && A && R && !o3 && opc==4 && HasLSE()) return LDSMAX(ctx, dec); // -> LDSMAXAL_64_memop
	if(size==3 && !VR && A && R && !o3 && opc==5 && HasLSE()) return LDSMIN(ctx, dec); // -> LDSMINAL_64_memop
	if(size==3 && !VR && A && R && !o3 && opc==6 && HasLSE()) return LDUMAX(ctx, dec); // -> LDUMAXAL_64_memop
	if(size==3 && !VR && A && R && !o3 && opc==7 && HasLSE()) return LDUMIN(ctx, dec); // -> LDUMINAL_64_memop
	if(size==3 && !VR && A && R && o3 && !opc && HasLSE()) return SWP(ctx, dec); // -> SWPAL_64_memop
	if(size==3 && VR && !A && !R && !o3 && !opc && HasLSFE()) return LDFADD(ctx, dec); // -> LDFADD_64
	if(size==3 && VR && !A && !R && !o3 && opc==4 && HasLSFE()) return LDFMAX(ctx, dec); // -> LDFMAX_64
	if(size==3 && VR && !A && !R && !o3 && opc==5 && HasLSFE()) return LDFMIN(ctx, dec); // -> LDFMIN_64
	if(size==3 && VR && !A && !R && !o3 && opc==6 && HasLSFE()) return LDFMAXNM(ctx, dec); // -> LDFMAXNM_64
	if(size==3 && VR && !A && !R && !o3 && opc==7 && HasLSFE()) return LDFMINNM(ctx, dec); // -> LDFMINNM_64
	if(size==3 && VR && !A && R && !o3 && !opc && HasLSFE()) return LDFADD(ctx, dec); // -> LDFADDL_64
	if(size==3 && VR && !A && R && !o3 && opc==4 && HasLSFE()) return LDFMAX(ctx, dec); // -> LDFMAXL_64
	if(size==3 && VR && !A && R && !o3 && opc==5 && HasLSFE()) return LDFMIN(ctx, dec); // -> LDFMINL_64
	if(size==3 && VR && !A && R && !o3 && opc==6 && HasLSFE()) return LDFMAXNM(ctx, dec); // -> LDFMAXNML_64
	if(size==3 && VR && !A && R && !o3 && opc==7 && HasLSFE()) return LDFMINNM(ctx, dec); // -> LDFMINNML_64
	if(size==3 && VR && A && !R && !o3 && !opc && HasLSFE()) return LDFADD(ctx, dec); // -> LDFADDA_64
	if(size==3 && VR && A && !R && !o3 && opc==4 && HasLSFE()) return LDFMAX(ctx, dec); // -> LDFMAXA_64
	if(size==3 && VR && A && !R && !o3 && opc==5 && HasLSFE()) return LDFMIN(ctx, dec); // -> LDFMINA_64
	if(size==3 && VR && A && !R && !o3 && opc==6 && HasLSFE()) return LDFMAXNM(ctx, dec); // -> LDFMAXNMA_64
	if(size==3 && VR && A && !R && !o3 && opc==7 && HasLSFE()) return LDFMINNM(ctx, dec); // -> LDFMINNMA_64
	if(size==3 && VR && A && R && !o3 && !opc && HasLSFE()) return LDFADD(ctx, dec); // -> LDFADDAL_64
	if(size==3 && VR && A && R && !o3 && opc==4 && HasLSFE()) return LDFMAX(ctx, dec); // -> LDFMAXAL_64
	if(size==3 && VR && A && R && !o3 && opc==5 && HasLSFE()) return LDFMIN(ctx, dec); // -> LDFMINAL_64
	if(size==3 && VR && A && R && !o3 && opc==6 && HasLSFE()) return LDFMAXNM(ctx, dec); // -> LDFMAXNMAL_64
	if(size==3 && VR && A && R && !o3 && opc==7 && HasLSFE()) return LDFMINNM(ctx, dec); // -> LDFMINNMAL_64
	if(VR && !A && o3 && Rt!=0x1f) UNALLOCATED(ENC_UNALLOCATED_896_MEMOP);
	if(!(size&2) && !VR && !A && R && o3 && opc==5) UNALLOCATED(ENC_UNALLOCATED_907_MEMOP);
	if(!(size&2) && !VR && A && R && o3 && opc==5) UNALLOCATED(ENC_UNALLOCATED_908_MEMOP);
	if(size==2 && !VR && !A && o3 && opc==2) UNALLOCATED(ENC_UNALLOCATED_909_MEMOP);
	if(size==2 && !VR && !A && o3 && opc==3) UNALLOCATED(ENC_UNALLOCATED_910_MEMOP);
	if(size==3 && !VR && !A && R && o3 && (opc&3)==1) UNALLOCATED(ENC_UNALLOCATED_911_MEMOP);
	if(!VR && A && R && o3 && opc==4) UNALLOCATED(ENC_UNALLOCATED_906_MEMOP);
	if(!(size&2) && !VR && !R && o3 && opc==5) UNALLOCATED(ENC_UNALLOCATED_904_MEMOP);
	if(size==2 && !VR && !A && o3 && (opc&3)==1) UNALLOCATED(ENC_UNALLOCATED_905_MEMOP);
	if(!VR && !A && o3 && opc==4) UNALLOCATED(ENC_UNALLOCATED_903_MEMOP);
	if(!(size&2) && !VR && A && o3 && (opc&6)==6) UNALLOCATED(ENC_UNALLOCATED_901_MEMOP);
	if((size&2)==2 && !VR && A && o3 && (opc&3)==1) UNALLOCATED(ENC_UNALLOCATED_902_MEMOP);
	if(!VR && !A && o3 && (opc&6)==6) UNALLOCATED(ENC_UNALLOCATED_899_MEMOP);
	if(VR && !o3 && opc==1) UNALLOCATED(ENC_UNALLOCATED_900_MEMOP);
	if((size&2)==2 && !VR && A && o3 && (opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_898_MEMOP);
	if(VR && !o3 && (opc&6)==2) UNALLOCATED(ENC_UNALLOCATED_897_MEMOP);
	if(VR && A && o3) UNALLOCATED(ENC_UNALLOCATED_895_MEMOP);
	UNMATCHED;
}

int decode_iclass_memop_unpriv(context *ctx, Instruction *dec)
{
	uint32_t sz=(INSWORD>>30)&1, A=(INSWORD>>23)&1, R=(INSWORD>>22)&1, o3=(INSWORD>>15)&1, opc=(INSWORD>>12)&7;
	if(!sz && !A && !R && !o3 && !opc && HasLSUI()) return LDTADD(ctx, dec); // -> LDTADD_32_memop_unpriv
	if(!sz && !A && !R && !o3 && opc==1 && HasLSUI()) return LDTCLR(ctx, dec); // -> LDTCLR_32_memop_unpriv
	if(!sz && !A && !R && !o3 && opc==3 && HasLSUI()) return LDTSET(ctx, dec); // -> LDTSET_32_memop_unpriv
	if(!sz && !A && !R && o3 && !opc && HasLSUI()) return SWPT(ctx, dec); // -> SWPT_32_memop_unpriv
	if(!sz && !A && R && !o3 && !opc && HasLSUI()) return LDTADD(ctx, dec); // -> LDTADDL_32_memop_unpriv
	if(!sz && !A && R && !o3 && opc==1 && HasLSUI()) return LDTCLR(ctx, dec); // -> LDTCLRL_32_memop_unpriv
	if(!sz && !A && R && !o3 && opc==3 && HasLSUI()) return LDTSET(ctx, dec); // -> LDTSETL_32_memop_unpriv
	if(!sz && !A && R && o3 && !opc && HasLSUI()) return SWPT(ctx, dec); // -> SWPTL_32_memop_unpriv
	if(!sz && A && !R && !o3 && !opc && HasLSUI()) return LDTADD(ctx, dec); // -> LDTADDA_32_memop_unpriv
	if(!sz && A && !R && !o3 && opc==1 && HasLSUI()) return LDTCLR(ctx, dec); // -> LDTCLRA_32_memop_unpriv
	if(!sz && A && !R && !o3 && opc==3 && HasLSUI()) return LDTSET(ctx, dec); // -> LDTSETA_32_memop_unpriv
	if(!sz && A && !R && o3 && !opc && HasLSUI()) return SWPT(ctx, dec); // -> SWPTA_32_memop_unpriv
	if(!sz && A && R && !o3 && !opc && HasLSUI()) return LDTADD(ctx, dec); // -> LDTADDAL_32_memop_unpriv
	if(!sz && A && R && !o3 && opc==1 && HasLSUI()) return LDTCLR(ctx, dec); // -> LDTCLRAL_32_memop_unpriv
	if(!sz && A && R && !o3 && opc==3 && HasLSUI()) return LDTSET(ctx, dec); // -> LDTSETAL_32_memop_unpriv
	if(!sz && A && R && o3 && !opc && HasLSUI()) return SWPT(ctx, dec); // -> SWPTAL_32_memop_unpriv
	if(sz && !A && !R && !o3 && !opc && HasLSUI()) return LDTADD(ctx, dec); // -> LDTADD_64_memop_unpriv
	if(sz && !A && !R && !o3 && opc==1 && HasLSUI()) return LDTCLR(ctx, dec); // -> LDTCLR_64_memop_unpriv
	if(sz && !A && !R && !o3 && opc==3 && HasLSUI()) return LDTSET(ctx, dec); // -> LDTSET_64_memop_unpriv
	if(sz && !A && !R && o3 && !opc && HasLSUI()) return SWPT(ctx, dec); // -> SWPT_64_memop_unpriv
	if(sz && !A && R && !o3 && !opc && HasLSUI()) return LDTADD(ctx, dec); // -> LDTADDL_64_memop_unpriv
	if(sz && !A && R && !o3 && opc==1 && HasLSUI()) return LDTCLR(ctx, dec); // -> LDTCLRL_64_memop_unpriv
	if(sz && !A && R && !o3 && opc==3 && HasLSUI()) return LDTSET(ctx, dec); // -> LDTSETL_64_memop_unpriv
	if(sz && !A && R && o3 && !opc && HasLSUI()) return SWPT(ctx, dec); // -> SWPTL_64_memop_unpriv
	if(sz && A && !R && !o3 && !opc && HasLSUI()) return LDTADD(ctx, dec); // -> LDTADDA_64_memop_unpriv
	if(sz && A && !R && !o3 && opc==1 && HasLSUI()) return LDTCLR(ctx, dec); // -> LDTCLRA_64_memop_unpriv
	if(sz && A && !R && !o3 && opc==3 && HasLSUI()) return LDTSET(ctx, dec); // -> LDTSETA_64_memop_unpriv
	if(sz && A && !R && o3 && !opc && HasLSUI()) return SWPT(ctx, dec); // -> SWPTA_64_memop_unpriv
	if(sz && A && R && !o3 && !opc && HasLSUI()) return LDTADD(ctx, dec); // -> LDTADDAL_64_memop_unpriv
	if(sz && A && R && !o3 && opc==1 && HasLSUI()) return LDTCLR(ctx, dec); // -> LDTCLRAL_64_memop_unpriv
	if(sz && A && R && !o3 && opc==3 && HasLSUI()) return LDTSET(ctx, dec); // -> LDTSETAL_64_memop_unpriv
	if(sz && A && R && o3 && !opc && HasLSUI()) return SWPT(ctx, dec); // -> SWPTAL_64_memop_unpriv
	if(opc==2) UNALLOCATED(ENC_UNALLOCATED_919_MEMOP_UNPRIV);
	if(o3 && (opc&5)==1) UNALLOCATED(ENC_UNALLOCATED_918_MEMOP_UNPRIV);
	if((opc&4)==4) UNALLOCATED(ENC_UNALLOCATED_917_MEMOP_UNPRIV);
	UNMATCHED;
}

int decode_iclass_comswap(context *ctx, Instruction *dec)
{
	uint32_t size=INSWORD>>30, L=(INSWORD>>22)&1, o0=(INSWORD>>15)&1, Rt2=(INSWORD>>10)&0x1f;
	if(!size && !L && !o0 && Rt2==0x1f && HasLSE()) return CASB(ctx, dec); // -> CASB_C32_comswap
	if(!size && !L && o0 && Rt2==0x1f && HasLSE()) return CASB(ctx, dec); // -> CASLB_C32_comswap
	if(!size && L && !o0 && Rt2==0x1f && HasLSE()) return CASB(ctx, dec); // -> CASAB_C32_comswap
	if(!size && L && o0 && Rt2==0x1f && HasLSE()) return CASB(ctx, dec); // -> CASALB_C32_comswap
	if(size==1 && !L && !o0 && Rt2==0x1f && HasLSE()) return CASH(ctx, dec); // -> CASH_C32_comswap
	if(size==1 && !L && o0 && Rt2==0x1f && HasLSE()) return CASH(ctx, dec); // -> CASLH_C32_comswap
	if(size==1 && L && !o0 && Rt2==0x1f && HasLSE()) return CASH(ctx, dec); // -> CASAH_C32_comswap
	if(size==1 && L && o0 && Rt2==0x1f && HasLSE()) return CASH(ctx, dec); // -> CASALH_C32_comswap
	if(size==2 && !L && !o0 && Rt2==0x1f && HasLSE()) return CAS(ctx, dec); // -> CAS_C32_comswap
	if(size==2 && !L && o0 && Rt2==0x1f && HasLSE()) return CAS(ctx, dec); // -> CASL_C32_comswap
	if(size==2 && L && !o0 && Rt2==0x1f && HasLSE()) return CAS(ctx, dec); // -> CASA_C32_comswap
	if(size==2 && L && o0 && Rt2==0x1f && HasLSE()) return CAS(ctx, dec); // -> CASAL_C32_comswap
	if(size==3 && !L && !o0 && Rt2==0x1f && HasLSE()) return CAS(ctx, dec); // -> CAS_C64_comswap
	if(size==3 && !L && o0 && Rt2==0x1f && HasLSE()) return CAS(ctx, dec); // -> CASL_C64_comswap
	if(size==3 && L && !o0 && Rt2==0x1f && HasLSE()) return CAS(ctx, dec); // -> CASA_C64_comswap
	if(size==3 && L && o0 && Rt2==0x1f && HasLSE()) return CAS(ctx, dec); // -> CASAL_C64_comswap
	if(Rt2!=0x1f) UNALLOCATED(ENC_UNALLOCATED_920_COMSWAP);
	UNMATCHED;
}

int decode_iclass_comswap_unpriv(context *ctx, Instruction *dec)
{
	uint32_t sz=(INSWORD>>30)&1, L=(INSWORD>>22)&1, o0=(INSWORD>>15)&1, Rt2=(INSWORD>>10)&0x1f;
	if(sz && !L && !o0 && Rt2==0x1f && HasLSUI()) return CAST(ctx, dec); // -> CAST_C64_comswap_unpriv
	if(sz && !L && o0 && Rt2==0x1f && HasLSUI()) return CAST(ctx, dec); // -> CASLT_C64_comswap_unpriv
	if(sz && L && !o0 && Rt2==0x1f && HasLSUI()) return CAST(ctx, dec); // -> CASAT_C64_comswap_unpriv
	if(sz && L && o0 && Rt2==0x1f && HasLSUI()) return CAST(ctx, dec); // -> CASALT_C64_comswap_unpriv
	if(sz && Rt2!=0x1f) UNALLOCATED(ENC_UNALLOCATED_922_COMSWAP_UNPRIV);
	if(!sz) UNALLOCATED(ENC_UNALLOCATED_921_COMSWAP_UNPRIV);
	UNMATCHED;
}

int decode_iclass_comswappr(context *ctx, Instruction *dec)
{
	uint32_t sz=(INSWORD>>30)&1, L=(INSWORD>>22)&1, o0=(INSWORD>>15)&1, Rt2=(INSWORD>>10)&0x1f;
	if(!sz && !L && !o0 && Rt2==0x1f && HasLSE()) return CASP(ctx, dec); // -> CASP_CP32_comswappr
	if(!sz && !L && o0 && Rt2==0x1f && HasLSE()) return CASP(ctx, dec); // -> CASPL_CP32_comswappr
	if(!sz && L && !o0 && Rt2==0x1f && HasLSE()) return CASP(ctx, dec); // -> CASPA_CP32_comswappr
	if(!sz && L && o0 && Rt2==0x1f && HasLSE()) return CASP(ctx, dec); // -> CASPAL_CP32_comswappr
	if(sz && !L && !o0 && Rt2==0x1f && HasLSE()) return CASP(ctx, dec); // -> CASP_CP64_comswappr
	if(sz && !L && o0 && Rt2==0x1f && HasLSE()) return CASP(ctx, dec); // -> CASPL_CP64_comswappr
	if(sz && L && !o0 && Rt2==0x1f && HasLSE()) return CASP(ctx, dec); // -> CASPA_CP64_comswappr
	if(sz && L && o0 && Rt2==0x1f && HasLSE()) return CASP(ctx, dec); // -> CASPAL_CP64_comswappr
	if(Rt2!=0x1f) UNALLOCATED(ENC_UNALLOCATED_923_COMSWAPPR);
	UNMATCHED;
}

int decode_iclass_comswappr_unpriv(context *ctx, Instruction *dec)
{
	uint32_t sz=(INSWORD>>30)&1, L=(INSWORD>>22)&1, o0=(INSWORD>>15)&1, Rt2=(INSWORD>>10)&0x1f;
	if(sz && !L && !o0 && Rt2==0x1f && HasLSUI()) return CASPT(ctx, dec); // -> CASPT_CP64_comswappr_unpriv
	if(sz && !L && o0 && Rt2==0x1f && HasLSUI()) return CASPT(ctx, dec); // -> CASPLT_CP64_comswappr_unpriv
	if(sz && L && !o0 && Rt2==0x1f && HasLSUI()) return CASPT(ctx, dec); // -> CASPAT_CP64_comswappr_unpriv
	if(sz && L && o0 && Rt2==0x1f && HasLSUI()) return CASPT(ctx, dec); // -> CASPALT_CP64_comswappr_unpriv
	if(sz && Rt2!=0x1f) UNALLOCATED(ENC_UNALLOCATED_925_COMSWAPPR_UNPRIV);
	if(!sz) UNALLOCATED(ENC_UNALLOCATED_924_COMSWAPPR_UNPRIV);
	UNMATCHED;
}

int decode_iclass_ldst_gcs(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>12)&7;
	if(!opc && HasGCS()) return GCSSTR(ctx, dec); // -> GCSSTR_64_ldst_gcs
	if(opc==1 && HasGCS()) return GCSSTTR(ctx, dec); // -> GCSSTTR_64_ldst_gcs
	if((opc&6)==2) UNALLOCATED(ENC_UNALLOCATED_927_LDST_GCS);
	if((opc&4)==4) UNALLOCATED(ENC_UNALLOCATED_926_LDST_GCS);
	UNMATCHED;
}

int decode_iclass_loadlit(context *ctx, Instruction *dec)
{
	uint32_t opc=INSWORD>>30, VR=(INSWORD>>26)&1;
	if(!opc && !VR) return LDR_lit_gen(ctx, dec); // -> LDR_32_loadlit
	if(!opc && VR && HasFP()) return LDR_lit_fpsimd(ctx, dec); // -> LDR_S_loadlit
	if(opc==1 && !VR) return LDR_lit_gen(ctx, dec); // -> LDR_64_loadlit
	if(opc==1 && VR && HasFP()) return LDR_lit_fpsimd(ctx, dec); // -> LDR_D_loadlit
	if(opc==2 && !VR) return LDRSW_lit(ctx, dec); // -> LDRSW_64_loadlit
	if(opc==2 && VR && HasFP()) return LDR_lit_fpsimd(ctx, dec); // -> LDR_Q_loadlit
	if(opc==3 && !VR) return PRFM_lit(ctx, dec); // -> PRFM_P_loadlit
	if(opc==3 && VR) UNALLOCATED(ENC_UNALLOCATED_928_LOADLIT);
	UNMATCHED;
}

int decode_iclass_ldstexclp(context *ctx, Instruction *dec)
{
	uint32_t sz=(INSWORD>>30)&1, L=(INSWORD>>22)&1, o0=(INSWORD>>15)&1;
	if(!sz && !L && !o0) return STXP(ctx, dec); // -> STXP_SP32_ldstexclp
	if(!sz && !L && o0) return STLXP(ctx, dec); // -> STLXP_SP32_ldstexclp
	if(!sz && L && !o0) return LDXP(ctx, dec); // -> LDXP_LP32_ldstexclp
	if(!sz && L && o0) return LDAXP(ctx, dec); // -> LDAXP_LP32_ldstexclp
	if(sz && !L && !o0) return STXP(ctx, dec); // -> STXP_SP64_ldstexclp
	if(sz && !L && o0) return STLXP(ctx, dec); // -> STLXP_SP64_ldstexclp
	if(sz && L && !o0) return LDXP(ctx, dec); // -> LDXP_LP64_ldstexclp
	if(sz && L && o0) return LDAXP(ctx, dec); // -> LDAXP_LP64_ldstexclp
	UNMATCHED;
}

int decode_iclass_ldstexclr(context *ctx, Instruction *dec)
{
	uint32_t size=INSWORD>>30, L=(INSWORD>>22)&1, o0=(INSWORD>>15)&1;
	if(!size && !L && !o0) return STXRB(ctx, dec); // -> STXRB_SR32_ldstexclr
	if(!size && !L && o0) return STLXRB(ctx, dec); // -> STLXRB_SR32_ldstexclr
	if(!size && L && !o0) return LDXRB(ctx, dec); // -> LDXRB_LR32_ldstexclr
	if(!size && L && o0) return LDAXRB(ctx, dec); // -> LDAXRB_LR32_ldstexclr
	if(size==1 && !L && !o0) return STXRH(ctx, dec); // -> STXRH_SR32_ldstexclr
	if(size==1 && !L && o0) return STLXRH(ctx, dec); // -> STLXRH_SR32_ldstexclr
	if(size==1 && L && !o0) return LDXRH(ctx, dec); // -> LDXRH_LR32_ldstexclr
	if(size==1 && L && o0) return LDAXRH(ctx, dec); // -> LDAXRH_LR32_ldstexclr
	if(size==2 && !L && !o0) return STXR(ctx, dec); // -> STXR_SR32_ldstexclr
	if(size==2 && !L && o0) return STLXR(ctx, dec); // -> STLXR_SR32_ldstexclr
	if(size==2 && L && !o0) return LDXR(ctx, dec); // -> LDXR_LR32_ldstexclr
	if(size==2 && L && o0) return LDAXR(ctx, dec); // -> LDAXR_LR32_ldstexclr
	if(size==3 && !L && !o0) return STXR(ctx, dec); // -> STXR_SR64_ldstexclr
	if(size==3 && !L && o0) return STLXR(ctx, dec); // -> STLXR_SR64_ldstexclr
	if(size==3 && L && !o0) return LDXR(ctx, dec); // -> LDXR_LR64_ldstexclr
	if(size==3 && L && o0) return LDAXR(ctx, dec); // -> LDAXR_LR64_ldstexclr
	UNMATCHED;
}

int decode_iclass_ldstexclr_unpriv(context *ctx, Instruction *dec)
{
	uint32_t sz=(INSWORD>>30)&1, L=(INSWORD>>22)&1, o0=(INSWORD>>15)&1;
	if(!sz && !L && !o0 && HasLSUI()) return STTXR(ctx, dec); // -> STTXR_SR32_ldstexclr_unpriv
	if(!sz && !L && o0 && HasLSUI()) return STLTXR(ctx, dec); // -> STLTXR_SR32_ldstexclr_unpriv
	if(!sz && L && !o0 && HasLSUI()) return LDTXR(ctx, dec); // -> LDTXR_LR32_ldstexclr_unpriv
	if(!sz && L && o0 && HasLSUI()) return LDATXR(ctx, dec); // -> LDATXR_LR32_ldstexclr_unpriv
	if(sz && !L && !o0 && HasLSUI()) return STTXR(ctx, dec); // -> STTXR_SR64_ldstexclr_unpriv
	if(sz && !L && o0 && HasLSUI()) return STLTXR(ctx, dec); // -> STLTXR_SR64_ldstexclr_unpriv
	if(sz && L && !o0 && HasLSUI()) return LDTXR(ctx, dec); // -> LDTXR_LR64_ldstexclr_unpriv
	if(sz && L && o0 && HasLSUI()) return LDATXR(ctx, dec); // -> LDATXR_LR64_ldstexclr_unpriv
	UNMATCHED;
}

int decode_iclass_ldsttags(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>22)&3, imm9=(INSWORD>>12)&0x1ff, op2=(INSWORD>>10)&3;
	if(!opc && !imm9 && !op2 && HasMTE2()) return STZGM(ctx, dec); // -> STZGM_64bulk_ldsttags
	if(opc==2 && !imm9 && !op2 && HasMTE2()) return STGM(ctx, dec); // -> STGM_64bulk_ldsttags
	if(opc==3 && !imm9 && !op2 && HasMTE2()) return LDGM(ctx, dec); // -> LDGM_64bulk_ldsttags
	if(opc!=1 && imm9 && !op2) UNALLOCATED(ENC_UNALLOCATED_929_LDSTTAGS);
	if(!opc && op2==1 && HasMTE()) return STG(ctx, dec); // -> STG_64Spost_ldsttags
	if(!opc && op2==2 && HasMTE()) return STG(ctx, dec); // -> STG_64Soffset_ldsttags
	if(!opc && op2==3 && HasMTE()) return STG(ctx, dec); // -> STG_64Spre_ldsttags
	if(opc==1 && !op2 && HasMTE()) return LDG(ctx, dec); // -> LDG_64Loffset_ldsttags
	if(opc==1 && op2==1 && HasMTE()) return STZG(ctx, dec); // -> STZG_64Spost_ldsttags
	if(opc==1 && op2==2 && HasMTE()) return STZG(ctx, dec); // -> STZG_64Soffset_ldsttags
	if(opc==1 && op2==3 && HasMTE()) return STZG(ctx, dec); // -> STZG_64Spre_ldsttags
	if(opc==2 && op2==1 && HasMTE()) return ST2G(ctx, dec); // -> ST2G_64Spost_ldsttags
	if(opc==2 && op2==2 && HasMTE()) return ST2G(ctx, dec); // -> ST2G_64Soffset_ldsttags
	if(opc==2 && op2==3 && HasMTE()) return ST2G(ctx, dec); // -> ST2G_64Spre_ldsttags
	if(opc==3 && op2==1 && HasMTE()) return STZ2G(ctx, dec); // -> STZ2G_64Spost_ldsttags
	if(opc==3 && op2==2 && HasMTE()) return STZ2G(ctx, dec); // -> STZ2G_64Soffset_ldsttags
	if(opc==3 && op2==3 && HasMTE()) return STZ2G(ctx, dec); // -> STZ2G_64Spre_ldsttags
	UNMATCHED;
}

int decode_iclass_ldstnapair_offs(context *ctx, Instruction *dec)
{
	uint32_t opc=INSWORD>>30, VR=(INSWORD>>26)&1, L=(INSWORD>>22)&1;
	if(!opc && !VR && !L) return STNP_gen(ctx, dec); // -> STNP_32_ldstnapair_offs
	if(!opc && !VR && L) return LDNP_gen(ctx, dec); // -> LDNP_32_ldstnapair_offs
	if(!opc && VR && !L && HasFP()) return STNP_fpsimd(ctx, dec); // -> STNP_S_ldstnapair_offs
	if(!opc && VR && L && HasFP()) return LDNP_fpsimd(ctx, dec); // -> LDNP_S_ldstnapair_offs
	if(opc==1 && VR && !L && HasFP()) return STNP_fpsimd(ctx, dec); // -> STNP_D_ldstnapair_offs
	if(opc==1 && VR && L && HasFP()) return LDNP_fpsimd(ctx, dec); // -> LDNP_D_ldstnapair_offs
	if(opc==2 && !VR && !L) return STNP_gen(ctx, dec); // -> STNP_64_ldstnapair_offs
	if(opc==2 && !VR && L) return LDNP_gen(ctx, dec); // -> LDNP_64_ldstnapair_offs
	if(opc==2 && VR && !L && HasFP()) return STNP_fpsimd(ctx, dec); // -> STNP_Q_ldstnapair_offs
	if(opc==2 && VR && L && HasFP()) return LDNP_fpsimd(ctx, dec); // -> LDNP_Q_ldstnapair_offs
	if(opc==3 && !VR && !L && HasLSUI()) return STTNP_gen(ctx, dec); // -> STTNP_64_ldstnapair_offs
	if(opc==3 && !VR && L && HasLSUI()) return LDTNP_gen(ctx, dec); // -> LDTNP_64_ldstnapair_offs
	if(opc==3 && VR && !L && HasFP() && HasLSUI()) return STTNP_fpsimd(ctx, dec); // -> STTNP_Q_ldstnapair_offs
	if(opc==3 && VR && L && HasFP() && HasLSUI()) return LDTNP_fpsimd(ctx, dec); // -> LDTNP_Q_ldstnapair_offs
	if(opc==1 && !VR) UNALLOCATED(ENC_UNALLOCATED_930_LDSTNAPAIR_OFFS);
	UNMATCHED;
}

int decode_iclass_ldstord(context *ctx, Instruction *dec)
{
	uint32_t size=INSWORD>>30, L=(INSWORD>>22)&1, o0=(INSWORD>>15)&1;
	if(!size && !L && !o0 && HasLOR()) return STLLRB(ctx, dec); // -> STLLRB_SL32_ldstord
	if(!size && !L && o0) return STLRB(ctx, dec); // -> STLRB_SL32_ldstord
	if(!size && L && !o0 && HasLOR()) return LDLARB(ctx, dec); // -> LDLARB_LR32_ldstord
	if(!size && L && o0) return LDARB(ctx, dec); // -> LDARB_LR32_ldstord
	if(size==1 && !L && !o0 && HasLOR()) return STLLRH(ctx, dec); // -> STLLRH_SL32_ldstord
	if(size==1 && !L && o0) return STLRH(ctx, dec); // -> STLRH_SL32_ldstord
	if(size==1 && L && !o0 && HasLOR()) return LDLARH(ctx, dec); // -> LDLARH_LR32_ldstord
	if(size==1 && L && o0) return LDARH(ctx, dec); // -> LDARH_LR32_ldstord
	if(size==2 && !L && !o0 && HasLOR()) return STLLR(ctx, dec); // -> STLLR_SL32_ldstord
	if(size==2 && !L && o0) return STLR(ctx, dec); // -> STLR_SL32_ldstord
	if(size==2 && L && !o0 && HasLOR()) return LDLAR(ctx, dec); // -> LDLAR_LR32_ldstord
	if(size==2 && L && o0) return LDAR(ctx, dec); // -> LDAR_LR32_ldstord
	if(size==3 && !L && !o0 && HasLOR()) return STLLR(ctx, dec); // -> STLLR_SL64_ldstord
	if(size==3 && !L && o0) return STLR(ctx, dec); // -> STLR_SL64_ldstord
	if(size==3 && L && !o0 && HasLOR()) return LDLAR(ctx, dec); // -> LDLAR_LR64_ldstord
	if(size==3 && L && o0) return LDAR(ctx, dec); // -> LDAR_LR64_ldstord
	UNMATCHED;
}

int decode_iclass_ldapstl_simd(context *ctx, Instruction *dec)
{
	uint32_t size=INSWORD>>30, opc=(INSWORD>>22)&3;
	if(!size && !opc && HasFP() && HasLRCPC3()) return STLUR_fpsimd(ctx, dec); // -> STLUR_B_ldapstl_simd
	if(!size && opc==1 && HasFP() && HasLRCPC3()) return LDAPUR_fpsimd(ctx, dec); // -> LDAPUR_B_ldapstl_simd
	if(!size && opc==2 && HasFP() && HasLRCPC3()) return STLUR_fpsimd(ctx, dec); // -> STLUR_Q_ldapstl_simd
	if(!size && opc==3 && HasFP() && HasLRCPC3()) return LDAPUR_fpsimd(ctx, dec); // -> LDAPUR_Q_ldapstl_simd
	if(size==1 && !opc && HasFP() && HasLRCPC3()) return STLUR_fpsimd(ctx, dec); // -> STLUR_H_ldapstl_simd
	if(size==1 && opc==1 && HasFP() && HasLRCPC3()) return LDAPUR_fpsimd(ctx, dec); // -> LDAPUR_H_ldapstl_simd
	if(size==2 && !opc && HasFP() && HasLRCPC3()) return STLUR_fpsimd(ctx, dec); // -> STLUR_S_ldapstl_simd
	if(size==2 && opc==1 && HasFP() && HasLRCPC3()) return LDAPUR_fpsimd(ctx, dec); // -> LDAPUR_S_ldapstl_simd
	if(size==3 && !opc && HasFP() && HasLRCPC3()) return STLUR_fpsimd(ctx, dec); // -> STLUR_D_ldapstl_simd
	if(size==3 && opc==1 && HasFP() && HasLRCPC3()) return LDAPUR_fpsimd(ctx, dec); // -> LDAPUR_D_ldapstl_simd
	if(size && (opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_931_LDAPSTL_SIMD);
	UNMATCHED;
}

int decode_iclass_ldapstl_unscaled(context *ctx, Instruction *dec)
{
	uint32_t size=INSWORD>>30, opc=(INSWORD>>22)&3;
	if(!size && !opc && HasLRCPC2()) return STLURB(ctx, dec); // -> STLURB_32_ldapstl_unscaled
	if(!size && opc==1 && HasLRCPC2()) return LDAPURB(ctx, dec); // -> LDAPURB_32_ldapstl_unscaled
	if(!size && opc==2 && HasLRCPC2()) return LDAPURSB(ctx, dec); // -> LDAPURSB_64_ldapstl_unscaled
	if(!size && opc==3 && HasLRCPC2()) return LDAPURSB(ctx, dec); // -> LDAPURSB_32_ldapstl_unscaled
	if(size==1 && !opc && HasLRCPC2()) return STLURH(ctx, dec); // -> STLURH_32_ldapstl_unscaled
	if(size==1 && opc==1 && HasLRCPC2()) return LDAPURH(ctx, dec); // -> LDAPURH_32_ldapstl_unscaled
	if(size==1 && opc==2 && HasLRCPC2()) return LDAPURSH(ctx, dec); // -> LDAPURSH_64_ldapstl_unscaled
	if(size==1 && opc==3 && HasLRCPC2()) return LDAPURSH(ctx, dec); // -> LDAPURSH_32_ldapstl_unscaled
	if(size==2 && !opc && HasLRCPC2()) return STLUR_gen(ctx, dec); // -> STLUR_32_ldapstl_unscaled
	if(size==2 && opc==1 && HasLRCPC2()) return LDAPUR_gen(ctx, dec); // -> LDAPUR_32_ldapstl_unscaled
	if(size==2 && opc==2 && HasLRCPC2()) return LDAPURSW(ctx, dec); // -> LDAPURSW_64_ldapstl_unscaled
	if(size==2 && opc==3) UNALLOCATED(ENC_UNALLOCATED_933_LDAPSTL_UNSCALED);
	if(size==3 && !opc && HasLRCPC2()) return STLUR_gen(ctx, dec); // -> STLUR_64_ldapstl_unscaled
	if(size==3 && opc==1 && HasLRCPC2()) return LDAPUR_gen(ctx, dec); // -> LDAPUR_64_ldapstl_unscaled
	if(size==3 && (opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_932_LDAPSTL_UNSCALED);
	UNMATCHED;
}

int decode_iclass_ldapstl_writeback(context *ctx, Instruction *dec)
{
	uint32_t size=INSWORD>>30, L=(INSWORD>>22)&1;
	if(size==2 && !L && HasLRCPC3()) return STLR(ctx, dec); // -> STLR_32S_ldapstl_writeback
	if(size==2 && L && HasLRCPC3()) return LDAPR(ctx, dec); // -> LDAPR_32L_ldapstl_writeback
	if(size==3 && !L && HasLRCPC3()) return STLR(ctx, dec); // -> STLR_64S_ldapstl_writeback
	if(size==3 && L && HasLRCPC3()) return LDAPR(ctx, dec); // -> LDAPR_64L_ldapstl_writeback
	if(!(size&2)) UNALLOCATED(ENC_UNALLOCATED_934_LDAPSTL_WRITEBACK);
	UNMATCHED;
}

int decode_iclass_ldiappstilp(context *ctx, Instruction *dec)
{
	uint32_t size=INSWORD>>30, L=(INSWORD>>22)&1, opc2=(INSWORD>>12)&15;
	if(size==2 && !L && !opc2 && HasLRCPC3()) return STILP(ctx, dec); // -> STILP_32SE_ldiappstilp
	if(size==2 && !L && opc2==1 && HasLRCPC3()) return STILP(ctx, dec); // -> STILP_32S_ldiappstilp
	if(size==2 && L && !opc2 && HasLRCPC3()) return LDIAPP(ctx, dec); // -> LDIAPP_32LE_ldiappstilp
	if(size==2 && L && opc2==1 && HasLRCPC3()) return LDIAPP(ctx, dec); // -> LDIAPP_32L_ldiappstilp
	if(size==3 && !L && !opc2 && HasLRCPC3()) return STILP(ctx, dec); // -> STILP_64SS_ldiappstilp
	if(size==3 && !L && opc2==1 && HasLRCPC3()) return STILP(ctx, dec); // -> STILP_64S_ldiappstilp
	if(size==3 && !L && opc2==5 && HasLSCP()) return STLP_gen(ctx, dec); // -> STLP_64_ldiappstilp
	if(size==3 && L && !opc2 && HasLRCPC3()) return LDIAPP(ctx, dec); // -> LDIAPP_64LS_ldiappstilp
	if(size==3 && L && opc2==1 && HasLRCPC3()) return LDIAPP(ctx, dec); // -> LDIAPP_64L_ldiappstilp
	if(size==3 && L && opc2==5 && HasLSCP()) return LDAP_gen(ctx, dec); // -> LDAP_64_ldiappstilp
	if(size==3 && L && opc2==6) UNALLOCATED(ENC_UNALLOCATED_942_LDIAPPSTILP);
	if(size==3 && L && opc2==7 && HasLSCP()) return LDAPP_gen(ctx, dec); // -> LDAPP_64_ldiappstilp
	if(size==3 && opc2==4) UNALLOCATED(ENC_UNALLOCATED_941_LDIAPPSTILP);
	if(size==3 && !L && (opc2&14)==6) UNALLOCATED(ENC_UNALLOCATED_940_LDIAPPSTILP);
	if((size&2)==2 && !L && (opc2&14)==2) UNALLOCATED(ENC_UNALLOCATED_938_LDIAPPSTILP);
	if((size&2)==2 && L && (opc2&14)==2) UNALLOCATED(ENC_UNALLOCATED_939_LDIAPPSTILP);
	if(size==2 && (opc2&12)==4) UNALLOCATED(ENC_UNALLOCATED_937_LDIAPPSTILP);
	if((size&2)==2 && (opc2&8)==8) UNALLOCATED(ENC_UNALLOCATED_936_LDIAPPSTILP);
	if(!(size&2)) UNALLOCATED(ENC_UNALLOCATED_935_LDIAPPSTILP);
	UNMATCHED;
}

int decode_iclass_ldst_immpost(context *ctx, Instruction *dec)
{
	uint32_t size=INSWORD>>30, VR=(INSWORD>>26)&1, opc=(INSWORD>>22)&3;
	if(!size && !VR && !opc) return STRB_imm(ctx, dec); // -> STRB_32_ldst_immpost
	if(!size && !VR && opc==1) return LDRB_imm(ctx, dec); // -> LDRB_32_ldst_immpost
	if(!size && !VR && opc==2) return LDRSB_imm(ctx, dec); // -> LDRSB_64_ldst_immpost
	if(!size && !VR && opc==3) return LDRSB_imm(ctx, dec); // -> LDRSB_32_ldst_immpost
	if(!size && VR && !opc && HasFP()) return STR_imm_fpsimd(ctx, dec); // -> STR_B_ldst_immpost
	if(!size && VR && opc==1 && HasFP()) return LDR_imm_fpsimd(ctx, dec); // -> LDR_B_ldst_immpost
	if(!size && VR && opc==2 && HasFP()) return STR_imm_fpsimd(ctx, dec); // -> STR_Q_ldst_immpost
	if(!size && VR && opc==3 && HasFP()) return LDR_imm_fpsimd(ctx, dec); // -> LDR_Q_ldst_immpost
	if(size==1 && !VR && !opc) return STRH_imm(ctx, dec); // -> STRH_32_ldst_immpost
	if(size==1 && !VR && opc==1) return LDRH_imm(ctx, dec); // -> LDRH_32_ldst_immpost
	if(size==1 && !VR && opc==2) return LDRSH_imm(ctx, dec); // -> LDRSH_64_ldst_immpost
	if(size==1 && !VR && opc==3) return LDRSH_imm(ctx, dec); // -> LDRSH_32_ldst_immpost
	if(size==1 && VR && !opc && HasFP()) return STR_imm_fpsimd(ctx, dec); // -> STR_H_ldst_immpost
	if(size==1 && VR && opc==1 && HasFP()) return LDR_imm_fpsimd(ctx, dec); // -> LDR_H_ldst_immpost
	if(size==2 && !VR && !opc) return STR_imm_gen(ctx, dec); // -> STR_32_ldst_immpost
	if(size==2 && !VR && opc==1) return LDR_imm_gen(ctx, dec); // -> LDR_32_ldst_immpost
	if(size==2 && !VR && opc==2) return LDRSW_imm(ctx, dec); // -> LDRSW_64_ldst_immpost
	if(size==2 && !VR && opc==3) UNALLOCATED(ENC_UNALLOCATED_946_LDST_IMMPOST);
	if(size==2 && VR && !opc && HasFP()) return STR_imm_fpsimd(ctx, dec); // -> STR_S_ldst_immpost
	if(size==2 && VR && opc==1 && HasFP()) return LDR_imm_fpsimd(ctx, dec); // -> LDR_S_ldst_immpost
	if(size==3 && !VR && !opc) return STR_imm_gen(ctx, dec); // -> STR_64_ldst_immpost
	if(size==3 && !VR && opc==1) return LDR_imm_gen(ctx, dec); // -> LDR_64_ldst_immpost
	if(size==3 && VR && !opc && HasFP()) return STR_imm_fpsimd(ctx, dec); // -> STR_D_ldst_immpost
	if(size==3 && VR && opc==1 && HasFP()) return LDR_imm_fpsimd(ctx, dec); // -> LDR_D_ldst_immpost
	if(size==1 && VR && (opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_944_LDST_IMMPOST);
	if(size==2 && VR && (opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_945_LDST_IMMPOST);
	if(size==3 && (opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_943_LDST_IMMPOST);
	UNMATCHED;
}

int decode_iclass_ldst_immpre(context *ctx, Instruction *dec)
{
	uint32_t size=INSWORD>>30, VR=(INSWORD>>26)&1, opc=(INSWORD>>22)&3;
	if(!size && !VR && !opc) return STRB_imm(ctx, dec); // -> STRB_32_ldst_immpre
	if(!size && !VR && opc==1) return LDRB_imm(ctx, dec); // -> LDRB_32_ldst_immpre
	if(!size && !VR && opc==2) return LDRSB_imm(ctx, dec); // -> LDRSB_64_ldst_immpre
	if(!size && !VR && opc==3) return LDRSB_imm(ctx, dec); // -> LDRSB_32_ldst_immpre
	if(!size && VR && !opc && HasFP()) return STR_imm_fpsimd(ctx, dec); // -> STR_B_ldst_immpre
	if(!size && VR && opc==1 && HasFP()) return LDR_imm_fpsimd(ctx, dec); // -> LDR_B_ldst_immpre
	if(!size && VR && opc==2 && HasFP()) return STR_imm_fpsimd(ctx, dec); // -> STR_Q_ldst_immpre
	if(!size && VR && opc==3 && HasFP()) return LDR_imm_fpsimd(ctx, dec); // -> LDR_Q_ldst_immpre
	if(size==1 && !VR && !opc) return STRH_imm(ctx, dec); // -> STRH_32_ldst_immpre
	if(size==1 && !VR && opc==1) return LDRH_imm(ctx, dec); // -> LDRH_32_ldst_immpre
	if(size==1 && !VR && opc==2) return LDRSH_imm(ctx, dec); // -> LDRSH_64_ldst_immpre
	if(size==1 && !VR && opc==3) return LDRSH_imm(ctx, dec); // -> LDRSH_32_ldst_immpre
	if(size==1 && VR && !opc && HasFP()) return STR_imm_fpsimd(ctx, dec); // -> STR_H_ldst_immpre
	if(size==1 && VR && opc==1 && HasFP()) return LDR_imm_fpsimd(ctx, dec); // -> LDR_H_ldst_immpre
	if(size==2 && !VR && !opc) return STR_imm_gen(ctx, dec); // -> STR_32_ldst_immpre
	if(size==2 && !VR && opc==1) return LDR_imm_gen(ctx, dec); // -> LDR_32_ldst_immpre
	if(size==2 && !VR && opc==2) return LDRSW_imm(ctx, dec); // -> LDRSW_64_ldst_immpre
	if(size==2 && !VR && opc==3) UNALLOCATED(ENC_UNALLOCATED_950_LDST_IMMPRE);
	if(size==2 && VR && !opc && HasFP()) return STR_imm_fpsimd(ctx, dec); // -> STR_S_ldst_immpre
	if(size==2 && VR && opc==1 && HasFP()) return LDR_imm_fpsimd(ctx, dec); // -> LDR_S_ldst_immpre
	if(size==3 && !VR && !opc) return STR_imm_gen(ctx, dec); // -> STR_64_ldst_immpre
	if(size==3 && !VR && opc==1) return LDR_imm_gen(ctx, dec); // -> LDR_64_ldst_immpre
	if(size==3 && VR && !opc && HasFP()) return STR_imm_fpsimd(ctx, dec); // -> STR_D_ldst_immpre
	if(size==3 && VR && opc==1 && HasFP()) return LDR_imm_fpsimd(ctx, dec); // -> LDR_D_ldst_immpre
	if(size==1 && VR && (opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_948_LDST_IMMPRE);
	if(size==2 && VR && (opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_949_LDST_IMMPRE);
	if(size==3 && (opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_947_LDST_IMMPRE);
	UNMATCHED;
}

int decode_iclass_ldst_pac(context *ctx, Instruction *dec)
{
	uint32_t size=INSWORD>>30, VR=(INSWORD>>26)&1, M=(INSWORD>>23)&1, W=(INSWORD>>11)&1;
	if(size==3 && !VR && !M && !W && HasPAuth()) return LDRA(ctx, dec); // -> LDRAA_64_ldst_pac
	if(size==3 && !VR && !M && W && HasPAuth()) return LDRA(ctx, dec); // -> LDRAA_64W_ldst_pac
	if(size==3 && !VR && M && !W && HasPAuth()) return LDRA(ctx, dec); // -> LDRAB_64_ldst_pac
	if(size==3 && !VR && M && W && HasPAuth()) return LDRA(ctx, dec); // -> LDRAB_64W_ldst_pac
	if(size==3 && VR) UNALLOCATED(ENC_UNALLOCATED_952_LDST_PAC);
	if(size!=3) UNALLOCATED(ENC_UNALLOCATED_951_LDST_PAC);
	UNMATCHED;
}

int decode_iclass_ldst_regoff(context *ctx, Instruction *dec)
{
	uint32_t size=INSWORD>>30, VR=(INSWORD>>26)&1, opc=(INSWORD>>22)&3, option=(INSWORD>>13)&7, Rt=INSWORD&0x1f;
	if(!size && !VR && !opc && option==3) return STRB_reg(ctx, dec); // -> STRB_32BL_ldst_regoff
	if(!size && !VR && !opc && option!=3) return STRB_reg(ctx, dec); // -> STRB_32B_ldst_regoff
	if(!size && !VR && opc==1 && option==3) return LDRB_reg(ctx, dec); // -> LDRB_32BL_ldst_regoff
	if(!size && !VR && opc==1 && option!=3) return LDRB_reg(ctx, dec); // -> LDRB_32B_ldst_regoff
	if(!size && !VR && opc==2 && option==3) return LDRSB_reg(ctx, dec); // -> LDRSB_64BL_ldst_regoff
	if(!size && !VR && opc==2 && option!=3) return LDRSB_reg(ctx, dec); // -> LDRSB_64B_ldst_regoff
	if(!size && !VR && opc==3 && option==3) return LDRSB_reg(ctx, dec); // -> LDRSB_32BL_ldst_regoff
	if(!size && !VR && opc==3 && option!=3) return LDRSB_reg(ctx, dec); // -> LDRSB_32B_ldst_regoff
	if(!size && VR && !opc && option==3 && HasFP()) return STR_reg_fpsimd(ctx, dec); // -> STR_BL_ldst_regoff
	if(!size && VR && !opc && option!=3 && HasFP()) return STR_reg_fpsimd(ctx, dec); // -> STR_B_ldst_regoff
	if(!size && VR && opc==1 && option==3 && HasFP()) return LDR_reg_fpsimd(ctx, dec); // -> LDR_BL_ldst_regoff
	if(!size && VR && opc==1 && option!=3 && HasFP()) return LDR_reg_fpsimd(ctx, dec); // -> LDR_B_ldst_regoff
	if(size==3 && !VR && opc==2 && (option&2)==2 && (Rt&0x18)==0x18 && HasRPRFM()) return RPRFM_reg(ctx, dec); // -> RPRFM_R_ldst_regoff
	if(size==3 && !VR && opc==2 && (option&2)==2 && (Rt&0x18)!=0x18) return PRFM_reg(ctx, dec); // -> PRFM_P_ldst_regoff
	if(size==3 && !VR && opc==2 && !(option&2)) UNALLOCATED(ENC_UNALLOCATED_955_LDST_REGOFF);
	if(!size && VR && opc==2 && HasFP()) return STR_reg_fpsimd(ctx, dec); // -> STR_Q_ldst_regoff
	if(!size && VR && opc==3 && HasFP()) return LDR_reg_fpsimd(ctx, dec); // -> LDR_Q_ldst_regoff
	if(size==1 && !VR && !opc) return STRH_reg(ctx, dec); // -> STRH_32_ldst_regoff
	if(size==1 && !VR && opc==1) return LDRH_reg(ctx, dec); // -> LDRH_32_ldst_regoff
	if(size==1 && !VR && opc==2) return LDRSH_reg(ctx, dec); // -> LDRSH_64_ldst_regoff
	if(size==1 && !VR && opc==3) return LDRSH_reg(ctx, dec); // -> LDRSH_32_ldst_regoff
	if(size==1 && VR && !opc && HasFP()) return STR_reg_fpsimd(ctx, dec); // -> STR_H_ldst_regoff
	if(size==1 && VR && opc==1 && HasFP()) return LDR_reg_fpsimd(ctx, dec); // -> LDR_H_ldst_regoff
	if(size==2 && !VR && !opc) return STR_reg_gen(ctx, dec); // -> STR_32_ldst_regoff
	if(size==2 && !VR && opc==1) return LDR_reg_gen(ctx, dec); // -> LDR_32_ldst_regoff
	if(size==2 && !VR && opc==2) return LDRSW_reg(ctx, dec); // -> LDRSW_64_ldst_regoff
	if(size==2 && VR && !opc && HasFP()) return STR_reg_fpsimd(ctx, dec); // -> STR_S_ldst_regoff
	if(size==2 && VR && opc==1 && HasFP()) return LDR_reg_fpsimd(ctx, dec); // -> LDR_S_ldst_regoff
	if(size==3 && !VR && !opc) return STR_reg_gen(ctx, dec); // -> STR_64_ldst_regoff
	if(size==3 && !VR && opc==1) return LDR_reg_gen(ctx, dec); // -> LDR_64_ldst_regoff
	if(size==3 && VR && !opc && HasFP()) return STR_reg_fpsimd(ctx, dec); // -> STR_D_ldst_regoff
	if(size==3 && VR && opc==1 && HasFP()) return LDR_reg_fpsimd(ctx, dec); // -> LDR_D_ldst_regoff
	if((size&2)==2 && !VR && opc==3) UNALLOCATED(ENC_UNALLOCATED_954_LDST_REGOFF);
	if(size && VR && (opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_953_LDST_REGOFF);
	UNMATCHED;
}

int decode_iclass_ldst_unpriv(context *ctx, Instruction *dec)
{
	uint32_t size=INSWORD>>30, VR=(INSWORD>>26)&1, opc=(INSWORD>>22)&3;
	if(!size && !VR && !opc) return STTRB(ctx, dec); // -> STTRB_32_ldst_unpriv
	if(!size && !VR && opc==1) return LDTRB(ctx, dec); // -> LDTRB_32_ldst_unpriv
	if(!size && !VR && opc==2) return LDTRSB(ctx, dec); // -> LDTRSB_64_ldst_unpriv
	if(!size && !VR && opc==3) return LDTRSB(ctx, dec); // -> LDTRSB_32_ldst_unpriv
	if(size==1 && !VR && !opc) return STTRH(ctx, dec); // -> STTRH_32_ldst_unpriv
	if(size==1 && !VR && opc==1) return LDTRH(ctx, dec); // -> LDTRH_32_ldst_unpriv
	if(size==1 && !VR && opc==2) return LDTRSH(ctx, dec); // -> LDTRSH_64_ldst_unpriv
	if(size==1 && !VR && opc==3) return LDTRSH(ctx, dec); // -> LDTRSH_32_ldst_unpriv
	if(size==2 && !VR && !opc) return STTR(ctx, dec); // -> STTR_32_ldst_unpriv
	if(size==2 && !VR && opc==1) return LDTR(ctx, dec); // -> LDTR_32_ldst_unpriv
	if(size==2 && !VR && opc==2) return LDTRSW(ctx, dec); // -> LDTRSW_64_ldst_unpriv
	if(size==2 && !VR && opc==3) UNALLOCATED(ENC_UNALLOCATED_958_LDST_UNPRIV);
	if(size==3 && !VR && !opc) return STTR(ctx, dec); // -> STTR_64_ldst_unpriv
	if(size==3 && !VR && opc==1) return LDTR(ctx, dec); // -> LDTR_64_ldst_unpriv
	if(size==3 && !VR && (opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_957_LDST_UNPRIV);
	if(VR) UNALLOCATED(ENC_UNALLOCATED_956_LDST_UNPRIV);
	UNMATCHED;
}

int decode_iclass_ldst_unscaled(context *ctx, Instruction *dec)
{
	uint32_t size=INSWORD>>30, VR=(INSWORD>>26)&1, opc=(INSWORD>>22)&3;
	if(!size && !VR && !opc) return STURB(ctx, dec); // -> STURB_32_ldst_unscaled
	if(!size && !VR && opc==1) return LDURB(ctx, dec); // -> LDURB_32_ldst_unscaled
	if(!size && !VR && opc==2) return LDURSB(ctx, dec); // -> LDURSB_64_ldst_unscaled
	if(!size && !VR && opc==3) return LDURSB(ctx, dec); // -> LDURSB_32_ldst_unscaled
	if(!size && VR && !opc && HasFP()) return STUR_fpsimd(ctx, dec); // -> STUR_B_ldst_unscaled
	if(!size && VR && opc==1 && HasFP()) return LDUR_fpsimd(ctx, dec); // -> LDUR_B_ldst_unscaled
	if(!size && VR && opc==2 && HasFP()) return STUR_fpsimd(ctx, dec); // -> STUR_Q_ldst_unscaled
	if(!size && VR && opc==3 && HasFP()) return LDUR_fpsimd(ctx, dec); // -> LDUR_Q_ldst_unscaled
	if(size==1 && !VR && !opc) return STURH(ctx, dec); // -> STURH_32_ldst_unscaled
	if(size==1 && !VR && opc==1) return LDURH(ctx, dec); // -> LDURH_32_ldst_unscaled
	if(size==1 && !VR && opc==2) return LDURSH(ctx, dec); // -> LDURSH_64_ldst_unscaled
	if(size==1 && !VR && opc==3) return LDURSH(ctx, dec); // -> LDURSH_32_ldst_unscaled
	if(size==1 && VR && !opc && HasFP()) return STUR_fpsimd(ctx, dec); // -> STUR_H_ldst_unscaled
	if(size==1 && VR && opc==1 && HasFP()) return LDUR_fpsimd(ctx, dec); // -> LDUR_H_ldst_unscaled
	if(size==2 && !VR && !opc) return STUR_gen(ctx, dec); // -> STUR_32_ldst_unscaled
	if(size==2 && !VR && opc==1) return LDUR_gen(ctx, dec); // -> LDUR_32_ldst_unscaled
	if(size==2 && !VR && opc==2) return LDURSW(ctx, dec); // -> LDURSW_64_ldst_unscaled
	if(size==2 && VR && !opc && HasFP()) return STUR_fpsimd(ctx, dec); // -> STUR_S_ldst_unscaled
	if(size==2 && VR && opc==1 && HasFP()) return LDUR_fpsimd(ctx, dec); // -> LDUR_S_ldst_unscaled
	if(size==3 && !VR && !opc) return STUR_gen(ctx, dec); // -> STUR_64_ldst_unscaled
	if(size==3 && !VR && opc==1) return LDUR_gen(ctx, dec); // -> LDUR_64_ldst_unscaled
	if(size==3 && !VR && opc==2) return PRFUM(ctx, dec); // -> PRFUM_P_ldst_unscaled
	if(size==3 && VR && !opc && HasFP()) return STUR_fpsimd(ctx, dec); // -> STUR_D_ldst_unscaled
	if(size==3 && VR && opc==1 && HasFP()) return LDUR_fpsimd(ctx, dec); // -> LDUR_D_ldst_unscaled
	if((size&2)==2 && !VR && opc==3) UNALLOCATED(ENC_UNALLOCATED_960_LDST_UNSCALED);
	if(size && VR && (opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_959_LDST_UNSCALED);
	UNMATCHED;
}

int decode_iclass_ldst_pos(context *ctx, Instruction *dec)
{
	uint32_t size=INSWORD>>30, VR=(INSWORD>>26)&1, opc=(INSWORD>>22)&3;
	if(!size && !VR && !opc) return STRB_imm(ctx, dec); // -> STRB_32_ldst_pos
	if(!size && !VR && opc==1) return LDRB_imm(ctx, dec); // -> LDRB_32_ldst_pos
	if(!size && !VR && opc==2) return LDRSB_imm(ctx, dec); // -> LDRSB_64_ldst_pos
	if(!size && !VR && opc==3) return LDRSB_imm(ctx, dec); // -> LDRSB_32_ldst_pos
	if(!size && VR && !opc && HasFP()) return STR_imm_fpsimd(ctx, dec); // -> STR_B_ldst_pos
	if(!size && VR && opc==1 && HasFP()) return LDR_imm_fpsimd(ctx, dec); // -> LDR_B_ldst_pos
	if(!size && VR && opc==2 && HasFP()) return STR_imm_fpsimd(ctx, dec); // -> STR_Q_ldst_pos
	if(!size && VR && opc==3 && HasFP()) return LDR_imm_fpsimd(ctx, dec); // -> LDR_Q_ldst_pos
	if(size==1 && !VR && !opc) return STRH_imm(ctx, dec); // -> STRH_32_ldst_pos
	if(size==1 && !VR && opc==1) return LDRH_imm(ctx, dec); // -> LDRH_32_ldst_pos
	if(size==1 && !VR && opc==2) return LDRSH_imm(ctx, dec); // -> LDRSH_64_ldst_pos
	if(size==1 && !VR && opc==3) return LDRSH_imm(ctx, dec); // -> LDRSH_32_ldst_pos
	if(size==1 && VR && !opc && HasFP()) return STR_imm_fpsimd(ctx, dec); // -> STR_H_ldst_pos
	if(size==1 && VR && opc==1 && HasFP()) return LDR_imm_fpsimd(ctx, dec); // -> LDR_H_ldst_pos
	if(size==2 && !VR && !opc) return STR_imm_gen(ctx, dec); // -> STR_32_ldst_pos
	if(size==2 && !VR && opc==1) return LDR_imm_gen(ctx, dec); // -> LDR_32_ldst_pos
	if(size==2 && !VR && opc==2) return LDRSW_imm(ctx, dec); // -> LDRSW_64_ldst_pos
	if(size==2 && VR && !opc && HasFP()) return STR_imm_fpsimd(ctx, dec); // -> STR_S_ldst_pos
	if(size==2 && VR && opc==1 && HasFP()) return LDR_imm_fpsimd(ctx, dec); // -> LDR_S_ldst_pos
	if(size==3 && !VR && !opc) return STR_imm_gen(ctx, dec); // -> STR_64_ldst_pos
	if(size==3 && !VR && opc==1) return LDR_imm_gen(ctx, dec); // -> LDR_64_ldst_pos
	if(size==3 && !VR && opc==2) return PRFM_imm(ctx, dec); // -> PRFM_P_ldst_pos
	if(size==3 && VR && !opc && HasFP()) return STR_imm_fpsimd(ctx, dec); // -> STR_D_ldst_pos
	if(size==3 && VR && opc==1 && HasFP()) return LDR_imm_fpsimd(ctx, dec); // -> LDR_D_ldst_pos
	if((size&2)==2 && !VR && opc==3) UNALLOCATED(ENC_UNALLOCATED_962_LDST_POS);
	if(size && VR && (opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_961_LDST_POS);
	UNMATCHED;
}

int decode_iclass_ldstpair_off(context *ctx, Instruction *dec)
{
	uint32_t opc=INSWORD>>30, VR=(INSWORD>>26)&1, L=(INSWORD>>22)&1;
	if(!opc && !VR && !L) return STP_gen(ctx, dec); // -> STP_32_ldstpair_off
	if(!opc && !VR && L) return LDP_gen(ctx, dec); // -> LDP_32_ldstpair_off
	if(!opc && VR && !L && HasFP()) return STP_fpsimd(ctx, dec); // -> STP_S_ldstpair_off
	if(!opc && VR && L && HasFP()) return LDP_fpsimd(ctx, dec); // -> LDP_S_ldstpair_off
	if(opc==1 && !VR && !L && HasMTE()) return STGP(ctx, dec); // -> STGP_64_ldstpair_off
	if(opc==1 && !VR && L) return LDPSW(ctx, dec); // -> LDPSW_64_ldstpair_off
	if(opc==1 && VR && !L && HasFP()) return STP_fpsimd(ctx, dec); // -> STP_D_ldstpair_off
	if(opc==1 && VR && L && HasFP()) return LDP_fpsimd(ctx, dec); // -> LDP_D_ldstpair_off
	if(opc==2 && !VR && !L) return STP_gen(ctx, dec); // -> STP_64_ldstpair_off
	if(opc==2 && !VR && L) return LDP_gen(ctx, dec); // -> LDP_64_ldstpair_off
	if(opc==2 && VR && !L && HasFP()) return STP_fpsimd(ctx, dec); // -> STP_Q_ldstpair_off
	if(opc==2 && VR && L && HasFP()) return LDP_fpsimd(ctx, dec); // -> LDP_Q_ldstpair_off
	if(opc==3 && !VR && !L && HasLSUI()) return STTP_gen(ctx, dec); // -> STTP_64_ldstpair_off
	if(opc==3 && !VR && L && HasLSUI()) return LDTP_gen(ctx, dec); // -> LDTP_64_ldstpair_off
	if(opc==3 && VR && !L && HasFP() && HasLSUI()) return STTP_fpsimd(ctx, dec); // -> STTP_Q_ldstpair_off
	if(opc==3 && VR && L && HasFP() && HasLSUI()) return LDTP_fpsimd(ctx, dec); // -> LDTP_Q_ldstpair_off
	UNMATCHED;
}

int decode_iclass_ldstpair_post(context *ctx, Instruction *dec)
{
	uint32_t opc=INSWORD>>30, VR=(INSWORD>>26)&1, L=(INSWORD>>22)&1;
	if(!opc && !VR && !L) return STP_gen(ctx, dec); // -> STP_32_ldstpair_post
	if(!opc && !VR && L) return LDP_gen(ctx, dec); // -> LDP_32_ldstpair_post
	if(!opc && VR && !L && HasFP()) return STP_fpsimd(ctx, dec); // -> STP_S_ldstpair_post
	if(!opc && VR && L && HasFP()) return LDP_fpsimd(ctx, dec); // -> LDP_S_ldstpair_post
	if(opc==1 && !VR && !L && HasMTE()) return STGP(ctx, dec); // -> STGP_64_ldstpair_post
	if(opc==1 && !VR && L) return LDPSW(ctx, dec); // -> LDPSW_64_ldstpair_post
	if(opc==1 && VR && !L && HasFP()) return STP_fpsimd(ctx, dec); // -> STP_D_ldstpair_post
	if(opc==1 && VR && L && HasFP()) return LDP_fpsimd(ctx, dec); // -> LDP_D_ldstpair_post
	if(opc==2 && !VR && !L) return STP_gen(ctx, dec); // -> STP_64_ldstpair_post
	if(opc==2 && !VR && L) return LDP_gen(ctx, dec); // -> LDP_64_ldstpair_post
	if(opc==2 && VR && !L && HasFP()) return STP_fpsimd(ctx, dec); // -> STP_Q_ldstpair_post
	if(opc==2 && VR && L && HasFP()) return LDP_fpsimd(ctx, dec); // -> LDP_Q_ldstpair_post
	if(opc==3 && !VR && !L && HasLSUI()) return STTP_gen(ctx, dec); // -> STTP_64_ldstpair_post
	if(opc==3 && !VR && L && HasLSUI()) return LDTP_gen(ctx, dec); // -> LDTP_64_ldstpair_post
	if(opc==3 && VR && !L && HasFP() && HasLSUI()) return STTP_fpsimd(ctx, dec); // -> STTP_Q_ldstpair_post
	if(opc==3 && VR && L && HasFP() && HasLSUI()) return LDTP_fpsimd(ctx, dec); // -> LDTP_Q_ldstpair_post
	UNMATCHED;
}

int decode_iclass_ldstpair_pre(context *ctx, Instruction *dec)
{
	uint32_t opc=INSWORD>>30, VR=(INSWORD>>26)&1, L=(INSWORD>>22)&1;
	if(!opc && !VR && !L) return STP_gen(ctx, dec); // -> STP_32_ldstpair_pre
	if(!opc && !VR && L) return LDP_gen(ctx, dec); // -> LDP_32_ldstpair_pre
	if(!opc && VR && !L && HasFP()) return STP_fpsimd(ctx, dec); // -> STP_S_ldstpair_pre
	if(!opc && VR && L && HasFP()) return LDP_fpsimd(ctx, dec); // -> LDP_S_ldstpair_pre
	if(opc==1 && !VR && !L && HasMTE()) return STGP(ctx, dec); // -> STGP_64_ldstpair_pre
	if(opc==1 && !VR && L) return LDPSW(ctx, dec); // -> LDPSW_64_ldstpair_pre
	if(opc==1 && VR && !L && HasFP()) return STP_fpsimd(ctx, dec); // -> STP_D_ldstpair_pre
	if(opc==1 && VR && L && HasFP()) return LDP_fpsimd(ctx, dec); // -> LDP_D_ldstpair_pre
	if(opc==2 && !VR && !L) return STP_gen(ctx, dec); // -> STP_64_ldstpair_pre
	if(opc==2 && !VR && L) return LDP_gen(ctx, dec); // -> LDP_64_ldstpair_pre
	if(opc==2 && VR && !L && HasFP()) return STP_fpsimd(ctx, dec); // -> STP_Q_ldstpair_pre
	if(opc==2 && VR && L && HasFP()) return LDP_fpsimd(ctx, dec); // -> LDP_Q_ldstpair_pre
	if(opc==3 && !VR && !L && HasLSUI()) return STTP_gen(ctx, dec); // -> STTP_64_ldstpair_pre
	if(opc==3 && !VR && L && HasLSUI()) return LDTP_gen(ctx, dec); // -> LDTP_64_ldstpair_pre
	if(opc==3 && VR && !L && HasFP() && HasLSUI()) return STTP_fpsimd(ctx, dec); // -> STTP_Q_ldstpair_pre
	if(opc==3 && VR && L && HasFP() && HasLSUI()) return LDTP_fpsimd(ctx, dec); // -> LDTP_Q_ldstpair_pre
	UNMATCHED;
}

int decode_iclass_memcms(context *ctx, Instruction *dec)
{
	uint32_t o0=(INSWORD>>26)&1, op1=(INSWORD>>22)&3, op2=(INSWORD>>12)&15;
	if(!o0 && !op1 && !op2 && HasMOPS()) return CPYFP(ctx, dec); // -> CPYFP_CPY_memcms
	if(!o0 && !op1 && op2==1 && HasMOPS()) return CPYFPWT(ctx, dec); // -> CPYFPWT_CPY_memcms
	if(!o0 && !op1 && op2==2 && HasMOPS()) return CPYFPRT(ctx, dec); // -> CPYFPRT_CPY_memcms
	if(!o0 && !op1 && op2==3 && HasMOPS()) return CPYFPT(ctx, dec); // -> CPYFPT_CPY_memcms
	if(!o0 && !op1 && op2==4 && HasMOPS()) return CPYFPWN(ctx, dec); // -> CPYFPWN_CPY_memcms
	if(!o0 && !op1 && op2==5 && HasMOPS()) return CPYFPWTWN(ctx, dec); // -> CPYFPWTWN_CPY_memcms
	if(!o0 && !op1 && op2==6 && HasMOPS()) return CPYFPRTWN(ctx, dec); // -> CPYFPRTWN_CPY_memcms
	if(!o0 && !op1 && op2==7 && HasMOPS()) return CPYFPTWN(ctx, dec); // -> CPYFPTWN_CPY_memcms
	if(!o0 && !op1 && op2==8 && HasMOPS()) return CPYFPRN(ctx, dec); // -> CPYFPRN_CPY_memcms
	if(!o0 && !op1 && op2==9 && HasMOPS()) return CPYFPWTRN(ctx, dec); // -> CPYFPWTRN_CPY_memcms
	if(!o0 && !op1 && op2==10 && HasMOPS()) return CPYFPRTRN(ctx, dec); // -> CPYFPRTRN_CPY_memcms
	if(!o0 && !op1 && op2==11 && HasMOPS()) return CPYFPTRN(ctx, dec); // -> CPYFPTRN_CPY_memcms
	if(!o0 && !op1 && op2==12 && HasMOPS()) return CPYFPN(ctx, dec); // -> CPYFPN_CPY_memcms
	if(!o0 && !op1 && op2==13 && HasMOPS()) return CPYFPWTN(ctx, dec); // -> CPYFPWTN_CPY_memcms
	if(!o0 && !op1 && op2==14 && HasMOPS()) return CPYFPRTN(ctx, dec); // -> CPYFPRTN_CPY_memcms
	if(!o0 && !op1 && op2==15 && HasMOPS()) return CPYFPTN(ctx, dec); // -> CPYFPTN_CPY_memcms
	if(!o0 && op1==1 && !op2 && HasMOPS()) return CPYFP(ctx, dec); // -> CPYFM_CPY_memcms
	if(!o0 && op1==1 && op2==1 && HasMOPS()) return CPYFPWT(ctx, dec); // -> CPYFMWT_CPY_memcms
	if(!o0 && op1==1 && op2==2 && HasMOPS()) return CPYFPRT(ctx, dec); // -> CPYFMRT_CPY_memcms
	if(!o0 && op1==1 && op2==3 && HasMOPS()) return CPYFPT(ctx, dec); // -> CPYFMT_CPY_memcms
	if(!o0 && op1==1 && op2==4 && HasMOPS()) return CPYFPWN(ctx, dec); // -> CPYFMWN_CPY_memcms
	if(!o0 && op1==1 && op2==5 && HasMOPS()) return CPYFPWTWN(ctx, dec); // -> CPYFMWTWN_CPY_memcms
	if(!o0 && op1==1 && op2==6 && HasMOPS()) return CPYFPRTWN(ctx, dec); // -> CPYFMRTWN_CPY_memcms
	if(!o0 && op1==1 && op2==7 && HasMOPS()) return CPYFPTWN(ctx, dec); // -> CPYFMTWN_CPY_memcms
	if(!o0 && op1==1 && op2==8 && HasMOPS()) return CPYFPRN(ctx, dec); // -> CPYFMRN_CPY_memcms
	if(!o0 && op1==1 && op2==9 && HasMOPS()) return CPYFPWTRN(ctx, dec); // -> CPYFMWTRN_CPY_memcms
	if(!o0 && op1==1 && op2==10 && HasMOPS()) return CPYFPRTRN(ctx, dec); // -> CPYFMRTRN_CPY_memcms
	if(!o0 && op1==1 && op2==11 && HasMOPS()) return CPYFPTRN(ctx, dec); // -> CPYFMTRN_CPY_memcms
	if(!o0 && op1==1 && op2==12 && HasMOPS()) return CPYFPN(ctx, dec); // -> CPYFMN_CPY_memcms
	if(!o0 && op1==1 && op2==13 && HasMOPS()) return CPYFPWTN(ctx, dec); // -> CPYFMWTN_CPY_memcms
	if(!o0 && op1==1 && op2==14 && HasMOPS()) return CPYFPRTN(ctx, dec); // -> CPYFMRTN_CPY_memcms
	if(!o0 && op1==1 && op2==15 && HasMOPS()) return CPYFPTN(ctx, dec); // -> CPYFMTN_CPY_memcms
	if(!o0 && op1==2 && !op2 && HasMOPS()) return CPYFP(ctx, dec); // -> CPYFE_CPY_memcms
	if(!o0 && op1==2 && op2==1 && HasMOPS()) return CPYFPWT(ctx, dec); // -> CPYFEWT_CPY_memcms
	if(!o0 && op1==2 && op2==2 && HasMOPS()) return CPYFPRT(ctx, dec); // -> CPYFERT_CPY_memcms
	if(!o0 && op1==2 && op2==3 && HasMOPS()) return CPYFPT(ctx, dec); // -> CPYFET_CPY_memcms
	if(!o0 && op1==2 && op2==4 && HasMOPS()) return CPYFPWN(ctx, dec); // -> CPYFEWN_CPY_memcms
	if(!o0 && op1==2 && op2==5 && HasMOPS()) return CPYFPWTWN(ctx, dec); // -> CPYFEWTWN_CPY_memcms
	if(!o0 && op1==2 && op2==6 && HasMOPS()) return CPYFPRTWN(ctx, dec); // -> CPYFERTWN_CPY_memcms
	if(!o0 && op1==2 && op2==7 && HasMOPS()) return CPYFPTWN(ctx, dec); // -> CPYFETWN_CPY_memcms
	if(!o0 && op1==2 && op2==8 && HasMOPS()) return CPYFPRN(ctx, dec); // -> CPYFERN_CPY_memcms
	if(!o0 && op1==2 && op2==9 && HasMOPS()) return CPYFPWTRN(ctx, dec); // -> CPYFEWTRN_CPY_memcms
	if(!o0 && op1==2 && op2==10 && HasMOPS()) return CPYFPRTRN(ctx, dec); // -> CPYFERTRN_CPY_memcms
	if(!o0 && op1==2 && op2==11 && HasMOPS()) return CPYFPTRN(ctx, dec); // -> CPYFETRN_CPY_memcms
	if(!o0 && op1==2 && op2==12 && HasMOPS()) return CPYFPN(ctx, dec); // -> CPYFEN_CPY_memcms
	if(!o0 && op1==2 && op2==13 && HasMOPS()) return CPYFPWTN(ctx, dec); // -> CPYFEWTN_CPY_memcms
	if(!o0 && op1==2 && op2==14 && HasMOPS()) return CPYFPRTN(ctx, dec); // -> CPYFERTN_CPY_memcms
	if(!o0 && op1==2 && op2==15 && HasMOPS()) return CPYFPTN(ctx, dec); // -> CPYFETN_CPY_memcms
	if(!o0 && op1==3 && !op2 && HasMOPS()) return SETP(ctx, dec); // -> SETP_SET_memcms
	if(!o0 && op1==3 && op2==1 && HasMOPS()) return SETPT(ctx, dec); // -> SETPT_SET_memcms
	if(!o0 && op1==3 && op2==2 && HasMOPS()) return SETPN(ctx, dec); // -> SETPN_SET_memcms
	if(!o0 && op1==3 && op2==3 && HasMOPS()) return SETPTN(ctx, dec); // -> SETPTN_SET_memcms
	if(!o0 && op1==3 && op2==4 && HasMOPS()) return SETP(ctx, dec); // -> SETM_SET_memcms
	if(!o0 && op1==3 && op2==5 && HasMOPS()) return SETPT(ctx, dec); // -> SETMT_SET_memcms
	if(!o0 && op1==3 && op2==6 && HasMOPS()) return SETPN(ctx, dec); // -> SETMN_SET_memcms
	if(!o0 && op1==3 && op2==7 && HasMOPS()) return SETPTN(ctx, dec); // -> SETMTN_SET_memcms
	if(!o0 && op1==3 && op2==8 && HasMOPS()) return SETP(ctx, dec); // -> SETE_SET_memcms
	if(!o0 && op1==3 && op2==9 && HasMOPS()) return SETPT(ctx, dec); // -> SETET_SET_memcms
	if(!o0 && op1==3 && op2==10 && HasMOPS()) return SETPN(ctx, dec); // -> SETEN_SET_memcms
	if(!o0 && op1==3 && op2==11 && HasMOPS()) return SETPTN(ctx, dec); // -> SETETN_SET_memcms
	if(o0 && !op1 && !op2 && HasMOPS()) return CPYP(ctx, dec); // -> CPYP_CPY_memcms
	if(o0 && !op1 && op2==1 && HasMOPS()) return CPYPWT(ctx, dec); // -> CPYPWT_CPY_memcms
	if(o0 && !op1 && op2==2 && HasMOPS()) return CPYPRT(ctx, dec); // -> CPYPRT_CPY_memcms
	if(o0 && !op1 && op2==3 && HasMOPS()) return CPYPT(ctx, dec); // -> CPYPT_CPY_memcms
	if(o0 && !op1 && op2==4 && HasMOPS()) return CPYPWN(ctx, dec); // -> CPYPWN_CPY_memcms
	if(o0 && !op1 && op2==5 && HasMOPS()) return CPYPWTWN(ctx, dec); // -> CPYPWTWN_CPY_memcms
	if(o0 && !op1 && op2==6 && HasMOPS()) return CPYPRTWN(ctx, dec); // -> CPYPRTWN_CPY_memcms
	if(o0 && !op1 && op2==7 && HasMOPS()) return CPYPTWN(ctx, dec); // -> CPYPTWN_CPY_memcms
	if(o0 && !op1 && op2==8 && HasMOPS()) return CPYPRN(ctx, dec); // -> CPYPRN_CPY_memcms
	if(o0 && !op1 && op2==9 && HasMOPS()) return CPYPWTRN(ctx, dec); // -> CPYPWTRN_CPY_memcms
	if(o0 && !op1 && op2==10 && HasMOPS()) return CPYPRTRN(ctx, dec); // -> CPYPRTRN_CPY_memcms
	if(o0 && !op1 && op2==11 && HasMOPS()) return CPYPTRN(ctx, dec); // -> CPYPTRN_CPY_memcms
	if(o0 && !op1 && op2==12 && HasMOPS()) return CPYPN(ctx, dec); // -> CPYPN_CPY_memcms
	if(o0 && !op1 && op2==13 && HasMOPS()) return CPYPWTN(ctx, dec); // -> CPYPWTN_CPY_memcms
	if(o0 && !op1 && op2==14 && HasMOPS()) return CPYPRTN(ctx, dec); // -> CPYPRTN_CPY_memcms
	if(o0 && !op1 && op2==15 && HasMOPS()) return CPYPTN(ctx, dec); // -> CPYPTN_CPY_memcms
	if(o0 && op1==1 && !op2 && HasMOPS()) return CPYP(ctx, dec); // -> CPYM_CPY_memcms
	if(o0 && op1==1 && op2==1 && HasMOPS()) return CPYPWT(ctx, dec); // -> CPYMWT_CPY_memcms
	if(o0 && op1==1 && op2==2 && HasMOPS()) return CPYPRT(ctx, dec); // -> CPYMRT_CPY_memcms
	if(o0 && op1==1 && op2==3 && HasMOPS()) return CPYPT(ctx, dec); // -> CPYMT_CPY_memcms
	if(o0 && op1==1 && op2==4 && HasMOPS()) return CPYPWN(ctx, dec); // -> CPYMWN_CPY_memcms
	if(o0 && op1==1 && op2==5 && HasMOPS()) return CPYPWTWN(ctx, dec); // -> CPYMWTWN_CPY_memcms
	if(o0 && op1==1 && op2==6 && HasMOPS()) return CPYPRTWN(ctx, dec); // -> CPYMRTWN_CPY_memcms
	if(o0 && op1==1 && op2==7 && HasMOPS()) return CPYPTWN(ctx, dec); // -> CPYMTWN_CPY_memcms
	if(o0 && op1==1 && op2==8 && HasMOPS()) return CPYPRN(ctx, dec); // -> CPYMRN_CPY_memcms
	if(o0 && op1==1 && op2==9 && HasMOPS()) return CPYPWTRN(ctx, dec); // -> CPYMWTRN_CPY_memcms
	if(o0 && op1==1 && op2==10 && HasMOPS()) return CPYPRTRN(ctx, dec); // -> CPYMRTRN_CPY_memcms
	if(o0 && op1==1 && op2==11 && HasMOPS()) return CPYPTRN(ctx, dec); // -> CPYMTRN_CPY_memcms
	if(o0 && op1==1 && op2==12 && HasMOPS()) return CPYPN(ctx, dec); // -> CPYMN_CPY_memcms
	if(o0 && op1==1 && op2==13 && HasMOPS()) return CPYPWTN(ctx, dec); // -> CPYMWTN_CPY_memcms
	if(o0 && op1==1 && op2==14 && HasMOPS()) return CPYPRTN(ctx, dec); // -> CPYMRTN_CPY_memcms
	if(o0 && op1==1 && op2==15 && HasMOPS()) return CPYPTN(ctx, dec); // -> CPYMTN_CPY_memcms
	if(o0 && op1==2 && !op2 && HasMOPS()) return CPYP(ctx, dec); // -> CPYE_CPY_memcms
	if(o0 && op1==2 && op2==1 && HasMOPS()) return CPYPWT(ctx, dec); // -> CPYEWT_CPY_memcms
	if(o0 && op1==2 && op2==2 && HasMOPS()) return CPYPRT(ctx, dec); // -> CPYERT_CPY_memcms
	if(o0 && op1==2 && op2==3 && HasMOPS()) return CPYPT(ctx, dec); // -> CPYET_CPY_memcms
	if(o0 && op1==2 && op2==4 && HasMOPS()) return CPYPWN(ctx, dec); // -> CPYEWN_CPY_memcms
	if(o0 && op1==2 && op2==5 && HasMOPS()) return CPYPWTWN(ctx, dec); // -> CPYEWTWN_CPY_memcms
	if(o0 && op1==2 && op2==6 && HasMOPS()) return CPYPRTWN(ctx, dec); // -> CPYERTWN_CPY_memcms
	if(o0 && op1==2 && op2==7 && HasMOPS()) return CPYPTWN(ctx, dec); // -> CPYETWN_CPY_memcms
	if(o0 && op1==2 && op2==8 && HasMOPS()) return CPYPRN(ctx, dec); // -> CPYERN_CPY_memcms
	if(o0 && op1==2 && op2==9 && HasMOPS()) return CPYPWTRN(ctx, dec); // -> CPYEWTRN_CPY_memcms
	if(o0 && op1==2 && op2==10 && HasMOPS()) return CPYPRTRN(ctx, dec); // -> CPYERTRN_CPY_memcms
	if(o0 && op1==2 && op2==11 && HasMOPS()) return CPYPTRN(ctx, dec); // -> CPYETRN_CPY_memcms
	if(o0 && op1==2 && op2==12 && HasMOPS()) return CPYPN(ctx, dec); // -> CPYEN_CPY_memcms
	if(o0 && op1==2 && op2==13 && HasMOPS()) return CPYPWTN(ctx, dec); // -> CPYEWTN_CPY_memcms
	if(o0 && op1==2 && op2==14 && HasMOPS()) return CPYPRTN(ctx, dec); // -> CPYERTN_CPY_memcms
	if(o0 && op1==2 && op2==15 && HasMOPS()) return CPYPTN(ctx, dec); // -> CPYETN_CPY_memcms
	if(o0 && op1==3 && !op2 && HasMOPS() && HasMTE()) return SETGP(ctx, dec); // -> SETGP_SET_memcms
	if(o0 && op1==3 && op2==1 && HasMOPS() && HasMTE()) return SETGPT(ctx, dec); // -> SETGPT_SET_memcms
	if(o0 && op1==3 && op2==2 && HasMOPS() && HasMTE()) return SETGPN(ctx, dec); // -> SETGPN_SET_memcms
	if(o0 && op1==3 && op2==3 && HasMOPS() && HasMTE()) return SETGPTN(ctx, dec); // -> SETGPTN_SET_memcms
	if(o0 && op1==3 && op2==4 && HasMOPS() && HasMTE()) return SETGP(ctx, dec); // -> SETGM_SET_memcms
	if(o0 && op1==3 && op2==5 && HasMOPS() && HasMTE()) return SETGPT(ctx, dec); // -> SETGMT_SET_memcms
	if(o0 && op1==3 && op2==6 && HasMOPS() && HasMTE()) return SETGPN(ctx, dec); // -> SETGMN_SET_memcms
	if(o0 && op1==3 && op2==7 && HasMOPS() && HasMTE()) return SETGPTN(ctx, dec); // -> SETGMTN_SET_memcms
	if(o0 && op1==3 && op2==8 && HasMOPS() && HasMTE()) return SETGP(ctx, dec); // -> SETGE_SET_memcms
	if(o0 && op1==3 && op2==9 && HasMOPS() && HasMTE()) return SETGPT(ctx, dec); // -> SETGET_SET_memcms
	if(o0 && op1==3 && op2==10 && HasMOPS() && HasMTE()) return SETGPN(ctx, dec); // -> SETGEN_SET_memcms
	if(o0 && op1==3 && op2==11 && HasMOPS() && HasMTE()) return SETGPTN(ctx, dec); // -> SETGETN_SET_memcms
	if(op1==3 && (op2&12)==12) UNALLOCATED(ENC_UNALLOCATED_963_MEMCMS);
	UNMATCHED;
}

int decode_iclass_rcwcomswap(context *ctx, Instruction *dec)
{
	uint32_t S=(INSWORD>>30)&1, A=(INSWORD>>23)&1, R=(INSWORD>>22)&1;
	if(!S && !A && !R && HasTHE()) return RCWCAS(ctx, dec); // -> RCWCAS_C64_rcwcomswap
	if(!S && !A && R && HasTHE()) return RCWCAS(ctx, dec); // -> RCWCASL_C64_rcwcomswap
	if(!S && A && !R && HasTHE()) return RCWCAS(ctx, dec); // -> RCWCASA_C64_rcwcomswap
	if(!S && A && R && HasTHE()) return RCWCAS(ctx, dec); // -> RCWCASAL_C64_rcwcomswap
	if(S && !A && !R && HasTHE()) return RCWSCAS(ctx, dec); // -> RCWSCAS_C64_rcwcomswap
	if(S && !A && R && HasTHE()) return RCWSCAS(ctx, dec); // -> RCWSCASL_C64_rcwcomswap
	if(S && A && !R && HasTHE()) return RCWSCAS(ctx, dec); // -> RCWSCASA_C64_rcwcomswap
	if(S && A && R && HasTHE()) return RCWSCAS(ctx, dec); // -> RCWSCASAL_C64_rcwcomswap
	UNMATCHED;
}

int decode_iclass_rcwcomswappr(context *ctx, Instruction *dec)
{
	uint32_t S=(INSWORD>>30)&1, A=(INSWORD>>23)&1, R=(INSWORD>>22)&1;
	if(!S && !A && !R && HasD128() && HasTHE()) return RCWCASP(ctx, dec); // -> RCWCASP_C64_rcwcomswappr
	if(!S && !A && R && HasD128() && HasTHE()) return RCWCASP(ctx, dec); // -> RCWCASPL_C64_rcwcomswappr
	if(!S && A && !R && HasD128() && HasTHE()) return RCWCASP(ctx, dec); // -> RCWCASPA_C64_rcwcomswappr
	if(!S && A && R && HasD128() && HasTHE()) return RCWCASP(ctx, dec); // -> RCWCASPAL_C64_rcwcomswappr
	if(S && !A && !R && HasD128() && HasTHE()) return RCWSCASP(ctx, dec); // -> RCWSCASP_C64_rcwcomswappr
	if(S && !A && R && HasD128() && HasTHE()) return RCWSCASP(ctx, dec); // -> RCWSCASPL_C64_rcwcomswappr
	if(S && A && !R && HasD128() && HasTHE()) return RCWSCASP(ctx, dec); // -> RCWSCASPA_C64_rcwcomswappr
	if(S && A && R && HasD128() && HasTHE()) return RCWSCASP(ctx, dec); // -> RCWSCASPAL_C64_rcwcomswappr
	UNMATCHED;
}

int decode_iclass_addsub_imm(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, op=(INSWORD>>30)&1, S=(INSWORD>>29)&1;
	if(!sf && !op && !S) return ADD_addsub_imm(ctx, dec); // -> ADD_32_addsub_imm
	if(!sf && !op && S) return ADDS_addsub_imm(ctx, dec); // -> ADDS_32S_addsub_imm
	if(!sf && op && !S) return SUB_addsub_imm(ctx, dec); // -> SUB_32_addsub_imm
	if(!sf && op && S) return SUBS_addsub_imm(ctx, dec); // -> SUBS_32S_addsub_imm
	if(sf && !op && !S) return ADD_addsub_imm(ctx, dec); // -> ADD_64_addsub_imm
	if(sf && !op && S) return ADDS_addsub_imm(ctx, dec); // -> ADDS_64S_addsub_imm
	if(sf && op && !S) return SUB_addsub_imm(ctx, dec); // -> SUB_64_addsub_imm
	if(sf && op && S) return SUBS_addsub_imm(ctx, dec); // -> SUBS_64S_addsub_imm
	UNMATCHED;
}

int decode_iclass_addsub_immtags(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, op=(INSWORD>>30)&1, S=(INSWORD>>29)&1;
	if(sf && !op && !S && HasMTE()) return ADDG(ctx, dec); // -> ADDG_64_addsub_immtags
	if(sf && op && !S && HasMTE()) return SUBG(ctx, dec); // -> SUBG_64_addsub_immtags
	if(sf && S) UNALLOCATED(ENC_UNALLOCATED_797_ADDSUB_IMMTAGS);
	if(!sf) UNALLOCATED(ENC_UNALLOCATED_796_ADDSUB_IMMTAGS);
	UNMATCHED;
}

int decode_iclass_bitfield(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, opc=(INSWORD>>29)&3, N=(INSWORD>>22)&1;
	if(!sf && !opc && !N) return SBFM(ctx, dec); // -> SBFM_32M_bitfield
	if(!sf && opc==1 && !N) return BFM(ctx, dec); // -> BFM_32M_bitfield
	if(!sf && opc==2 && !N) return UBFM(ctx, dec); // -> UBFM_32M_bitfield
	if(!sf && opc==3 && !N) UNALLOCATED(ENC_UNALLOCATED_800_BITFIELD);
	if(sf && !opc && N) return SBFM(ctx, dec); // -> SBFM_64M_bitfield
	if(sf && opc==1 && N) return BFM(ctx, dec); // -> BFM_64M_bitfield
	if(sf && opc==2 && N) return UBFM(ctx, dec); // -> UBFM_64M_bitfield
	if(sf && opc==3 && N) UNALLOCATED(ENC_UNALLOCATED_801_BITFIELD);
	if(!sf && N) UNALLOCATED(ENC_UNALLOCATED_798_BITFIELD);
	if(sf && !N) UNALLOCATED(ENC_UNALLOCATED_799_BITFIELD);
	UNMATCHED;
}

int decode_iclass_dp_1src_imm(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, opc=(INSWORD>>21)&3, Rd=INSWORD&0x1f;
	if(sf && !opc && Rd==0x1f && HasPAuth_LR()) return AUTIASPPC_imm(ctx, dec); // -> AUTIASPPC_only_dp_1src_imm
	if(sf && opc==1 && Rd==0x1f && HasPAuth_LR()) return AUTIBSPPC_imm(ctx, dec); // -> AUTIBSPPC_only_dp_1src_imm
	if(sf && !(opc&2) && Rd!=0x1f) UNALLOCATED(ENC_UNALLOCATED_804_DP_1SRC_IMM);
	if(sf && (opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_803_DP_1SRC_IMM);
	if(!sf) UNALLOCATED(ENC_UNALLOCATED_802_DP_1SRC_IMM);
	UNMATCHED;
}

int decode_iclass_extract(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, op21=(INSWORD>>29)&3, N=(INSWORD>>22)&1, o0=(INSWORD>>21)&1, imms=(INSWORD>>10)&0x3f;
	if(!sf && !op21 && !N && !o0 && !(imms&0x20)) return EXTR(ctx, dec); // -> EXTR_32_extract
	if(!sf && !op21 && !N && !o0 && (imms&0x20)==0x20) UNALLOCATED(ENC_UNALLOCATED_810_EXTRACT);
	if(!sf && !op21 && N && !o0) UNALLOCATED(ENC_UNALLOCATED_808_EXTRACT);
	if(sf && !op21 && !N && !o0) UNALLOCATED(ENC_UNALLOCATED_809_EXTRACT);
	if(sf && !op21 && N && !o0) return EXTR(ctx, dec); // -> EXTR_64_extract
	if(!op21 && o0) UNALLOCATED(ENC_UNALLOCATED_807_EXTRACT);
	if(op21==1) UNALLOCATED(ENC_UNALLOCATED_805_EXTRACT);
	if(op21==2) UNALLOCATED(ENC_UNALLOCATED_806_EXTRACT);
	UNMATCHED;
}

int decode_iclass_log_imm(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, opc=(INSWORD>>29)&3, N=(INSWORD>>22)&1;
	if(!sf && !opc && !N) return AND_log_imm(ctx, dec); // -> AND_32_log_imm
	if(!sf && opc==1 && !N) return ORR_log_imm(ctx, dec); // -> ORR_32_log_imm
	if(!sf && opc==2 && !N) return EOR_log_imm(ctx, dec); // -> EOR_32_log_imm
	if(!sf && opc==3 && !N) return ANDS_log_imm(ctx, dec); // -> ANDS_32S_log_imm
	if(sf && !opc) return AND_log_imm(ctx, dec); // -> AND_64_log_imm
	if(sf && opc==1) return ORR_log_imm(ctx, dec); // -> ORR_64_log_imm
	if(sf && opc==2) return EOR_log_imm(ctx, dec); // -> EOR_64_log_imm
	if(sf && opc==3) return ANDS_log_imm(ctx, dec); // -> ANDS_64S_log_imm
	if(!sf && N) UNALLOCATED(ENC_UNALLOCATED_811_LOG_IMM);
	UNMATCHED;
}

int decode_iclass_minmax_imm(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, op=(INSWORD>>30)&1, S=(INSWORD>>29)&1, opc=(INSWORD>>18)&15;
	if(!sf && !op && !S && !opc && HasCSSC()) return SMAX_imm(ctx, dec); // -> SMAX_32_minmax_imm
	if(!sf && !op && !S && opc==1 && HasCSSC()) return UMAX_imm(ctx, dec); // -> UMAX_32U_minmax_imm
	if(!sf && !op && !S && opc==2 && HasCSSC()) return SMIN_imm(ctx, dec); // -> SMIN_32_minmax_imm
	if(!sf && !op && !S && opc==3 && HasCSSC()) return UMIN_imm(ctx, dec); // -> UMIN_32U_minmax_imm
	if(sf && !op && !S && !opc && HasCSSC()) return SMAX_imm(ctx, dec); // -> SMAX_64_minmax_imm
	if(sf && !op && !S && opc==1 && HasCSSC()) return UMAX_imm(ctx, dec); // -> UMAX_64U_minmax_imm
	if(sf && !op && !S && opc==2 && HasCSSC()) return SMIN_imm(ctx, dec); // -> SMIN_64_minmax_imm
	if(sf && !op && !S && opc==3 && HasCSSC()) return UMIN_imm(ctx, dec); // -> UMIN_64U_minmax_imm
	if(!op && !S && (opc&12)==4) UNALLOCATED(ENC_UNALLOCATED_815_MINMAX_IMM);
	if(!op && !S && (opc&8)==8) UNALLOCATED(ENC_UNALLOCATED_814_MINMAX_IMM);
	if(!op && S) UNALLOCATED(ENC_UNALLOCATED_813_MINMAX_IMM);
	if(op) UNALLOCATED(ENC_UNALLOCATED_812_MINMAX_IMM);
	UNMATCHED;
}

int decode_iclass_movewide(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, opc=(INSWORD>>29)&3, hw=(INSWORD>>21)&3;
	if(!sf && !opc && !(hw&2)) return MOVN(ctx, dec); // -> MOVN_32_movewide
	if(!sf && opc==2 && !(hw&2)) return MOVZ(ctx, dec); // -> MOVZ_32_movewide
	if(!sf && opc==3 && !(hw&2)) return MOVK(ctx, dec); // -> MOVK_32_movewide
	if(sf && opc==1 && (hw&2)==2) UNALLOCATED(ENC_UNALLOCATED_818_MOVEWIDE);
	if(opc==1 && !(hw&2)) UNALLOCATED(ENC_UNALLOCATED_817_MOVEWIDE);
	if(sf && !opc) return MOVN(ctx, dec); // -> MOVN_64_movewide
	if(sf && opc==2) return MOVZ(ctx, dec); // -> MOVZ_64_movewide
	if(sf && opc==3) return MOVK(ctx, dec); // -> MOVK_64_movewide
	if(!sf && (hw&2)==2) UNALLOCATED(ENC_UNALLOCATED_816_MOVEWIDE);
	UNMATCHED;
}

int decode_iclass_pcreladdr(context *ctx, Instruction *dec)
{
	uint32_t op=INSWORD>>31;
	if(!op) return ADR(ctx, dec); // -> ADR_only_pcreladdr
	if(op) return ADRP(ctx, dec); // -> ADRP_only_pcreladdr
	UNMATCHED;
}

int decode_iclass_addsub_pt(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, op=(INSWORD>>30)&1, S=(INSWORD>>29)&1;
	if(sf && !op && !S && HasCPA()) return ADDPT(ctx, dec); // -> ADDPT_64_addsub_pt
	if(sf && op && !S && HasCPA()) return SUBPT(ctx, dec); // -> SUBPT_64_addsub_pt
	if(sf && S) UNALLOCATED(ENC_UNALLOCATED_965_ADDSUB_PT);
	if(!sf) UNALLOCATED(ENC_UNALLOCATED_964_ADDSUB_PT);
	UNMATCHED;
}

int decode_iclass_addsub_ext(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, op=(INSWORD>>30)&1, S=(INSWORD>>29)&1, opt=(INSWORD>>22)&3;
	if(!sf && !op && !S && !opt) return ADD_addsub_ext(ctx, dec); // -> ADD_32_addsub_ext
	if(!sf && !op && S && !opt) return ADDS_addsub_ext(ctx, dec); // -> ADDS_32S_addsub_ext
	if(!sf && op && !S && !opt) return SUB_addsub_ext(ctx, dec); // -> SUB_32_addsub_ext
	if(!sf && op && S && !opt) return SUBS_addsub_ext(ctx, dec); // -> SUBS_32S_addsub_ext
	if(sf && !op && !S && !opt) return ADD_addsub_ext(ctx, dec); // -> ADD_64_addsub_ext
	if(sf && !op && S && !opt) return ADDS_addsub_ext(ctx, dec); // -> ADDS_64S_addsub_ext
	if(sf && op && !S && !opt) return SUB_addsub_ext(ctx, dec); // -> SUB_64_addsub_ext
	if(sf && op && S && !opt) return SUBS_addsub_ext(ctx, dec); // -> SUBS_64S_addsub_ext
	if(opt) UNALLOCATED(ENC_UNALLOCATED_966_ADDSUB_EXT);
	UNMATCHED;
}

int decode_iclass_addsub_shift(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, op=(INSWORD>>30)&1, S=(INSWORD>>29)&1;
	if(!sf && !op && !S) return ADD_addsub_shift(ctx, dec); // -> ADD_32_addsub_shift
	if(!sf && !op && S) return ADDS_addsub_shift(ctx, dec); // -> ADDS_32_addsub_shift
	if(!sf && op && !S) return SUB_addsub_shift(ctx, dec); // -> SUB_32_addsub_shift
	if(!sf && op && S) return SUBS_addsub_shift(ctx, dec); // -> SUBS_32_addsub_shift
	if(sf && !op && !S) return ADD_addsub_shift(ctx, dec); // -> ADD_64_addsub_shift
	if(sf && !op && S) return ADDS_addsub_shift(ctx, dec); // -> ADDS_64_addsub_shift
	if(sf && op && !S) return SUB_addsub_shift(ctx, dec); // -> SUB_64_addsub_shift
	if(sf && op && S) return SUBS_addsub_shift(ctx, dec); // -> SUBS_64_addsub_shift
	UNMATCHED;
}

int decode_iclass_addsub_carry(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, op=(INSWORD>>30)&1, S=(INSWORD>>29)&1;
	if(!sf && !op && !S) return ADC(ctx, dec); // -> ADC_32_addsub_carry
	if(!sf && !op && S) return ADCS(ctx, dec); // -> ADCS_32_addsub_carry
	if(!sf && op && !S) return SBC(ctx, dec); // -> SBC_32_addsub_carry
	if(!sf && op && S) return SBCS(ctx, dec); // -> SBCS_32_addsub_carry
	if(sf && !op && !S) return ADC(ctx, dec); // -> ADC_64_addsub_carry
	if(sf && !op && S) return ADCS(ctx, dec); // -> ADCS_64_addsub_carry
	if(sf && op && !S) return SBC(ctx, dec); // -> SBC_64_addsub_carry
	if(sf && op && S) return SBCS(ctx, dec); // -> SBCS_64_addsub_carry
	UNMATCHED;
}

int decode_iclass_condcmp_imm(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, op=(INSWORD>>30)&1, S=(INSWORD>>29)&1, o2=(INSWORD>>10)&1, o3=(INSWORD>>4)&1;
	if(!sf && !op && S && !o2 && !o3) return CCMN_imm(ctx, dec); // -> CCMN_32_condcmp_imm
	if(!sf && op && S && !o2 && !o3) return CCMP_imm(ctx, dec); // -> CCMP_32_condcmp_imm
	if(sf && !op && S && !o2 && !o3) return CCMN_imm(ctx, dec); // -> CCMN_64_condcmp_imm
	if(sf && op && S && !o2 && !o3) return CCMP_imm(ctx, dec); // -> CCMP_64_condcmp_imm
	if(S && !o2 && o3) UNALLOCATED(ENC_UNALLOCATED_969_CONDCMP_IMM);
	if(S && o2) UNALLOCATED(ENC_UNALLOCATED_968_CONDCMP_IMM);
	if(!S) UNALLOCATED(ENC_UNALLOCATED_967_CONDCMP_IMM);
	UNMATCHED;
}

int decode_iclass_condcmp_reg(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, op=(INSWORD>>30)&1, S=(INSWORD>>29)&1, o2=(INSWORD>>10)&1, o3=(INSWORD>>4)&1;
	if(!sf && !op && S && !o2 && !o3) return CCMN_reg(ctx, dec); // -> CCMN_32_condcmp_reg
	if(!sf && op && S && !o2 && !o3) return CCMP_reg(ctx, dec); // -> CCMP_32_condcmp_reg
	if(sf && !op && S && !o2 && !o3) return CCMN_reg(ctx, dec); // -> CCMN_64_condcmp_reg
	if(sf && op && S && !o2 && !o3) return CCMP_reg(ctx, dec); // -> CCMP_64_condcmp_reg
	if(S && !o2 && o3) UNALLOCATED(ENC_UNALLOCATED_972_CONDCMP_REG);
	if(S && o2) UNALLOCATED(ENC_UNALLOCATED_971_CONDCMP_REG);
	if(!S) UNALLOCATED(ENC_UNALLOCATED_970_CONDCMP_REG);
	UNMATCHED;
}

int decode_iclass_condsel(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, op=(INSWORD>>30)&1, S=(INSWORD>>29)&1, op2=(INSWORD>>10)&3;
	if(!sf && !op && !S && !op2) return CSEL(ctx, dec); // -> CSEL_32_condsel
	if(!sf && !op && !S && op2==1) return CSINC(ctx, dec); // -> CSINC_32_condsel
	if(!sf && op && !S && !op2) return CSINV(ctx, dec); // -> CSINV_32_condsel
	if(!sf && op && !S && op2==1) return CSNEG(ctx, dec); // -> CSNEG_32_condsel
	if(sf && !op && !S && !op2) return CSEL(ctx, dec); // -> CSEL_64_condsel
	if(sf && !op && !S && op2==1) return CSINC(ctx, dec); // -> CSINC_64_condsel
	if(sf && op && !S && !op2) return CSINV(ctx, dec); // -> CSINV_64_condsel
	if(sf && op && !S && op2==1) return CSNEG(ctx, dec); // -> CSNEG_64_condsel
	if(!S && (op2&2)==2) UNALLOCATED(ENC_UNALLOCATED_974_CONDSEL);
	if(S) UNALLOCATED(ENC_UNALLOCATED_973_CONDSEL);
	UNMATCHED;
}

int decode_iclass_dp_1src(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, S=(INSWORD>>29)&1, opcode2=(INSWORD>>16)&0x1f, opcode=(INSWORD>>10)&0x3f, Rn=(INSWORD>>5)&0x1f, Rd=INSWORD&0x1f;
	if(sf && !S && opcode2==1 && opcode==0x20 && Rn==0x1f && Rd==0x1e && HasPAuth_LR()) return PACNBIASPPC(ctx, dec); // -> PACNBIASPPC_64LR_dp_1src
	if(sf && !S && opcode2==1 && opcode==0x21 && Rn==0x1f && Rd==0x1e && HasPAuth_LR()) return PACNBIBSPPC(ctx, dec); // -> PACNBIBSPPC_64LR_dp_1src
	if(sf && !S && opcode2==1 && opcode==0x22 && Rn==0x1f && Rd==0x1e && HasPAuth_LR()) return PACIA171615(ctx, dec); // -> PACIA171615_64LR_dp_1src
	if(sf && !S && opcode2==1 && opcode==0x23 && Rn==0x1f && Rd==0x1e && HasPAuth_LR()) return PACIB171615(ctx, dec); // -> PACIB171615_64LR_dp_1src
	if(sf && !S && opcode2==1 && opcode==0x28 && Rn==0x1f && Rd==0x1e && HasPAuth_LR()) return PACIASPPC(ctx, dec); // -> PACIASPPC_64LR_dp_1src
	if(sf && !S && opcode2==1 && opcode==0x29 && Rn==0x1f && Rd==0x1e && HasPAuth_LR()) return PACIBSPPC(ctx, dec); // -> PACIBSPPC_64LR_dp_1src
	if(sf && !S && opcode2==1 && opcode==0x2e && Rn==0x1f && Rd==0x1e && HasPAuth_LR()) return AUTIA171615(ctx, dec); // -> AUTIA171615_64LR_dp_1src
	if(sf && !S && opcode2==1 && opcode==0x2f && Rn==0x1f && Rd==0x1e && HasPAuth_LR()) return AUTIB171615(ctx, dec); // -> AUTIB171615_64LR_dp_1src
	if(sf && !S && opcode2==1 && (opcode&0x3e)==0x2a && Rn==0x1f && Rd==0x1e) UNALLOCATED(ENC_UNALLOCATED_997_DP_1SRC);
	if(sf && !S && opcode2==1 && (opcode&0x3e)==0x2c && Rn==0x1f && Rd==0x1e) UNALLOCATED(ENC_UNALLOCATED_998_DP_1SRC);
	if(sf && !S && opcode2==1 && (opcode&0x3c)==0x20 && Rn!=0x1f && Rd==0x1e) UNALLOCATED(ENC_UNALLOCATED_995_DP_1SRC);
	if(sf && !S && opcode2==1 && (opcode&0x38)==0x28 && Rn!=0x1f && Rd==0x1e) UNALLOCATED(ENC_UNALLOCATED_994_DP_1SRC);
	if(sf && !S && opcode2==1 && opcode==8 && Rn==0x1f && HasPAuth()) return PACIA(ctx, dec); // -> PACIZA_64Z_dp_1src
	if(sf && !S && opcode2==1 && opcode==9 && Rn==0x1f && HasPAuth()) return PACIB(ctx, dec); // -> PACIZB_64Z_dp_1src
	if(sf && !S && opcode2==1 && opcode==10 && Rn==0x1f && HasPAuth()) return PACDA(ctx, dec); // -> PACDZA_64Z_dp_1src
	if(sf && !S && opcode2==1 && opcode==11 && Rn==0x1f && HasPAuth()) return PACDB(ctx, dec); // -> PACDZB_64Z_dp_1src
	if(sf && !S && opcode2==1 && opcode==12 && Rn==0x1f && HasPAuth()) return AUTIA(ctx, dec); // -> AUTIZA_64Z_dp_1src
	if(sf && !S && opcode2==1 && opcode==13 && Rn==0x1f && HasPAuth()) return AUTIB(ctx, dec); // -> AUTIZB_64Z_dp_1src
	if(sf && !S && opcode2==1 && opcode==14 && Rn==0x1f && HasPAuth()) return AUTDA(ctx, dec); // -> AUTDZA_64Z_dp_1src
	if(sf && !S && opcode2==1 && opcode==15 && Rn==0x1f && HasPAuth()) return AUTDB(ctx, dec); // -> AUTDZB_64Z_dp_1src
	if(sf && !S && opcode2==1 && opcode==0x10 && Rn==0x1f && HasPAuth()) return XPAC(ctx, dec); // -> XPACI_64Z_dp_1src
	if(sf && !S && opcode2==1 && opcode==0x11 && Rn==0x1f && HasPAuth()) return XPAC(ctx, dec); // -> XPACD_64Z_dp_1src
	if(sf && !S && opcode2==1 && opcode==0x24 && Rd==0x1e && HasPAuth_LR()) return AUTIASPPCR(ctx, dec); // -> AUTIASPPCR_64LRR_dp_1src
	if(sf && !S && opcode2==1 && opcode==0x25 && Rd==0x1e && HasPAuth_LR()) return AUTIBSPPCR(ctx, dec); // -> AUTIBSPPCR_64LRR_dp_1src
	if(sf && !S && opcode2==1 && (opcode&0x3e)==0x10 && Rn!=0x1f) UNALLOCATED(ENC_UNALLOCATED_993_DP_1SRC);
	if(sf && !S && opcode2==1 && (opcode&0x3e)==0x26 && Rd==0x1e) UNALLOCATED(ENC_UNALLOCATED_996_DP_1SRC);
	if(sf && !S && opcode2==1 && (opcode&0x38)==8 && Rn!=0x1f) UNALLOCATED(ENC_UNALLOCATED_987_DP_1SRC);
	if(sf && !S && opcode2==1 && (opcode&0x30)==0x20 && Rd!=0x1e) UNALLOCATED(ENC_UNALLOCATED_985_DP_1SRC);
	if(!sf && !S && !opcode2 && !opcode) return RBIT_int(ctx, dec); // -> RBIT_32_dp_1src
	if(!sf && !S && !opcode2 && opcode==1) return REV16_int(ctx, dec); // -> REV16_32_dp_1src
	if(!sf && !S && !opcode2 && opcode==2) return REV(ctx, dec); // -> REV_32_dp_1src
	if(!sf && !S && !opcode2 && opcode==3) UNALLOCATED(ENC_UNALLOCATED_992_DP_1SRC);
	if(!sf && !S && !opcode2 && opcode==4) return CLZ_int(ctx, dec); // -> CLZ_32_dp_1src
	if(!sf && !S && !opcode2 && opcode==5) return CLS_int(ctx, dec); // -> CLS_32_dp_1src
	if(!sf && !S && !opcode2 && opcode==6 && HasCSSC()) return CTZ(ctx, dec); // -> CTZ_32_dp_1src
	if(!sf && !S && !opcode2 && opcode==7 && HasCSSC()) return CNT(ctx, dec); // -> CNT_32_dp_1src
	if(!sf && !S && !opcode2 && opcode==8 && HasCSSC()) return ABS(ctx, dec); // -> ABS_32_dp_1src
	if(sf && !S && !opcode2 && !opcode) return RBIT_int(ctx, dec); // -> RBIT_64_dp_1src
	if(sf && !S && !opcode2 && opcode==1) return REV16_int(ctx, dec); // -> REV16_64_dp_1src
	if(sf && !S && !opcode2 && opcode==2) return REV32_int(ctx, dec); // -> REV32_64_dp_1src
	if(sf && !S && !opcode2 && opcode==3) return REV(ctx, dec); // -> REV_64_dp_1src
	if(sf && !S && !opcode2 && opcode==4) return CLZ_int(ctx, dec); // -> CLZ_64_dp_1src
	if(sf && !S && !opcode2 && opcode==5) return CLS_int(ctx, dec); // -> CLS_64_dp_1src
	if(sf && !S && !opcode2 && opcode==6 && HasCSSC()) return CTZ(ctx, dec); // -> CTZ_64_dp_1src
	if(sf && !S && !opcode2 && opcode==7 && HasCSSC()) return CNT(ctx, dec); // -> CNT_64_dp_1src
	if(sf && !S && !opcode2 && opcode==8 && HasCSSC()) return ABS(ctx, dec); // -> ABS_64_dp_1src
	if(sf && !S && opcode2==1 && !opcode && HasPAuth()) return PACIA(ctx, dec); // -> PACIA_64P_dp_1src
	if(sf && !S && opcode2==1 && opcode==1 && HasPAuth()) return PACIB(ctx, dec); // -> PACIB_64P_dp_1src
	if(sf && !S && opcode2==1 && opcode==2 && HasPAuth()) return PACDA(ctx, dec); // -> PACDA_64P_dp_1src
	if(sf && !S && opcode2==1 && opcode==3 && HasPAuth()) return PACDB(ctx, dec); // -> PACDB_64P_dp_1src
	if(sf && !S && opcode2==1 && opcode==4 && HasPAuth()) return AUTIA(ctx, dec); // -> AUTIA_64P_dp_1src
	if(sf && !S && opcode2==1 && opcode==5 && HasPAuth()) return AUTIB(ctx, dec); // -> AUTIB_64P_dp_1src
	if(sf && !S && opcode2==1 && opcode==6 && HasPAuth()) return AUTDA(ctx, dec); // -> AUTDA_64P_dp_1src
	if(sf && !S && opcode2==1 && opcode==7 && HasPAuth()) return AUTDB(ctx, dec); // -> AUTDB_64P_dp_1src
	if(!S && !opcode2 && opcode==9) UNALLOCATED(ENC_UNALLOCATED_991_DP_1SRC);
	if(sf && !S && opcode2==1 && (opcode&0x3e)==0x12) UNALLOCATED(ENC_UNALLOCATED_990_DP_1SRC);
	if(!S && !opcode2 && (opcode&0x3e)==10) UNALLOCATED(ENC_UNALLOCATED_989_DP_1SRC);
	if(sf && !S && opcode2==1 && (opcode&0x3c)==0x14) UNALLOCATED(ENC_UNALLOCATED_988_DP_1SRC);
	if(!S && !opcode2 && (opcode&0x3c)==12) UNALLOCATED(ENC_UNALLOCATED_986_DP_1SRC);
	if(sf && !S && opcode2==1 && (opcode&0x38)==0x18) UNALLOCATED(ENC_UNALLOCATED_984_DP_1SRC);
	if(sf && !S && opcode2==1 && (opcode&0x30)==0x30) UNALLOCATED(ENC_UNALLOCATED_983_DP_1SRC);
	if(!S && !opcode2 && (opcode&0x30)==0x10) UNALLOCATED(ENC_UNALLOCATED_982_DP_1SRC);
	if(!S && !opcode2 && (opcode&0x20)==0x20) UNALLOCATED(ENC_UNALLOCATED_981_DP_1SRC);
	if(!sf && !S && opcode2==1) UNALLOCATED(ENC_UNALLOCATED_980_DP_1SRC);
	if(!S && (opcode2&0x1e)==2) UNALLOCATED(ENC_UNALLOCATED_979_DP_1SRC);
	if(!S && (opcode2&0x1c)==4) UNALLOCATED(ENC_UNALLOCATED_978_DP_1SRC);
	if(!S && (opcode2&0x18)==8) UNALLOCATED(ENC_UNALLOCATED_977_DP_1SRC);
	if(!S && (opcode2&0x10)==0x10) UNALLOCATED(ENC_UNALLOCATED_976_DP_1SRC);
	if(S) UNALLOCATED(ENC_UNALLOCATED_975_DP_1SRC);
	UNMATCHED;
}

int decode_iclass_dp_2src(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, S=(INSWORD>>29)&1, opcode=(INSWORD>>10)&0x3f;
	if(!sf && !S && opcode==2) return UDIV(ctx, dec); // -> UDIV_32_dp_2src
	if(!sf && !S && opcode==3) return SDIV(ctx, dec); // -> SDIV_32_dp_2src
	if(!sf && !S && opcode==8) return LSLV(ctx, dec); // -> LSLV_32_dp_2src
	if(!sf && !S && opcode==9) return LSRV(ctx, dec); // -> LSRV_32_dp_2src
	if(!sf && !S && opcode==10) return ASRV(ctx, dec); // -> ASRV_32_dp_2src
	if(!sf && !S && opcode==11) return RORV(ctx, dec); // -> RORV_32_dp_2src
	if(!sf && !S && opcode==0x10 && HasCRC32()) return CRC32(ctx, dec); // -> CRC32B_32C_dp_2src
	if(!sf && !S && opcode==0x11 && HasCRC32()) return CRC32(ctx, dec); // -> CRC32H_32C_dp_2src
	if(!sf && !S && opcode==0x12 && HasCRC32()) return CRC32(ctx, dec); // -> CRC32W_32C_dp_2src
	if(!sf && !S && opcode==0x14 && HasCRC32()) return CRC32C(ctx, dec); // -> CRC32CB_32C_dp_2src
	if(!sf && !S && opcode==0x15 && HasCRC32()) return CRC32C(ctx, dec); // -> CRC32CH_32C_dp_2src
	if(!sf && !S && opcode==0x16 && HasCRC32()) return CRC32C(ctx, dec); // -> CRC32CW_32C_dp_2src
	if(!sf && !S && opcode==0x18 && HasCSSC()) return SMAX_reg(ctx, dec); // -> SMAX_32_dp_2src
	if(!sf && !S && opcode==0x19 && HasCSSC()) return UMAX_reg(ctx, dec); // -> UMAX_32_dp_2src
	if(!sf && !S && opcode==0x1a && HasCSSC()) return SMIN_reg(ctx, dec); // -> SMIN_32_dp_2src
	if(!sf && !S && opcode==0x1b && HasCSSC()) return UMIN_reg(ctx, dec); // -> UMIN_32_dp_2src
	if(sf && !S && !opcode && HasMTE()) return SUBP(ctx, dec); // -> SUBP_64S_dp_2src
	if(sf && !S && opcode==2) return UDIV(ctx, dec); // -> UDIV_64_dp_2src
	if(sf && !S && opcode==3) return SDIV(ctx, dec); // -> SDIV_64_dp_2src
	if(sf && !S && opcode==4 && HasMTE()) return IRG(ctx, dec); // -> IRG_64I_dp_2src
	if(sf && !S && opcode==5 && HasMTE()) return GMI(ctx, dec); // -> GMI_64G_dp_2src
	if(sf && !S && opcode==8) return LSLV(ctx, dec); // -> LSLV_64_dp_2src
	if(sf && !S && opcode==9) return LSRV(ctx, dec); // -> LSRV_64_dp_2src
	if(sf && !S && opcode==10) return ASRV(ctx, dec); // -> ASRV_64_dp_2src
	if(sf && !S && opcode==11) return RORV(ctx, dec); // -> RORV_64_dp_2src
	if(sf && !S && opcode==12 && HasPAuth()) return PACGA(ctx, dec); // -> PACGA_64P_dp_2src
	if(sf && !S && opcode==13) UNALLOCATED(ENC_UNALLOCATED_1013_DP_2SRC);
	if(sf && !S && opcode==0x11) UNALLOCATED(ENC_UNALLOCATED_1014_DP_2SRC);
	if(sf && !S && opcode==0x13 && HasCRC32()) return CRC32(ctx, dec); // -> CRC32X_64C_dp_2src
	if(sf && !S && opcode==0x15) UNALLOCATED(ENC_UNALLOCATED_1015_DP_2SRC);
	if(sf && !S && opcode==0x17 && HasCRC32()) return CRC32C(ctx, dec); // -> CRC32CX_64C_dp_2src
	if(sf && !S && opcode==0x18 && HasCSSC()) return SMAX_reg(ctx, dec); // -> SMAX_64_dp_2src
	if(sf && !S && opcode==0x19 && HasCSSC()) return UMAX_reg(ctx, dec); // -> UMAX_64_dp_2src
	if(sf && !S && opcode==0x1a && HasCSSC()) return SMIN_reg(ctx, dec); // -> SMIN_64_dp_2src
	if(sf && !S && opcode==0x1b && HasCSSC()) return UMIN_reg(ctx, dec); // -> UMIN_64_dp_2src
	if(sf && S && !opcode && HasMTE()) return SUBPS(ctx, dec); // -> SUBPS_64S_dp_2src
	if(!sf && !S && (opcode&0x3e)==4) UNALLOCATED(ENC_UNALLOCATED_1009_DP_2SRC);
	if(!sf && !S && (opcode&0x3b)==0x13) UNALLOCATED(ENC_UNALLOCATED_1010_DP_2SRC);
	if(sf && opcode==1) UNALLOCATED(ENC_UNALLOCATED_1012_DP_2SRC);
	if(sf && !S && (opcode&0x3e)==14) UNALLOCATED(ENC_UNALLOCATED_1011_DP_2SRC);
	if(!S && (opcode&0x3e)==6) UNALLOCATED(ENC_UNALLOCATED_1007_DP_2SRC);
	if(S && (opcode&0x3e)==2) UNALLOCATED(ENC_UNALLOCATED_1008_DP_2SRC);
	if(!sf && !(opcode&0x3e)) UNALLOCATED(ENC_UNALLOCATED_1004_DP_2SRC);
	if(sf && !S && (opcode&0x39)==0x10) UNALLOCATED(ENC_UNALLOCATED_1005_DP_2SRC);
	if(sf && !S && (opcode&0x3c)==0x1c) UNALLOCATED(ENC_UNALLOCATED_1006_DP_2SRC);
	if(S && (opcode&0x3c)==4) UNALLOCATED(ENC_UNALLOCATED_1003_DP_2SRC);
	if(!sf && !S && (opcode&0x2c)==12) UNALLOCATED(ENC_UNALLOCATED_1002_DP_2SRC);
	if(S && (opcode&0x38)==8) UNALLOCATED(ENC_UNALLOCATED_1001_DP_2SRC);
	if(S && (opcode&0x30)==0x10) UNALLOCATED(ENC_UNALLOCATED_1000_DP_2SRC);
	if((opcode&0x20)==0x20) UNALLOCATED(ENC_UNALLOCATED_999_DP_2SRC);
	UNMATCHED;
}

int decode_iclass_dp_3src(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, op54=(INSWORD>>29)&3, op31=(INSWORD>>21)&7, o0=(INSWORD>>15)&1;
	if(!sf && !op54 && !op31 && !o0) return MADD(ctx, dec); // -> MADD_32A_dp_3src
	if(!sf && !op54 && !op31 && o0) return MSUB(ctx, dec); // -> MSUB_32A_dp_3src
	if(sf && !op54 && !op31 && !o0) return MADD(ctx, dec); // -> MADD_64A_dp_3src
	if(sf && !op54 && !op31 && o0) return MSUB(ctx, dec); // -> MSUB_64A_dp_3src
	if(sf && !op54 && op31==1 && !o0) return SMADDL(ctx, dec); // -> SMADDL_64WA_dp_3src
	if(sf && !op54 && op31==1 && o0) return SMSUBL(ctx, dec); // -> SMSUBL_64WA_dp_3src
	if(sf && !op54 && op31==2 && !o0) return SMULH(ctx, dec); // -> SMULH_64_dp_3src
	if(sf && !op54 && op31==3 && !o0 && HasCPA()) return MADDPT(ctx, dec); // -> MADDPT_64A_dp_3src
	if(sf && !op54 && op31==3 && o0 && HasCPA()) return MSUBPT(ctx, dec); // -> MSUBPT_64A_dp_3src
	if(sf && !op54 && op31==5 && !o0) return UMADDL(ctx, dec); // -> UMADDL_64WA_dp_3src
	if(sf && !op54 && op31==5 && o0) return UMSUBL(ctx, dec); // -> UMSUBL_64WA_dp_3src
	if(sf && !op54 && op31==6 && !o0) return UMULH(ctx, dec); // -> UMULH_64_dp_3src
	if(sf && !op54 && (op31&3)==2 && o0) UNALLOCATED(ENC_UNALLOCATED_1021_DP_3SRC);
	if(sf && !op54 && op31==7) UNALLOCATED(ENC_UNALLOCATED_1020_DP_3SRC);
	if(!op54 && op31==4) UNALLOCATED(ENC_UNALLOCATED_1019_DP_3SRC);
	if(!sf && !op54 && (op31&3)==1) UNALLOCATED(ENC_UNALLOCATED_1018_DP_3SRC);
	if(!sf && !op54 && (op31&2)==2) UNALLOCATED(ENC_UNALLOCATED_1017_DP_3SRC);
	if(op54) UNALLOCATED(ENC_UNALLOCATED_1016_DP_3SRC);
	UNMATCHED;
}

int decode_iclass_setf(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, op=(INSWORD>>30)&1, S=(INSWORD>>29)&1, opcode2=(INSWORD>>15)&0x3f, sz=(INSWORD>>14)&1, o3=(INSWORD>>4)&1, mask=INSWORD&15;
	if(!sf && !op && S && !opcode2 && !sz && !o3 && mask==13 && HasFlagM()) return SETF(ctx, dec); // -> SETF8_only_setf
	if(!sf && !op && S && !opcode2 && sz && !o3 && mask==13 && HasFlagM()) return SETF(ctx, dec); // -> SETF16_only_setf
	if(!sf && !op && S && !opcode2 && !o3 && mask!=13) UNALLOCATED(ENC_UNALLOCATED_1027_SETF);
	if(!sf && !op && S && !opcode2 && o3) UNALLOCATED(ENC_UNALLOCATED_1026_SETF);
	if(!sf && !op && S && opcode2) UNALLOCATED(ENC_UNALLOCATED_1025_SETF);
	if(!sf && !op && !S) UNALLOCATED(ENC_UNALLOCATED_1024_SETF);
	if(!sf && op) UNALLOCATED(ENC_UNALLOCATED_1023_SETF);
	if(sf) UNALLOCATED(ENC_UNALLOCATED_1022_SETF);
	UNMATCHED;
}

int decode_iclass_log_shift(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, opc=(INSWORD>>29)&3, N=(INSWORD>>21)&1;
	if(!sf && !opc && !N) return AND_log_shift(ctx, dec); // -> AND_32_log_shift
	if(!sf && !opc && N) return BIC_log_shift(ctx, dec); // -> BIC_32_log_shift
	if(!sf && opc==1 && !N) return ORR_log_shift(ctx, dec); // -> ORR_32_log_shift
	if(!sf && opc==1 && N) return ORN_log_shift(ctx, dec); // -> ORN_32_log_shift
	if(!sf && opc==2 && !N) return EOR_log_shift(ctx, dec); // -> EOR_32_log_shift
	if(!sf && opc==2 && N) return EON(ctx, dec); // -> EON_32_log_shift
	if(!sf && opc==3 && !N) return ANDS_log_shift(ctx, dec); // -> ANDS_32_log_shift
	if(!sf && opc==3 && N) return BICS(ctx, dec); // -> BICS_32_log_shift
	if(sf && !opc && !N) return AND_log_shift(ctx, dec); // -> AND_64_log_shift
	if(sf && !opc && N) return BIC_log_shift(ctx, dec); // -> BIC_64_log_shift
	if(sf && opc==1 && !N) return ORR_log_shift(ctx, dec); // -> ORR_64_log_shift
	if(sf && opc==1 && N) return ORN_log_shift(ctx, dec); // -> ORN_64_log_shift
	if(sf && opc==2 && !N) return EOR_log_shift(ctx, dec); // -> EOR_64_log_shift
	if(sf && opc==2 && N) return EON(ctx, dec); // -> EON_64_log_shift
	if(sf && opc==3 && !N) return ANDS_log_shift(ctx, dec); // -> ANDS_64_log_shift
	if(sf && opc==3 && N) return BICS(ctx, dec); // -> BICS_64_log_shift
	UNMATCHED;
}

int decode_iclass_rmif(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, op=(INSWORD>>30)&1, S=(INSWORD>>29)&1, o2=(INSWORD>>4)&1;
	if(sf && !op && S && !o2 && HasFlagM()) return RMIF(ctx, dec); // -> RMIF_only_rmif
	if(sf && !op && S && o2) UNALLOCATED(ENC_UNALLOCATED_1031_RMIF);
	if(sf && !op && !S) UNALLOCATED(ENC_UNALLOCATED_1030_RMIF);
	if(sf && op) UNALLOCATED(ENC_UNALLOCATED_1029_RMIF);
	if(!sf) UNALLOCATED(ENC_UNALLOCATED_1028_RMIF);
	UNMATCHED;
}

int decode_iclass_asimdall(context *ctx, Instruction *dec)
{
	uint32_t Q=(INSWORD>>30)&1, U=(INSWORD>>29)&1, size=(INSWORD>>22)&3, opcode=(INSWORD>>12)&0x1f;
	if(Q && U && !size && opcode==12 && HasAdvSIMD()) return FMAXNMV_advsimd(ctx, dec); // -> FMAXNMV_asimdall_only_SD
	if(Q && U && !size && opcode==15 && HasAdvSIMD()) return FMAXV_advsimd(ctx, dec); // -> FMAXV_asimdall_only_SD
	if(Q && U && size==2 && opcode==12 && HasAdvSIMD()) return FMINNMV_advsimd(ctx, dec); // -> FMINNMV_asimdall_only_SD
	if(Q && U && size==2 && opcode==15 && HasAdvSIMD()) return FMINV_advsimd(ctx, dec); // -> FMINV_asimdall_only_SD
	if(!U && !size && opcode==12 && HasAdvSIMD() && HasFP16()) return FMAXNMV_advsimd(ctx, dec); // -> FMAXNMV_asimdall_only_H
	if(!U && !size && opcode==15 && HasAdvSIMD() && HasFP16()) return FMAXV_advsimd(ctx, dec); // -> FMAXV_asimdall_only_H
	if(!U && size==2 && opcode==12 && HasAdvSIMD() && HasFP16()) return FMINNMV_advsimd(ctx, dec); // -> FMINNMV_asimdall_only_H
	if(!U && size==2 && opcode==15 && HasAdvSIMD() && HasFP16()) return FMINV_advsimd(ctx, dec); // -> FMINV_asimdall_only_H
	if(!Q && U && !(size&1) && opcode==15) UNALLOCATED(ENC_UNALLOCATED_1045_ASIMDALL);
	if(Q && U && !(size&1) && opcode==14) UNALLOCATED(ENC_UNALLOCATED_1046_ASIMDALL);
	if(!U && !(size&1) && opcode==14) UNALLOCATED(ENC_UNALLOCATED_1044_ASIMDALL);
	if(!Q && U && !(size&1) && (opcode&0x1d)==12) UNALLOCATED(ENC_UNALLOCATED_1043_ASIMDALL);
	if(!(size&1) && opcode==13) UNALLOCATED(ENC_UNALLOCATED_1042_ASIMDALL);
	if(!U && opcode==3 && HasAdvSIMD()) return SADDLV_advsimd(ctx, dec); // -> SADDLV_asimdall_only
	if(!U && opcode==10 && HasAdvSIMD()) return SMAXV_advsimd(ctx, dec); // -> SMAXV_asimdall_only
	if(!U && opcode==0x1a && HasAdvSIMD()) return SMINV_advsimd(ctx, dec); // -> SMINV_asimdall_only
	if(!U && opcode==0x1b && HasAdvSIMD()) return ADDV_advsimd(ctx, dec); // -> ADDV_asimdall_only
	if(U && opcode==3 && HasAdvSIMD()) return UADDLV_advsimd(ctx, dec); // -> UADDLV_asimdall_only
	if(U && opcode==10 && HasAdvSIMD()) return UMAXV_advsimd(ctx, dec); // -> UMAXV_asimdall_only
	if(U && opcode==0x1a && HasAdvSIMD()) return UMINV_advsimd(ctx, dec); // -> UMINV_asimdall_only
	if(U && opcode==0x1b) UNALLOCATED(ENC_UNALLOCATED_1041_ASIMDALL);
	if(opcode==1) UNALLOCATED(ENC_UNALLOCATED_1039_ASIMDALL);
	if(opcode==11) UNALLOCATED(ENC_UNALLOCATED_1040_ASIMDALL);
	if(!(opcode&0x1d)) UNALLOCATED(ENC_UNALLOCATED_1038_ASIMDALL);
	if(!(size&1) && (opcode&0x1c)==4) UNALLOCATED(ENC_UNALLOCATED_1035_ASIMDALL);
	if(!(size&1) && (opcode&0x1c)==0x14) UNALLOCATED(ENC_UNALLOCATED_1036_ASIMDALL);
	if(!(size&1) && (opcode&0x1c)==0x1c) UNALLOCATED(ENC_UNALLOCATED_1037_ASIMDALL);
	if((opcode&14)==8) UNALLOCATED(ENC_UNALLOCATED_1034_ASIMDALL);
	if((opcode&0x1c)==0x10) UNALLOCATED(ENC_UNALLOCATED_1033_ASIMDALL);
	if(size&1 && (opcode&4)==4) UNALLOCATED(ENC_UNALLOCATED_1032_ASIMDALL);
	UNMATCHED;
}

int decode_iclass_asimdins(context *ctx, Instruction *dec)
{
	uint32_t Q=(INSWORD>>30)&1, op=(INSWORD>>29)&1, imm5=(INSWORD>>16)&0x1f, imm4=(INSWORD>>11)&15;
	if(Q && !op && (imm5&15)==8 && imm4==7 && HasAdvSIMD()) return UMOV_advsimd(ctx, dec); // -> UMOV_asimdins_X_x
	if(Q && !op && (imm5&15)==9 && imm4==7) UNALLOCATED(ENC_UNALLOCATED_1055_ASIMDINS);
	if(Q && !op && (imm5&14)==10 && imm4==7) UNALLOCATED(ENC_UNALLOCATED_1054_ASIMDINS);
	if(Q && !op && (imm5&12)==12 && imm4==7) UNALLOCATED(ENC_UNALLOCATED_1053_ASIMDINS);
	if(Q && !op && !(imm5&8) && imm4==7) UNALLOCATED(ENC_UNALLOCATED_1052_ASIMDINS);
	if(!Q && !op && imm4==5 && HasAdvSIMD()) return SMOV_advsimd(ctx, dec); // -> SMOV_asimdins_W_w
	if(!Q && !op && imm4==7 && HasAdvSIMD()) return UMOV_advsimd(ctx, dec); // -> UMOV_asimdins_W_w
	if(Q && !op && imm4==2) UNALLOCATED(ENC_UNALLOCATED_1051_ASIMDINS);
	if(Q && !op && imm4==3 && HasAdvSIMD()) return INS_advsimd_gen(ctx, dec); // -> INS_asimdins_IR_r
	if(Q && !op && imm4==5 && HasAdvSIMD()) return SMOV_advsimd(ctx, dec); // -> SMOV_asimdins_X_x
	if(!op && !imm4 && HasAdvSIMD()) return DUP_advsimd_elt(ctx, dec); // -> DUP_asimdins_DV_v
	if(!op && imm4==1 && HasAdvSIMD()) return DUP_advsimd_gen(ctx, dec); // -> DUP_asimdins_DR_r
	if(!Q && !op && (imm4&14)==2) UNALLOCATED(ENC_UNALLOCATED_1050_ASIMDINS);
	if(!op && (imm4&13)==4) UNALLOCATED(ENC_UNALLOCATED_1049_ASIMDINS);
	if(!op && (imm4&8)==8) UNALLOCATED(ENC_UNALLOCATED_1048_ASIMDINS);
	if(!Q && op) UNALLOCATED(ENC_UNALLOCATED_1047_ASIMDINS);
	if(Q && op && HasAdvSIMD()) return INS_advsimd_elt(ctx, dec); // -> INS_asimdins_IV_v
	UNMATCHED;
}

int decode_iclass_asimdext(context *ctx, Instruction *dec)
{
	uint32_t op2=(INSWORD>>22)&3;
	if(!op2 && HasAdvSIMD()) return EXT_advsimd(ctx, dec); // -> EXT_asimdext_only
	if(op2) UNALLOCATED(ENC_UNALLOCATED_1056_ASIMDEXT);
	UNMATCHED;
}

int decode_iclass_asimdimm(context *ctx, Instruction *dec)
{
	uint32_t Q=(INSWORD>>30)&1, op=(INSWORD>>29)&1, cmode=(INSWORD>>12)&15, o2=(INSWORD>>11)&1;
	if(!Q && op && cmode==14 && !o2 && HasAdvSIMD()) return MOVI_advsimd(ctx, dec); // -> MOVI_asimdimm_D_ds
	if(!Q && op && cmode==15 && !o2) UNALLOCATED(ENC_UNALLOCATED_1059_ASIMDIMM);
	if(Q && op && cmode==14 && !o2 && HasAdvSIMD()) return MOVI_advsimd(ctx, dec); // -> MOVI_asimdimm_D2_d
	if(Q && op && cmode==15 && !o2 && HasAdvSIMD()) return FMOV_advsimd(ctx, dec); // -> FMOV_asimdimm_D2_d
	if(!op && cmode==14 && !o2 && HasAdvSIMD()) return MOVI_advsimd(ctx, dec); // -> MOVI_asimdimm_N_b
	if(!op && cmode==15 && !o2 && HasAdvSIMD()) return FMOV_advsimd(ctx, dec); // -> FMOV_asimdimm_S_s
	if(!op && cmode==15 && o2 && HasAdvSIMD() && HasFP16()) return FMOV_advsimd(ctx, dec); // -> FMOV_asimdimm_H_h
	if(!op && cmode!=15 && o2) UNALLOCATED(ENC_UNALLOCATED_1058_ASIMDIMM);
	if(!op && (cmode&13)==8 && !o2 && HasAdvSIMD()) return MOVI_advsimd(ctx, dec); // -> MOVI_asimdimm_L_hl
	if(!op && (cmode&13)==9 && !o2 && HasAdvSIMD()) return ORR_advsimd_imm(ctx, dec); // -> ORR_asimdimm_L_hl
	if(!op && (cmode&14)==12 && !o2 && HasAdvSIMD()) return MOVI_advsimd(ctx, dec); // -> MOVI_asimdimm_M_sm
	if(op && (cmode&13)==8 && !o2 && HasAdvSIMD()) return MVNI_advsimd(ctx, dec); // -> MVNI_asimdimm_L_hl
	if(op && (cmode&13)==9 && !o2 && HasAdvSIMD()) return BIC_advsimd_imm(ctx, dec); // -> BIC_asimdimm_L_hl
	if(op && (cmode&14)==12 && !o2 && HasAdvSIMD()) return MVNI_advsimd(ctx, dec); // -> MVNI_asimdimm_M_sm
	if(!op && !(cmode&9) && !o2 && HasAdvSIMD()) return MOVI_advsimd(ctx, dec); // -> MOVI_asimdimm_L_sl
	if(!op && (cmode&9)==1 && !o2 && HasAdvSIMD()) return ORR_advsimd_imm(ctx, dec); // -> ORR_asimdimm_L_sl
	if(op && !(cmode&9) && !o2 && HasAdvSIMD()) return MVNI_advsimd(ctx, dec); // -> MVNI_asimdimm_L_sl
	if(op && (cmode&9)==1 && !o2 && HasAdvSIMD()) return BIC_advsimd_imm(ctx, dec); // -> BIC_asimdimm_L_sl
	if(op && o2) UNALLOCATED(ENC_UNALLOCATED_1057_ASIMDIMM);
	UNMATCHED;
}

int decode_iclass_asimdperm(context *ctx, Instruction *dec)
{
	uint32_t opcode=(INSWORD>>12)&7;
	if(opcode==1 && HasAdvSIMD()) return UZP1_advsimd(ctx, dec); // -> UZP1_asimdperm_only
	if(opcode==2 && HasAdvSIMD()) return TRN1_advsimd(ctx, dec); // -> TRN1_asimdperm_only
	if(opcode==3 && HasAdvSIMD()) return ZIP1_advsimd(ctx, dec); // -> ZIP1_asimdperm_only
	if(opcode==5 && HasAdvSIMD()) return UZP2_advsimd(ctx, dec); // -> UZP2_asimdperm_only
	if(opcode==6 && HasAdvSIMD()) return TRN2_advsimd(ctx, dec); // -> TRN2_asimdperm_only
	if(opcode==7 && HasAdvSIMD()) return ZIP2_advsimd(ctx, dec); // -> ZIP2_asimdperm_only
	if(!(opcode&3)) UNALLOCATED(ENC_UNALLOCATED_1060_ASIMDPERM);
	UNMATCHED;
}

int decode_iclass_asisdone(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>29)&1, imm4=(INSWORD>>11)&15;
	if(!op && !imm4 && HasAdvSIMD()) return DUP_advsimd_elt(ctx, dec); // -> DUP_asisdone_only
	if(!op && imm4) UNALLOCATED(ENC_UNALLOCATED_1062_ASISDONE);
	if(op) UNALLOCATED(ENC_UNALLOCATED_1061_ASISDONE);
	UNMATCHED;
}

int decode_iclass_asisdpair(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>29)&1, size=(INSWORD>>22)&3, opcode=(INSWORD>>12)&0x1f;
	if(!U && !size && opcode==12 && HasAdvSIMD() && HasFP16()) return FMAXNMP_advsimd_pair(ctx, dec); // -> FMAXNMP_asisdpair_only_H
	if(!U && !size && opcode==13 && HasAdvSIMD() && HasFP16()) return FADDP_advsimd_pair(ctx, dec); // -> FADDP_asisdpair_only_H
	if(!U && !size && opcode==15 && HasAdvSIMD() && HasFP16()) return FMAXP_advsimd_pair(ctx, dec); // -> FMAXP_asisdpair_only_H
	if(!U && size==2 && opcode==12 && HasAdvSIMD() && HasFP16()) return FMINNMP_advsimd_pair(ctx, dec); // -> FMINNMP_asisdpair_only_H
	if(!U && size==2 && opcode==15 && HasAdvSIMD() && HasFP16()) return FMINP_advsimd_pair(ctx, dec); // -> FMINP_asisdpair_only_H
	if(!U && size==3 && opcode==11) UNALLOCATED(ENC_UNALLOCATED_1073_ASISDPAIR);
	if(!U && size==3 && opcode==0x1b && HasAdvSIMD()) return ADDP_advsimd_pair(ctx, dec); // -> ADDP_asisdpair_only
	if(U && size==3 && opcode==13) UNALLOCATED(ENC_UNALLOCATED_1074_ASISDPAIR);
	if(size==2 && opcode==13) UNALLOCATED(ENC_UNALLOCATED_1072_ASISDPAIR);
	if(!U && size&1 && opcode==12) UNALLOCATED(ENC_UNALLOCATED_1071_ASISDPAIR);
	if(!U && size==3 && (opcode&15)==10) UNALLOCATED(ENC_UNALLOCATED_1070_ASISDPAIR);
	if(U && !(size&2) && opcode==12 && HasAdvSIMD()) return FMAXNMP_advsimd_pair(ctx, dec); // -> FMAXNMP_asisdpair_only_SD
	if(U && !(size&2) && opcode==13 && HasAdvSIMD()) return FADDP_advsimd_pair(ctx, dec); // -> FADDP_asisdpair_only_SD
	if(U && !(size&2) && opcode==15 && HasAdvSIMD()) return FMAXP_advsimd_pair(ctx, dec); // -> FMAXP_asisdpair_only_SD
	if(U && (size&2)==2 && opcode==12 && HasAdvSIMD()) return FMINNMP_advsimd_pair(ctx, dec); // -> FMINNMP_asisdpair_only_SD
	if(U && (size&2)==2 && opcode==15 && HasAdvSIMD()) return FMINP_advsimd_pair(ctx, dec); // -> FMINP_asisdpair_only_SD
	if(!U && size&1 && (opcode&0x1d)==13) UNALLOCATED(ENC_UNALLOCATED_1069_ASISDPAIR);
	if(!U && size==3 && (opcode&14)==8) UNALLOCATED(ENC_UNALLOCATED_1068_ASISDPAIR);
	if(opcode==14) UNALLOCATED(ENC_UNALLOCATED_1067_ASISDPAIR);
	if(!U && size!=3 && (opcode&12)==8) UNALLOCATED(ENC_UNALLOCATED_1066_ASISDPAIR);
	if((opcode&0x1c)==0x1c) UNALLOCATED(ENC_UNALLOCATED_1065_ASISDPAIR);
	if(U && (opcode&12)==8) UNALLOCATED(ENC_UNALLOCATED_1064_ASISDPAIR);
	if(!(opcode&8)) UNALLOCATED(ENC_UNALLOCATED_1063_ASISDPAIR);
	UNMATCHED;
}

int decode_iclass_asisdshf(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>29)&1, immh=(INSWORD>>19)&15, opcode=(INSWORD>>11)&0x1f;
	if(!U && immh && opcode==14 && HasAdvSIMD()) return SQSHL_advsimd_imm(ctx, dec); // -> SQSHL_asisdshf_R
	if(!U && immh && opcode==0x12 && HasAdvSIMD()) return SQSHRN_advsimd(ctx, dec); // -> SQSHRN_asisdshf_N
	if(!U && immh && opcode==0x13 && HasAdvSIMD()) return SQRSHRN_advsimd(ctx, dec); // -> SQRSHRN_asisdshf_N
	if(!U && immh && opcode==0x1c && HasAdvSIMD()) return SCVTF_advsimd_fix(ctx, dec); // -> SCVTF_asisdshf_C
	if(!U && immh && opcode==0x1f && HasAdvSIMD()) return FCVTZS_advsimd_fix(ctx, dec); // -> FCVTZS_asisdshf_C
	if(U && !immh && opcode==12) UNALLOCATED(ENC_UNALLOCATED_1091_ASISDSHF);
	if(U && immh && opcode==12 && HasAdvSIMD()) return SQSHLU_advsimd(ctx, dec); // -> SQSHLU_asisdshf_R
	if(U && immh && opcode==14 && HasAdvSIMD()) return UQSHL_advsimd_imm(ctx, dec); // -> UQSHL_asisdshf_R
	if(U && immh && opcode==0x10 && HasAdvSIMD()) return SQSHRUN_advsimd(ctx, dec); // -> SQSHRUN_asisdshf_N
	if(U && immh && opcode==0x11 && HasAdvSIMD()) return SQRSHRUN_advsimd(ctx, dec); // -> SQRSHRUN_asisdshf_N
	if(U && immh && opcode==0x12 && HasAdvSIMD()) return UQSHRN_advsimd(ctx, dec); // -> UQSHRN_asisdshf_N
	if(U && immh && opcode==0x13 && HasAdvSIMD()) return UQRSHRN_advsimd(ctx, dec); // -> UQRSHRN_asisdshf_N
	if(U && immh && opcode==0x1c && HasAdvSIMD()) return UCVTF_advsimd_fix(ctx, dec); // -> UCVTF_asisdshf_C
	if(U && immh && opcode==0x1f && HasAdvSIMD()) return FCVTZU_advsimd_fix(ctx, dec); // -> FCVTZU_asisdshf_C
	if(!immh && opcode==0x1c) UNALLOCATED(ENC_UNALLOCATED_1089_ASISDSHF);
	if(!immh && opcode==0x1f) UNALLOCATED(ENC_UNALLOCATED_1090_ASISDSHF);
	if(immh && opcode==0x1e) UNALLOCATED(ENC_UNALLOCATED_1084_ASISDSHF);
	if(U && !immh && (opcode&0x1e)==0x10) UNALLOCATED(ENC_UNALLOCATED_1088_ASISDSHF);
	if(!immh && (opcode&15)==14) UNALLOCATED(ENC_UNALLOCATED_1087_ASISDSHF);
	if(!immh && (opcode&0x1e)==0x12) UNALLOCATED(ENC_UNALLOCATED_1086_ASISDSHF);
	if(!U && (immh&8)==8 && !opcode && HasAdvSIMD()) return SSHR_advsimd(ctx, dec); // -> SSHR_asisdshf_R
	if(!U && (immh&8)==8 && opcode==2 && HasAdvSIMD()) return SSRA_advsimd(ctx, dec); // -> SSRA_asisdshf_R
	if(!U && (immh&8)==8 && opcode==4 && HasAdvSIMD()) return SRSHR_advsimd(ctx, dec); // -> SRSHR_asisdshf_R
	if(!U && (immh&8)==8 && opcode==6 && HasAdvSIMD()) return SRSRA_advsimd(ctx, dec); // -> SRSRA_asisdshf_R
	if(!U && (immh&8)==8 && opcode==8) UNALLOCATED(ENC_UNALLOCATED_1085_ASISDSHF);
	if(!U && (immh&8)==8 && opcode==10 && HasAdvSIMD()) return SHL_advsimd(ctx, dec); // -> SHL_asisdshf_R
	if(U && (immh&8)==8 && !opcode && HasAdvSIMD()) return USHR_advsimd(ctx, dec); // -> USHR_asisdshf_R
	if(U && (immh&8)==8 && opcode==2 && HasAdvSIMD()) return USRA_advsimd(ctx, dec); // -> USRA_asisdshf_R
	if(U && (immh&8)==8 && opcode==4 && HasAdvSIMD()) return URSHR_advsimd(ctx, dec); // -> URSHR_asisdshf_R
	if(U && (immh&8)==8 && opcode==6 && HasAdvSIMD()) return URSRA_advsimd(ctx, dec); // -> URSRA_asisdshf_R
	if(U && (immh&8)==8 && opcode==8 && HasAdvSIMD()) return SRI_advsimd(ctx, dec); // -> SRI_asisdshf_R
	if(U && (immh&8)==8 && opcode==10 && HasAdvSIMD()) return SLI_advsimd(ctx, dec); // -> SLI_asisdshf_R
	if(!U && opcode==12) UNALLOCATED(ENC_UNALLOCATED_1083_ASISDSHF);
	if(opcode==0x1d) UNALLOCATED(ENC_UNALLOCATED_1082_ASISDSHF);
	if(!(immh&8) && (opcode&0x1d)==0x19) UNALLOCATED(ENC_UNALLOCATED_1081_ASISDSHF);
	if(!U && (opcode&0x1e)==0x10) UNALLOCATED(ENC_UNALLOCATED_1080_ASISDSHF);
	if(!(immh&8) && (opcode&13)==8) UNALLOCATED(ENC_UNALLOCATED_1078_ASISDSHF);
	if(!(immh&8) && !(opcode&0x19)) UNALLOCATED(ENC_UNALLOCATED_1077_ASISDSHF);
	if((immh&8)==8 && (opcode&0x1c)==0x18) UNALLOCATED(ENC_UNALLOCATED_1079_ASISDSHF);
	if((opcode&0x1c)==0x14) UNALLOCATED(ENC_UNALLOCATED_1076_ASISDSHF);
	if((opcode&0x11)==1) UNALLOCATED(ENC_UNALLOCATED_1075_ASISDSHF);
	UNMATCHED;
}

int decode_iclass_asisddiff(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>29)&1, opcode=(INSWORD>>12)&15;
	if(!U && opcode==9 && HasAdvSIMD()) return SQDMLAL_advsimd_vec(ctx, dec); // -> SQDMLAL_asisddiff_only
	if(!U && opcode==11 && HasAdvSIMD()) return SQDMLSL_advsimd_vec(ctx, dec); // -> SQDMLSL_asisddiff_only
	if(!U && opcode==13 && HasAdvSIMD()) return SQDMULL_advsimd_vec(ctx, dec); // -> SQDMULL_asisddiff_only
	if(!U && opcode==15) UNALLOCATED(ENC_UNALLOCATED_1095_ASISDDIFF);
	if(!U && (opcode&9)==8) UNALLOCATED(ENC_UNALLOCATED_1094_ASISDDIFF);
	if(!U && !(opcode&8)) UNALLOCATED(ENC_UNALLOCATED_1093_ASISDDIFF);
	if(U) UNALLOCATED(ENC_UNALLOCATED_1092_ASISDDIFF);
	UNMATCHED;
}

int decode_iclass_asisdsame(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>29)&1, size=(INSWORD>>22)&3, opcode=(INSWORD>>11)&0x1f;
	if(!U && size==3 && opcode==6 && HasAdvSIMD()) return CMGT_advsimd_reg(ctx, dec); // -> CMGT_asisdsame_only
	if(!U && size==3 && opcode==7 && HasAdvSIMD()) return CMGE_advsimd_reg(ctx, dec); // -> CMGE_asisdsame_only
	if(!U && size==3 && opcode==8 && HasAdvSIMD()) return SSHL_advsimd(ctx, dec); // -> SSHL_asisdsame_only
	if(!U && size==3 && opcode==10 && HasAdvSIMD()) return SRSHL_advsimd(ctx, dec); // -> SRSHL_asisdsame_only
	if(!U && size==3 && opcode==0x10 && HasAdvSIMD()) return ADD_advsimd(ctx, dec); // -> ADD_asisdsame_only
	if(!U && size==3 && opcode==0x11 && HasAdvSIMD()) return CMTST_advsimd(ctx, dec); // -> CMTST_asisdsame_only
	if(U && size==3 && opcode==6 && HasAdvSIMD()) return CMHI_advsimd(ctx, dec); // -> CMHI_asisdsame_only
	if(U && size==3 && opcode==7 && HasAdvSIMD()) return CMHS_advsimd(ctx, dec); // -> CMHS_asisdsame_only
	if(U && size==3 && opcode==8 && HasAdvSIMD()) return USHL_advsimd(ctx, dec); // -> USHL_asisdsame_only
	if(U && size==3 && opcode==10 && HasAdvSIMD()) return URSHL_advsimd(ctx, dec); // -> URSHL_asisdsame_only
	if(U && size==3 && opcode==0x10 && HasAdvSIMD()) return SUB_advsimd(ctx, dec); // -> SUB_asisdsame_only
	if(U && size==3 && opcode==0x11 && HasAdvSIMD()) return CMEQ_advsimd_reg(ctx, dec); // -> CMEQ_asisdsame_only
	if(size==1 && opcode==6) UNALLOCATED(ENC_UNALLOCATED_1118_ASISDSAME);
	if(size==3 && !opcode) UNALLOCATED(ENC_UNALLOCATED_1119_ASISDSAME);
	if(size==3 && opcode==2) UNALLOCATED(ENC_UNALLOCATED_1120_ASISDSAME);
	if(size==3 && opcode==0x15) UNALLOCATED(ENC_UNALLOCATED_1121_ASISDSAME);
	if(size!=2 && opcode==0x14) UNALLOCATED(ENC_UNALLOCATED_1111_ASISDSAME);
	if(size!=3 && opcode==7) UNALLOCATED(ENC_UNALLOCATED_1110_ASISDSAME);
	if(!U && !(size&2) && opcode==0x1b && HasAdvSIMD()) return FMULX_advsimd_vec(ctx, dec); // -> FMULX_asisdsame_only
	if(!U && !(size&2) && opcode==0x1c && HasAdvSIMD()) return FCMEQ_advsimd_reg(ctx, dec); // -> FCMEQ_asisdsame_only
	if(!U && !(size&2) && opcode==0x1f && HasAdvSIMD()) return FRECPS_advsimd(ctx, dec); // -> FRECPS_asisdsame_only
	if(!U && (size&2)==2 && opcode==0x1a) UNALLOCATED(ENC_UNALLOCATED_1115_ASISDSAME);
	if(!U && (size&2)==2 && opcode==0x1b) UNALLOCATED(ENC_UNALLOCATED_1116_ASISDSAME);
	if(!U && (size&2)==2 && opcode==0x1c) UNALLOCATED(ENC_UNALLOCATED_1117_ASISDSAME);
	if(!U && (size&2)==2 && opcode==0x1f && HasAdvSIMD()) return FRSQRTS_advsimd(ctx, dec); // -> FRSQRTS_asisdsame_only
	if(U && !(size&2) && opcode==0x1c && HasAdvSIMD()) return FCMGE_advsimd_reg(ctx, dec); // -> FCMGE_asisdsame_only
	if(U && !(size&2) && opcode==0x1d && HasAdvSIMD()) return FACGE_advsimd(ctx, dec); // -> FACGE_asisdsame_only
	if(U && (size&2)==2 && opcode==0x1a && HasAdvSIMD()) return FABD_advsimd(ctx, dec); // -> FABD_asisdsame_only
	if(U && (size&2)==2 && opcode==0x1c && HasAdvSIMD()) return FCMGT_advsimd_reg(ctx, dec); // -> FCMGT_asisdsame_only
	if(U && (size&2)==2 && opcode==0x1d && HasAdvSIMD()) return FACGT_advsimd(ctx, dec); // -> FACGT_asisdsame_only
	if(size&1 && opcode==4) UNALLOCATED(ENC_UNALLOCATED_1114_ASISDSAME);
	if((size&2)==2 && opcode==0x12) UNALLOCATED(ENC_UNALLOCATED_1112_ASISDSAME);
	if((size&2)==2 && opcode==0x18) UNALLOCATED(ENC_UNALLOCATED_1113_ASISDSAME);
	if(!U && opcode==1 && HasAdvSIMD()) return SQADD_advsimd(ctx, dec); // -> SQADD_asisdsame_only
	if(!U && opcode==5 && HasAdvSIMD()) return SQSUB_advsimd(ctx, dec); // -> SQSUB_asisdsame_only
	if(!U && opcode==9 && HasAdvSIMD()) return SQSHL_advsimd_reg(ctx, dec); // -> SQSHL_asisdsame_only
	if(!U && opcode==11 && HasAdvSIMD()) return SQRSHL_advsimd(ctx, dec); // -> SQRSHL_asisdsame_only
	if(!U && opcode==0x16 && HasAdvSIMD()) return SQDMULH_advsimd_vec(ctx, dec); // -> SQDMULH_asisdsame_only
	if(!U && opcode==0x17) UNALLOCATED(ENC_UNALLOCATED_1107_ASISDSAME);
	if(!U && opcode==0x1d) UNALLOCATED(ENC_UNALLOCATED_1108_ASISDSAME);
	if(U && opcode==1 && HasAdvSIMD()) return UQADD_advsimd(ctx, dec); // -> UQADD_asisdsame_only
	if(U && opcode==5 && HasAdvSIMD()) return UQSUB_advsimd(ctx, dec); // -> UQSUB_asisdsame_only
	if(U && opcode==9 && HasAdvSIMD()) return UQSHL_advsimd_reg(ctx, dec); // -> UQSHL_asisdsame_only
	if(U && opcode==11 && HasAdvSIMD()) return UQRSHL_advsimd(ctx, dec); // -> UQRSHL_asisdsame_only
	if(U && opcode==0x16 && HasAdvSIMD()) return SQRDMULH_advsimd_vec(ctx, dec); // -> SQRDMULH_asisdsame_only
	if(U && opcode==0x1b) UNALLOCATED(ENC_UNALLOCATED_1109_ASISDSAME);
	if(opcode==0x19) UNALLOCATED(ENC_UNALLOCATED_1105_ASISDSAME);
	if(opcode==0x1e) UNALLOCATED(ENC_UNALLOCATED_1106_ASISDSAME);
	if(size&1 && (opcode&0x1d)==12) UNALLOCATED(ENC_UNALLOCATED_1104_ASISDSAME);
	if(!(size&2) && (opcode&0x1b)==0x11) UNALLOCATED(ENC_UNALLOCATED_1101_ASISDSAME);
	if(size==2 && !(opcode&0x15)) UNALLOCATED(ENC_UNALLOCATED_1102_ASISDSAME);
	if(size==2 && (opcode&0x1a)==0x10) UNALLOCATED(ENC_UNALLOCATED_1103_ASISDSAME);
	if(U && (opcode&0x17)==0x17) UNALLOCATED(ENC_UNALLOCATED_1100_ASISDSAME);
	if((opcode&15)==3) UNALLOCATED(ENC_UNALLOCATED_1099_ASISDSAME);
	if((opcode&0x1d)==13) UNALLOCATED(ENC_UNALLOCATED_1098_ASISDSAME);
	if(!(size&1) && (opcode&0x15)==4) UNALLOCATED(ENC_UNALLOCATED_1097_ASISDSAME);
	if(!(size&2) && !(opcode&5)) UNALLOCATED(ENC_UNALLOCATED_1096_ASISDSAME);
	UNMATCHED;
}

int decode_iclass_asisdsamefp16(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>29)&1, a=(INSWORD>>23)&1, opcode=(INSWORD>>11)&7;
	if(!U && !a && opcode==3 && HasAdvSIMD() && HasFP16()) return FMULX_advsimd_vec(ctx, dec); // -> FMULX_asisdsamefp16_only
	if(!U && !a && opcode==4 && HasAdvSIMD() && HasFP16()) return FCMEQ_advsimd_reg(ctx, dec); // -> FCMEQ_asisdsamefp16_only
	if(!U && !a && opcode==6) UNALLOCATED(ENC_UNALLOCATED_1128_ASISDSAMEFP16);
	if(!U && !a && opcode==7 && HasAdvSIMD() && HasFP16()) return FRECPS_advsimd(ctx, dec); // -> FRECPS_asisdsamefp16_only
	if(!U && a && opcode==3) UNALLOCATED(ENC_UNALLOCATED_1129_ASISDSAMEFP16);
	if(!U && a && opcode==4) UNALLOCATED(ENC_UNALLOCATED_1130_ASISDSAMEFP16);
	if(!U && a && opcode==7 && HasAdvSIMD() && HasFP16()) return FRSQRTS_advsimd(ctx, dec); // -> FRSQRTS_asisdsamefp16_only
	if(U && !a && opcode==4 && HasAdvSIMD() && HasFP16()) return FCMGE_advsimd_reg(ctx, dec); // -> FCMGE_asisdsamefp16_only
	if(U && !a && opcode==5 && HasAdvSIMD() && HasFP16()) return FACGE_advsimd(ctx, dec); // -> FACGE_asisdsamefp16_only
	if(U && a && opcode==2 && HasAdvSIMD() && HasFP16()) return FABD_advsimd(ctx, dec); // -> FABD_asisdsamefp16_only
	if(U && a && opcode==4 && HasAdvSIMD() && HasFP16()) return FCMGT_advsimd_reg(ctx, dec); // -> FCMGT_asisdsamefp16_only
	if(U && a && opcode==5 && HasAdvSIMD() && HasFP16()) return FACGT_advsimd(ctx, dec); // -> FACGT_asisdsamefp16_only
	if(!a && opcode==2) UNALLOCATED(ENC_UNALLOCATED_1127_ASISDSAMEFP16);
	if(!U && opcode==5) UNALLOCATED(ENC_UNALLOCATED_1125_ASISDSAMEFP16);
	if(!U && a && (opcode&3)==2) UNALLOCATED(ENC_UNALLOCATED_1124_ASISDSAMEFP16);
	if(U && opcode==3) UNALLOCATED(ENC_UNALLOCATED_1126_ASISDSAMEFP16);
	if(U && (opcode&6)==6) UNALLOCATED(ENC_UNALLOCATED_1123_ASISDSAMEFP16);
	if(!(opcode&6)) UNALLOCATED(ENC_UNALLOCATED_1122_ASISDSAMEFP16);
	UNMATCHED;
}

int decode_iclass_asisdsame2(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>29)&1, opcode=(INSWORD>>11)&15;
	if(U && !opcode && HasRDM()) return SQRDMLAH_advsimd_vec(ctx, dec); // -> SQRDMLAH_asisdsame2_only
	if(U && opcode==1 && HasRDM()) return SQRDMLSH_advsimd_vec(ctx, dec); // -> SQRDMLSH_asisdsame2_only
	if(U && (opcode&14)==2) UNALLOCATED(ENC_UNALLOCATED_1134_ASISDSAME2);
	if(U && (opcode&12)==4) UNALLOCATED(ENC_UNALLOCATED_1133_ASISDSAME2);
	if(U && (opcode&8)==8) UNALLOCATED(ENC_UNALLOCATED_1132_ASISDSAME2);
	if(!U) UNALLOCATED(ENC_UNALLOCATED_1131_ASISDSAME2);
	UNMATCHED;
}

int decode_iclass_asisdmisc(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>29)&1, size=(INSWORD>>22)&3, opcode=(INSWORD>>12)&0x1f;
	if(!U && size==2 && opcode==10) UNALLOCATED(ENC_UNALLOCATED_1152_ASISDMISC);
	if(!U && size==3 && opcode==8 && HasAdvSIMD()) return CMGT_advsimd_zero(ctx, dec); // -> CMGT_asisdmisc_Z
	if(!U && size==3 && opcode==9 && HasAdvSIMD()) return CMEQ_advsimd_zero(ctx, dec); // -> CMEQ_asisdmisc_Z
	if(!U && size==3 && opcode==10 && HasAdvSIMD()) return CMLT_advsimd(ctx, dec); // -> CMLT_asisdmisc_Z
	if(!U && size==3 && opcode==11 && HasAdvSIMD()) return ABS_advsimd(ctx, dec); // -> ABS_asisdmisc_R
	if(U && !size && opcode==0x16) UNALLOCATED(ENC_UNALLOCATED_1153_ASISDMISC);
	if(U && size==1 && opcode==0x16 && HasAdvSIMD()) return FCVTXN_advsimd(ctx, dec); // -> FCVTXN_asisdmisc_N
	if(U && size==3 && opcode==8 && HasAdvSIMD()) return CMGE_advsimd_zero(ctx, dec); // -> CMGE_asisdmisc_Z
	if(U && size==3 && opcode==9 && HasAdvSIMD()) return CMLE_advsimd(ctx, dec); // -> CMLE_asisdmisc_Z
	if(U && size==3 && opcode==11 && HasAdvSIMD()) return NEG_advsimd(ctx, dec); // -> NEG_asisdmisc_R
	if(size==2 && opcode==8) UNALLOCATED(ENC_UNALLOCATED_1151_ASISDMISC);
	if(!U && !(size&2) && opcode==0x1a && HasAdvSIMD()) return FCVTNS_advsimd(ctx, dec); // -> FCVTNS_asisdmisc_R
	if(!U && !(size&2) && opcode==0x1b && HasAdvSIMD()) return FCVTMS_advsimd(ctx, dec); // -> FCVTMS_asisdmisc_R
	if(!U && !(size&2) && opcode==0x1c && HasAdvSIMD()) return FCVTAS_advsimd(ctx, dec); // -> FCVTAS_asisdmisc_R
	if(!U && !(size&2) && opcode==0x1d && HasAdvSIMD()) return SCVTF_advsimd_int(ctx, dec); // -> SCVTF_asisdmisc_R
	if(!U && (size&2)==2 && opcode==12 && HasAdvSIMD()) return FCMGT_advsimd_zero(ctx, dec); // -> FCMGT_asisdmisc_FZ
	if(!U && (size&2)==2 && opcode==13 && HasAdvSIMD()) return FCMEQ_advsimd_zero(ctx, dec); // -> FCMEQ_asisdmisc_FZ
	if(!U && (size&2)==2 && opcode==14 && HasAdvSIMD()) return FCMLT_advsimd(ctx, dec); // -> FCMLT_asisdmisc_FZ
	if(!U && (size&2)==2 && opcode==0x1a && HasAdvSIMD()) return FCVTPS_advsimd(ctx, dec); // -> FCVTPS_asisdmisc_R
	if(!U && (size&2)==2 && opcode==0x1b && HasAdvSIMD()) return FCVTZS_advsimd_int(ctx, dec); // -> FCVTZS_asisdmisc_R
	if(!U && (size&2)==2 && opcode==0x1d && HasAdvSIMD()) return FRECPE_advsimd(ctx, dec); // -> FRECPE_asisdmisc_R
	if(!U && (size&2)==2 && opcode==0x1e) UNALLOCATED(ENC_UNALLOCATED_1149_ASISDMISC);
	if(!U && (size&2)==2 && opcode==0x1f && HasAdvSIMD()) return FRECPX_advsimd(ctx, dec); // -> FRECPX_asisdmisc_R
	if(U && !(size&2) && opcode==0x1a && HasAdvSIMD()) return FCVTNU_advsimd(ctx, dec); // -> FCVTNU_asisdmisc_R
	if(U && !(size&2) && opcode==0x1b && HasAdvSIMD()) return FCVTMU_advsimd(ctx, dec); // -> FCVTMU_asisdmisc_R
	if(U && !(size&2) && opcode==0x1c && HasAdvSIMD()) return FCVTAU_advsimd(ctx, dec); // -> FCVTAU_asisdmisc_R
	if(U && !(size&2) && opcode==0x1d && HasAdvSIMD()) return UCVTF_advsimd_int(ctx, dec); // -> UCVTF_asisdmisc_R
	if(U && (size&2)==2 && opcode==12 && HasAdvSIMD()) return FCMGE_advsimd_zero(ctx, dec); // -> FCMGE_asisdmisc_FZ
	if(U && (size&2)==2 && opcode==13 && HasAdvSIMD()) return FCMLE_advsimd(ctx, dec); // -> FCMLE_asisdmisc_FZ
	if(U && (size&2)==2 && opcode==0x1a && HasAdvSIMD()) return FCVTPU_advsimd(ctx, dec); // -> FCVTPU_asisdmisc_R
	if(U && (size&2)==2 && opcode==0x1b && HasAdvSIMD()) return FCVTZU_advsimd_int(ctx, dec); // -> FCVTZU_asisdmisc_R
	if(U && (size&2)==2 && opcode==0x1d && HasAdvSIMD()) return FRSQRTE_advsimd(ctx, dec); // -> FRSQRTE_asisdmisc_R
	if(U && (size&2)==2 && opcode==0x1f) UNALLOCATED(ENC_UNALLOCATED_1150_ASISDMISC);
	if((size&2)==2 && opcode==15) UNALLOCATED(ENC_UNALLOCATED_1147_ASISDMISC);
	if((size&2)==2 && opcode==0x1c) UNALLOCATED(ENC_UNALLOCATED_1148_ASISDMISC);
	if(size==2 && (opcode&0x1d)==9) UNALLOCATED(ENC_UNALLOCATED_1146_ASISDMISC);
	if(!U && opcode==3 && HasAdvSIMD()) return SUQADD_advsimd(ctx, dec); // -> SUQADD_asisdmisc_R
	if(!U && opcode==7 && HasAdvSIMD()) return SQABS_advsimd(ctx, dec); // -> SQABS_asisdmisc_R
	if(!U && opcode==0x12) UNALLOCATED(ENC_UNALLOCATED_1142_ASISDMISC);
	if(!U && opcode==0x14 && HasAdvSIMD()) return SQXTN_advsimd(ctx, dec); // -> SQXTN_asisdmisc_N
	if(!U && opcode==0x16) UNALLOCATED(ENC_UNALLOCATED_1143_ASISDMISC);
	if(U && opcode==3 && HasAdvSIMD()) return USQADD_advsimd(ctx, dec); // -> USQADD_asisdmisc_R
	if(U && opcode==7 && HasAdvSIMD()) return SQNEG_advsimd(ctx, dec); // -> SQNEG_asisdmisc_R
	if(U && opcode==0x12 && HasAdvSIMD()) return SQXTUN_advsimd(ctx, dec); // -> SQXTUN_asisdmisc_N
	if(U && opcode==0x14 && HasAdvSIMD()) return UQXTN_advsimd(ctx, dec); // -> UQXTN_asisdmisc_N
	if(U && (size&2)==2 && (opcode&0x1b)==10) UNALLOCATED(ENC_UNALLOCATED_1144_ASISDMISC);
	if(U && (size&2)==2 && (opcode&0x17)==0x16) UNALLOCATED(ENC_UNALLOCATED_1145_ASISDMISC);
	if(opcode==0x19) UNALLOCATED(ENC_UNALLOCATED_1141_ASISDMISC);
	if(!(size&2) && (opcode&0x1e)==0x1e) UNALLOCATED(ENC_UNALLOCATED_1140_ASISDMISC);
	if((opcode&0x1b)==1) UNALLOCATED(ENC_UNALLOCATED_1138_ASISDMISC);
	if((opcode&0x17)==0x10) UNALLOCATED(ENC_UNALLOCATED_1139_ASISDMISC);
	if(!(opcode&0x19)) UNALLOCATED(ENC_UNALLOCATED_1136_ASISDMISC);
	if((opcode&0x19)==0x11) UNALLOCATED(ENC_UNALLOCATED_1137_ASISDMISC);
	if(!(size&2) && (opcode&0x18)==8) UNALLOCATED(ENC_UNALLOCATED_1135_ASISDMISC);
	UNMATCHED;
}

int decode_iclass_asisdmiscfp16(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>29)&1, a=(INSWORD>>23)&1, opcode=(INSWORD>>12)&0x1f;
	if(!U && !a && opcode==0x1a && HasAdvSIMD() && HasFP16()) return FCVTNS_advsimd(ctx, dec); // -> FCVTNS_asisdmiscfp16_R
	if(!U && !a && opcode==0x1b && HasAdvSIMD() && HasFP16()) return FCVTMS_advsimd(ctx, dec); // -> FCVTMS_asisdmiscfp16_R
	if(!U && !a && opcode==0x1c && HasAdvSIMD() && HasFP16()) return FCVTAS_advsimd(ctx, dec); // -> FCVTAS_asisdmiscfp16_R
	if(!U && !a && opcode==0x1d && HasAdvSIMD() && HasFP16()) return SCVTF_advsimd_int(ctx, dec); // -> SCVTF_asisdmiscfp16_R
	if(!U && a && opcode==12 && HasAdvSIMD() && HasFP16()) return FCMGT_advsimd_zero(ctx, dec); // -> FCMGT_asisdmiscfp16_FZ
	if(!U && a && opcode==13 && HasAdvSIMD() && HasFP16()) return FCMEQ_advsimd_zero(ctx, dec); // -> FCMEQ_asisdmiscfp16_FZ
	if(!U && a && opcode==14 && HasAdvSIMD() && HasFP16()) return FCMLT_advsimd(ctx, dec); // -> FCMLT_asisdmiscfp16_FZ
	if(!U && a && opcode==15) UNALLOCATED(ENC_UNALLOCATED_1162_ASISDMISCFP16);
	if(!U && a && opcode==0x1a && HasAdvSIMD() && HasFP16()) return FCVTPS_advsimd(ctx, dec); // -> FCVTPS_asisdmiscfp16_R
	if(!U && a && opcode==0x1b && HasAdvSIMD() && HasFP16()) return FCVTZS_advsimd_int(ctx, dec); // -> FCVTZS_asisdmiscfp16_R
	if(!U && a && opcode==0x1d && HasAdvSIMD() && HasFP16()) return FRECPE_advsimd(ctx, dec); // -> FRECPE_asisdmiscfp16_R
	if(!U && a && opcode==0x1e) UNALLOCATED(ENC_UNALLOCATED_1163_ASISDMISCFP16);
	if(!U && a && opcode==0x1f && HasAdvSIMD() && HasFP16()) return FRECPX_advsimd(ctx, dec); // -> FRECPX_asisdmiscfp16_R
	if(U && !a && opcode==0x1a && HasAdvSIMD() && HasFP16()) return FCVTNU_advsimd(ctx, dec); // -> FCVTNU_asisdmiscfp16_R
	if(U && !a && opcode==0x1b && HasAdvSIMD() && HasFP16()) return FCVTMU_advsimd(ctx, dec); // -> FCVTMU_asisdmiscfp16_R
	if(U && !a && opcode==0x1c && HasAdvSIMD() && HasFP16()) return FCVTAU_advsimd(ctx, dec); // -> FCVTAU_asisdmiscfp16_R
	if(U && !a && opcode==0x1d && HasAdvSIMD() && HasFP16()) return UCVTF_advsimd_int(ctx, dec); // -> UCVTF_asisdmiscfp16_R
	if(U && a && opcode==12 && HasAdvSIMD() && HasFP16()) return FCMGE_advsimd_zero(ctx, dec); // -> FCMGE_asisdmiscfp16_FZ
	if(U && a && opcode==13 && HasAdvSIMD() && HasFP16()) return FCMLE_advsimd(ctx, dec); // -> FCMLE_asisdmiscfp16_FZ
	if(U && a && opcode==0x1a && HasAdvSIMD() && HasFP16()) return FCVTPU_advsimd(ctx, dec); // -> FCVTPU_asisdmiscfp16_R
	if(U && a && opcode==0x1b && HasAdvSIMD() && HasFP16()) return FCVTZU_advsimd_int(ctx, dec); // -> FCVTZU_asisdmiscfp16_R
	if(U && a && opcode==0x1d && HasAdvSIMD() && HasFP16()) return FRSQRTE_advsimd(ctx, dec); // -> FRSQRTE_asisdmiscfp16_R
	if(a && opcode==0x1c) UNALLOCATED(ENC_UNALLOCATED_1161_ASISDMISCFP16);
	if(!U && !a && (opcode&0x1e)==0x1e) UNALLOCATED(ENC_UNALLOCATED_1159_ASISDMISCFP16);
	if(U && a && (opcode&0x1e)==14) UNALLOCATED(ENC_UNALLOCATED_1160_ASISDMISCFP16);
	if(U && (opcode&0x1e)==0x1e) UNALLOCATED(ENC_UNALLOCATED_1158_ASISDMISCFP16);
	if((opcode&0x1e)==0x18) UNALLOCATED(ENC_UNALLOCATED_1157_ASISDMISCFP16);
	if(a && (opcode&0x1c)==8) UNALLOCATED(ENC_UNALLOCATED_1156_ASISDMISCFP16);
	if(!a && (opcode&0x18)==8) UNALLOCATED(ENC_UNALLOCATED_1155_ASISDMISCFP16);
	if(!(opcode&8)) UNALLOCATED(ENC_UNALLOCATED_1154_ASISDMISCFP16);
	UNMATCHED;
}

int decode_iclass_asisdelem(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>29)&1, size=(INSWORD>>22)&3, opcode=(INSWORD>>12)&15;
	if(!U && !size && opcode==1 && HasAdvSIMD() && HasFP16()) return FMLA_advsimd_elt(ctx, dec); // -> FMLA_asisdelem_RH_H
	if(!U && !size && opcode==5 && HasAdvSIMD() && HasFP16()) return FMLS_advsimd_elt(ctx, dec); // -> FMLS_asisdelem_RH_H
	if(!U && !size && opcode==9 && HasAdvSIMD() && HasFP16()) return FMUL_advsimd_elt(ctx, dec); // -> FMUL_asisdelem_RH_H
	if(U && !size && opcode==9 && HasAdvSIMD() && HasFP16()) return FMULX_advsimd_elt(ctx, dec); // -> FMULX_asisdelem_RH_H
	if(size==1 && opcode==9) UNALLOCATED(ENC_UNALLOCATED_1171_ASISDELEM);
	if(!U && size==1 && (opcode&11)==1) UNALLOCATED(ENC_UNALLOCATED_1170_ASISDELEM);
	if(!U && (size&2)==2 && opcode==1 && HasAdvSIMD()) return FMLA_advsimd_elt(ctx, dec); // -> FMLA_asisdelem_R_SD
	if(!U && (size&2)==2 && opcode==5 && HasAdvSIMD()) return FMLS_advsimd_elt(ctx, dec); // -> FMLS_asisdelem_R_SD
	if(!U && (size&2)==2 && opcode==9 && HasAdvSIMD()) return FMUL_advsimd_elt(ctx, dec); // -> FMUL_asisdelem_R_SD
	if(U && (size&2)==2 && opcode==9 && HasAdvSIMD()) return FMULX_advsimd_elt(ctx, dec); // -> FMULX_asisdelem_R_SD
	if(!U && opcode==3 && HasAdvSIMD()) return SQDMLAL_advsimd_elt(ctx, dec); // -> SQDMLAL_asisdelem_L
	if(!U && opcode==7 && HasAdvSIMD()) return SQDMLSL_advsimd_elt(ctx, dec); // -> SQDMLSL_asisdelem_L
	if(!U && opcode==11 && HasAdvSIMD()) return SQDMULL_advsimd_elt(ctx, dec); // -> SQDMULL_asisdelem_L
	if(!U && opcode==12 && HasAdvSIMD()) return SQDMULH_advsimd_elt(ctx, dec); // -> SQDMULH_asisdelem_R
	if(!U && opcode==13 && HasAdvSIMD()) return SQRDMULH_advsimd_elt(ctx, dec); // -> SQRDMULH_asisdelem_R
	if(U && opcode==11) UNALLOCATED(ENC_UNALLOCATED_1169_ASISDELEM);
	if(U && opcode==13 && HasRDM()) return SQRDMLAH_advsimd_elt(ctx, dec); // -> SQRDMLAH_asisdelem_R
	if(U && opcode==15 && HasRDM()) return SQRDMLSH_advsimd_elt(ctx, dec); // -> SQRDMLSH_asisdelem_R
	if(!U && (opcode&13)==8) UNALLOCATED(ENC_UNALLOCATED_1167_ASISDELEM);
	if(!U && (opcode&14)==14) UNALLOCATED(ENC_UNALLOCATED_1168_ASISDELEM);
	if(!U && !(opcode&9)) UNALLOCATED(ENC_UNALLOCATED_1165_ASISDELEM);
	if(U && (opcode&9)==8) UNALLOCATED(ENC_UNALLOCATED_1166_ASISDELEM);
	if(U && !(opcode&8)) UNALLOCATED(ENC_UNALLOCATED_1164_ASISDELEM);
	UNMATCHED;
}

int decode_iclass_asimdshf(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>29)&1, immh=(INSWORD>>19)&15, opcode=(INSWORD>>11)&0x1f;
	if(!U && immh && !opcode && HasAdvSIMD()) return SSHR_advsimd(ctx, dec); // -> SSHR_asimdshf_R
	if(!U && immh && opcode==2 && HasAdvSIMD()) return SSRA_advsimd(ctx, dec); // -> SSRA_asimdshf_R
	if(!U && immh && opcode==4 && HasAdvSIMD()) return SRSHR_advsimd(ctx, dec); // -> SRSHR_asimdshf_R
	if(!U && immh && opcode==6 && HasAdvSIMD()) return SRSRA_advsimd(ctx, dec); // -> SRSRA_asimdshf_R
	if(!U && immh && opcode==10 && HasAdvSIMD()) return SHL_advsimd(ctx, dec); // -> SHL_asimdshf_R
	if(!U && immh && opcode==14 && HasAdvSIMD()) return SQSHL_advsimd_imm(ctx, dec); // -> SQSHL_asimdshf_R
	if(!U && immh && opcode==0x10 && HasAdvSIMD()) return SHRN_advsimd(ctx, dec); // -> SHRN_asimdshf_N
	if(!U && immh && opcode==0x11 && HasAdvSIMD()) return RSHRN_advsimd(ctx, dec); // -> RSHRN_asimdshf_N
	if(!U && immh && opcode==0x12 && HasAdvSIMD()) return SQSHRN_advsimd(ctx, dec); // -> SQSHRN_asimdshf_N
	if(!U && immh && opcode==0x13 && HasAdvSIMD()) return SQRSHRN_advsimd(ctx, dec); // -> SQRSHRN_asimdshf_N
	if(!U && immh && opcode==0x14 && HasAdvSIMD()) return SSHLL_advsimd(ctx, dec); // -> SSHLL_asimdshf_L
	if(!U && immh && opcode==0x1c && HasAdvSIMD()) return SCVTF_advsimd_fix(ctx, dec); // -> SCVTF_asimdshf_C
	if(!U && immh && opcode==0x1f && HasAdvSIMD()) return FCVTZS_advsimd_fix(ctx, dec); // -> FCVTZS_asimdshf_C
	if(U && immh && !opcode && HasAdvSIMD()) return USHR_advsimd(ctx, dec); // -> USHR_asimdshf_R
	if(U && immh && opcode==2 && HasAdvSIMD()) return USRA_advsimd(ctx, dec); // -> USRA_asimdshf_R
	if(U && immh && opcode==4 && HasAdvSIMD()) return URSHR_advsimd(ctx, dec); // -> URSHR_asimdshf_R
	if(U && immh && opcode==6 && HasAdvSIMD()) return URSRA_advsimd(ctx, dec); // -> URSRA_asimdshf_R
	if(U && immh && opcode==8 && HasAdvSIMD()) return SRI_advsimd(ctx, dec); // -> SRI_asimdshf_R
	if(U && immh && opcode==10 && HasAdvSIMD()) return SLI_advsimd(ctx, dec); // -> SLI_asimdshf_R
	if(U && immh && opcode==12 && HasAdvSIMD()) return SQSHLU_advsimd(ctx, dec); // -> SQSHLU_asimdshf_R
	if(U && immh && opcode==14 && HasAdvSIMD()) return UQSHL_advsimd_imm(ctx, dec); // -> UQSHL_asimdshf_R
	if(U && immh && opcode==0x10 && HasAdvSIMD()) return SQSHRUN_advsimd(ctx, dec); // -> SQSHRUN_asimdshf_N
	if(U && immh && opcode==0x11 && HasAdvSIMD()) return SQRSHRUN_advsimd(ctx, dec); // -> SQRSHRUN_asimdshf_N
	if(U && immh && opcode==0x12 && HasAdvSIMD()) return UQSHRN_advsimd(ctx, dec); // -> UQSHRN_asimdshf_N
	if(U && immh && opcode==0x13 && HasAdvSIMD()) return UQRSHRN_advsimd(ctx, dec); // -> UQRSHRN_asimdshf_N
	if(U && immh && opcode==0x14 && HasAdvSIMD()) return USHLL_advsimd(ctx, dec); // -> USHLL_asimdshf_L
	if(U && immh && opcode==0x1c && HasAdvSIMD()) return UCVTF_advsimd_fix(ctx, dec); // -> UCVTF_asimdshf_C
	if(U && immh && opcode==0x1f && HasAdvSIMD()) return FCVTZU_advsimd_fix(ctx, dec); // -> FCVTZU_asimdshf_C
	if(immh && opcode==0x1d) UNALLOCATED(ENC_UNALLOCATED_1177_ASIMDSHF);
	if(!U && immh && (opcode&0x1b)==8) UNALLOCATED(ENC_UNALLOCATED_1176_ASIMDSHF);
	if(immh && (opcode&0x17)==0x16) UNALLOCATED(ENC_UNALLOCATED_1175_ASIMDSHF);
	if(immh && (opcode&0x1d)==0x15) UNALLOCATED(ENC_UNALLOCATED_1174_ASIMDSHF);
	if(immh && (opcode&0x1c)==0x18) UNALLOCATED(ENC_UNALLOCATED_1173_ASIMDSHF);
	if(immh && (opcode&0x11)==1) UNALLOCATED(ENC_UNALLOCATED_1172_ASIMDSHF);
	UNMATCHED;
}

int decode_iclass_asimdtbl(context *ctx, Instruction *dec)
{
	uint32_t Q=(INSWORD>>30)&1, op2=(INSWORD>>22)&3, len=(INSWORD>>13)&3, op=(INSWORD>>12)&1;
	if(!op2 && !len && !op && HasAdvSIMD()) return TBL_advsimd(ctx, dec); // -> TBL_asimdtbl_L1_1
	if(!op2 && !len && op && HasAdvSIMD()) return TBX_advsimd(ctx, dec); // -> TBX_asimdtbl_L1_1
	if(!op2 && len==1 && !op && HasAdvSIMD()) return TBL_advsimd(ctx, dec); // -> TBL_asimdtbl_L2_2
	if(!op2 && len==1 && op && HasAdvSIMD()) return TBX_advsimd(ctx, dec); // -> TBX_asimdtbl_L2_2
	if(!op2 && len==2 && !op && HasAdvSIMD()) return TBL_advsimd(ctx, dec); // -> TBL_asimdtbl_L3_3
	if(!op2 && len==2 && op && HasAdvSIMD()) return TBX_advsimd(ctx, dec); // -> TBX_asimdtbl_L3_3
	if(!op2 && len==3 && !op && HasAdvSIMD()) return TBL_advsimd(ctx, dec); // -> TBL_asimdtbl_L4_4
	if(!op2 && len==3 && op && HasAdvSIMD()) return TBX_advsimd(ctx, dec); // -> TBX_asimdtbl_L4_4
	if(Q && op2==1 && !(len&1) && !op) UNALLOCATED(ENC_UNALLOCATED_1180_ASIMDTBL);
	if(Q && op2==1 && len&1 && !op && HasAdvSIMD() && HasLUT()) return LUTI4_advsimd(ctx, dec); // -> LUTI4_asimdtbl_L5
	if(Q && op2==1 && op && HasAdvSIMD() && HasLUT()) return LUTI4_advsimd(ctx, dec); // -> LUTI4_asimdtbl_L7
	if(Q && op2==2 && !op) UNALLOCATED(ENC_UNALLOCATED_1179_ASIMDTBL);
	if(Q && op2==2 && op && HasAdvSIMD() && HasLUT()) return LUTI2_advsimd(ctx, dec); // -> LUTI2_asimdtbl_L5
	if(!Q && op2) UNALLOCATED(ENC_UNALLOCATED_1178_ASIMDTBL);
	if(Q && op2==3 && HasAdvSIMD() && HasLUT()) return LUTI2_advsimd(ctx, dec); // -> LUTI2_asimdtbl_L6
	UNMATCHED;
}

int decode_iclass_asimddiff(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>29)&1, opcode=(INSWORD>>12)&15;
	if(!U && !opcode && HasAdvSIMD()) return SADDL_advsimd(ctx, dec); // -> SADDL_asimddiff_L
	if(!U && opcode==1 && HasAdvSIMD()) return SADDW_advsimd(ctx, dec); // -> SADDW_asimddiff_W
	if(!U && opcode==2 && HasAdvSIMD()) return SSUBL_advsimd(ctx, dec); // -> SSUBL_asimddiff_L
	if(!U && opcode==3 && HasAdvSIMD()) return SSUBW_advsimd(ctx, dec); // -> SSUBW_asimddiff_W
	if(!U && opcode==4 && HasAdvSIMD()) return ADDHN_advsimd(ctx, dec); // -> ADDHN_asimddiff_N
	if(!U && opcode==5 && HasAdvSIMD()) return SABAL_advsimd(ctx, dec); // -> SABAL_asimddiff_L
	if(!U && opcode==6 && HasAdvSIMD()) return SUBHN_advsimd(ctx, dec); // -> SUBHN_asimddiff_N
	if(!U && opcode==7 && HasAdvSIMD()) return SABDL_advsimd(ctx, dec); // -> SABDL_asimddiff_L
	if(!U && opcode==8 && HasAdvSIMD()) return SMLAL_advsimd_vec(ctx, dec); // -> SMLAL_asimddiff_L
	if(!U && opcode==9 && HasAdvSIMD()) return SQDMLAL_advsimd_vec(ctx, dec); // -> SQDMLAL_asimddiff_L
	if(!U && opcode==10 && HasAdvSIMD()) return SMLSL_advsimd_vec(ctx, dec); // -> SMLSL_asimddiff_L
	if(!U && opcode==11 && HasAdvSIMD()) return SQDMLSL_advsimd_vec(ctx, dec); // -> SQDMLSL_asimddiff_L
	if(!U && opcode==12 && HasAdvSIMD()) return SMULL_advsimd_vec(ctx, dec); // -> SMULL_asimddiff_L
	if(!U && opcode==13 && HasAdvSIMD()) return SQDMULL_advsimd_vec(ctx, dec); // -> SQDMULL_asimddiff_L
	if(!U && opcode==14 && HasAdvSIMD()) return PMULL_advsimd(ctx, dec); // -> PMULL_asimddiff_L
	if(!U && opcode==15) UNALLOCATED(ENC_UNALLOCATED_1182_ASIMDDIFF);
	if(U && !opcode && HasAdvSIMD()) return UADDL_advsimd(ctx, dec); // -> UADDL_asimddiff_L
	if(U && opcode==1 && HasAdvSIMD()) return UADDW_advsimd(ctx, dec); // -> UADDW_asimddiff_W
	if(U && opcode==2 && HasAdvSIMD()) return USUBL_advsimd(ctx, dec); // -> USUBL_asimddiff_L
	if(U && opcode==3 && HasAdvSIMD()) return USUBW_advsimd(ctx, dec); // -> USUBW_asimddiff_W
	if(U && opcode==4 && HasAdvSIMD()) return RADDHN_advsimd(ctx, dec); // -> RADDHN_asimddiff_N
	if(U && opcode==5 && HasAdvSIMD()) return UABAL_advsimd(ctx, dec); // -> UABAL_asimddiff_L
	if(U && opcode==6 && HasAdvSIMD()) return RSUBHN_advsimd(ctx, dec); // -> RSUBHN_asimddiff_N
	if(U && opcode==7 && HasAdvSIMD()) return UABDL_advsimd(ctx, dec); // -> UABDL_asimddiff_L
	if(U && opcode==8 && HasAdvSIMD()) return UMLAL_advsimd_vec(ctx, dec); // -> UMLAL_asimddiff_L
	if(U && opcode==10 && HasAdvSIMD()) return UMLSL_advsimd_vec(ctx, dec); // -> UMLSL_asimddiff_L
	if(U && opcode==12 && HasAdvSIMD()) return UMULL_advsimd_vec(ctx, dec); // -> UMULL_asimddiff_L
	if(U && opcode==14) UNALLOCATED(ENC_UNALLOCATED_1183_ASIMDDIFF);
	if(U && (opcode&9)==9) UNALLOCATED(ENC_UNALLOCATED_1181_ASIMDDIFF);
	UNMATCHED;
}

int decode_iclass_asimdsame(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>29)&1, size=(INSWORD>>22)&3, opcode=(INSWORD>>11)&0x1f;
	if(!U && !size && opcode==3 && HasAdvSIMD()) return AND_advsimd(ctx, dec); // -> AND_asimdsame_only
	if(!U && !size && opcode==0x1d && HasFHM()) return FMLAL_advsimd_vec(ctx, dec); // -> FMLAL_asimdsame_F
	if(!U && size==1 && opcode==3 && HasAdvSIMD()) return BIC_advsimd_reg(ctx, dec); // -> BIC_asimdsame_only
	if(!U && size==2 && opcode==3 && HasAdvSIMD()) return ORR_advsimd_reg(ctx, dec); // -> ORR_asimdsame_only
	if(!U && size==2 && opcode==0x1d && HasFHM()) return FMLSL_advsimd_vec(ctx, dec); // -> FMLSL_asimdsame_F
	if(!U && size==3 && opcode==3 && HasAdvSIMD()) return ORN_advsimd(ctx, dec); // -> ORN_asimdsame_only
	if(U && !size && opcode==3 && HasAdvSIMD()) return EOR_advsimd(ctx, dec); // -> EOR_asimdsame_only
	if(U && !size && opcode==0x19 && HasFHM()) return FMLAL_advsimd_vec(ctx, dec); // -> FMLAL2_asimdsame_F
	if(U && size==1 && opcode==3 && HasAdvSIMD()) return BSL_advsimd(ctx, dec); // -> BSL_asimdsame_only
	if(U && size==2 && opcode==3 && HasAdvSIMD()) return BIT_advsimd(ctx, dec); // -> BIT_asimdsame_only
	if(U && size==2 && opcode==0x19 && HasFHM()) return FMLSL_advsimd_vec(ctx, dec); // -> FMLSL2_asimdsame_F
	if(U && size==3 && opcode==3 && HasAdvSIMD()) return BIF_advsimd(ctx, dec); // -> BIF_asimdsame_only
	if(!U && size&1 && opcode==0x1d) UNALLOCATED(ENC_UNALLOCATED_1186_ASIMDSAME);
	if(!U && !(size&2) && opcode==0x18 && HasAdvSIMD()) return FMAXNM_advsimd(ctx, dec); // -> FMAXNM_asimdsame_only
	if(!U && !(size&2) && opcode==0x19 && HasAdvSIMD()) return FMLA_advsimd_vec(ctx, dec); // -> FMLA_asimdsame_only
	if(!U && !(size&2) && opcode==0x1a && HasAdvSIMD()) return FADD_advsimd(ctx, dec); // -> FADD_asimdsame_only
	if(!U && !(size&2) && opcode==0x1b && HasAdvSIMD()) return FMULX_advsimd_vec(ctx, dec); // -> FMULX_asimdsame_only
	if(!U && !(size&2) && opcode==0x1c && HasAdvSIMD()) return FCMEQ_advsimd_reg(ctx, dec); // -> FCMEQ_asimdsame_only
	if(!U && !(size&2) && opcode==0x1e && HasAdvSIMD()) return FMAX_advsimd(ctx, dec); // -> FMAX_asimdsame_only
	if(!U && !(size&2) && opcode==0x1f && HasAdvSIMD()) return FRECPS_advsimd(ctx, dec); // -> FRECPS_asimdsame_only
	if(!U && (size&2)==2 && opcode==0x18 && HasAdvSIMD()) return FMINNM_advsimd(ctx, dec); // -> FMINNM_asimdsame_only
	if(!U && (size&2)==2 && opcode==0x19 && HasAdvSIMD()) return FMLS_advsimd_vec(ctx, dec); // -> FMLS_asimdsame_only
	if(!U && (size&2)==2 && opcode==0x1a && HasAdvSIMD()) return FSUB_advsimd(ctx, dec); // -> FSUB_asimdsame_only
	if(!U && (size&2)==2 && opcode==0x1b && HasAdvSIMD() && HasFAMINMAX()) return FAMAX_advsimd(ctx, dec); // -> FAMAX_asimdsame_only
	if(!U && (size&2)==2 && opcode==0x1c) UNALLOCATED(ENC_UNALLOCATED_1185_ASIMDSAME);
	if(!U && (size&2)==2 && opcode==0x1e && HasAdvSIMD()) return FMIN_advsimd(ctx, dec); // -> FMIN_asimdsame_only
	if(!U && (size&2)==2 && opcode==0x1f && HasAdvSIMD()) return FRSQRTS_advsimd(ctx, dec); // -> FRSQRTS_asimdsame_only
	if(U && size&1 && opcode==0x19) UNALLOCATED(ENC_UNALLOCATED_1187_ASIMDSAME);
	if(U && !(size&2) && opcode==0x18 && HasAdvSIMD()) return FMAXNMP_advsimd_vec(ctx, dec); // -> FMAXNMP_asimdsame_only
	if(U && !(size&2) && opcode==0x1a && HasAdvSIMD()) return FADDP_advsimd_vec(ctx, dec); // -> FADDP_asimdsame_only
	if(U && !(size&2) && opcode==0x1b && HasAdvSIMD()) return FMUL_advsimd_vec(ctx, dec); // -> FMUL_asimdsame_only
	if(U && !(size&2) && opcode==0x1c && HasAdvSIMD()) return FCMGE_advsimd_reg(ctx, dec); // -> FCMGE_asimdsame_only
	if(U && !(size&2) && opcode==0x1d && HasAdvSIMD()) return FACGE_advsimd(ctx, dec); // -> FACGE_asimdsame_only
	if(U && !(size&2) && opcode==0x1e && HasAdvSIMD()) return FMAXP_advsimd_vec(ctx, dec); // -> FMAXP_asimdsame_only
	if(U && !(size&2) && opcode==0x1f && HasAdvSIMD()) return FDIV_advsimd(ctx, dec); // -> FDIV_asimdsame_only
	if(U && (size&2)==2 && opcode==0x18 && HasAdvSIMD()) return FMINNMP_advsimd_vec(ctx, dec); // -> FMINNMP_asimdsame_only
	if(U && (size&2)==2 && opcode==0x1a && HasAdvSIMD()) return FABD_advsimd(ctx, dec); // -> FABD_asimdsame_only
	if(U && (size&2)==2 && opcode==0x1b && HasAdvSIMD() && HasFAMINMAX()) return FAMIN_advsimd(ctx, dec); // -> FAMIN_asimdsame_only
	if(U && (size&2)==2 && opcode==0x1c && HasAdvSIMD()) return FCMGT_advsimd_reg(ctx, dec); // -> FCMGT_asimdsame_only
	if(U && (size&2)==2 && opcode==0x1d && HasAdvSIMD()) return FACGT_advsimd(ctx, dec); // -> FACGT_asimdsame_only
	if(U && (size&2)==2 && opcode==0x1e && HasAdvSIMD()) return FMINP_advsimd_vec(ctx, dec); // -> FMINP_asimdsame_only
	if(U && (size&2)==2 && opcode==0x1f && HasFP8()) return FSCALE_advsimd(ctx, dec); // -> FSCALE_asimdsame_only
	if(!U && !opcode && HasAdvSIMD()) return SHADD_advsimd(ctx, dec); // -> SHADD_asimdsame_only
	if(!U && opcode==1 && HasAdvSIMD()) return SQADD_advsimd(ctx, dec); // -> SQADD_asimdsame_only
	if(!U && opcode==2 && HasAdvSIMD()) return SRHADD_advsimd(ctx, dec); // -> SRHADD_asimdsame_only
	if(!U && opcode==4 && HasAdvSIMD()) return SHSUB_advsimd(ctx, dec); // -> SHSUB_asimdsame_only
	if(!U && opcode==5 && HasAdvSIMD()) return SQSUB_advsimd(ctx, dec); // -> SQSUB_asimdsame_only
	if(!U && opcode==6 && HasAdvSIMD()) return CMGT_advsimd_reg(ctx, dec); // -> CMGT_asimdsame_only
	if(!U && opcode==7 && HasAdvSIMD()) return CMGE_advsimd_reg(ctx, dec); // -> CMGE_asimdsame_only
	if(!U && opcode==8 && HasAdvSIMD()) return SSHL_advsimd(ctx, dec); // -> SSHL_asimdsame_only
	if(!U && opcode==9 && HasAdvSIMD()) return SQSHL_advsimd_reg(ctx, dec); // -> SQSHL_asimdsame_only
	if(!U && opcode==10 && HasAdvSIMD()) return SRSHL_advsimd(ctx, dec); // -> SRSHL_asimdsame_only
	if(!U && opcode==11 && HasAdvSIMD()) return SQRSHL_advsimd(ctx, dec); // -> SQRSHL_asimdsame_only
	if(!U && opcode==12 && HasAdvSIMD()) return SMAX_advsimd(ctx, dec); // -> SMAX_asimdsame_only
	if(!U && opcode==13 && HasAdvSIMD()) return SMIN_advsimd(ctx, dec); // -> SMIN_asimdsame_only
	if(!U && opcode==14 && HasAdvSIMD()) return SABD_advsimd(ctx, dec); // -> SABD_asimdsame_only
	if(!U && opcode==15 && HasAdvSIMD()) return SABA_advsimd(ctx, dec); // -> SABA_asimdsame_only
	if(!U && opcode==0x10 && HasAdvSIMD()) return ADD_advsimd(ctx, dec); // -> ADD_asimdsame_only
	if(!U && opcode==0x11 && HasAdvSIMD()) return CMTST_advsimd(ctx, dec); // -> CMTST_asimdsame_only
	if(!U && opcode==0x12 && HasAdvSIMD()) return MLA_advsimd_vec(ctx, dec); // -> MLA_asimdsame_only
	if(!U && opcode==0x13 && HasAdvSIMD()) return MUL_advsimd_vec(ctx, dec); // -> MUL_asimdsame_only
	if(!U && opcode==0x14 && HasAdvSIMD()) return SMAXP_advsimd(ctx, dec); // -> SMAXP_asimdsame_only
	if(!U && opcode==0x15 && HasAdvSIMD()) return SMINP_advsimd(ctx, dec); // -> SMINP_asimdsame_only
	if(!U && opcode==0x16 && HasAdvSIMD()) return SQDMULH_advsimd_vec(ctx, dec); // -> SQDMULH_asimdsame_only
	if(!U && opcode==0x17 && HasAdvSIMD()) return ADDP_advsimd_vec(ctx, dec); // -> ADDP_asimdsame_only
	if(U && !opcode && HasAdvSIMD()) return UHADD_advsimd(ctx, dec); // -> UHADD_asimdsame_only
	if(U && opcode==1 && HasAdvSIMD()) return UQADD_advsimd(ctx, dec); // -> UQADD_asimdsame_only
	if(U && opcode==2 && HasAdvSIMD()) return URHADD_advsimd(ctx, dec); // -> URHADD_asimdsame_only
	if(U && opcode==4 && HasAdvSIMD()) return UHSUB_advsimd(ctx, dec); // -> UHSUB_asimdsame_only
	if(U && opcode==5 && HasAdvSIMD()) return UQSUB_advsimd(ctx, dec); // -> UQSUB_asimdsame_only
	if(U && opcode==6 && HasAdvSIMD()) return CMHI_advsimd(ctx, dec); // -> CMHI_asimdsame_only
	if(U && opcode==7 && HasAdvSIMD()) return CMHS_advsimd(ctx, dec); // -> CMHS_asimdsame_only
	if(U && opcode==8 && HasAdvSIMD()) return USHL_advsimd(ctx, dec); // -> USHL_asimdsame_only
	if(U && opcode==9 && HasAdvSIMD()) return UQSHL_advsimd_reg(ctx, dec); // -> UQSHL_asimdsame_only
	if(U && opcode==10 && HasAdvSIMD()) return URSHL_advsimd(ctx, dec); // -> URSHL_asimdsame_only
	if(U && opcode==11 && HasAdvSIMD()) return UQRSHL_advsimd(ctx, dec); // -> UQRSHL_asimdsame_only
	if(U && opcode==12 && HasAdvSIMD()) return UMAX_advsimd(ctx, dec); // -> UMAX_asimdsame_only
	if(U && opcode==13 && HasAdvSIMD()) return UMIN_advsimd(ctx, dec); // -> UMIN_asimdsame_only
	if(U && opcode==14 && HasAdvSIMD()) return UABD_advsimd(ctx, dec); // -> UABD_asimdsame_only
	if(U && opcode==15 && HasAdvSIMD()) return UABA_advsimd(ctx, dec); // -> UABA_asimdsame_only
	if(U && opcode==0x10 && HasAdvSIMD()) return SUB_advsimd(ctx, dec); // -> SUB_asimdsame_only
	if(U && opcode==0x11 && HasAdvSIMD()) return CMEQ_advsimd_reg(ctx, dec); // -> CMEQ_asimdsame_only
	if(U && opcode==0x12 && HasAdvSIMD()) return MLS_advsimd_vec(ctx, dec); // -> MLS_asimdsame_only
	if(U && opcode==0x13 && HasAdvSIMD()) return PMUL_advsimd(ctx, dec); // -> PMUL_asimdsame_only
	if(U && opcode==0x14 && HasAdvSIMD()) return UMAXP_advsimd(ctx, dec); // -> UMAXP_asimdsame_only
	if(U && opcode==0x15 && HasAdvSIMD()) return UMINP_advsimd(ctx, dec); // -> UMINP_asimdsame_only
	if(U && opcode==0x16 && HasAdvSIMD()) return SQRDMULH_advsimd_vec(ctx, dec); // -> SQRDMULH_asimdsame_only
	if(U && opcode==0x17) UNALLOCATED(ENC_UNALLOCATED_1184_ASIMDSAME);
	UNMATCHED;
}

int decode_iclass_asimdsamefp16(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>29)&1, a=(INSWORD>>23)&1, opcode=(INSWORD>>11)&7;
	if(!U && !a && !opcode && HasAdvSIMD() && HasFP16()) return FMAXNM_advsimd(ctx, dec); // -> FMAXNM_asimdsamefp16_only
	if(!U && !a && opcode==1 && HasAdvSIMD() && HasFP16()) return FMLA_advsimd_vec(ctx, dec); // -> FMLA_asimdsamefp16_only
	if(!U && !a && opcode==2 && HasAdvSIMD() && HasFP16()) return FADD_advsimd(ctx, dec); // -> FADD_asimdsamefp16_only
	if(!U && !a && opcode==3 && HasAdvSIMD() && HasFP16()) return FMULX_advsimd_vec(ctx, dec); // -> FMULX_asimdsamefp16_only
	if(!U && !a && opcode==4 && HasAdvSIMD() && HasFP16()) return FCMEQ_advsimd_reg(ctx, dec); // -> FCMEQ_asimdsamefp16_only
	if(!U && !a && opcode==5) UNALLOCATED(ENC_UNALLOCATED_1190_ASIMDSAMEFP16);
	if(!U && !a && opcode==6 && HasAdvSIMD() && HasFP16()) return FMAX_advsimd(ctx, dec); // -> FMAX_asimdsamefp16_only
	if(!U && !a && opcode==7 && HasAdvSIMD() && HasFP16()) return FRECPS_advsimd(ctx, dec); // -> FRECPS_asimdsamefp16_only
	if(!U && a && !opcode && HasAdvSIMD() && HasFP16()) return FMINNM_advsimd(ctx, dec); // -> FMINNM_asimdsamefp16_only
	if(!U && a && opcode==1 && HasAdvSIMD() && HasFP16()) return FMLS_advsimd_vec(ctx, dec); // -> FMLS_asimdsamefp16_only
	if(!U && a && opcode==2 && HasAdvSIMD() && HasFP16()) return FSUB_advsimd(ctx, dec); // -> FSUB_asimdsamefp16_only
	if(!U && a && opcode==3 && HasAdvSIMD() && HasFAMINMAX()) return FAMAX_advsimd(ctx, dec); // -> FAMAX_asimdsamefp16_only
	if(!U && a && opcode==6 && HasAdvSIMD() && HasFP16()) return FMIN_advsimd(ctx, dec); // -> FMIN_asimdsamefp16_only
	if(!U && a && opcode==7 && HasAdvSIMD() && HasFP16()) return FRSQRTS_advsimd(ctx, dec); // -> FRSQRTS_asimdsamefp16_only
	if(U && !a && !opcode && HasAdvSIMD() && HasFP16()) return FMAXNMP_advsimd_vec(ctx, dec); // -> FMAXNMP_asimdsamefp16_only
	if(U && !a && opcode==2 && HasAdvSIMD() && HasFP16()) return FADDP_advsimd_vec(ctx, dec); // -> FADDP_asimdsamefp16_only
	if(U && !a && opcode==3 && HasAdvSIMD() && HasFP16()) return FMUL_advsimd_vec(ctx, dec); // -> FMUL_asimdsamefp16_only
	if(U && !a && opcode==4 && HasAdvSIMD() && HasFP16()) return FCMGE_advsimd_reg(ctx, dec); // -> FCMGE_asimdsamefp16_only
	if(U && !a && opcode==5 && HasAdvSIMD() && HasFP16()) return FACGE_advsimd(ctx, dec); // -> FACGE_asimdsamefp16_only
	if(U && !a && opcode==6 && HasAdvSIMD() && HasFP16()) return FMAXP_advsimd_vec(ctx, dec); // -> FMAXP_asimdsamefp16_only
	if(U && !a && opcode==7 && HasAdvSIMD() && HasFP16()) return FDIV_advsimd(ctx, dec); // -> FDIV_asimdsamefp16_only
	if(U && a && !opcode && HasAdvSIMD() && HasFP16()) return FMINNMP_advsimd_vec(ctx, dec); // -> FMINNMP_asimdsamefp16_only
	if(U && a && opcode==2 && HasAdvSIMD() && HasFP16()) return FABD_advsimd(ctx, dec); // -> FABD_asimdsamefp16_only
	if(U && a && opcode==3 && HasAdvSIMD() && HasFAMINMAX()) return FAMIN_advsimd(ctx, dec); // -> FAMIN_asimdsamefp16_only
	if(U && a && opcode==4 && HasAdvSIMD() && HasFP16()) return FCMGT_advsimd_reg(ctx, dec); // -> FCMGT_asimdsamefp16_only
	if(U && a && opcode==5 && HasAdvSIMD() && HasFP16()) return FACGT_advsimd(ctx, dec); // -> FACGT_asimdsamefp16_only
	if(U && a && opcode==6 && HasAdvSIMD() && HasFP16()) return FMINP_advsimd_vec(ctx, dec); // -> FMINP_asimdsamefp16_only
	if(U && a && opcode==7 && HasFP8()) return FSCALE_advsimd(ctx, dec); // -> FSCALE_asimdsamefp16_only
	if(!U && a && (opcode&6)==4) UNALLOCATED(ENC_UNALLOCATED_1188_ASIMDSAMEFP16);
	if(U && opcode==1) UNALLOCATED(ENC_UNALLOCATED_1189_ASIMDSAMEFP16);
	UNMATCHED;
}

int decode_iclass_asimdsame2(context *ctx, Instruction *dec)
{
	uint32_t Q=(INSWORD>>30)&1, U=(INSWORD>>29)&1, size=(INSWORD>>22)&3, opcode=(INSWORD>>11)&15;
	if(!Q && !U && !size && opcode==8 && HasFP8FMA()) return FMLALLBB_advsimd_vec(ctx, dec); // -> FMLALLBB_asimdsame2_G
	if(!Q && !U && size==1 && opcode==8 && HasFP8FMA()) return FMLALLBB_advsimd_vec(ctx, dec); // -> FMLALLBT_asimdsame2_G
	if(!Q && !U && size==3 && opcode==15 && HasFP8FMA()) return FMLALB_advsimd_vec(ctx, dec); // -> FMLALB_asimdsame2_J
	if(Q && !U && !size && opcode==8 && HasFP8FMA()) return FMLALLBB_advsimd_vec(ctx, dec); // -> FMLALLTB_asimdsame2_G
	if(Q && !U && size==1 && opcode==8 && HasFP8FMA()) return FMLALLBB_advsimd_vec(ctx, dec); // -> FMLALLTT_asimdsame2_G
	if(Q && !U && size==1 && opcode==13 && HasF16F32MM()) return FMMLA_advsimd_fp16fp32(ctx, dec); // -> FMMLA_asimd_FP16FP32
	if(Q && !U && size==2 && opcode==4 && HasI8MM()) return SMMLA_advsimd_vec(ctx, dec); // -> SMMLA_asimdsame2_G
	if(Q && !U && size==2 && opcode==5 && HasI8MM()) return USMMLA_advsimd_vec(ctx, dec); // -> USMMLA_asimdsame2_G
	if(Q && !U && size==3 && opcode==13 && HasF16MM()) return FMMLA_advsimd_fp16fp16(ctx, dec); // -> FMMLA_asimd_FP16FP16
	if(Q && !U && size==3 && opcode==15 && HasFP8FMA()) return FMLALB_advsimd_vec(ctx, dec); // -> FMLALT_asimdsame2_J
	if(Q && U && !size && opcode==13 && HasF8F16MM()) return FMMLA_FP8FP16(ctx, dec); // -> FMMLA_asimd_FP8FP16
	if(Q && U && size==1 && opcode==13 && HasBF16()) return BFMMLA_advsimd(ctx, dec); // -> BFMMLA_asimdsame2_E
	if(Q && U && size==2 && opcode==4 && HasI8MM()) return UMMLA_advsimd_vec(ctx, dec); // -> UMMLA_asimdsame2_G
	if(Q && U && size==2 && opcode==5) UNALLOCATED(ENC_UNALLOCATED_1207_ASIMDSAME2);
	if(Q && U && size==2 && opcode==13 && HasF8F32MM()) return FMMLA_FP8FP32(ctx, dec); // -> FMMLA_asimd_FP8FP32
	if(Q && U && size==3 && opcode==13) UNALLOCATED(ENC_UNALLOCATED_1208_ASIMDSAME2);
	if(!U && !size && opcode==3) UNALLOCATED(ENC_UNALLOCATED_1206_ASIMDSAME2);
	if(!U && !size && opcode==14 && HasFP8()) return FCVTN_advsimd_328(ctx, dec); // -> FCVTN_asimdsame2_H
	if(!U && !size && opcode==15 && HasFP8DOT4()) return FDOT_advsimd_4wayvec(ctx, dec); // -> FDOT_asimdsame2_DD
	if(!U && size==1 && opcode==14 && HasFP8()) return FCVTN_advsimd_168(ctx, dec); // -> FCVTN_asimdsame2_D
	if(!U && size==1 && opcode==15 && HasFP8DOT2()) return FDOT_advsimd_2wayvec(ctx, dec); // -> FDOT_asimdsame2_D
	if(!U && size==2 && opcode==3 && HasI8MM()) return USDOT_advsimd_vec(ctx, dec); // -> USDOT_asimdsame2_D
	if(!U && size==2 && opcode==15 && HasF16F32DOT()) return FDOT_advsimd_fp16fp32(ctx, dec); // -> FDOT_asimdsame2_FP16FP32
	if(U && size==1 && opcode==15 && HasBF16()) return BFDOT_advsimd_vec(ctx, dec); // -> BFDOT_asimdsame2_D
	if(U && size==3 && opcode==15 && HasBF16()) return BFMLAL_advsimd_vec(ctx, dec); // -> BFMLAL_asimdsame2_F_
	if(Q && !U && !(size&1) && opcode==13) UNALLOCATED(ENC_UNALLOCATED_1205_ASIMDSAME2);
	if(!U && !(size&1) && opcode==1) UNALLOCATED(ENC_UNALLOCATED_1201_ASIMDSAME2);
	if(!U && !(size&1) && opcode==9) UNALLOCATED(ENC_UNALLOCATED_1202_ASIMDSAME2);
	if(!U && !(size&1) && opcode==11) UNALLOCATED(ENC_UNALLOCATED_1203_ASIMDSAME2);
	if(!U && !(size&2) && opcode==10) UNALLOCATED(ENC_UNALLOCATED_1199_ASIMDSAME2);
	if(!U && !(size&2) && opcode==12) UNALLOCATED(ENC_UNALLOCATED_1200_ASIMDSAME2);
	if(U && !(size&1) && opcode==15) UNALLOCATED(ENC_UNALLOCATED_1204_ASIMDSAME2);
	if(Q && size==2 && (opcode&14)==6) UNALLOCATED(ENC_UNALLOCATED_1198_ASIMDSAME2);
	if(!U && !opcode) UNALLOCATED(ENC_UNALLOCATED_1196_ASIMDSAME2);
	if(!U && opcode==2 && HasDotProd()) return SDOT_advsimd_vec(ctx, dec); // -> SDOT_asimdsame2_D
	if(U && !opcode && HasRDM()) return SQRDMLAH_advsimd_vec(ctx, dec); // -> SQRDMLAH_asimdsame2_only
	if(U && opcode==1 && HasRDM()) return SQRDMLSH_advsimd_vec(ctx, dec); // -> SQRDMLSH_asimdsame2_only
	if(U && opcode==2 && HasDotProd()) return UDOT_advsimd_vec(ctx, dec); // -> UDOT_asimdsame2_D
	if(U && opcode==3) UNALLOCATED(ENC_UNALLOCATED_1197_ASIMDSAME2);
	if(!Q && opcode==13) UNALLOCATED(ENC_UNALLOCATED_1195_ASIMDSAME2);
	if(Q && size!=2 && (opcode&12)==4) UNALLOCATED(ENC_UNALLOCATED_1192_ASIMDSAME2);
	if(!U && size&1 && (opcode&5)==1) UNALLOCATED(ENC_UNALLOCATED_1194_ASIMDSAME2);
	if(!U && (size&2)==2 && (opcode&9)==8) UNALLOCATED(ENC_UNALLOCATED_1193_ASIMDSAME2);
	if(U && (opcode&13)==12 && HasFCMA()) return FCADD_advsimd_vec(ctx, dec); // -> FCADD_asimdsame2_C
	if(U && (opcode&12)==8 && HasFCMA()) return FCMLA_advsimd_vec(ctx, dec); // -> FCMLA_asimdsame2_C
	if(!Q && (opcode&12)==4) UNALLOCATED(ENC_UNALLOCATED_1191_ASIMDSAME2);
	UNMATCHED;
}

int decode_iclass_asimdmisc(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>29)&1, size=(INSWORD>>22)&3, opcode=(INSWORD>>12)&0x1f;
	if(!U && size==2 && opcode==0x16 && HasBF16()) return BFCVTN_advsimd(ctx, dec); // -> BFCVTN_asimdmisc_4S
	if(U && !size && opcode==5 && HasAdvSIMD()) return NOT_advsimd(ctx, dec); // -> NOT_asimdmisc_R
	if(U && !size && opcode==0x17 && HasFP8()) return F12CVTL_advsimd(ctx, dec); // -> F1CVTL_asimdmisc_V
	if(U && size==1 && opcode==5 && HasAdvSIMD()) return RBIT_advsimd(ctx, dec); // -> RBIT_asimdmisc_R
	if(U && size==1 && opcode==0x16 && HasAdvSIMD()) return FCVTXN_advsimd(ctx, dec); // -> FCVTXN_asimdmisc_N
	if(U && size==1 && opcode==0x17 && HasFP8()) return F12CVTL_advsimd(ctx, dec); // -> F2CVTL_asimdmisc_V
	if(U && size==2 && opcode==0x17 && HasFP8()) return BF12CVTL_advsimd(ctx, dec); // -> BF1CVTL_asimdmisc_V
	if(U && size==3 && opcode==0x17 && HasFP8()) return BF12CVTL_advsimd(ctx, dec); // -> BF2CVTL_asimdmisc_V
	if(size==2 && opcode==0x1e) UNALLOCATED(ENC_UNALLOCATED_1221_ASIMDMISC);
	if(!U && !(size&2) && opcode==0x16 && HasAdvSIMD()) return FCVTN_advsimd(ctx, dec); // -> FCVTN_asimdmisc_N
	if(!U && !(size&2) && opcode==0x17 && HasAdvSIMD()) return FCVTL_advsimd(ctx, dec); // -> FCVTL_asimdmisc_L
	if(!U && !(size&2) && opcode==0x18 && HasAdvSIMD()) return FRINTN_advsimd(ctx, dec); // -> FRINTN_asimdmisc_R
	if(!U && !(size&2) && opcode==0x19 && HasAdvSIMD()) return FRINTM_advsimd(ctx, dec); // -> FRINTM_asimdmisc_R
	if(!U && !(size&2) && opcode==0x1a && HasAdvSIMD()) return FCVTNS_advsimd(ctx, dec); // -> FCVTNS_asimdmisc_R
	if(!U && !(size&2) && opcode==0x1b && HasAdvSIMD()) return FCVTMS_advsimd(ctx, dec); // -> FCVTMS_asimdmisc_R
	if(!U && !(size&2) && opcode==0x1c && HasAdvSIMD()) return FCVTAS_advsimd(ctx, dec); // -> FCVTAS_asimdmisc_R
	if(!U && !(size&2) && opcode==0x1d && HasAdvSIMD()) return SCVTF_advsimd_int(ctx, dec); // -> SCVTF_asimdmisc_R
	if(!U && !(size&2) && opcode==0x1e && HasFRINTTS()) return FRINT32Z_advsimd(ctx, dec); // -> FRINT32Z_asimdmisc_R
	if(!U && !(size&2) && opcode==0x1f && HasFRINTTS()) return FRINT64Z_advsimd(ctx, dec); // -> FRINT64Z_asimdmisc_R
	if(!U && (size&2)==2 && opcode==12 && HasAdvSIMD()) return FCMGT_advsimd_zero(ctx, dec); // -> FCMGT_asimdmisc_FZ
	if(!U && (size&2)==2 && opcode==13 && HasAdvSIMD()) return FCMEQ_advsimd_zero(ctx, dec); // -> FCMEQ_asimdmisc_FZ
	if(!U && (size&2)==2 && opcode==14 && HasAdvSIMD()) return FCMLT_advsimd(ctx, dec); // -> FCMLT_asimdmisc_FZ
	if(!U && (size&2)==2 && opcode==15 && HasAdvSIMD()) return FABS_advsimd(ctx, dec); // -> FABS_asimdmisc_R
	if(!U && (size&2)==2 && opcode==0x18 && HasAdvSIMD()) return FRINTP_advsimd(ctx, dec); // -> FRINTP_asimdmisc_R
	if(!U && (size&2)==2 && opcode==0x19 && HasAdvSIMD()) return FRINTZ_advsimd(ctx, dec); // -> FRINTZ_asimdmisc_R
	if(!U && (size&2)==2 && opcode==0x1a && HasAdvSIMD()) return FCVTPS_advsimd(ctx, dec); // -> FCVTPS_asimdmisc_R
	if(!U && (size&2)==2 && opcode==0x1b && HasAdvSIMD()) return FCVTZS_advsimd_int(ctx, dec); // -> FCVTZS_asimdmisc_R
	if(!U && (size&2)==2 && opcode==0x1c && HasAdvSIMD()) return URECPE_advsimd(ctx, dec); // -> URECPE_asimdmisc_R
	if(!U && (size&2)==2 && opcode==0x1d && HasAdvSIMD()) return FRECPE_advsimd(ctx, dec); // -> FRECPE_asimdmisc_R
	if(U && !(size&1) && opcode==0x16) UNALLOCATED(ENC_UNALLOCATED_1220_ASIMDMISC);
	if(U && !(size&2) && opcode==1) UNALLOCATED(ENC_UNALLOCATED_1217_ASIMDMISC);
	if(U && !(size&2) && opcode==0x18 && HasAdvSIMD()) return FRINTA_advsimd(ctx, dec); // -> FRINTA_asimdmisc_R
	if(U && !(size&2) && opcode==0x19 && HasAdvSIMD()) return FRINTX_advsimd(ctx, dec); // -> FRINTX_asimdmisc_R
	if(U && !(size&2) && opcode==0x1a && HasAdvSIMD()) return FCVTNU_advsimd(ctx, dec); // -> FCVTNU_asimdmisc_R
	if(U && !(size&2) && opcode==0x1b && HasAdvSIMD()) return FCVTMU_advsimd(ctx, dec); // -> FCVTMU_asimdmisc_R
	if(U && !(size&2) && opcode==0x1c && HasAdvSIMD()) return FCVTAU_advsimd(ctx, dec); // -> FCVTAU_asimdmisc_R
	if(U && !(size&2) && opcode==0x1d && HasAdvSIMD()) return UCVTF_advsimd_int(ctx, dec); // -> UCVTF_asimdmisc_R
	if(U && !(size&2) && opcode==0x1e && HasFRINTTS()) return FRINT32X_advsimd(ctx, dec); // -> FRINT32X_asimdmisc_R
	if(U && !(size&2) && opcode==0x1f && HasFRINTTS()) return FRINT64X_advsimd(ctx, dec); // -> FRINT64X_asimdmisc_R
	if(U && (size&2)==2 && opcode==12 && HasAdvSIMD()) return FCMGE_advsimd_zero(ctx, dec); // -> FCMGE_asimdmisc_FZ
	if(U && (size&2)==2 && opcode==13 && HasAdvSIMD()) return FCMLE_advsimd(ctx, dec); // -> FCMLE_asimdmisc_FZ
	if(U && (size&2)==2 && opcode==14) UNALLOCATED(ENC_UNALLOCATED_1218_ASIMDMISC);
	if(U && (size&2)==2 && opcode==15 && HasAdvSIMD()) return FNEG_advsimd(ctx, dec); // -> FNEG_asimdmisc_R
	if(U && (size&2)==2 && opcode==0x18) UNALLOCATED(ENC_UNALLOCATED_1219_ASIMDMISC);
	if(U && (size&2)==2 && opcode==0x19 && HasAdvSIMD()) return FRINTI_advsimd(ctx, dec); // -> FRINTI_asimdmisc_R
	if(U && (size&2)==2 && opcode==0x1a && HasAdvSIMD()) return FCVTPU_advsimd(ctx, dec); // -> FCVTPU_asimdmisc_R
	if(U && (size&2)==2 && opcode==0x1b && HasAdvSIMD()) return FCVTZU_advsimd_int(ctx, dec); // -> FCVTZU_asimdmisc_R
	if(U && (size&2)==2 && opcode==0x1c && HasAdvSIMD()) return URSQRTE_advsimd(ctx, dec); // -> URSQRTE_asimdmisc_R
	if(U && (size&2)==2 && opcode==0x1d && HasAdvSIMD()) return FRSQRTE_advsimd(ctx, dec); // -> FRSQRTE_asimdmisc_R
	if(U && (size&2)==2 && opcode==0x1f && HasAdvSIMD()) return FSQRT_advsimd(ctx, dec); // -> FSQRT_asimdmisc_R
	if(size==3 && (opcode&0x17)==0x16) UNALLOCATED(ENC_UNALLOCATED_1216_ASIMDMISC);
	if(!U && !opcode && HasAdvSIMD()) return REV64_advsimd(ctx, dec); // -> REV64_asimdmisc_R
	if(!U && opcode==1 && HasAdvSIMD()) return REV16_advsimd(ctx, dec); // -> REV16_asimdmisc_R
	if(!U && opcode==2 && HasAdvSIMD()) return SADDLP_advsimd(ctx, dec); // -> SADDLP_asimdmisc_P
	if(!U && opcode==3 && HasAdvSIMD()) return SUQADD_advsimd(ctx, dec); // -> SUQADD_asimdmisc_R
	if(!U && opcode==4 && HasAdvSIMD()) return CLS_advsimd(ctx, dec); // -> CLS_asimdmisc_R
	if(!U && opcode==5 && HasAdvSIMD()) return CNT_advsimd(ctx, dec); // -> CNT_asimdmisc_R
	if(!U && opcode==6 && HasAdvSIMD()) return SADALP_advsimd(ctx, dec); // -> SADALP_asimdmisc_P
	if(!U && opcode==7 && HasAdvSIMD()) return SQABS_advsimd(ctx, dec); // -> SQABS_asimdmisc_R
	if(!U && opcode==8 && HasAdvSIMD()) return CMGT_advsimd_zero(ctx, dec); // -> CMGT_asimdmisc_Z
	if(!U && opcode==9 && HasAdvSIMD()) return CMEQ_advsimd_zero(ctx, dec); // -> CMEQ_asimdmisc_Z
	if(!U && opcode==10 && HasAdvSIMD()) return CMLT_advsimd(ctx, dec); // -> CMLT_asimdmisc_Z
	if(!U && opcode==11 && HasAdvSIMD()) return ABS_advsimd(ctx, dec); // -> ABS_asimdmisc_R
	if(!U && opcode==0x12 && HasAdvSIMD()) return XTN_advsimd(ctx, dec); // -> XTN_asimdmisc_N
	if(!U && opcode==0x13) UNALLOCATED(ENC_UNALLOCATED_1213_ASIMDMISC);
	if(!U && opcode==0x14 && HasAdvSIMD()) return SQXTN_advsimd(ctx, dec); // -> SQXTN_asimdmisc_N
	if(!U && (size&2)==2 && (opcode&0x17)==0x17) UNALLOCATED(ENC_UNALLOCATED_1212_ASIMDMISC);
	if(U && !opcode && HasAdvSIMD()) return REV32_advsimd(ctx, dec); // -> REV32_asimdmisc_R
	if(U && opcode==2 && HasAdvSIMD()) return UADDLP_advsimd(ctx, dec); // -> UADDLP_asimdmisc_P
	if(U && opcode==3 && HasAdvSIMD()) return USQADD_advsimd(ctx, dec); // -> USQADD_asimdmisc_R
	if(U && opcode==4 && HasAdvSIMD()) return CLZ_advsimd(ctx, dec); // -> CLZ_asimdmisc_R
	if(U && opcode==6 && HasAdvSIMD()) return UADALP_advsimd(ctx, dec); // -> UADALP_asimdmisc_P
	if(U && opcode==7 && HasAdvSIMD()) return SQNEG_advsimd(ctx, dec); // -> SQNEG_asimdmisc_R
	if(U && opcode==8 && HasAdvSIMD()) return CMGE_advsimd_zero(ctx, dec); // -> CMGE_asimdmisc_Z
	if(U && opcode==9 && HasAdvSIMD()) return CMLE_advsimd(ctx, dec); // -> CMLE_asimdmisc_Z
	if(U && opcode==10) UNALLOCATED(ENC_UNALLOCATED_1215_ASIMDMISC);
	if(U && opcode==11 && HasAdvSIMD()) return NEG_advsimd(ctx, dec); // -> NEG_asimdmisc_R
	if(U && opcode==0x12 && HasAdvSIMD()) return SQXTUN_advsimd(ctx, dec); // -> SQXTUN_asimdmisc_N
	if(U && opcode==0x13 && HasAdvSIMD()) return SHLL_advsimd(ctx, dec); // -> SHLL_asimdmisc_S
	if(U && opcode==0x14 && HasAdvSIMD()) return UQXTN_advsimd(ctx, dec); // -> UQXTN_asimdmisc_N
	if(U && (size&2)==2 && (opcode&0x1b)==1) UNALLOCATED(ENC_UNALLOCATED_1214_ASIMDMISC);
	if(opcode==0x15) UNALLOCATED(ENC_UNALLOCATED_1211_ASIMDMISC);
	if((opcode&0x1e)==0x10) UNALLOCATED(ENC_UNALLOCATED_1210_ASIMDMISC);
	if(!(size&2) && (opcode&0x1c)==12) UNALLOCATED(ENC_UNALLOCATED_1209_ASIMDMISC);
	UNMATCHED;
}

int decode_iclass_asimdmiscfp16(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>29)&1, a=(INSWORD>>23)&1, opcode=(INSWORD>>12)&0x1f;
	if(!U && !a && opcode==0x18 && HasAdvSIMD() && HasFP16()) return FRINTN_advsimd(ctx, dec); // -> FRINTN_asimdmiscfp16_R
	if(!U && !a && opcode==0x19 && HasAdvSIMD() && HasFP16()) return FRINTM_advsimd(ctx, dec); // -> FRINTM_asimdmiscfp16_R
	if(!U && !a && opcode==0x1a && HasAdvSIMD() && HasFP16()) return FCVTNS_advsimd(ctx, dec); // -> FCVTNS_asimdmiscfp16_R
	if(!U && !a && opcode==0x1b && HasAdvSIMD() && HasFP16()) return FCVTMS_advsimd(ctx, dec); // -> FCVTMS_asimdmiscfp16_R
	if(!U && !a && opcode==0x1c && HasAdvSIMD() && HasFP16()) return FCVTAS_advsimd(ctx, dec); // -> FCVTAS_asimdmiscfp16_R
	if(!U && !a && opcode==0x1d && HasAdvSIMD() && HasFP16()) return SCVTF_advsimd_int(ctx, dec); // -> SCVTF_asimdmiscfp16_R
	if(!U && a && opcode==12 && HasAdvSIMD() && HasFP16()) return FCMGT_advsimd_zero(ctx, dec); // -> FCMGT_asimdmiscfp16_FZ
	if(!U && a && opcode==13 && HasAdvSIMD() && HasFP16()) return FCMEQ_advsimd_zero(ctx, dec); // -> FCMEQ_asimdmiscfp16_FZ
	if(!U && a && opcode==14 && HasAdvSIMD() && HasFP16()) return FCMLT_advsimd(ctx, dec); // -> FCMLT_asimdmiscfp16_FZ
	if(!U && a && opcode==15 && HasAdvSIMD() && HasFP16()) return FABS_advsimd(ctx, dec); // -> FABS_asimdmiscfp16_R
	if(!U && a && opcode==0x18 && HasAdvSIMD() && HasFP16()) return FRINTP_advsimd(ctx, dec); // -> FRINTP_asimdmiscfp16_R
	if(!U && a && opcode==0x19 && HasAdvSIMD() && HasFP16()) return FRINTZ_advsimd(ctx, dec); // -> FRINTZ_asimdmiscfp16_R
	if(!U && a && opcode==0x1a && HasAdvSIMD() && HasFP16()) return FCVTPS_advsimd(ctx, dec); // -> FCVTPS_asimdmiscfp16_R
	if(!U && a && opcode==0x1b && HasAdvSIMD() && HasFP16()) return FCVTZS_advsimd_int(ctx, dec); // -> FCVTZS_asimdmiscfp16_R
	if(!U && a && opcode==0x1d && HasAdvSIMD() && HasFP16()) return FRECPE_advsimd(ctx, dec); // -> FRECPE_asimdmiscfp16_R
	if(U && !a && opcode==0x18 && HasAdvSIMD() && HasFP16()) return FRINTA_advsimd(ctx, dec); // -> FRINTA_asimdmiscfp16_R
	if(U && !a && opcode==0x19 && HasAdvSIMD() && HasFP16()) return FRINTX_advsimd(ctx, dec); // -> FRINTX_asimdmiscfp16_R
	if(U && !a && opcode==0x1a && HasAdvSIMD() && HasFP16()) return FCVTNU_advsimd(ctx, dec); // -> FCVTNU_asimdmiscfp16_R
	if(U && !a && opcode==0x1b && HasAdvSIMD() && HasFP16()) return FCVTMU_advsimd(ctx, dec); // -> FCVTMU_asimdmiscfp16_R
	if(U && !a && opcode==0x1c && HasAdvSIMD() && HasFP16()) return FCVTAU_advsimd(ctx, dec); // -> FCVTAU_asimdmiscfp16_R
	if(U && !a && opcode==0x1d && HasAdvSIMD() && HasFP16()) return UCVTF_advsimd_int(ctx, dec); // -> UCVTF_asimdmiscfp16_R
	if(U && a && opcode==12 && HasAdvSIMD() && HasFP16()) return FCMGE_advsimd_zero(ctx, dec); // -> FCMGE_asimdmiscfp16_FZ
	if(U && a && opcode==13 && HasAdvSIMD() && HasFP16()) return FCMLE_advsimd(ctx, dec); // -> FCMLE_asimdmiscfp16_FZ
	if(U && a && opcode==15 && HasAdvSIMD() && HasFP16()) return FNEG_advsimd(ctx, dec); // -> FNEG_asimdmiscfp16_R
	if(U && a && opcode==0x18) UNALLOCATED(ENC_UNALLOCATED_1229_ASIMDMISCFP16);
	if(U && a && opcode==0x19 && HasAdvSIMD() && HasFP16()) return FRINTI_advsimd(ctx, dec); // -> FRINTI_asimdmiscfp16_R
	if(U && a && opcode==0x1a && HasAdvSIMD() && HasFP16()) return FCVTPU_advsimd(ctx, dec); // -> FCVTPU_asimdmiscfp16_R
	if(U && a && opcode==0x1b && HasAdvSIMD() && HasFP16()) return FCVTZU_advsimd_int(ctx, dec); // -> FCVTZU_asimdmiscfp16_R
	if(U && a && opcode==0x1d && HasAdvSIMD() && HasFP16()) return FRSQRTE_advsimd(ctx, dec); // -> FRSQRTE_asimdmiscfp16_R
	if(U && a && opcode==0x1f && HasAdvSIMD() && HasFP16()) return FSQRT_advsimd(ctx, dec); // -> FSQRT_asimdmiscfp16_R
	if(a && opcode==0x1c) UNALLOCATED(ENC_UNALLOCATED_1228_ASIMDMISCFP16);
	if(!U && a && (opcode&0x1e)==0x1e) UNALLOCATED(ENC_UNALLOCATED_1226_ASIMDMISCFP16);
	if(U && a && (opcode&15)==14) UNALLOCATED(ENC_UNALLOCATED_1227_ASIMDMISCFP16);
	if(!a && (opcode&0x1e)==0x1e) UNALLOCATED(ENC_UNALLOCATED_1225_ASIMDMISCFP16);
	if(a && (opcode&0x1c)==8) UNALLOCATED(ENC_UNALLOCATED_1224_ASIMDMISCFP16);
	if(!a && (opcode&0x18)==8) UNALLOCATED(ENC_UNALLOCATED_1223_ASIMDMISCFP16);
	if(!(opcode&8)) UNALLOCATED(ENC_UNALLOCATED_1222_ASIMDMISCFP16);
	UNMATCHED;
}

int decode_iclass_asimdelem(context *ctx, Instruction *dec)
{
	uint32_t Q=(INSWORD>>30)&1, U=(INSWORD>>29)&1, size=(INSWORD>>22)&3, opcode=(INSWORD>>12)&15;
	if(!Q && !U && size==3 && !opcode && HasFP8FMA()) return FMLALB_advsimd_elem(ctx, dec); // -> FMLALB_asimdelem_H
	if(!Q && U && !size && opcode==8 && HasFP8FMA()) return FMLALLBB_advsimd_elem(ctx, dec); // -> FMLALLBB_asimdelem_J
	if(!Q && U && size==1 && opcode==8 && HasFP8FMA()) return FMLALLBB_advsimd_elem(ctx, dec); // -> FMLALLBT_asimdelem_J
	if(Q && !U && size==3 && !opcode && HasFP8FMA()) return FMLALB_advsimd_elem(ctx, dec); // -> FMLALT_asimdelem_H
	if(Q && U && !size && opcode==8 && HasFP8FMA()) return FMLALLBB_advsimd_elem(ctx, dec); // -> FMLALLTB_asimdelem_J
	if(Q && U && size==1 && opcode==8 && HasFP8FMA()) return FMLALLBB_advsimd_elem(ctx, dec); // -> FMLALLTT_asimdelem_J
	if(!U && !size && !opcode && HasFP8DOT4()) return FDOT_advsimd_4wayelem(ctx, dec); // -> FDOT_asimdelem_D
	if(!U && !size && opcode==1 && HasAdvSIMD() && HasFP16()) return FMLA_advsimd_elt(ctx, dec); // -> FMLA_asimdelem_RH_H
	if(!U && !size && opcode==5 && HasAdvSIMD() && HasFP16()) return FMLS_advsimd_elt(ctx, dec); // -> FMLS_asimdelem_RH_H
	if(!U && !size && opcode==9 && HasAdvSIMD() && HasFP16()) return FMUL_advsimd_elt(ctx, dec); // -> FMUL_asimdelem_RH_H
	if(!U && !size && opcode==15 && HasI8MM()) return SUDOT_advsimd_elt(ctx, dec); // -> SUDOT_asimdelem_D
	if(!U && size==1 && !opcode && HasFP8DOT2()) return FDOT_advsimd_2wayelem(ctx, dec); // -> FDOT_asimdelem_G
	if(!U && size==1 && opcode==9 && HasF16F32DOT()) return FDOT_advsimd_elt_fp16fp32(ctx, dec); // -> FDOT_asimdelem_FP16FP32
	if(!U && size==1 && opcode==15 && HasBF16()) return BFDOT_advsimd_elt(ctx, dec); // -> BFDOT_asimdelem_E
	if(!U && size==2 && !opcode && HasFHM()) return FMLAL_advsimd_elt(ctx, dec); // -> FMLAL_asimdelem_LH
	if(!U && size==2 && opcode==4 && HasFHM()) return FMLSL_advsimd_elt(ctx, dec); // -> FMLSL_asimdelem_LH
	if(!U && size==2 && opcode==15 && HasI8MM()) return USDOT_advsimd_elt(ctx, dec); // -> USDOT_asimdelem_D
	if(!U && size==3 && opcode==15 && HasBF16()) return BFMLAL_advsimd_elt(ctx, dec); // -> BFMLAL_asimdelem_F
	if(!U && size!=2 && opcode==4) UNALLOCATED(ENC_UNALLOCATED_1232_ASIMDELEM);
	if(U && !size && opcode==9 && HasAdvSIMD() && HasFP16()) return FMULX_advsimd_elt(ctx, dec); // -> FMULX_asimdelem_RH_H
	if(U && size==1 && opcode==9) UNALLOCATED(ENC_UNALLOCATED_1235_ASIMDELEM);
	if(U && size==2 && opcode==8 && HasFHM()) return FMLAL_advsimd_elt(ctx, dec); // -> FMLAL2_asimdelem_LH
	if(U && size==2 && opcode==12 && HasFHM()) return FMLSL_advsimd_elt(ctx, dec); // -> FMLSL2_asimdelem_LH
	if(!U && size==1 && (opcode&11)==1) UNALLOCATED(ENC_UNALLOCATED_1231_ASIMDELEM);
	if(!U && (size&2)==2 && opcode==1 && HasAdvSIMD()) return FMLA_advsimd_elt(ctx, dec); // -> FMLA_asimdelem_R_SD
	if(!U && (size&2)==2 && opcode==5 && HasAdvSIMD()) return FMLS_advsimd_elt(ctx, dec); // -> FMLS_asimdelem_R_SD
	if(!U && (size&2)==2 && opcode==9 && HasAdvSIMD()) return FMUL_advsimd_elt(ctx, dec); // -> FMUL_asimdelem_R_SD
	if(U && !(size&2) && opcode==12) UNALLOCATED(ENC_UNALLOCATED_1233_ASIMDELEM);
	if(U && (size&2)==2 && opcode==9 && HasAdvSIMD()) return FMULX_advsimd_elt(ctx, dec); // -> FMULX_asimdelem_R_SD
	if(U && size==3 && (opcode&11)==8) UNALLOCATED(ENC_UNALLOCATED_1234_ASIMDELEM);
	if(!U && opcode==2 && HasAdvSIMD()) return SMLAL_advsimd_elt(ctx, dec); // -> SMLAL_asimdelem_L
	if(!U && opcode==3 && HasAdvSIMD()) return SQDMLAL_advsimd_elt(ctx, dec); // -> SQDMLAL_asimdelem_L
	if(!U && opcode==6 && HasAdvSIMD()) return SMLSL_advsimd_elt(ctx, dec); // -> SMLSL_asimdelem_L
	if(!U && opcode==7 && HasAdvSIMD()) return SQDMLSL_advsimd_elt(ctx, dec); // -> SQDMLSL_asimdelem_L
	if(!U && opcode==8 && HasAdvSIMD()) return MUL_advsimd_elt(ctx, dec); // -> MUL_asimdelem_R
	if(!U && opcode==10 && HasAdvSIMD()) return SMULL_advsimd_elt(ctx, dec); // -> SMULL_asimdelem_L
	if(!U && opcode==11 && HasAdvSIMD()) return SQDMULL_advsimd_elt(ctx, dec); // -> SQDMULL_asimdelem_L
	if(!U && opcode==12 && HasAdvSIMD()) return SQDMULH_advsimd_elt(ctx, dec); // -> SQDMULH_asimdelem_R
	if(!U && opcode==13 && HasAdvSIMD()) return SQRDMULH_advsimd_elt(ctx, dec); // -> SQRDMULH_asimdelem_R
	if(!U && opcode==14 && HasDotProd()) return SDOT_advsimd_elt(ctx, dec); // -> SDOT_asimdelem_D
	if(U && !opcode && HasAdvSIMD()) return MLA_advsimd_elt(ctx, dec); // -> MLA_asimdelem_R
	if(U && opcode==2 && HasAdvSIMD()) return UMLAL_advsimd_elt(ctx, dec); // -> UMLAL_asimdelem_L
	if(U && opcode==4 && HasAdvSIMD()) return MLS_advsimd_elt(ctx, dec); // -> MLS_asimdelem_R
	if(U && opcode==6 && HasAdvSIMD()) return UMLSL_advsimd_elt(ctx, dec); // -> UMLSL_asimdelem_L
	if(U && opcode==10 && HasAdvSIMD()) return UMULL_advsimd_elt(ctx, dec); // -> UMULL_asimdelem_L
	if(U && opcode==11) UNALLOCATED(ENC_UNALLOCATED_1230_ASIMDELEM);
	if(U && opcode==13 && HasRDM()) return SQRDMLAH_advsimd_elt(ctx, dec); // -> SQRDMLAH_asimdelem_R
	if(U && opcode==14 && HasDotProd()) return UDOT_advsimd_elt(ctx, dec); // -> UDOT_asimdelem_D
	if(U && opcode==15 && HasRDM()) return SQRDMLSH_advsimd_elt(ctx, dec); // -> SQRDMLSH_asimdelem_R
	if(U && (opcode&9)==1 && HasFCMA()) return FCMLA_advsimd_elt(ctx, dec); // -> FCMLA_advsimd_elt
	UNMATCHED;
}

int decode_iclass_float2fix(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, S=(INSWORD>>29)&1, ftype=(INSWORD>>22)&3, rmode=(INSWORD>>19)&3, opcode=(INSWORD>>16)&7;
	if(!sf && !S && !ftype && !rmode && opcode==2 && HasFP()) return SCVTF_float_fix(ctx, dec); // -> SCVTF_S32_float2fix
	if(!sf && !S && !ftype && !rmode && opcode==3 && HasFP()) return UCVTF_float_fix(ctx, dec); // -> UCVTF_S32_float2fix
	if(!sf && !S && !ftype && rmode==3 && !opcode && HasFP()) return FCVTZS_float_fix(ctx, dec); // -> FCVTZS_32S_float2fix
	if(!sf && !S && !ftype && rmode==3 && opcode==1 && HasFP()) return FCVTZU_float_fix(ctx, dec); // -> FCVTZU_32S_float2fix
	if(!sf && !S && ftype==1 && !rmode && opcode==2 && HasFP()) return SCVTF_float_fix(ctx, dec); // -> SCVTF_D32_float2fix
	if(!sf && !S && ftype==1 && !rmode && opcode==3 && HasFP()) return UCVTF_float_fix(ctx, dec); // -> UCVTF_D32_float2fix
	if(!sf && !S && ftype==1 && rmode==3 && !opcode && HasFP()) return FCVTZS_float_fix(ctx, dec); // -> FCVTZS_32D_float2fix
	if(!sf && !S && ftype==1 && rmode==3 && opcode==1 && HasFP()) return FCVTZU_float_fix(ctx, dec); // -> FCVTZU_32D_float2fix
	if(!sf && !S && ftype==3 && !rmode && opcode==2 && HasFP16()) return SCVTF_float_fix(ctx, dec); // -> SCVTF_H32_float2fix
	if(!sf && !S && ftype==3 && !rmode && opcode==3 && HasFP16()) return UCVTF_float_fix(ctx, dec); // -> UCVTF_H32_float2fix
	if(!sf && !S && ftype==3 && rmode==3 && !opcode && HasFP16()) return FCVTZS_float_fix(ctx, dec); // -> FCVTZS_32H_float2fix
	if(!sf && !S && ftype==3 && rmode==3 && opcode==1 && HasFP16()) return FCVTZU_float_fix(ctx, dec); // -> FCVTZU_32H_float2fix
	if(sf && !S && !ftype && !rmode && opcode==2 && HasFP()) return SCVTF_float_fix(ctx, dec); // -> SCVTF_S64_float2fix
	if(sf && !S && !ftype && !rmode && opcode==3 && HasFP()) return UCVTF_float_fix(ctx, dec); // -> UCVTF_S64_float2fix
	if(sf && !S && !ftype && rmode==3 && !opcode && HasFP()) return FCVTZS_float_fix(ctx, dec); // -> FCVTZS_64S_float2fix
	if(sf && !S && !ftype && rmode==3 && opcode==1 && HasFP()) return FCVTZU_float_fix(ctx, dec); // -> FCVTZU_64S_float2fix
	if(sf && !S && ftype==1 && !rmode && opcode==2 && HasFP()) return SCVTF_float_fix(ctx, dec); // -> SCVTF_D64_float2fix
	if(sf && !S && ftype==1 && !rmode && opcode==3 && HasFP()) return UCVTF_float_fix(ctx, dec); // -> UCVTF_D64_float2fix
	if(sf && !S && ftype==1 && rmode==3 && !opcode && HasFP()) return FCVTZS_float_fix(ctx, dec); // -> FCVTZS_64D_float2fix
	if(sf && !S && ftype==1 && rmode==3 && opcode==1 && HasFP()) return FCVTZU_float_fix(ctx, dec); // -> FCVTZU_64D_float2fix
	if(sf && !S && ftype==3 && !rmode && opcode==2 && HasFP16()) return SCVTF_float_fix(ctx, dec); // -> SCVTF_H64_float2fix
	if(sf && !S && ftype==3 && !rmode && opcode==3 && HasFP16()) return UCVTF_float_fix(ctx, dec); // -> UCVTF_H64_float2fix
	if(sf && !S && ftype==3 && rmode==3 && !opcode && HasFP16()) return FCVTZS_float_fix(ctx, dec); // -> FCVTZS_64H_float2fix
	if(sf && !S && ftype==3 && rmode==3 && opcode==1 && HasFP16()) return FCVTZU_float_fix(ctx, dec); // -> FCVTZU_64H_float2fix
	if(!S && ftype!=2 && rmode&1 && (opcode&6)==2) UNALLOCATED(ENC_UNALLOCATED_1241_FLOAT2FIX);
	if(!S && ftype!=2 && !(rmode&2) && !(opcode&6)) UNALLOCATED(ENC_UNALLOCATED_1239_FLOAT2FIX);
	if(!S && ftype!=2 && rmode==2 && !(opcode&4)) UNALLOCATED(ENC_UNALLOCATED_1240_FLOAT2FIX);
	if(!S && ftype==2 && !(opcode&4)) UNALLOCATED(ENC_UNALLOCATED_1238_FLOAT2FIX);
	if(!S && (opcode&4)==4) UNALLOCATED(ENC_UNALLOCATED_1237_FLOAT2FIX);
	if(S) UNALLOCATED(ENC_UNALLOCATED_1236_FLOAT2FIX);
	UNMATCHED;
}

int decode_iclass_float2int(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, S=(INSWORD>>29)&1, ftype=(INSWORD>>22)&3, rmode=(INSWORD>>19)&3, opcode=(INSWORD>>16)&7;
	if(!sf && !S && !ftype && !rmode && !opcode && HasFP()) return FCVTNS_float(ctx, dec); // -> FCVTNS_32S_float2int
	if(!sf && !S && !ftype && !rmode && opcode==1 && HasFP()) return FCVTNU_float(ctx, dec); // -> FCVTNU_32S_float2int
	if(!sf && !S && !ftype && !rmode && opcode==2 && HasFP()) return SCVTF_float_int(ctx, dec); // -> SCVTF_S32_float2int
	if(!sf && !S && !ftype && !rmode && opcode==3 && HasFP()) return UCVTF_float_int(ctx, dec); // -> UCVTF_S32_float2int
	if(!sf && !S && !ftype && !rmode && opcode==4 && HasFP()) return FCVTAS_float(ctx, dec); // -> FCVTAS_32S_float2int
	if(!sf && !S && !ftype && !rmode && opcode==5 && HasFP()) return FCVTAU_float(ctx, dec); // -> FCVTAU_32S_float2int
	if(!sf && !S && !ftype && !rmode && opcode==6 && HasFP()) return FMOV_float_gen(ctx, dec); // -> FMOV_32S_float2int
	if(!sf && !S && !ftype && !rmode && opcode==7 && HasFP()) return FMOV_float_gen(ctx, dec); // -> FMOV_S32_float2int
	if(!sf && !S && !ftype && rmode==1 && !opcode && HasFP()) return FCVTPS_float(ctx, dec); // -> FCVTPS_32S_float2int
	if(!sf && !S && !ftype && rmode==1 && opcode==1 && HasFP()) return FCVTPU_float(ctx, dec); // -> FCVTPU_32S_float2int
	if(!sf && !S && !ftype && rmode==2 && !opcode && HasFP()) return FCVTMS_float(ctx, dec); // -> FCVTMS_32S_float2int
	if(!sf && !S && !ftype && rmode==2 && opcode==1 && HasFP()) return FCVTMU_float(ctx, dec); // -> FCVTMU_32S_float2int
	if(!sf && !S && !ftype && rmode==3 && !opcode && HasFP()) return FCVTZS_float_int(ctx, dec); // -> FCVTZS_32S_float2int
	if(!sf && !S && !ftype && rmode==3 && opcode==1 && HasFP()) return FCVTZU_float_int(ctx, dec); // -> FCVTZU_32S_float2int
	if(!sf && !S && ftype==1 && !rmode && !opcode && HasFP()) return FCVTNS_float(ctx, dec); // -> FCVTNS_32D_float2int
	if(!sf && !S && ftype==1 && !rmode && opcode==1 && HasFP()) return FCVTNU_float(ctx, dec); // -> FCVTNU_32D_float2int
	if(!sf && !S && ftype==1 && !rmode && opcode==2 && HasFP()) return SCVTF_float_int(ctx, dec); // -> SCVTF_D32_float2int
	if(!sf && !S && ftype==1 && !rmode && opcode==3 && HasFP()) return UCVTF_float_int(ctx, dec); // -> UCVTF_D32_float2int
	if(!sf && !S && ftype==1 && !rmode && opcode==4 && HasFP()) return FCVTAS_float(ctx, dec); // -> FCVTAS_32D_float2int
	if(!sf && !S && ftype==1 && !rmode && opcode==5 && HasFP()) return FCVTAU_float(ctx, dec); // -> FCVTAU_32D_float2int
	if(!sf && !S && ftype==1 && rmode==1 && !opcode && HasFP()) return FCVTPS_float(ctx, dec); // -> FCVTPS_32D_float2int
	if(!sf && !S && ftype==1 && rmode==1 && opcode==1 && HasFP()) return FCVTPU_float(ctx, dec); // -> FCVTPU_32D_float2int
	if(!sf && !S && ftype==1 && rmode==1 && opcode==2 && HasFPRCVT()) return FCVTNS_sisd(ctx, dec); // -> FCVTNS_sisd_32D
	if(!sf && !S && ftype==1 && rmode==1 && opcode==3 && HasFPRCVT()) return FCVTNU_sisd(ctx, dec); // -> FCVTNU_sisd_32D
	if(!sf && !S && ftype==1 && rmode==2 && !opcode && HasFP()) return FCVTMS_float(ctx, dec); // -> FCVTMS_32D_float2int
	if(!sf && !S && ftype==1 && rmode==2 && opcode==1 && HasFP()) return FCVTMU_float(ctx, dec); // -> FCVTMU_32D_float2int
	if(!sf && !S && ftype==1 && rmode==2 && opcode==2 && HasFPRCVT()) return FCVTPS_sisd(ctx, dec); // -> FCVTPS_sisd_32D
	if(!sf && !S && ftype==1 && rmode==2 && opcode==3 && HasFPRCVT()) return FCVTPU_sisd(ctx, dec); // -> FCVTPU_sisd_32D
	if(!sf && !S && ftype==1 && rmode==2 && opcode==4 && HasFPRCVT()) return FCVTMS_sisd(ctx, dec); // -> FCVTMS_sisd_32D
	if(!sf && !S && ftype==1 && rmode==2 && opcode==5 && HasFPRCVT()) return FCVTMU_sisd(ctx, dec); // -> FCVTMU_sisd_32D
	if(!sf && !S && ftype==1 && rmode==2 && opcode==6 && HasFPRCVT()) return FCVTZS_sisd(ctx, dec); // -> FCVTZS_sisd_32D
	if(!sf && !S && ftype==1 && rmode==2 && opcode==7 && HasFPRCVT()) return FCVTZU_sisd(ctx, dec); // -> FCVTZU_sisd_32D
	if(!sf && !S && ftype==1 && rmode==3 && !opcode && HasFP()) return FCVTZS_float_int(ctx, dec); // -> FCVTZS_32D_float2int
	if(!sf && !S && ftype==1 && rmode==3 && opcode==1 && HasFP()) return FCVTZU_float_int(ctx, dec); // -> FCVTZU_32D_float2int
	if(!sf && !S && ftype==1 && rmode==3 && opcode==2 && HasFPRCVT()) return FCVTAS_sisd(ctx, dec); // -> FCVTAS_sisd_32D
	if(!sf && !S && ftype==1 && rmode==3 && opcode==3 && HasFPRCVT()) return FCVTAU_sisd(ctx, dec); // -> FCVTAU_sisd_32D
	if(!sf && !S && ftype==1 && rmode==3 && opcode==4 && HasFPRCVT()) return SCVTF_sisd(ctx, dec); // -> SCVTF_sisd_32D
	if(!sf && !S && ftype==1 && rmode==3 && opcode==5 && HasFPRCVT()) return UCVTF_sisd(ctx, dec); // -> UCVTF_sisd_32D
	if(!sf && !S && ftype==1 && rmode==3 && opcode==6 && HasJSCVT()) return FJCVTZS(ctx, dec); // -> FJCVTZS_32D_float2int
	if(!sf && !S && ftype==1 && rmode==3 && opcode==7) UNALLOCATED(ENC_UNALLOCATED_1258_FLOAT2INT);
	if(!sf && !S && ftype==3 && !rmode && !opcode && HasFP16()) return FCVTNS_float(ctx, dec); // -> FCVTNS_32H_float2int
	if(!sf && !S && ftype==3 && !rmode && opcode==1 && HasFP16()) return FCVTNU_float(ctx, dec); // -> FCVTNU_32H_float2int
	if(!sf && !S && ftype==3 && !rmode && opcode==2 && HasFP16()) return SCVTF_float_int(ctx, dec); // -> SCVTF_H32_float2int
	if(!sf && !S && ftype==3 && !rmode && opcode==3 && HasFP16()) return UCVTF_float_int(ctx, dec); // -> UCVTF_H32_float2int
	if(!sf && !S && ftype==3 && !rmode && opcode==4 && HasFP16()) return FCVTAS_float(ctx, dec); // -> FCVTAS_32H_float2int
	if(!sf && !S && ftype==3 && !rmode && opcode==5 && HasFP16()) return FCVTAU_float(ctx, dec); // -> FCVTAU_32H_float2int
	if(!sf && !S && ftype==3 && !rmode && opcode==6 && HasFP16()) return FMOV_float_gen(ctx, dec); // -> FMOV_32H_float2int
	if(!sf && !S && ftype==3 && !rmode && opcode==7 && HasFP16()) return FMOV_float_gen(ctx, dec); // -> FMOV_H32_float2int
	if(!sf && !S && ftype==3 && rmode==1 && !opcode && HasFP16()) return FCVTPS_float(ctx, dec); // -> FCVTPS_32H_float2int
	if(!sf && !S && ftype==3 && rmode==1 && opcode==1 && HasFP16()) return FCVTPU_float(ctx, dec); // -> FCVTPU_32H_float2int
	if(!sf && !S && ftype==3 && rmode==1 && opcode==2 && HasFPRCVT()) return FCVTNS_sisd(ctx, dec); // -> FCVTNS_sisd_32H
	if(!sf && !S && ftype==3 && rmode==1 && opcode==3 && HasFPRCVT()) return FCVTNU_sisd(ctx, dec); // -> FCVTNU_sisd_32H
	if(!sf && !S && ftype==3 && rmode==2 && !opcode && HasFP16()) return FCVTMS_float(ctx, dec); // -> FCVTMS_32H_float2int
	if(!sf && !S && ftype==3 && rmode==2 && opcode==1 && HasFP16()) return FCVTMU_float(ctx, dec); // -> FCVTMU_32H_float2int
	if(!sf && !S && ftype==3 && rmode==2 && opcode==2 && HasFPRCVT()) return FCVTPS_sisd(ctx, dec); // -> FCVTPS_sisd_32H
	if(!sf && !S && ftype==3 && rmode==2 && opcode==3 && HasFPRCVT()) return FCVTPU_sisd(ctx, dec); // -> FCVTPU_sisd_32H
	if(!sf && !S && ftype==3 && rmode==2 && opcode==4 && HasFPRCVT()) return FCVTMS_sisd(ctx, dec); // -> FCVTMS_sisd_32H
	if(!sf && !S && ftype==3 && rmode==2 && opcode==5 && HasFPRCVT()) return FCVTMU_sisd(ctx, dec); // -> FCVTMU_sisd_32H
	if(!sf && !S && ftype==3 && rmode==2 && opcode==6 && HasFPRCVT()) return FCVTZS_sisd(ctx, dec); // -> FCVTZS_sisd_32H
	if(!sf && !S && ftype==3 && rmode==2 && opcode==7 && HasFPRCVT()) return FCVTZU_sisd(ctx, dec); // -> FCVTZU_sisd_32H
	if(!sf && !S && ftype==3 && rmode==3 && !opcode && HasFP16()) return FCVTZS_float_int(ctx, dec); // -> FCVTZS_32H_float2int
	if(!sf && !S && ftype==3 && rmode==3 && opcode==1 && HasFP16()) return FCVTZU_float_int(ctx, dec); // -> FCVTZU_32H_float2int
	if(!sf && !S && ftype==3 && rmode==3 && opcode==2 && HasFPRCVT()) return FCVTAS_sisd(ctx, dec); // -> FCVTAS_sisd_32H
	if(!sf && !S && ftype==3 && rmode==3 && opcode==3 && HasFPRCVT()) return FCVTAU_sisd(ctx, dec); // -> FCVTAU_sisd_32H
	if(!sf && !S && ftype==3 && rmode==3 && opcode==4 && HasFPRCVT()) return SCVTF_sisd(ctx, dec); // -> SCVTF_sisd_32H
	if(!sf && !S && ftype==3 && rmode==3 && opcode==5 && HasFPRCVT()) return UCVTF_sisd(ctx, dec); // -> UCVTF_sisd_32H
	if(sf && !S && !ftype && !rmode && !opcode && HasFP()) return FCVTNS_float(ctx, dec); // -> FCVTNS_64S_float2int
	if(sf && !S && !ftype && !rmode && opcode==1 && HasFP()) return FCVTNU_float(ctx, dec); // -> FCVTNU_64S_float2int
	if(sf && !S && !ftype && !rmode && opcode==2 && HasFP()) return SCVTF_float_int(ctx, dec); // -> SCVTF_S64_float2int
	if(sf && !S && !ftype && !rmode && opcode==3 && HasFP()) return UCVTF_float_int(ctx, dec); // -> UCVTF_S64_float2int
	if(sf && !S && !ftype && !rmode && opcode==4 && HasFP()) return FCVTAS_float(ctx, dec); // -> FCVTAS_64S_float2int
	if(sf && !S && !ftype && !rmode && opcode==5 && HasFP()) return FCVTAU_float(ctx, dec); // -> FCVTAU_64S_float2int
	if(sf && !S && !ftype && rmode==1 && !opcode && HasFP()) return FCVTPS_float(ctx, dec); // -> FCVTPS_64S_float2int
	if(sf && !S && !ftype && rmode==1 && opcode==1 && HasFP()) return FCVTPU_float(ctx, dec); // -> FCVTPU_64S_float2int
	if(sf && !S && !ftype && rmode==1 && opcode==2 && HasFPRCVT()) return FCVTNS_sisd(ctx, dec); // -> FCVTNS_sisd_64S
	if(sf && !S && !ftype && rmode==1 && opcode==3 && HasFPRCVT()) return FCVTNU_sisd(ctx, dec); // -> FCVTNU_sisd_64S
	if(sf && !S && !ftype && rmode==2 && !opcode && HasFP()) return FCVTMS_float(ctx, dec); // -> FCVTMS_64S_float2int
	if(sf && !S && !ftype && rmode==2 && opcode==1 && HasFP()) return FCVTMU_float(ctx, dec); // -> FCVTMU_64S_float2int
	if(sf && !S && !ftype && rmode==2 && opcode==2 && HasFPRCVT()) return FCVTPS_sisd(ctx, dec); // -> FCVTPS_sisd_64S
	if(sf && !S && !ftype && rmode==2 && opcode==3 && HasFPRCVT()) return FCVTPU_sisd(ctx, dec); // -> FCVTPU_sisd_64S
	if(sf && !S && !ftype && rmode==2 && opcode==4 && HasFPRCVT()) return FCVTMS_sisd(ctx, dec); // -> FCVTMS_sisd_64S
	if(sf && !S && !ftype && rmode==2 && opcode==5 && HasFPRCVT()) return FCVTMU_sisd(ctx, dec); // -> FCVTMU_sisd_64S
	if(sf && !S && !ftype && rmode==2 && opcode==6 && HasFPRCVT()) return FCVTZS_sisd(ctx, dec); // -> FCVTZS_sisd_64S
	if(sf && !S && !ftype && rmode==2 && opcode==7 && HasFPRCVT()) return FCVTZU_sisd(ctx, dec); // -> FCVTZU_sisd_64S
	if(sf && !S && !ftype && rmode==3 && !opcode && HasFP()) return FCVTZS_float_int(ctx, dec); // -> FCVTZS_64S_float2int
	if(sf && !S && !ftype && rmode==3 && opcode==1 && HasFP()) return FCVTZU_float_int(ctx, dec); // -> FCVTZU_64S_float2int
	if(sf && !S && !ftype && rmode==3 && opcode==2 && HasFPRCVT()) return FCVTAS_sisd(ctx, dec); // -> FCVTAS_sisd_64S
	if(sf && !S && !ftype && rmode==3 && opcode==3 && HasFPRCVT()) return FCVTAU_sisd(ctx, dec); // -> FCVTAU_sisd_64S
	if(sf && !S && !ftype && rmode==3 && opcode==4 && HasFPRCVT()) return SCVTF_sisd(ctx, dec); // -> SCVTF_sisd_64S
	if(sf && !S && !ftype && rmode==3 && opcode==5 && HasFPRCVT()) return UCVTF_sisd(ctx, dec); // -> UCVTF_sisd_64S
	if(sf && !S && ftype==1 && !rmode && !opcode && HasFP()) return FCVTNS_float(ctx, dec); // -> FCVTNS_64D_float2int
	if(sf && !S && ftype==1 && !rmode && opcode==1 && HasFP()) return FCVTNU_float(ctx, dec); // -> FCVTNU_64D_float2int
	if(sf && !S && ftype==1 && !rmode && opcode==2 && HasFP()) return SCVTF_float_int(ctx, dec); // -> SCVTF_D64_float2int
	if(sf && !S && ftype==1 && !rmode && opcode==3 && HasFP()) return UCVTF_float_int(ctx, dec); // -> UCVTF_D64_float2int
	if(sf && !S && ftype==1 && !rmode && opcode==4 && HasFP()) return FCVTAS_float(ctx, dec); // -> FCVTAS_64D_float2int
	if(sf && !S && ftype==1 && !rmode && opcode==5 && HasFP()) return FCVTAU_float(ctx, dec); // -> FCVTAU_64D_float2int
	if(sf && !S && ftype==1 && !rmode && opcode==6 && HasFP()) return FMOV_float_gen(ctx, dec); // -> FMOV_64D_float2int
	if(sf && !S && ftype==1 && !rmode && opcode==7 && HasFP()) return FMOV_float_gen(ctx, dec); // -> FMOV_D64_float2int
	if(sf && !S && ftype==1 && rmode==1 && !opcode && HasFP()) return FCVTPS_float(ctx, dec); // -> FCVTPS_64D_float2int
	if(sf && !S && ftype==1 && rmode==1 && opcode==1 && HasFP()) return FCVTPU_float(ctx, dec); // -> FCVTPU_64D_float2int
	if(sf && !S && ftype==1 && rmode==2 && !opcode && HasFP()) return FCVTMS_float(ctx, dec); // -> FCVTMS_64D_float2int
	if(sf && !S && ftype==1 && rmode==2 && opcode==1 && HasFP()) return FCVTMU_float(ctx, dec); // -> FCVTMU_64D_float2int
	if(sf && !S && ftype==1 && rmode==3 && !opcode && HasFP()) return FCVTZS_float_int(ctx, dec); // -> FCVTZS_64D_float2int
	if(sf && !S && ftype==1 && rmode==3 && opcode==1 && HasFP()) return FCVTZU_float_int(ctx, dec); // -> FCVTZU_64D_float2int
	if(sf && !S && ftype==2 && rmode==1 && opcode==6 && HasFP()) return FMOV_float_gen(ctx, dec); // -> FMOV_64VX_float2int
	if(sf && !S && ftype==2 && rmode==1 && opcode==7 && HasFP()) return FMOV_float_gen(ctx, dec); // -> FMOV_V64I_float2int
	if(sf && !S && ftype==3 && !rmode && !opcode && HasFP16()) return FCVTNS_float(ctx, dec); // -> FCVTNS_64H_float2int
	if(sf && !S && ftype==3 && !rmode && opcode==1 && HasFP16()) return FCVTNU_float(ctx, dec); // -> FCVTNU_64H_float2int
	if(sf && !S && ftype==3 && !rmode && opcode==2 && HasFP16()) return SCVTF_float_int(ctx, dec); // -> SCVTF_H64_float2int
	if(sf && !S && ftype==3 && !rmode && opcode==3 && HasFP16()) return UCVTF_float_int(ctx, dec); // -> UCVTF_H64_float2int
	if(sf && !S && ftype==3 && !rmode && opcode==4 && HasFP16()) return FCVTAS_float(ctx, dec); // -> FCVTAS_64H_float2int
	if(sf && !S && ftype==3 && !rmode && opcode==5 && HasFP16()) return FCVTAU_float(ctx, dec); // -> FCVTAU_64H_float2int
	if(sf && !S && ftype==3 && !rmode && opcode==6 && HasFP16()) return FMOV_float_gen(ctx, dec); // -> FMOV_64H_float2int
	if(sf && !S && ftype==3 && !rmode && opcode==7 && HasFP16()) return FMOV_float_gen(ctx, dec); // -> FMOV_H64_float2int
	if(sf && !S && ftype==3 && rmode==1 && !opcode && HasFP16()) return FCVTPS_float(ctx, dec); // -> FCVTPS_64H_float2int
	if(sf && !S && ftype==3 && rmode==1 && opcode==1 && HasFP16()) return FCVTPU_float(ctx, dec); // -> FCVTPU_64H_float2int
	if(sf && !S && ftype==3 && rmode==1 && opcode==2 && HasFPRCVT()) return FCVTNS_sisd(ctx, dec); // -> FCVTNS_sisd_64H
	if(sf && !S && ftype==3 && rmode==1 && opcode==3 && HasFPRCVT()) return FCVTNU_sisd(ctx, dec); // -> FCVTNU_sisd_64H
	if(sf && !S && ftype==3 && rmode==2 && !opcode && HasFP16()) return FCVTMS_float(ctx, dec); // -> FCVTMS_64H_float2int
	if(sf && !S && ftype==3 && rmode==2 && opcode==1 && HasFP16()) return FCVTMU_float(ctx, dec); // -> FCVTMU_64H_float2int
	if(sf && !S && ftype==3 && rmode==2 && opcode==2 && HasFPRCVT()) return FCVTPS_sisd(ctx, dec); // -> FCVTPS_sisd_64H
	if(sf && !S && ftype==3 && rmode==2 && opcode==3 && HasFPRCVT()) return FCVTPU_sisd(ctx, dec); // -> FCVTPU_sisd_64H
	if(sf && !S && ftype==3 && rmode==2 && opcode==4 && HasFPRCVT()) return FCVTMS_sisd(ctx, dec); // -> FCVTMS_sisd_64H
	if(sf && !S && ftype==3 && rmode==2 && opcode==5 && HasFPRCVT()) return FCVTMU_sisd(ctx, dec); // -> FCVTMU_sisd_64H
	if(sf && !S && ftype==3 && rmode==2 && opcode==6 && HasFPRCVT()) return FCVTZS_sisd(ctx, dec); // -> FCVTZS_sisd_64H
	if(sf && !S && ftype==3 && rmode==2 && opcode==7 && HasFPRCVT()) return FCVTZU_sisd(ctx, dec); // -> FCVTZU_sisd_64H
	if(sf && !S && ftype==3 && rmode==3 && !opcode && HasFP16()) return FCVTZS_float_int(ctx, dec); // -> FCVTZS_64H_float2int
	if(sf && !S && ftype==3 && rmode==3 && opcode==1 && HasFP16()) return FCVTZU_float_int(ctx, dec); // -> FCVTZU_64H_float2int
	if(sf && !S && ftype==3 && rmode==3 && opcode==2 && HasFPRCVT()) return FCVTAS_sisd(ctx, dec); // -> FCVTAS_sisd_64H
	if(sf && !S && ftype==3 && rmode==3 && opcode==3 && HasFPRCVT()) return FCVTAU_sisd(ctx, dec); // -> FCVTAU_sisd_64H
	if(sf && !S && ftype==3 && rmode==3 && opcode==4 && HasFPRCVT()) return SCVTF_sisd(ctx, dec); // -> SCVTF_sisd_64H
	if(sf && !S && ftype==3 && rmode==3 && opcode==5 && HasFPRCVT()) return UCVTF_sisd(ctx, dec); // -> UCVTF_sisd_64H
	if(!sf && !S && !ftype && rmode && (opcode&6)==2) UNALLOCATED(ENC_UNALLOCATED_1250_FLOAT2INT);
	if(!sf && !S && ftype==2 && rmode==3 && (opcode&6)==6) UNALLOCATED(ENC_UNALLOCATED_1257_FLOAT2INT);
	if(!S && ftype!=2 && rmode==1 && (opcode&6)==4) UNALLOCATED(ENC_UNALLOCATED_1249_FLOAT2INT);
	if(!sf && !S && !(ftype&1) && rmode==1 && (opcode&6)==6) UNALLOCATED(ENC_UNALLOCATED_1252_FLOAT2INT);
	if(!sf && !S && ftype==1 && !(rmode&2) && (opcode&6)==6) UNALLOCATED(ENC_UNALLOCATED_1251_FLOAT2INT);
	if(sf && !S && !(ftype&1) && rmode==3 && (opcode&6)==6) UNALLOCATED(ENC_UNALLOCATED_1256_FLOAT2INT);
	if(sf && !S && !ftype && !(rmode&2) && (opcode&6)==6) UNALLOCATED(ENC_UNALLOCATED_1253_FLOAT2INT);
	if(sf && !S && ftype==1 && rmode==1 && (opcode&2)==2) UNALLOCATED(ENC_UNALLOCATED_1254_FLOAT2INT);
	if(sf && !S && ftype==1 && (rmode&2)==2 && (opcode&6)==2) UNALLOCATED(ENC_UNALLOCATED_1255_FLOAT2INT);
	if(!S && ftype==2 && rmode&1 && (opcode&6)==4) UNALLOCATED(ENC_UNALLOCATED_1247_FLOAT2INT);
	if(!S && ftype==3 && rmode&1 && (opcode&6)==6) UNALLOCATED(ENC_UNALLOCATED_1248_FLOAT2INT);
	if(!sf && !S && !ftype && (rmode&2)==2 && (opcode&4)==4) UNALLOCATED(ENC_UNALLOCATED_1245_FLOAT2INT);
	if(sf && !S && ftype==1 && (rmode&2)==2 && (opcode&4)==4) UNALLOCATED(ENC_UNALLOCATED_1246_FLOAT2INT);
	if(!S && ftype==2 && rmode&1 && !(opcode&4)) UNALLOCATED(ENC_UNALLOCATED_1244_FLOAT2INT);
	if(!S && ftype==2 && !(rmode&1)) UNALLOCATED(ENC_UNALLOCATED_1243_FLOAT2INT);
	if(S) UNALLOCATED(ENC_UNALLOCATED_1242_FLOAT2INT);
	UNMATCHED;
}

int decode_iclass_cryptoaes(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, opcode=(INSWORD>>12)&0x1f;
	if(!size && opcode==4 && HasAES()) return AESE_advsimd(ctx, dec); // -> AESE_B_cryptoaes
	if(!size && opcode==5 && HasAES()) return AESD_advsimd(ctx, dec); // -> AESD_B_cryptoaes
	if(!size && opcode==6 && HasAES()) return AESMC_advsimd(ctx, dec); // -> AESMC_B_cryptoaes
	if(!size && opcode==7 && HasAES()) return AESIMC_advsimd(ctx, dec); // -> AESIMC_B_cryptoaes
	if(!size && !(opcode&0x1c)) UNALLOCATED(ENC_UNALLOCATED_1262_CRYPTOAES);
	if(!size && (opcode&0x18)==8) UNALLOCATED(ENC_UNALLOCATED_1261_CRYPTOAES);
	if(!size && (opcode&0x10)==0x10) UNALLOCATED(ENC_UNALLOCATED_1260_CRYPTOAES);
	if(size) UNALLOCATED(ENC_UNALLOCATED_1259_CRYPTOAES);
	UNMATCHED;
}

int decode_iclass_crypto4(context *ctx, Instruction *dec)
{
	uint32_t Op0=(INSWORD>>21)&3;
	if(!Op0 && HasSHA3()) return EOR3_advsimd(ctx, dec); // -> EOR3_VVV16_crypto4
	if(Op0==1 && HasSHA3()) return BCAX_advsimd(ctx, dec); // -> BCAX_VVV16_crypto4
	if(Op0==2 && HasSM3()) return SM3SS1_advsimd(ctx, dec); // -> SM3SS1_VVV4_crypto4
	if(Op0==3) UNALLOCATED(ENC_UNALLOCATED_1263_CRYPTO4);
	UNMATCHED;
}

int decode_iclass_cryptosha3(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, opcode=(INSWORD>>12)&7;
	if(!size && !opcode && HasSHA1()) return SHA1C_advsimd(ctx, dec); // -> SHA1C_QSV_cryptosha3
	if(!size && opcode==1 && HasSHA1()) return SHA1P_advsimd(ctx, dec); // -> SHA1P_QSV_cryptosha3
	if(!size && opcode==2 && HasSHA1()) return SHA1M_advsimd(ctx, dec); // -> SHA1M_QSV_cryptosha3
	if(!size && opcode==3 && HasSHA1()) return SHA1SU0_advsimd(ctx, dec); // -> SHA1SU0_VVV_cryptosha3
	if(!size && opcode==4 && HasSHA256()) return SHA256H_advsimd(ctx, dec); // -> SHA256H_QQV_cryptosha3
	if(!size && opcode==5 && HasSHA256()) return SHA256H2_advsimd(ctx, dec); // -> SHA256H2_QQV_cryptosha3
	if(!size && opcode==6 && HasSHA256()) return SHA256SU1_advsimd(ctx, dec); // -> SHA256SU1_VVV_cryptosha3
	if(!size && opcode==7) UNALLOCATED(ENC_UNALLOCATED_1265_CRYPTOSHA3);
	if(size) UNALLOCATED(ENC_UNALLOCATED_1264_CRYPTOSHA3);
	UNMATCHED;
}

int decode_iclass_cryptosha512_3(context *ctx, Instruction *dec)
{
	uint32_t O=(INSWORD>>14)&1, opcode=(INSWORD>>10)&3;
	if(!O && !opcode && HasSHA512()) return SHA512H_advsimd(ctx, dec); // -> SHA512H_QQV_cryptosha512_3
	if(!O && opcode==1 && HasSHA512()) return SHA512H2_advsimd(ctx, dec); // -> SHA512H2_QQV_cryptosha512_3
	if(!O && opcode==2 && HasSHA512()) return SHA512SU1_advsimd(ctx, dec); // -> SHA512SU1_VVV2_cryptosha512_3
	if(!O && opcode==3 && HasSHA3()) return RAX1_advsimd(ctx, dec); // -> RAX1_VVV2_cryptosha512_3
	if(O && !opcode && HasSM3()) return SM3PARTW1_advsimd(ctx, dec); // -> SM3PARTW1_VVV4_cryptosha512_3
	if(O && opcode==1 && HasSM3()) return SM3PARTW2_advsimd(ctx, dec); // -> SM3PARTW2_VVV4_cryptosha512_3
	if(O && opcode==2 && HasSM4()) return SM4EKEY_advsimd(ctx, dec); // -> SM4EKEY_VVV4_cryptosha512_3
	if(O && opcode==3) UNALLOCATED(ENC_UNALLOCATED_1266_CRYPTOSHA512_3);
	UNMATCHED;
}

int decode_iclass_crypto3_imm2(context *ctx, Instruction *dec)
{
	uint32_t opcode=(INSWORD>>10)&3;
	if(!opcode && HasSM3()) return SM3TT1A_advsimd(ctx, dec); // -> SM3TT1A_VVV4_crypto3_imm2
	if(opcode==1 && HasSM3()) return SM3TT1B_advsimd(ctx, dec); // -> SM3TT1B_VVV4_crypto3_imm2
	if(opcode==2 && HasSM3()) return SM3TT2A_advsimd(ctx, dec); // -> SM3TT2A_VVV4_crypto3_imm2
	if(opcode==3 && HasSM3()) return SM3TT2B_advsimd(ctx, dec); // -> SM3TT2B_VVV_crypto3_imm2
	UNMATCHED;
}

int decode_iclass_crypto3_imm6(context *ctx, Instruction *dec)
{
	return XAR_advsimd(ctx, dec);
}

int decode_iclass_cryptosha2(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, opcode=(INSWORD>>12)&0x1f;
	if(!size && !opcode && HasSHA1()) return SHA1H_advsimd(ctx, dec); // -> SHA1H_SS_cryptosha2
	if(!size && opcode==1 && HasSHA1()) return SHA1SU1_advsimd(ctx, dec); // -> SHA1SU1_VV_cryptosha2
	if(!size && opcode==2 && HasSHA256()) return SHA256SU0_advsimd(ctx, dec); // -> SHA256SU0_VV_cryptosha2
	if(!size && opcode==3) UNALLOCATED(ENC_UNALLOCATED_1271_CRYPTOSHA2);
	if(!size && (opcode&0x1c)==4) UNALLOCATED(ENC_UNALLOCATED_1270_CRYPTOSHA2);
	if(!size && (opcode&0x18)==8) UNALLOCATED(ENC_UNALLOCATED_1269_CRYPTOSHA2);
	if(!size && (opcode&0x10)==0x10) UNALLOCATED(ENC_UNALLOCATED_1268_CRYPTOSHA2);
	if(size) UNALLOCATED(ENC_UNALLOCATED_1267_CRYPTOSHA2);
	UNMATCHED;
}

int decode_iclass_cryptosha512_2(context *ctx, Instruction *dec)
{
	uint32_t opcode=(INSWORD>>10)&3;
	if(!opcode && HasSHA512()) return SHA512SU0_advsimd(ctx, dec); // -> SHA512SU0_VV2_cryptosha512_2
	if(opcode==1 && HasSM4()) return SM4E_advsimd(ctx, dec); // -> SM4E_VV4_cryptosha512_2
	if((opcode&2)==2) UNALLOCATED(ENC_UNALLOCATED_1272_CRYPTOSHA512_2);
	UNMATCHED;
}

int decode_iclass_floatcmp(context *ctx, Instruction *dec)
{
	uint32_t M=INSWORD>>31, S=(INSWORD>>29)&1, ftype=(INSWORD>>22)&3, op=(INSWORD>>14)&3, opcode2=INSWORD&0x1f;
	if(!M && !S && !ftype && !op && !opcode2 && HasFP()) return FCMP_float(ctx, dec); // -> FCMP_S_floatcmp
	if(!M && !S && !ftype && !op && opcode2==8 && HasFP()) return FCMP_float(ctx, dec); // -> FCMP_SZ_floatcmp
	if(!M && !S && !ftype && !op && opcode2==0x10 && HasFP()) return FCMPE_float(ctx, dec); // -> FCMPE_S_floatcmp
	if(!M && !S && !ftype && !op && opcode2==0x18 && HasFP()) return FCMPE_float(ctx, dec); // -> FCMPE_SZ_floatcmp
	if(!M && !S && ftype==1 && !op && !opcode2 && HasFP()) return FCMP_float(ctx, dec); // -> FCMP_D_floatcmp
	if(!M && !S && ftype==1 && !op && opcode2==8 && HasFP()) return FCMP_float(ctx, dec); // -> FCMP_DZ_floatcmp
	if(!M && !S && ftype==1 && !op && opcode2==0x10 && HasFP()) return FCMPE_float(ctx, dec); // -> FCMPE_D_floatcmp
	if(!M && !S && ftype==1 && !op && opcode2==0x18 && HasFP()) return FCMPE_float(ctx, dec); // -> FCMPE_DZ_floatcmp
	if(!M && !S && ftype==3 && !op && !opcode2 && HasFP16()) return FCMP_float(ctx, dec); // -> FCMP_H_floatcmp
	if(!M && !S && ftype==3 && !op && opcode2==8 && HasFP16()) return FCMP_float(ctx, dec); // -> FCMP_HZ_floatcmp
	if(!M && !S && ftype==3 && !op && opcode2==0x10 && HasFP16()) return FCMPE_float(ctx, dec); // -> FCMPE_H_floatcmp
	if(!M && !S && ftype==3 && !op && opcode2==0x18 && HasFP16()) return FCMPE_float(ctx, dec); // -> FCMPE_HZ_floatcmp
	if(!M && !S && ftype==2 && !op && !(opcode2&7)) UNALLOCATED(ENC_UNALLOCATED_1279_FLOATCMP);
	if(!M && !S && !op && (opcode2&7)==1) UNALLOCATED(ENC_UNALLOCATED_1278_FLOATCMP);
	if(!M && !S && !op && (opcode2&6)==2) UNALLOCATED(ENC_UNALLOCATED_1277_FLOATCMP);
	if(!M && !S && !op && (opcode2&4)==4) UNALLOCATED(ENC_UNALLOCATED_1276_FLOATCMP);
	if(!M && !S && op) UNALLOCATED(ENC_UNALLOCATED_1275_FLOATCMP);
	if(!M && S) UNALLOCATED(ENC_UNALLOCATED_1274_FLOATCMP);
	if(M) UNALLOCATED(ENC_UNALLOCATED_1273_FLOATCMP);
	UNMATCHED;
}

int decode_iclass_floatccmp(context *ctx, Instruction *dec)
{
	uint32_t M=INSWORD>>31, S=(INSWORD>>29)&1, ftype=(INSWORD>>22)&3, op=(INSWORD>>4)&1;
	if(!M && !S && !ftype && !op && HasFP()) return FCCMP_float(ctx, dec); // -> FCCMP_S_floatccmp
	if(!M && !S && !ftype && op && HasFP()) return FCCMPE_float(ctx, dec); // -> FCCMPE_S_floatccmp
	if(!M && !S && ftype==1 && !op && HasFP()) return FCCMP_float(ctx, dec); // -> FCCMP_D_floatccmp
	if(!M && !S && ftype==1 && op && HasFP()) return FCCMPE_float(ctx, dec); // -> FCCMPE_D_floatccmp
	if(!M && !S && ftype==3 && !op && HasFP16()) return FCCMP_float(ctx, dec); // -> FCCMP_H_floatccmp
	if(!M && !S && ftype==3 && op && HasFP16()) return FCCMPE_float(ctx, dec); // -> FCCMPE_H_floatccmp
	if(!M && !S && ftype==2) UNALLOCATED(ENC_UNALLOCATED_1282_FLOATCCMP);
	if(!M && S) UNALLOCATED(ENC_UNALLOCATED_1281_FLOATCCMP);
	if(M) UNALLOCATED(ENC_UNALLOCATED_1280_FLOATCCMP);
	UNMATCHED;
}

int decode_iclass_floatsel(context *ctx, Instruction *dec)
{
	uint32_t M=INSWORD>>31, S=(INSWORD>>29)&1, ftype=(INSWORD>>22)&3;
	if(!M && !S && !ftype && HasFP()) return FCSEL_float(ctx, dec); // -> FCSEL_S_floatsel
	if(!M && !S && ftype==1 && HasFP()) return FCSEL_float(ctx, dec); // -> FCSEL_D_floatsel
	if(!M && !S && ftype==2) UNALLOCATED(ENC_UNALLOCATED_1285_FLOATSEL);
	if(!M && !S && ftype==3 && HasFP16()) return FCSEL_float(ctx, dec); // -> FCSEL_H_floatsel
	if(!M && S) UNALLOCATED(ENC_UNALLOCATED_1284_FLOATSEL);
	if(M) UNALLOCATED(ENC_UNALLOCATED_1283_FLOATSEL);
	UNMATCHED;
}

int decode_iclass_floatdp1(context *ctx, Instruction *dec)
{
	uint32_t M=INSWORD>>31, S=(INSWORD>>29)&1, ftype=(INSWORD>>22)&3, opcode=(INSWORD>>15)&0x3f;
	if(!M && !S && !ftype && !opcode && HasFP()) return FMOV_float(ctx, dec); // -> FMOV_S_floatdp1
	if(!M && !S && !ftype && opcode==1 && HasFP()) return FABS_float(ctx, dec); // -> FABS_S_floatdp1
	if(!M && !S && !ftype && opcode==2 && HasFP()) return FNEG_float(ctx, dec); // -> FNEG_S_floatdp1
	if(!M && !S && !ftype && opcode==3 && HasFP()) return FSQRT_float(ctx, dec); // -> FSQRT_S_floatdp1
	if(!M && !S && !ftype && opcode==5 && HasFP()) return FCVT_float(ctx, dec); // -> FCVT_DS_floatdp1
	if(!M && !S && !ftype && opcode==7 && HasFP()) return FCVT_float(ctx, dec); // -> FCVT_HS_floatdp1
	if(!M && !S && !ftype && opcode==8 && HasFP()) return FRINTN_float(ctx, dec); // -> FRINTN_S_floatdp1
	if(!M && !S && !ftype && opcode==9 && HasFP()) return FRINTP_float(ctx, dec); // -> FRINTP_S_floatdp1
	if(!M && !S && !ftype && opcode==10 && HasFP()) return FRINTM_float(ctx, dec); // -> FRINTM_S_floatdp1
	if(!M && !S && !ftype && opcode==11 && HasFP()) return FRINTZ_float(ctx, dec); // -> FRINTZ_S_floatdp1
	if(!M && !S && !ftype && opcode==12 && HasFP()) return FRINTA_float(ctx, dec); // -> FRINTA_S_floatdp1
	if(!M && !S && !ftype && opcode==14 && HasFP()) return FRINTX_float(ctx, dec); // -> FRINTX_S_floatdp1
	if(!M && !S && !ftype && opcode==15 && HasFP()) return FRINTI_float(ctx, dec); // -> FRINTI_S_floatdp1
	if(!M && !S && !ftype && opcode==0x10 && HasFRINTTS()) return FRINT32Z_float(ctx, dec); // -> FRINT32Z_S_floatdp1
	if(!M && !S && !ftype && opcode==0x11 && HasFRINTTS()) return FRINT32X_float(ctx, dec); // -> FRINT32X_S_floatdp1
	if(!M && !S && !ftype && opcode==0x12 && HasFRINTTS()) return FRINT64Z_float(ctx, dec); // -> FRINT64Z_S_floatdp1
	if(!M && !S && !ftype && opcode==0x13 && HasFRINTTS()) return FRINT64X_float(ctx, dec); // -> FRINT64X_S_floatdp1
	if(!M && !S && ftype==1 && !opcode && HasFP()) return FMOV_float(ctx, dec); // -> FMOV_D_floatdp1
	if(!M && !S && ftype==1 && opcode==1 && HasFP()) return FABS_float(ctx, dec); // -> FABS_D_floatdp1
	if(!M && !S && ftype==1 && opcode==2 && HasFP()) return FNEG_float(ctx, dec); // -> FNEG_D_floatdp1
	if(!M && !S && ftype==1 && opcode==3 && HasFP()) return FSQRT_float(ctx, dec); // -> FSQRT_D_floatdp1
	if(!M && !S && ftype==1 && opcode==4 && HasFP()) return FCVT_float(ctx, dec); // -> FCVT_SD_floatdp1
	if(!M && !S && ftype==1 && opcode==5) UNALLOCATED(ENC_UNALLOCATED_1296_FLOATDP1);
	if(!M && !S && ftype==1 && opcode==6 && HasBF16()) return BFCVT_float(ctx, dec); // -> BFCVT_BS_floatdp1
	if(!M && !S && ftype==1 && opcode==7 && HasFP()) return FCVT_float(ctx, dec); // -> FCVT_HD_floatdp1
	if(!M && !S && ftype==1 && opcode==8 && HasFP()) return FRINTN_float(ctx, dec); // -> FRINTN_D_floatdp1
	if(!M && !S && ftype==1 && opcode==9 && HasFP()) return FRINTP_float(ctx, dec); // -> FRINTP_D_floatdp1
	if(!M && !S && ftype==1 && opcode==10 && HasFP()) return FRINTM_float(ctx, dec); // -> FRINTM_D_floatdp1
	if(!M && !S && ftype==1 && opcode==11 && HasFP()) return FRINTZ_float(ctx, dec); // -> FRINTZ_D_floatdp1
	if(!M && !S && ftype==1 && opcode==12 && HasFP()) return FRINTA_float(ctx, dec); // -> FRINTA_D_floatdp1
	if(!M && !S && ftype==1 && opcode==14 && HasFP()) return FRINTX_float(ctx, dec); // -> FRINTX_D_floatdp1
	if(!M && !S && ftype==1 && opcode==15 && HasFP()) return FRINTI_float(ctx, dec); // -> FRINTI_D_floatdp1
	if(!M && !S && ftype==1 && opcode==0x10 && HasFRINTTS()) return FRINT32Z_float(ctx, dec); // -> FRINT32Z_D_floatdp1
	if(!M && !S && ftype==1 && opcode==0x11 && HasFRINTTS()) return FRINT32X_float(ctx, dec); // -> FRINT32X_D_floatdp1
	if(!M && !S && ftype==1 && opcode==0x12 && HasFRINTTS()) return FRINT64Z_float(ctx, dec); // -> FRINT64Z_D_floatdp1
	if(!M && !S && ftype==1 && opcode==0x13 && HasFRINTTS()) return FRINT64X_float(ctx, dec); // -> FRINT64X_D_floatdp1
	if(!M && !S && ftype==3 && !opcode && HasFP16()) return FMOV_float(ctx, dec); // -> FMOV_H_floatdp1
	if(!M && !S && ftype==3 && opcode==1 && HasFP16()) return FABS_float(ctx, dec); // -> FABS_H_floatdp1
	if(!M && !S && ftype==3 && opcode==2 && HasFP16()) return FNEG_float(ctx, dec); // -> FNEG_H_floatdp1
	if(!M && !S && ftype==3 && opcode==3 && HasFP16()) return FSQRT_float(ctx, dec); // -> FSQRT_H_floatdp1
	if(!M && !S && ftype==3 && opcode==4 && HasFP()) return FCVT_float(ctx, dec); // -> FCVT_SH_floatdp1
	if(!M && !S && ftype==3 && opcode==5 && HasFP()) return FCVT_float(ctx, dec); // -> FCVT_DH_floatdp1
	if(!M && !S && ftype==3 && opcode==8 && HasFP16()) return FRINTN_float(ctx, dec); // -> FRINTN_H_floatdp1
	if(!M && !S && ftype==3 && opcode==9 && HasFP16()) return FRINTP_float(ctx, dec); // -> FRINTP_H_floatdp1
	if(!M && !S && ftype==3 && opcode==10 && HasFP16()) return FRINTM_float(ctx, dec); // -> FRINTM_H_floatdp1
	if(!M && !S && ftype==3 && opcode==11 && HasFP16()) return FRINTZ_float(ctx, dec); // -> FRINTZ_H_floatdp1
	if(!M && !S && ftype==3 && opcode==12 && HasFP16()) return FRINTA_float(ctx, dec); // -> FRINTA_H_floatdp1
	if(!M && !S && ftype==3 && opcode==14 && HasFP16()) return FRINTX_float(ctx, dec); // -> FRINTX_H_floatdp1
	if(!M && !S && ftype==3 && opcode==15 && HasFP16()) return FRINTI_float(ctx, dec); // -> FRINTI_H_floatdp1
	if(!M && !S && ftype!=2 && opcode==13) UNALLOCATED(ENC_UNALLOCATED_1295_FLOATDP1);
	if(!M && !S && !ftype && (opcode&0x3d)==4) UNALLOCATED(ENC_UNALLOCATED_1293_FLOATDP1);
	if(!M && !S && ftype==3 && (opcode&0x3e)==6) UNALLOCATED(ENC_UNALLOCATED_1294_FLOATDP1);
	if(!M && !S && !(ftype&2) && (opcode&0x3c)==0x14) UNALLOCATED(ENC_UNALLOCATED_1292_FLOATDP1);
	if(!M && !S && !(ftype&2) && (opcode&0x38)==0x18) UNALLOCATED(ENC_UNALLOCATED_1290_FLOATDP1);
	if(!M && !S && ftype==3 && (opcode&0x30)==0x10) UNALLOCATED(ENC_UNALLOCATED_1291_FLOATDP1);
	if(!M && !S && ftype==2 && !(opcode&0x20)) UNALLOCATED(ENC_UNALLOCATED_1289_FLOATDP1);
	if(!M && !S && (opcode&0x20)==0x20) UNALLOCATED(ENC_UNALLOCATED_1288_FLOATDP1);
	if(!M && S) UNALLOCATED(ENC_UNALLOCATED_1287_FLOATDP1);
	if(M) UNALLOCATED(ENC_UNALLOCATED_1286_FLOATDP1);
	UNMATCHED;
}

int decode_iclass_floatdp2(context *ctx, Instruction *dec)
{
	uint32_t M=INSWORD>>31, S=(INSWORD>>29)&1, ftype=(INSWORD>>22)&3, opcode=(INSWORD>>12)&15;
	if(!M && !S && !ftype && !opcode && HasFP()) return FMUL_float(ctx, dec); // -> FMUL_S_floatdp2
	if(!M && !S && !ftype && opcode==1 && HasFP()) return FDIV_float(ctx, dec); // -> FDIV_S_floatdp2
	if(!M && !S && !ftype && opcode==2 && HasFP()) return FADD_float(ctx, dec); // -> FADD_S_floatdp2
	if(!M && !S && !ftype && opcode==3 && HasFP()) return FSUB_float(ctx, dec); // -> FSUB_S_floatdp2
	if(!M && !S && !ftype && opcode==4 && HasFP()) return FMAX_float(ctx, dec); // -> FMAX_S_floatdp2
	if(!M && !S && !ftype && opcode==5 && HasFP()) return FMIN_float(ctx, dec); // -> FMIN_S_floatdp2
	if(!M && !S && !ftype && opcode==6 && HasFP()) return FMAXNM_float(ctx, dec); // -> FMAXNM_S_floatdp2
	if(!M && !S && !ftype && opcode==7 && HasFP()) return FMINNM_float(ctx, dec); // -> FMINNM_S_floatdp2
	if(!M && !S && !ftype && opcode==8 && HasFP()) return FNMUL_float(ctx, dec); // -> FNMUL_S_floatdp2
	if(!M && !S && ftype==1 && !opcode && HasFP()) return FMUL_float(ctx, dec); // -> FMUL_D_floatdp2
	if(!M && !S && ftype==1 && opcode==1 && HasFP()) return FDIV_float(ctx, dec); // -> FDIV_D_floatdp2
	if(!M && !S && ftype==1 && opcode==2 && HasFP()) return FADD_float(ctx, dec); // -> FADD_D_floatdp2
	if(!M && !S && ftype==1 && opcode==3 && HasFP()) return FSUB_float(ctx, dec); // -> FSUB_D_floatdp2
	if(!M && !S && ftype==1 && opcode==4 && HasFP()) return FMAX_float(ctx, dec); // -> FMAX_D_floatdp2
	if(!M && !S && ftype==1 && opcode==5 && HasFP()) return FMIN_float(ctx, dec); // -> FMIN_D_floatdp2
	if(!M && !S && ftype==1 && opcode==6 && HasFP()) return FMAXNM_float(ctx, dec); // -> FMAXNM_D_floatdp2
	if(!M && !S && ftype==1 && opcode==7 && HasFP()) return FMINNM_float(ctx, dec); // -> FMINNM_D_floatdp2
	if(!M && !S && ftype==1 && opcode==8 && HasFP()) return FNMUL_float(ctx, dec); // -> FNMUL_D_floatdp2
	if(!M && !S && ftype==3 && !opcode && HasFP16()) return FMUL_float(ctx, dec); // -> FMUL_H_floatdp2
	if(!M && !S && ftype==3 && opcode==1 && HasFP16()) return FDIV_float(ctx, dec); // -> FDIV_H_floatdp2
	if(!M && !S && ftype==3 && opcode==2 && HasFP16()) return FADD_float(ctx, dec); // -> FADD_H_floatdp2
	if(!M && !S && ftype==3 && opcode==3 && HasFP16()) return FSUB_float(ctx, dec); // -> FSUB_H_floatdp2
	if(!M && !S && ftype==3 && opcode==4 && HasFP16()) return FMAX_float(ctx, dec); // -> FMAX_H_floatdp2
	if(!M && !S && ftype==3 && opcode==5 && HasFP16()) return FMIN_float(ctx, dec); // -> FMIN_H_floatdp2
	if(!M && !S && ftype==3 && opcode==6 && HasFP16()) return FMAXNM_float(ctx, dec); // -> FMAXNM_H_floatdp2
	if(!M && !S && ftype==3 && opcode==7 && HasFP16()) return FMINNM_float(ctx, dec); // -> FMINNM_H_floatdp2
	if(!M && !S && ftype==3 && opcode==8 && HasFP16()) return FNMUL_float(ctx, dec); // -> FNMUL_H_floatdp2
	if(!M && !S && ftype!=2 && opcode==9) UNALLOCATED(ENC_UNALLOCATED_1302_FLOATDP2);
	if(!M && !S && ftype!=2 && (opcode&14)==10) UNALLOCATED(ENC_UNALLOCATED_1301_FLOATDP2);
	if(!M && !S && ftype!=2 && (opcode&12)==12) UNALLOCATED(ENC_UNALLOCATED_1300_FLOATDP2);
	if(!M && !S && ftype==2) UNALLOCATED(ENC_UNALLOCATED_1299_FLOATDP2);
	if(!M && S) UNALLOCATED(ENC_UNALLOCATED_1298_FLOATDP2);
	if(M) UNALLOCATED(ENC_UNALLOCATED_1297_FLOATDP2);
	UNMATCHED;
}

int decode_iclass_floatdp3(context *ctx, Instruction *dec)
{
	uint32_t M=INSWORD>>31, S=(INSWORD>>29)&1, ftype=(INSWORD>>22)&3, o1=(INSWORD>>21)&1, o0=(INSWORD>>15)&1;
	if(!M && !S && !ftype && !o1 && !o0 && HasFP()) return FMADD_float(ctx, dec); // -> FMADD_S_floatdp3
	if(!M && !S && !ftype && !o1 && o0 && HasFP()) return FMSUB_float(ctx, dec); // -> FMSUB_S_floatdp3
	if(!M && !S && !ftype && o1 && !o0 && HasFP()) return FNMADD_float(ctx, dec); // -> FNMADD_S_floatdp3
	if(!M && !S && !ftype && o1 && o0 && HasFP()) return FNMSUB_float(ctx, dec); // -> FNMSUB_S_floatdp3
	if(!M && !S && ftype==1 && !o1 && !o0 && HasFP()) return FMADD_float(ctx, dec); // -> FMADD_D_floatdp3
	if(!M && !S && ftype==1 && !o1 && o0 && HasFP()) return FMSUB_float(ctx, dec); // -> FMSUB_D_floatdp3
	if(!M && !S && ftype==1 && o1 && !o0 && HasFP()) return FNMADD_float(ctx, dec); // -> FNMADD_D_floatdp3
	if(!M && !S && ftype==1 && o1 && o0 && HasFP()) return FNMSUB_float(ctx, dec); // -> FNMSUB_D_floatdp3
	if(!M && !S && ftype==3 && !o1 && !o0 && HasFP16()) return FMADD_float(ctx, dec); // -> FMADD_H_floatdp3
	if(!M && !S && ftype==3 && !o1 && o0 && HasFP16()) return FMSUB_float(ctx, dec); // -> FMSUB_H_floatdp3
	if(!M && !S && ftype==3 && o1 && !o0 && HasFP16()) return FNMADD_float(ctx, dec); // -> FNMADD_H_floatdp3
	if(!M && !S && ftype==3 && o1 && o0 && HasFP16()) return FNMSUB_float(ctx, dec); // -> FNMSUB_H_floatdp3
	if(!M && !S && ftype==2) UNALLOCATED(ENC_UNALLOCATED_1305_FLOATDP3);
	if(!M && S) UNALLOCATED(ENC_UNALLOCATED_1304_FLOATDP3);
	if(M) UNALLOCATED(ENC_UNALLOCATED_1303_FLOATDP3);
	UNMATCHED;
}

int decode_iclass_floatimm(context *ctx, Instruction *dec)
{
	uint32_t M=INSWORD>>31, S=(INSWORD>>29)&1, ftype=(INSWORD>>22)&3, imm5=(INSWORD>>5)&0x1f;
	if(!M && !S && !ftype && !imm5 && HasFP()) return FMOV_float_imm(ctx, dec); // -> FMOV_S_floatimm
	if(!M && !S && ftype==1 && !imm5 && HasFP()) return FMOV_float_imm(ctx, dec); // -> FMOV_D_floatimm
	if(!M && !S && ftype==2 && !imm5) UNALLOCATED(ENC_UNALLOCATED_1309_FLOATIMM);
	if(!M && !S && ftype==3 && !imm5 && HasFP16()) return FMOV_float_imm(ctx, dec); // -> FMOV_H_floatimm
	if(!M && !S && imm5) UNALLOCATED(ENC_UNALLOCATED_1308_FLOATIMM);
	if(!M && S) UNALLOCATED(ENC_UNALLOCATED_1307_FLOATIMM);
	if(M) UNALLOCATED(ENC_UNALLOCATED_1306_FLOATIMM);
	UNMATCHED;
}

int decode_iclass_perm_undef(context *ctx, Instruction *dec)
{
	return UDF_perm_undef(ctx, dec);
}

int decode_iclass_mortlach_addhv(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>22)&1, V=(INSWORD>>16)&1, opc2=INSWORD&7;
	if(!op && !V && !(opc2&4) && HasSME()) return addha_za_pp_z(ctx, dec); // -> addha_za_pp_z_32
	if(!op && V && !(opc2&4) && HasSME()) return addva_za_pp_z(ctx, dec); // -> addva_za_pp_z_32
	if(!op && (opc2&4)==4) UNALLOCATED(ENC_UNALLOCATED_697_MORTLACH_ADDHV);
	if(op && !V && HasSME_I16I64()) return addha_za_pp_z(ctx, dec); // -> addha_za_pp_z_64
	if(op && V && HasSME_I16I64()) return addva_za_pp_z(ctx, dec); // -> addva_za_pp_z_64
	UNMATCHED;
}

int decode_iclass_mortlach_f32f32_prod(context *ctx, Instruction *dec)
{
	uint32_t S=(INSWORD>>4)&1;
	if(!S && HasSME()) return fmopa_za_pp_zz(ctx, dec); // -> fmopa_za_pp_zz_32
	if(S && HasSME()) return fmops_za_pp_zz(ctx, dec); // -> fmops_za_pp_zz_32
	UNMATCHED;
}

int decode_iclass_mortlach_b16f32_prod(context *ctx, Instruction *dec)
{
	uint32_t S=(INSWORD>>4)&1;
	if(!S && HasSME()) return bfmopa_za32_pp_zz(ctx, dec); // -> bfmopa_za32_pp_zz_
	if(S && HasSME()) return bfmops_za32_pp_zz(ctx, dec); // -> bfmops_za32_pp_zz_
	UNMATCHED;
}

int decode_iclass_mortlach_f16f32_prod(context *ctx, Instruction *dec)
{
	uint32_t S=(INSWORD>>4)&1;
	if(!S && HasSME()) return fmopa_za32_pp_zz(ctx, dec); // -> fmopa_za32_pp_zz_16
	if(S && HasSME()) return fmops_za32_pp_zz(ctx, dec); // -> fmops_za32_pp_zz_16
	UNMATCHED;
}

int decode_iclass_mortlach_f8f32_prod(context *ctx, Instruction *dec)
{
	return fmopa_za32_pp_z8z8(ctx, dec);
}

int decode_iclass_mortlach_i8i32_prod(context *ctx, Instruction *dec)
{
	uint32_t u0=(INSWORD>>24)&1, u1=(INSWORD>>21)&1, S=(INSWORD>>4)&1;
	if(!u0 && !u1 && !S && HasSME()) return smopa_za_pp_zz(ctx, dec); // -> smopa_za_pp_zz_32
	if(!u0 && !u1 && S && HasSME()) return smops_za_pp_zz(ctx, dec); // -> smops_za_pp_zz_32
	if(!u0 && u1 && !S && HasSME()) return sumopa_za_pp_zz(ctx, dec); // -> sumopa_za_pp_zz_32
	if(!u0 && u1 && S && HasSME()) return sumops_za_pp_zz(ctx, dec); // -> sumops_za_pp_zz_32
	if(u0 && !u1 && !S && HasSME()) return usmopa_za_pp_zz(ctx, dec); // -> usmopa_za_pp_zz_32
	if(u0 && !u1 && S && HasSME()) return usmops_za_pp_zz(ctx, dec); // -> usmops_za_pp_zz_32
	if(u0 && u1 && !S && HasSME()) return umopa_za_pp_zz(ctx, dec); // -> umopa_za_pp_zz_32
	if(u0 && u1 && S && HasSME()) return umops_za_pp_zz(ctx, dec); // -> umops_za_pp_zz_32
	UNMATCHED;
}

int decode_iclass_mortlach_i16i32_prod(context *ctx, Instruction *dec)
{
	uint32_t u0=(INSWORD>>24)&1, S=(INSWORD>>4)&1;
	if(!u0 && !S && HasSME2()) return smopa_za32_pp_zz(ctx, dec); // -> smopa_za32_pp_zz_16
	if(!u0 && S && HasSME2()) return smops_za32_pp_zz(ctx, dec); // -> smops_za32_pp_zz_16
	if(u0 && !S && HasSME2()) return umopa_za32_pp_zz(ctx, dec); // -> umopa_za32_pp_zz_16
	if(u0 && S && HasSME2()) return umops_za32_pp_zz(ctx, dec); // -> umops_za32_pp_zz_16
	UNMATCHED;
}

int decode_iclass_mortlach_contig_load(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>22)&3;
	if(!msz && HasSME()) return ld1b_za_p_rrr(ctx, dec); // -> ld1b_za_p_rrr_
	if(msz==1 && HasSME()) return ld1h_za_p_rrr(ctx, dec); // -> ld1h_za_p_rrr_
	if(msz==2 && HasSME()) return ld1w_za_p_rrr(ctx, dec); // -> ld1w_za_p_rrr_
	if(msz==3 && HasSME()) return ld1d_za_p_rrr(ctx, dec); // -> ld1d_za_p_rrr_
	UNMATCHED;
}

int decode_iclass_mortlach_contig_store(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>22)&3;
	if(!msz && HasSME()) return st1b_za_p_rrr(ctx, dec); // -> st1b_za_p_rrr_
	if(msz==1 && HasSME()) return st1h_za_p_rrr(ctx, dec); // -> st1h_za_p_rrr_
	if(msz==2 && HasSME()) return st1w_za_p_rrr(ctx, dec); // -> st1w_za_p_rrr_
	if(msz==3 && HasSME()) return st1d_za_p_rrr(ctx, dec); // -> st1d_za_p_rrr_
	UNMATCHED;
}

int decode_iclass_mortlach_ctxt_ldst(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>21)&1;
	if(!op && HasSME()) return ldr_za_ri(ctx, dec); // -> ldr_za_ri_
	if(op && HasSME()) return str_za_ri(ctx, dec); // -> str_za_ri_
	UNMATCHED;
}

int decode_iclass_mortlach_zt_ldst(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&0x3f, opc2=INSWORD&3;
	if(opc==0x1f && !opc2 && HasSME2()) return ldr_zt_br(ctx, dec); // -> ldr_zt_br_
	if(opc==0x3f && !opc2 && HasSME2()) return str_zt_br(ctx, dec); // -> str_zt_br_
	if((opc&0x1f)==0x1f && opc2) UNALLOCATED(ENC_UNALLOCATED_703_MORTLACH_ZT_LDST);
	if((opc&0x1f)==0x1e) UNALLOCATED(ENC_UNALLOCATED_702_MORTLACH_ZT_LDST);
	if((opc&0x1e)==0x1c) UNALLOCATED(ENC_UNALLOCATED_701_MORTLACH_ZT_LDST);
	if((opc&0x1c)==0x18) UNALLOCATED(ENC_UNALLOCATED_700_MORTLACH_ZT_LDST);
	if((opc&0x18)==0x10) UNALLOCATED(ENC_UNALLOCATED_699_MORTLACH_ZT_LDST);
	if(!(opc&0x10)) UNALLOCATED(ENC_UNALLOCATED_698_MORTLACH_ZT_LDST);
	UNMATCHED;
}

int decode_iclass_mortlach_contig_qload(context *ctx, Instruction *dec)
{
	return ld1q_za_p_rrr(ctx, dec);
}

int decode_iclass_mortlach_contig_qstore(context *ctx, Instruction *dec)
{
	return st1q_za_p_rrr(ctx, dec);
}

int decode_iclass_mortlach_extract_pred(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, Q=(INSWORD>>16)&1;
	if(!size && !Q && HasSME()) return mova_z_p_rza(ctx, dec); // -> mova_z_p_rza_b
	if(size==1 && !Q && HasSME()) return mova_z_p_rza(ctx, dec); // -> mova_z_p_rza_h
	if(size==2 && !Q && HasSME()) return mova_z_p_rza(ctx, dec); // -> mova_z_p_rza_w
	if(size==3 && !Q && HasSME()) return mova_z_p_rza(ctx, dec); // -> mova_z_p_rza_d
	if(size==3 && Q && HasSME()) return mova_z_p_rza(ctx, dec); // -> mova_z_p_rza_q
	if(size!=3 && Q) UNALLOCATED(ENC_UNALLOCATED_704_MORTLACH_EXTRACT_PRED);
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_extract_ctg(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3;
	if(!size && HasSME2()) return mova_mz2_za(ctx, dec); // -> mova_mz2_za_b1
	if(size==1 && HasSME2()) return mova_mz2_za(ctx, dec); // -> mova_mz2_za_h1
	if(size==2 && HasSME2()) return mova_mz2_za(ctx, dec); // -> mova_mz2_za_w1
	if(size==3 && HasSME2()) return mova_mz2_za(ctx, dec); // -> mova_mz2_za_d1
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_extract_ctg(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, opc=(INSWORD>>5)&7;
	if(!size && !(opc&4) && HasSME2()) return mova_mz4_za(ctx, dec); // -> mova_mz4_za_b1
	if(size==1 && !(opc&4) && HasSME2()) return mova_mz4_za(ctx, dec); // -> mova_mz4_za_h1
	if(size==2 && !(opc&4) && HasSME2()) return mova_mz4_za(ctx, dec); // -> mova_mz4_za_w1
	if(size!=3 && (opc&4)==4) UNALLOCATED(ENC_UNALLOCATED_705_MORTLACH_MULTI4_EXTRACT_CTG);
	if(size==3 && HasSME2()) return mova_mz4_za(ctx, dec); // -> mova_mz4_za_d1
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_za_extract_ctg(context *ctx, Instruction *dec)
{
	return mova_mz_za2(ctx, dec);
}

int decode_iclass_mortlach_multi4_za_extract_ctg(context *ctx, Instruction *dec)
{
	return mova_mz_za4(ctx, dec);
}

int decode_iclass_mortlach_extract_zero(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, Q=(INSWORD>>16)&1;
	if(!size && !Q && HasSME2p1()) return movaz_z_rza(ctx, dec); // -> movaz_z_rza_b
	if(size==1 && !Q && HasSME2p1()) return movaz_z_rza(ctx, dec); // -> movaz_z_rza_h
	if(size==2 && !Q && HasSME2p1()) return movaz_z_rza(ctx, dec); // -> movaz_z_rza_w
	if(size==3 && !Q && HasSME2p1()) return movaz_z_rza(ctx, dec); // -> movaz_z_rza_d
	if(size==3 && Q && HasSME2p1()) return movaz_z_rza(ctx, dec); // -> movaz_z_rza_q
	if(size!=3 && Q) UNALLOCATED(ENC_UNALLOCATED_706_MORTLACH_EXTRACT_ZERO);
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_extract_zero(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3;
	if(!size && HasSME2p1()) return movaz_mz2_za(ctx, dec); // -> movaz_mz2_za_b1
	if(size==1 && HasSME2p1()) return movaz_mz2_za(ctx, dec); // -> movaz_mz2_za_h1
	if(size==2 && HasSME2p1()) return movaz_mz2_za(ctx, dec); // -> movaz_mz2_za_w1
	if(size==3 && HasSME2p1()) return movaz_mz2_za(ctx, dec); // -> movaz_mz2_za_d1
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_extract_zero(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, opc=(INSWORD>>5)&7;
	if(!size && !(opc&4) && HasSME2p1()) return movaz_mz4_za(ctx, dec); // -> movaz_mz4_za_b1
	if(size==1 && !(opc&4) && HasSME2p1()) return movaz_mz4_za(ctx, dec); // -> movaz_mz4_za_h1
	if(size==2 && !(opc&4) && HasSME2p1()) return movaz_mz4_za(ctx, dec); // -> movaz_mz4_za_w1
	if(size!=3 && (opc&4)==4) UNALLOCATED(ENC_UNALLOCATED_707_MORTLACH_MULTI4_EXTRACT_ZERO);
	if(size==3 && HasSME2p1()) return movaz_mz4_za(ctx, dec); // -> movaz_mz4_za_d1
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_za_extract_zero(context *ctx, Instruction *dec)
{
	return movaz_mz_za2(ctx, dec);
}

int decode_iclass_mortlach_multi4_za_extract_zero(context *ctx, Instruction *dec)
{
	return movaz_mz_za4(ctx, dec);
}

int decode_iclass_mortlach_insert_pred(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, Q=(INSWORD>>16)&1;
	if(!size && !Q && HasSME()) return mova_za_p_rz(ctx, dec); // -> mova_za_p_rz_b
	if(size==1 && !Q && HasSME()) return mova_za_p_rz(ctx, dec); // -> mova_za_p_rz_h
	if(size==2 && !Q && HasSME()) return mova_za_p_rz(ctx, dec); // -> mova_za_p_rz_w
	if(size==3 && !Q && HasSME()) return mova_za_p_rz(ctx, dec); // -> mova_za_p_rz_d
	if(size==3 && Q && HasSME()) return mova_za_p_rz(ctx, dec); // -> mova_za_p_rz_q
	if(size!=3 && Q) UNALLOCATED(ENC_UNALLOCATED_708_MORTLACH_INSERT_PRED);
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_insert_ctg(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3;
	if(!size && HasSME2()) return mova_za2_z(ctx, dec); // -> mova_za2_z_b1
	if(size==1 && HasSME2()) return mova_za2_z(ctx, dec); // -> mova_za2_z_h1
	if(size==2 && HasSME2()) return mova_za2_z(ctx, dec); // -> mova_za2_z_w1
	if(size==3 && HasSME2()) return mova_za2_z(ctx, dec); // -> mova_za2_z_d1
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_insert_ctg(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, opc=INSWORD&7;
	if(!size && !(opc&4) && HasSME2()) return mova_za4_z(ctx, dec); // -> mova_za4_z_b1
	if(size==1 && !(opc&4) && HasSME2()) return mova_za4_z(ctx, dec); // -> mova_za4_z_h1
	if(size==2 && !(opc&4) && HasSME2()) return mova_za4_z(ctx, dec); // -> mova_za4_z_w1
	if(size!=3 && (opc&4)==4) UNALLOCATED(ENC_UNALLOCATED_709_MORTLACH_MULTI4_INSERT_CTG);
	if(size==3 && HasSME2()) return mova_za4_z(ctx, dec); // -> mova_za4_z_d1
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_za_insert_ctg(context *ctx, Instruction *dec)
{
	return mova_za_mz2(ctx, dec);
}

int decode_iclass_mortlach_multi4_za_insert_ctg(context *ctx, Instruction *dec)
{
	return mova_za_mz4(ctx, dec);
}

int decode_iclass_mortlach_f64f64_prod(context *ctx, Instruction *dec)
{
	uint32_t S=(INSWORD>>4)&1;
	if(!S && HasSME_F64F64()) return fmopa_za_pp_zz(ctx, dec); // -> fmopa_za_pp_zz_64
	if(S && HasSME_F64F64()) return fmops_za_pp_zz(ctx, dec); // -> fmops_za_pp_zz_64
	UNMATCHED;
}

int decode_iclass_mortlach_i16i64_prod(context *ctx, Instruction *dec)
{
	uint32_t u0=(INSWORD>>24)&1, u1=(INSWORD>>21)&1, S=(INSWORD>>4)&1;
	if(!u0 && !u1 && !S && HasSME_I16I64()) return smopa_za_pp_zz(ctx, dec); // -> smopa_za_pp_zz_64
	if(!u0 && !u1 && S && HasSME_I16I64()) return smops_za_pp_zz(ctx, dec); // -> smops_za_pp_zz_64
	if(!u0 && u1 && !S && HasSME_I16I64()) return sumopa_za_pp_zz(ctx, dec); // -> sumopa_za_pp_zz_64
	if(!u0 && u1 && S && HasSME_I16I64()) return sumops_za_pp_zz(ctx, dec); // -> sumops_za_pp_zz_64
	if(u0 && !u1 && !S && HasSME_I16I64()) return usmopa_za_pp_zz(ctx, dec); // -> usmopa_za_pp_zz_64
	if(u0 && !u1 && S && HasSME_I16I64()) return usmops_za_pp_zz(ctx, dec); // -> usmops_za_pp_zz_64
	if(u0 && u1 && !S && HasSME_I16I64()) return umopa_za_pp_zz(ctx, dec); // -> umopa_za_pp_zz_64
	if(u0 && u1 && S && HasSME_I16I64()) return umops_za_pp_zz(ctx, dec); // -> umops_za_pp_zz_64
	UNMATCHED;
}

int decode_iclass_mortlach_zero(context *ctx, Instruction *dec)
{
	return zero_za_i(ctx, dec);
}

int decode_iclass_mortlach_expand_2dst_ctg(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>15)&15, opc2=(INSWORD>>10)&3;
	if(!(opc&12) && !opc2) UNALLOCATED(ENC_UNALLOCATED_711_MORTLACH_EXPAND_2DST_CTG);
	if((opc&12)==4 && !opc2 && HasSME2()) return luti4_mz2_ztz(ctx, dec); // -> luti4_mz2_ztz_1
	if((opc&8)==8 && !opc2 && HasSME2()) return luti2_mz2_ztz(ctx, dec); // -> luti2_mz2_ztz_1
	if(opc2) UNALLOCATED(ENC_UNALLOCATED_710_MORTLACH_EXPAND_2DST_CTG);
	UNMATCHED;
}

int decode_iclass_mortlach_expand_4dst_ctg(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&7, opc2=(INSWORD>>10)&3;
	if(!(opc&6) && !opc2) UNALLOCATED(ENC_UNALLOCATED_713_MORTLACH_EXPAND_4DST_CTG);
	if((opc&6)==2 && !opc2 && HasSME2()) return luti4_mz4_ztz(ctx, dec); // -> luti4_mz4_ztz_1
	if((opc&4)==4 && !opc2 && HasSME2()) return luti2_mz4_ztz(ctx, dec); // -> luti2_mz4_ztz_1
	if(opc2) UNALLOCATED(ENC_UNALLOCATED_712_MORTLACH_EXPAND_4DST_CTG);
	UNMATCHED;
}

int decode_iclass_mortlach_expand_1dst(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>14)&0x1f, size=(INSWORD>>12)&3, opc2=(INSWORD>>10)&3;
	if(opc==1 && !size && !opc2 && HasSME2p3()) return luti6_z_ztz(ctx, dec); // -> luti6_z_ztz_
	if(opc==1 && size && !opc2) UNALLOCATED(ENC_UNALLOCATED_718_MORTLACH_EXPAND_1DST);
	if(!opc && !opc2) UNALLOCATED(ENC_UNALLOCATED_717_MORTLACH_EXPAND_1DST);
	if((opc&0x1e)==2 && !opc2) UNALLOCATED(ENC_UNALLOCATED_716_MORTLACH_EXPAND_1DST);
	if((opc&0x1c)==4 && !opc2) UNALLOCATED(ENC_UNALLOCATED_715_MORTLACH_EXPAND_1DST);
	if((opc&0x18)==8 && !opc2 && HasSME2()) return luti4_z_ztz(ctx, dec); // -> luti4_z_ztz_
	if((opc&0x10)==0x10 && !opc2 && HasSME2()) return luti2_z_ztz(ctx, dec); // -> luti2_z_ztz_
	if(opc2) UNALLOCATED(ENC_UNALLOCATED_714_MORTLACH_EXPAND_1DST);
	UNMATCHED;
}

int decode_iclass_mortlach_expand_4dst2src_ctg(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>10)&3;
	if(!opc && HasSME_LUTv2()) return luti4_mz4_ztmz2(ctx, dec); // -> luti4_mz4_ztmz2_1
	if(opc) UNALLOCATED(ENC_UNALLOCATED_719_MORTLACH_EXPAND_4DST2SRC_CTG);
	UNMATCHED;
}

int decode_iclass_mortlach_expand_4dst3src_ctg(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>12)&3, opc=(INSWORD>>10)&3;
	if(!size && !opc && HasSME2p3()) return luti6_mz4_ztz(ctx, dec); // -> luti6_mz4_ztmz3_1
	if(!size && opc) UNALLOCATED(ENC_UNALLOCATED_721_MORTLACH_EXPAND_4DST3SRC_CTG);
	if(size) UNALLOCATED(ENC_UNALLOCATED_720_MORTLACH_EXPAND_4DST3SRC_CTG);
	UNMATCHED;
}

int decode_iclass_mortlach_expand_2dst_nctg(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>15)&15, opc2=(INSWORD>>10)&3;
	if(!(opc&12) && !opc2) UNALLOCATED(ENC_UNALLOCATED_723_MORTLACH_EXPAND_2DST_NCTG);
	if((opc&12)==4 && !opc2 && HasSME2p1()) return luti4_mz2_ztz(ctx, dec); // -> luti4_mz2_ztz_8
	if((opc&8)==8 && !opc2 && HasSME2p1()) return luti2_mz2_ztz(ctx, dec); // -> luti2_mz2_ztz_8
	if(opc2) UNALLOCATED(ENC_UNALLOCATED_722_MORTLACH_EXPAND_2DST_NCTG);
	UNMATCHED;
}

int decode_iclass_mortlach_expand_4dst_nctg(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&7, opc2=(INSWORD>>10)&3;
	if(!(opc&6) && !opc2) UNALLOCATED(ENC_UNALLOCATED_725_MORTLACH_EXPAND_4DST_NCTG);
	if((opc&6)==2 && !opc2 && HasSME2p1()) return luti4_mz4_ztz(ctx, dec); // -> luti4_mz4_ztz_4
	if((opc&4)==4 && !opc2 && HasSME2p1()) return luti2_mz4_ztz(ctx, dec); // -> luti2_mz4_ztz_4
	if(opc2) UNALLOCATED(ENC_UNALLOCATED_724_MORTLACH_EXPAND_4DST_NCTG);
	UNMATCHED;
}

int decode_iclass_mortlach_expand_4dst2src_nctg(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>10)&3;
	if(!opc && HasSME2p1() && HasSME_LUTv2()) return luti4_mz4_ztmz2(ctx, dec); // -> luti4_mz4_ztmz2_4
	if(opc) UNALLOCATED(ENC_UNALLOCATED_726_MORTLACH_EXPAND_4DST2SRC_NCTG);
	UNMATCHED;
}

int decode_iclass_mortlach_expand_4dst3src_nctg(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>12)&3, opc=(INSWORD>>10)&3;
	if(!size && !opc && HasSME2p3()) return luti6_mz4_ztz(ctx, dec); // -> luti6_mz4_ztmz3_4
	if(!size && opc) UNALLOCATED(ENC_UNALLOCATED_728_MORTLACH_EXPAND_4DST3SRC_NCTG);
	if(size) UNALLOCATED(ENC_UNALLOCATED_727_MORTLACH_EXPAND_4DST3SRC_NCTG);
	UNMATCHED;
}

int decode_iclass_mortlach_extract_zt(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>5)&0x7f;
	if(opc==0x1f && HasSME2()) return movt_r_zt(ctx, dec); // -> movt_r_zt_
	if(opc!=0x1f) UNALLOCATED(ENC_UNALLOCATED_729_MORTLACH_EXTRACT_ZT);
	UNMATCHED;
}

int decode_iclass_mortlach_insert_zt(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>5)&0x7f;
	if(opc==0x1f && HasSME2()) return movt_zt_r(ctx, dec); // -> movt_zt_r_
	if(opc!=0x1f) UNALLOCATED(ENC_UNALLOCATED_730_MORTLACH_INSERT_ZT);
	UNMATCHED;
}

int decode_iclass_mortlach_move_to_zt(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>5)&0x7f;
	if(opc==0x1f && HasSME_LUTv2()) return movt_zt_z(ctx, dec); // -> movt_zt_z_
	if(opc!=0x1f) UNALLOCATED(ENC_UNALLOCATED_731_MORTLACH_MOVE_TO_ZT);
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_fmul_mm(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3;
	if(!size && HasSME2() && HasSVE_BFSCALE()) return bfmul_mz_zzw(ctx, dec); // -> bfmul_mz_zzw_2x2
	if(size && HasSME2p2()) return fmul_mz_zzw(ctx, dec); // -> fmul_mz_zzw_2x2
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_fmul_mm(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3;
	if(!size && HasSME2() && HasSVE_BFSCALE()) return bfmul_mz_zzw(ctx, dec); // -> bfmul_mz_zzw_4x4
	if(size && HasSME2p2()) return fmul_mz_zzw(ctx, dec); // -> fmul_mz_zzw_4x4
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_mla_long_long_idx_s(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>5)&1, U=(INSWORD>>4)&1, S=(INSWORD>>3)&1;
	if(!op && !U && !S && HasSME2()) return smlall_za_zzi(ctx, dec); // -> smlall_za_zzi_s4xi
	if(!op && !U && S && HasSME2()) return smlsll_za_zzi(ctx, dec); // -> smlsll_za_zzi_s4xi
	if(!op && U && !S && HasSME2()) return umlall_za_zzi(ctx, dec); // -> umlall_za_zzi_s4xi
	if(!op && U && S && HasSME2()) return umlsll_za_zzi(ctx, dec); // -> umlsll_za_zzi_s4xi
	if(op && !U && !S && HasSME2()) return usmlall_za_zzi(ctx, dec); // -> usmlall_za_zzi_s4xi
	if(op && U && !S && HasSME2()) return sumlall_za_zzi(ctx, dec); // -> sumlall_za_zzi_s4xi
	if(op && S) UNALLOCATED(ENC_UNALLOCATED_732_MORTLACH_MULTI4_MLA_LONG_LONG_IDX_S);
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_fp8_fma_long_long_idx(context *ctx, Instruction *dec)
{
	return fmlall_za32_z8z8i(ctx, dec);
}

int decode_iclass_mortlach_multi4_zza_idx_h(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>5)&1, S=(INSWORD>>4)&1;
	if(!op && !S && HasSME_F16F16()) return fmla_za_zzi(ctx, dec); // -> fmla_za_zzi_h4xi
	if(!op && S && HasSME_F16F16()) return fmls_za_zzi(ctx, dec); // -> fmls_za_zzi_h4xi
	if(op && !S && HasSME_B16B16()) return bfmla_za_zzi(ctx, dec); // -> bfmla_za_zzi_h4xi
	if(op && S && HasSME_B16B16()) return bfmls_za_zzi(ctx, dec); // -> bfmls_za_zzi_h4xi
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_fp8_fdot_idx_h(context *ctx, Instruction *dec)
{
	return fdot_za_z8z8i(ctx, dec);
}

int decode_iclass_mortlach_multi4_zza_idx_s(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>12)&1, opc2=(INSWORD>>3)&7;
	if(!op && !opc2 && HasSME2()) return fmla_za_zzi(ctx, dec); // -> fmla_za_zzi_s4xi
	if(!op && opc2==1 && HasSME_F8F32()) return fdot_za32_z8z8i(ctx, dec); // -> fdot_za32_z8z8i_4xi
	if(!op && opc2==2 && HasSME2()) return fmls_za_zzi(ctx, dec); // -> fmls_za_zzi_s4xi
	if(!op && opc2==3) UNALLOCATED(ENC_UNALLOCATED_733_MORTLACH_MULTI4_ZZA_IDX_S);
	if(!op && opc2==4 && HasSME2()) return svdot_za_zzi(ctx, dec); // -> svdot_za_zzi_s4xi
	if(!op && opc2==5 && HasSME2()) return usvdot_za_zzi(ctx, dec); // -> usvdot_za_zzi_s4xi
	if(!op && opc2==6 && HasSME2()) return uvdot_za_zzi(ctx, dec); // -> uvdot_za_zzi_s4xi
	if(!op && opc2==7 && HasSME2()) return suvdot_za_zzi(ctx, dec); // -> suvdot_za_zzi_s4xi
	if(op && !opc2 && HasSME2()) return sdot_za32_zzi(ctx, dec); // -> sdot_za32_zzi_4xi
	if(op && opc2==1 && HasSME2()) return fdot_za_zzi(ctx, dec); // -> fdot_za_zzi_4xi
	if(op && opc2==2 && HasSME2()) return udot_za32_zzi(ctx, dec); // -> udot_za32_zzi_4xi
	if(op && opc2==3 && HasSME2()) return bfdot_za_zzi(ctx, dec); // -> bfdot_za_zzi_4xi
	if(op && opc2==4 && HasSME2()) return sdot_za_zzi(ctx, dec); // -> sdot_za_zzi_s4xi
	if(op && opc2==5 && HasSME2()) return usdot_za_zzi(ctx, dec); // -> usdot_za_zzi_s4xi
	if(op && opc2==6 && HasSME2()) return udot_za_zzi(ctx, dec); // -> udot_za_zzi_s4xi
	if(op && opc2==7 && HasSME2()) return sudot_za_zzi(ctx, dec); // -> sudot_za_zzi_s4xi
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_mla_long_long_idx_d(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>4)&1, S=(INSWORD>>3)&1;
	if(!U && !S && HasSME2() && HasSME_I16I64()) return smlall_za_zzi(ctx, dec); // -> smlall_za_zzi_d4xi
	if(!U && S && HasSME2() && HasSME_I16I64()) return smlsll_za_zzi(ctx, dec); // -> smlsll_za_zzi_d4xi
	if(U && !S && HasSME2() && HasSME_I16I64()) return umlall_za_zzi(ctx, dec); // -> umlall_za_zzi_d4xi
	if(U && S && HasSME2() && HasSME_I16I64()) return umlsll_za_zzi(ctx, dec); // -> umlsll_za_zzi_d4xi
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_fma_long_idx(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>4)&1, S=(INSWORD>>3)&1;
	if(!op && !S && HasSME2()) return fmlal_za_zzi(ctx, dec); // -> fmlal_za_zzi_4xi
	if(!op && S && HasSME2()) return fmlsl_za_zzi(ctx, dec); // -> fmlsl_za_zzi_4xi
	if(op && !S && HasSME2()) return bfmlal_za_zzi(ctx, dec); // -> bfmlal_za_zzi_4xi
	if(op && S && HasSME2()) return bfmlsl_za_zzi(ctx, dec); // -> bfmlsl_za_zzi_4xi
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_fp8_fma_long_idx(context *ctx, Instruction *dec)
{
	return fmlal_za_z8z8i(ctx, dec);
}

int decode_iclass_mortlach_multi4_zza_idx_d(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>11)&1, opc2=(INSWORD>>3)&3;
	if(!op && !opc2 && HasSME2() && HasSME_F64F64()) return fmla_za_zzi(ctx, dec); // -> fmla_za_zzi_d4xi
	if(!op && opc2==1 && HasSME2() && HasSME_I16I64()) return sdot_za_zzi(ctx, dec); // -> sdot_za_zzi_d4xi
	if(!op && opc2==2 && HasSME2() && HasSME_F64F64()) return fmls_za_zzi(ctx, dec); // -> fmls_za_zzi_d4xi
	if(!op && opc2==3 && HasSME2() && HasSME_I16I64()) return udot_za_zzi(ctx, dec); // -> udot_za_zzi_d4xi
	if(op && opc2==1 && HasSME2() && HasSME_I16I64()) return svdot_za_zzi(ctx, dec); // -> svdot_za_zzi_d4xi
	if(op && opc2==3 && HasSME2() && HasSME_I16I64()) return uvdot_za_zzi(ctx, dec); // -> uvdot_za_zzi_d4xi
	if(op && !(opc2&1)) UNALLOCATED(ENC_UNALLOCATED_734_MORTLACH_MULTI4_ZZA_IDX_D);
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_mla_long_idx(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>4)&1, S=(INSWORD>>3)&1;
	if(!U && !S && HasSME2()) return smlal_za_zzi(ctx, dec); // -> smlal_za_zzi_4xi
	if(!U && S && HasSME2()) return smlsl_za_zzi(ctx, dec); // -> smlsl_za_zzi_4xi
	if(U && !S && HasSME2()) return umlal_za_zzi(ctx, dec); // -> umlal_za_zzi_4xi
	if(U && S && HasSME2()) return umlsl_za_zzi(ctx, dec); // -> umlsl_za_zzi_4xi
	UNMATCHED;
}

int decode_iclass_mortlach_multi1_mla_long_long_idx_s(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>4)&1, S=(INSWORD>>3)&1, op=(INSWORD>>2)&1;
	if(!U && !S && !op && HasSME2()) return smlall_za_zzi(ctx, dec); // -> smlall_za_zzi_s
	if(!U && !S && op && HasSME2()) return usmlall_za_zzi(ctx, dec); // -> usmlall_za_zzi_s
	if(!U && S && !op && HasSME2()) return smlsll_za_zzi(ctx, dec); // -> smlsll_za_zzi_s
	if(U && !S && !op && HasSME2()) return umlall_za_zzi(ctx, dec); // -> umlall_za_zzi_s
	if(U && !S && op && HasSME2()) return sumlall_za_zzi(ctx, dec); // -> sumlall_za_zzi_s
	if(U && S && !op && HasSME2()) return umlsll_za_zzi(ctx, dec); // -> umlsll_za_zzi_s
	if(S && op) UNALLOCATED(ENC_UNALLOCATED_735_MORTLACH_MULTI1_MLA_LONG_LONG_IDX_S);
	UNMATCHED;
}

int decode_iclass_mortlach_multi1_fp8_fma_long_long_idx(context *ctx, Instruction *dec)
{
	return fmlall_za32_z8z8i(ctx, dec);
}

int decode_iclass_mortlach_multi1_mla_long_long_idx_d(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>4)&1, S=(INSWORD>>3)&1;
	if(!U && !S && HasSME2() && HasSME_I16I64()) return smlall_za_zzi(ctx, dec); // -> smlall_za_zzi_d
	if(!U && S && HasSME2() && HasSME_I16I64()) return smlsll_za_zzi(ctx, dec); // -> smlsll_za_zzi_d
	if(U && !S && HasSME2() && HasSME_I16I64()) return umlall_za_zzi(ctx, dec); // -> umlall_za_zzi_d
	if(U && S && HasSME2() && HasSME_I16I64()) return umlsll_za_zzi(ctx, dec); // -> umlsll_za_zzi_d
	UNMATCHED;
}

int decode_iclass_mortlach_multi1_fma_long_idx(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>4)&1, S=(INSWORD>>3)&1;
	if(!op && !S && HasSME2()) return fmlal_za_zzi(ctx, dec); // -> fmlal_za_zzi_1
	if(!op && S && HasSME2()) return fmlsl_za_zzi(ctx, dec); // -> fmlsl_za_zzi_1
	if(op && !S && HasSME2()) return bfmlal_za_zzi(ctx, dec); // -> bfmlal_za_zzi_1
	if(op && S && HasSME2()) return bfmlsl_za_zzi(ctx, dec); // -> bfmlsl_za_zzi_1
	UNMATCHED;
}

int decode_iclass_mortlach_multi1_fp8_fma_long_idx(context *ctx, Instruction *dec)
{
	return fmlal_za_z8z8i(ctx, dec);
}

int decode_iclass_mortlach_multi1_mla_long_idx(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>4)&1, S=(INSWORD>>3)&1;
	if(!U && !S && HasSME2()) return smlal_za_zzi(ctx, dec); // -> smlal_za_zzi_1
	if(!U && S && HasSME2()) return smlsl_za_zzi(ctx, dec); // -> smlsl_za_zzi_1
	if(U && !S && HasSME2()) return umlal_za_zzi(ctx, dec); // -> umlal_za_zzi_1
	if(U && S && HasSME2()) return umlsl_za_zzi(ctx, dec); // -> umlsl_za_zzi_1
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_mla_long_long_idx_s(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>5)&1, U=(INSWORD>>4)&1, S=(INSWORD>>3)&1;
	if(!op && !U && !S && HasSME2()) return smlall_za_zzi(ctx, dec); // -> smlall_za_zzi_s2xi
	if(!op && !U && S && HasSME2()) return smlsll_za_zzi(ctx, dec); // -> smlsll_za_zzi_s2xi
	if(!op && U && !S && HasSME2()) return umlall_za_zzi(ctx, dec); // -> umlall_za_zzi_s2xi
	if(!op && U && S && HasSME2()) return umlsll_za_zzi(ctx, dec); // -> umlsll_za_zzi_s2xi
	if(op && !U && !S && HasSME2()) return usmlall_za_zzi(ctx, dec); // -> usmlall_za_zzi_s2xi
	if(op && U && !S && HasSME2()) return sumlall_za_zzi(ctx, dec); // -> sumlall_za_zzi_s2xi
	if(op && S) UNALLOCATED(ENC_UNALLOCATED_736_MORTLACH_MULTI2_MLA_LONG_LONG_IDX_S);
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_zza_idx_h(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>5)&1, S=(INSWORD>>4)&1;
	if(!op && !S && HasSME_F16F16()) return fmla_za_zzi(ctx, dec); // -> fmla_za_zzi_h2xi
	if(!op && S && HasSME_F16F16()) return fmls_za_zzi(ctx, dec); // -> fmls_za_zzi_h2xi
	if(op && !S && HasSME_B16B16()) return bfmla_za_zzi(ctx, dec); // -> bfmla_za_zzi_h2xi
	if(op && S && HasSME_B16B16()) return bfmls_za_zzi(ctx, dec); // -> bfmls_za_zzi_h2xi
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_zza_idx_s(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>12)&1, opc2=(INSWORD>>3)&7;
	if(!op && !opc2 && HasSME2()) return fmla_za_zzi(ctx, dec); // -> fmla_za_zzi_s2xi
	if(!op && opc2==1 && HasSME2()) return fvdot_za_zzi(ctx, dec); // -> fvdot_za_zzi_2xi
	if(!op && opc2==2 && HasSME2()) return fmls_za_zzi(ctx, dec); // -> fmls_za_zzi_s2xi
	if(!op && opc2==3 && HasSME2()) return bfvdot_za_zzi(ctx, dec); // -> bfvdot_za_zzi_2xi
	if(!op && opc2==4 && HasSME2()) return svdot_za32_zzi(ctx, dec); // -> svdot_za32_zzi_2xi
	if(!op && opc2==5) UNALLOCATED(ENC_UNALLOCATED_737_MORTLACH_MULTI2_ZZA_IDX_S);
	if(!op && opc2==6 && HasSME2()) return uvdot_za32_zzi(ctx, dec); // -> uvdot_za32_zzi_2xi
	if(!op && opc2==7 && HasSME_F8F32()) return fdot_za32_z8z8i(ctx, dec); // -> fdot_za32_z8z8i_2xi
	if(op && !opc2 && HasSME2()) return sdot_za32_zzi(ctx, dec); // -> sdot_za32_zzi_2xi
	if(op && opc2==1 && HasSME2()) return fdot_za_zzi(ctx, dec); // -> fdot_za_zzi_2xi
	if(op && opc2==2 && HasSME2()) return udot_za32_zzi(ctx, dec); // -> udot_za32_zzi_2xi
	if(op && opc2==3 && HasSME2()) return bfdot_za_zzi(ctx, dec); // -> bfdot_za_zzi_2xi
	if(op && opc2==4 && HasSME2()) return sdot_za_zzi(ctx, dec); // -> sdot_za_zzi_s2xi
	if(op && opc2==5 && HasSME2()) return usdot_za_zzi(ctx, dec); // -> usdot_za_zzi_s2xi
	if(op && opc2==6 && HasSME2()) return udot_za_zzi(ctx, dec); // -> udot_za_zzi_s2xi
	if(op && opc2==7 && HasSME2()) return sudot_za_zzi(ctx, dec); // -> sudot_za_zzi_s2xi
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_mla_long_long_idx_d(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>4)&1, S=(INSWORD>>3)&1;
	if(!U && !S && HasSME2() && HasSME_I16I64()) return smlall_za_zzi(ctx, dec); // -> smlall_za_zzi_d2xi
	if(!U && S && HasSME2() && HasSME_I16I64()) return smlsll_za_zzi(ctx, dec); // -> smlsll_za_zzi_d2xi
	if(U && !S && HasSME2() && HasSME_I16I64()) return umlall_za_zzi(ctx, dec); // -> umlall_za_zzi_d2xi
	if(U && S && HasSME2() && HasSME_I16I64()) return umlsll_za_zzi(ctx, dec); // -> umlsll_za_zzi_d2xi
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_fp8_fma_long_long_idx(context *ctx, Instruction *dec)
{
	return fmlall_za32_z8z8i(ctx, dec);
}

int decode_iclass_mortlach_multi2_fma_long_idx(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>4)&1, S=(INSWORD>>3)&1;
	if(!op && !S && HasSME2()) return fmlal_za_zzi(ctx, dec); // -> fmlal_za_zzi_2xi
	if(!op && S && HasSME2()) return fmlsl_za_zzi(ctx, dec); // -> fmlsl_za_zzi_2xi
	if(op && !S && HasSME2()) return bfmlal_za_zzi(ctx, dec); // -> bfmlal_za_zzi_2xi
	if(op && S && HasSME2()) return bfmlsl_za_zzi(ctx, dec); // -> bfmlsl_za_zzi_2xi
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_fp8_fma_long_idx(context *ctx, Instruction *dec)
{
	return fmlal_za_z8z8i(ctx, dec);
}

int decode_iclass_mortlach_multi2_fp8_fvdot_idx_s(context *ctx, Instruction *dec)
{
	uint32_t T=(INSWORD>>4)&1;
	if(!T && HasSME_F8F32()) return fvdotb_za32_z8z8i(ctx, dec); // -> fvdotb_za32_z8z8i_2xi
	if(T && HasSME_F8F32()) return fvdott_za32_z8z8i(ctx, dec); // -> fvdott_za32_z8z8i_2xi
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_zza_idx_d(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>3)&3;
	if(!opc && HasSME2() && HasSME_F64F64()) return fmla_za_zzi(ctx, dec); // -> fmla_za_zzi_d2xi
	if(opc==1 && HasSME2() && HasSME_I16I64()) return sdot_za_zzi(ctx, dec); // -> sdot_za_zzi_d2xi
	if(opc==2 && HasSME2() && HasSME_F64F64()) return fmls_za_zzi(ctx, dec); // -> fmls_za_zzi_d2xi
	if(opc==3 && HasSME2() && HasSME_I16I64()) return udot_za_zzi(ctx, dec); // -> udot_za_zzi_d2xi
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_mla_long_idx(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>4)&1, S=(INSWORD>>3)&1;
	if(!U && !S && HasSME2()) return smlal_za_zzi(ctx, dec); // -> smlal_za_zzi_2xi
	if(!U && S && HasSME2()) return smlsl_za_zzi(ctx, dec); // -> smlsl_za_zzi_2xi
	if(U && !S && HasSME2()) return umlal_za_zzi(ctx, dec); // -> umlal_za_zzi_2xi
	if(U && S && HasSME2()) return umlsl_za_zzi(ctx, dec); // -> umlsl_za_zzi_2xi
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_fp8_fdot_idx(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>12)&1;
	if(!op && HasSME_F8F16()) return fdot_za_z8z8i(ctx, dec); // -> fdot_za_z8z8i_2xi
	if(op && HasSME_F8F16()) return fvdot_za_z8z8i(ctx, dec); // -> fvdot_za_z8z8i_2xi
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_lut6_16_ctg(context *ctx, Instruction *dec)
{
	return luti6_mz4_zmz2(ctx, dec);
}

int decode_iclass_mortlach_multi4_lut6_16_nctg(context *ctx, Instruction *dec)
{
	return luti6_mz4_zmz2(ctx, dec);
}

int decode_iclass_mortlach_multi2_cld_cldnt_ss_ctg(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>13)&3, N=INSWORD&1;
	if(!msz && !N && HasSME2() && HasSVE2p1()) return ld1b_mz_p_br(ctx, dec); // -> ld1b_mz_p_br_2
	if(!msz && N && HasSME2() && HasSVE2p1()) return ldnt1b_mz_p_br(ctx, dec); // -> ldnt1b_mz_p_br_2
	if(msz==1 && !N && HasSME2() && HasSVE2p1()) return ld1h_mz_p_br(ctx, dec); // -> ld1h_mz_p_br_2
	if(msz==1 && N && HasSME2() && HasSVE2p1()) return ldnt1h_mz_p_br(ctx, dec); // -> ldnt1h_mz_p_br_2
	if(msz==2 && !N && HasSME2() && HasSVE2p1()) return ld1w_mz_p_br(ctx, dec); // -> ld1w_mz_p_br_2
	if(msz==2 && N && HasSME2() && HasSVE2p1()) return ldnt1w_mz_p_br(ctx, dec); // -> ldnt1w_mz_p_br_2
	if(msz==3 && !N && HasSME2() && HasSVE2p1()) return ld1d_mz_p_br(ctx, dec); // -> ld1d_mz_p_br_2
	if(msz==3 && N && HasSME2() && HasSVE2p1()) return ldnt1d_mz_p_br(ctx, dec); // -> ldnt1d_mz_p_br_2
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_cld_cldnt_ss_ctg(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>13)&3, N=INSWORD&1;
	if(!msz && !N && HasSME2() && HasSVE2p1()) return ld1b_mz_p_br(ctx, dec); // -> ld1b_mz_p_br_4
	if(!msz && N && HasSME2() && HasSVE2p1()) return ldnt1b_mz_p_br(ctx, dec); // -> ldnt1b_mz_p_br_4
	if(msz==1 && !N && HasSME2() && HasSVE2p1()) return ld1h_mz_p_br(ctx, dec); // -> ld1h_mz_p_br_4
	if(msz==1 && N && HasSME2() && HasSVE2p1()) return ldnt1h_mz_p_br(ctx, dec); // -> ldnt1h_mz_p_br_4
	if(msz==2 && !N && HasSME2() && HasSVE2p1()) return ld1w_mz_p_br(ctx, dec); // -> ld1w_mz_p_br_4
	if(msz==2 && N && HasSME2() && HasSVE2p1()) return ldnt1w_mz_p_br(ctx, dec); // -> ldnt1w_mz_p_br_4
	if(msz==3 && !N && HasSME2() && HasSVE2p1()) return ld1d_mz_p_br(ctx, dec); // -> ld1d_mz_p_br_4
	if(msz==3 && N && HasSME2() && HasSVE2p1()) return ldnt1d_mz_p_br(ctx, dec); // -> ldnt1d_mz_p_br_4
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_cst_cstnt_ss_ctg(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>13)&3, N=INSWORD&1;
	if(!msz && !N && HasSME2() && HasSVE2p1()) return st1b_mz_p_br(ctx, dec); // -> st1b_mz_p_br_2
	if(!msz && N && HasSME2() && HasSVE2p1()) return stnt1b_mz_p_br(ctx, dec); // -> stnt1b_mz_p_br_2
	if(msz==1 && !N && HasSME2() && HasSVE2p1()) return st1h_mz_p_br(ctx, dec); // -> st1h_mz_p_br_2
	if(msz==1 && N && HasSME2() && HasSVE2p1()) return stnt1h_mz_p_br(ctx, dec); // -> stnt1h_mz_p_br_2
	if(msz==2 && !N && HasSME2() && HasSVE2p1()) return st1w_mz_p_br(ctx, dec); // -> st1w_mz_p_br_2
	if(msz==2 && N && HasSME2() && HasSVE2p1()) return stnt1w_mz_p_br(ctx, dec); // -> stnt1w_mz_p_br_2
	if(msz==3 && !N && HasSME2() && HasSVE2p1()) return st1d_mz_p_br(ctx, dec); // -> st1d_mz_p_br_2
	if(msz==3 && N && HasSME2() && HasSVE2p1()) return stnt1d_mz_p_br(ctx, dec); // -> stnt1d_mz_p_br_2
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_cst_cstnt_ss_ctg(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>13)&3, N=INSWORD&1;
	if(!msz && !N && HasSME2() && HasSVE2p1()) return st1b_mz_p_br(ctx, dec); // -> st1b_mz_p_br_4
	if(!msz && N && HasSME2() && HasSVE2p1()) return stnt1b_mz_p_br(ctx, dec); // -> stnt1b_mz_p_br_4
	if(msz==1 && !N && HasSME2() && HasSVE2p1()) return st1h_mz_p_br(ctx, dec); // -> st1h_mz_p_br_4
	if(msz==1 && N && HasSME2() && HasSVE2p1()) return stnt1h_mz_p_br(ctx, dec); // -> stnt1h_mz_p_br_4
	if(msz==2 && !N && HasSME2() && HasSVE2p1()) return st1w_mz_p_br(ctx, dec); // -> st1w_mz_p_br_4
	if(msz==2 && N && HasSME2() && HasSVE2p1()) return stnt1w_mz_p_br(ctx, dec); // -> stnt1w_mz_p_br_4
	if(msz==3 && !N && HasSME2() && HasSVE2p1()) return st1d_mz_p_br(ctx, dec); // -> st1d_mz_p_br_4
	if(msz==3 && N && HasSME2() && HasSVE2p1()) return stnt1d_mz_p_br(ctx, dec); // -> stnt1d_mz_p_br_4
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_cld_cldnt_si_ctg(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>13)&3, N=INSWORD&1;
	if(!msz && !N && HasSME2() && HasSVE2p1()) return ld1b_mz_p_bi(ctx, dec); // -> ld1b_mz_p_bi_2
	if(!msz && N && HasSME2() && HasSVE2p1()) return ldnt1b_mz_p_bi(ctx, dec); // -> ldnt1b_mz_p_bi_2
	if(msz==1 && !N && HasSME2() && HasSVE2p1()) return ld1h_mz_p_bi(ctx, dec); // -> ld1h_mz_p_bi_2
	if(msz==1 && N && HasSME2() && HasSVE2p1()) return ldnt1h_mz_p_bi(ctx, dec); // -> ldnt1h_mz_p_bi_2
	if(msz==2 && !N && HasSME2() && HasSVE2p1()) return ld1w_mz_p_bi(ctx, dec); // -> ld1w_mz_p_bi_2
	if(msz==2 && N && HasSME2() && HasSVE2p1()) return ldnt1w_mz_p_bi(ctx, dec); // -> ldnt1w_mz_p_bi_2
	if(msz==3 && !N && HasSME2() && HasSVE2p1()) return ld1d_mz_p_bi(ctx, dec); // -> ld1d_mz_p_bi_2
	if(msz==3 && N && HasSME2() && HasSVE2p1()) return ldnt1d_mz_p_bi(ctx, dec); // -> ldnt1d_mz_p_bi_2
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_cld_cldnt_si_ctg(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>13)&3, N=INSWORD&1;
	if(!msz && !N && HasSME2() && HasSVE2p1()) return ld1b_mz_p_bi(ctx, dec); // -> ld1b_mz_p_bi_4
	if(!msz && N && HasSME2() && HasSVE2p1()) return ldnt1b_mz_p_bi(ctx, dec); // -> ldnt1b_mz_p_bi_4
	if(msz==1 && !N && HasSME2() && HasSVE2p1()) return ld1h_mz_p_bi(ctx, dec); // -> ld1h_mz_p_bi_4
	if(msz==1 && N && HasSME2() && HasSVE2p1()) return ldnt1h_mz_p_bi(ctx, dec); // -> ldnt1h_mz_p_bi_4
	if(msz==2 && !N && HasSME2() && HasSVE2p1()) return ld1w_mz_p_bi(ctx, dec); // -> ld1w_mz_p_bi_4
	if(msz==2 && N && HasSME2() && HasSVE2p1()) return ldnt1w_mz_p_bi(ctx, dec); // -> ldnt1w_mz_p_bi_4
	if(msz==3 && !N && HasSME2() && HasSVE2p1()) return ld1d_mz_p_bi(ctx, dec); // -> ld1d_mz_p_bi_4
	if(msz==3 && N && HasSME2() && HasSVE2p1()) return ldnt1d_mz_p_bi(ctx, dec); // -> ldnt1d_mz_p_bi_4
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_cst_cstnt_si_ctg(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>13)&3, N=INSWORD&1;
	if(!msz && !N && HasSME2() && HasSVE2p1()) return st1b_mz_p_bi(ctx, dec); // -> st1b_mz_p_bi_2
	if(!msz && N && HasSME2() && HasSVE2p1()) return stnt1b_mz_p_bi(ctx, dec); // -> stnt1b_mz_p_bi_2
	if(msz==1 && !N && HasSME2() && HasSVE2p1()) return st1h_mz_p_bi(ctx, dec); // -> st1h_mz_p_bi_2
	if(msz==1 && N && HasSME2() && HasSVE2p1()) return stnt1h_mz_p_bi(ctx, dec); // -> stnt1h_mz_p_bi_2
	if(msz==2 && !N && HasSME2() && HasSVE2p1()) return st1w_mz_p_bi(ctx, dec); // -> st1w_mz_p_bi_2
	if(msz==2 && N && HasSME2() && HasSVE2p1()) return stnt1w_mz_p_bi(ctx, dec); // -> stnt1w_mz_p_bi_2
	if(msz==3 && !N && HasSME2() && HasSVE2p1()) return st1d_mz_p_bi(ctx, dec); // -> st1d_mz_p_bi_2
	if(msz==3 && N && HasSME2() && HasSVE2p1()) return stnt1d_mz_p_bi(ctx, dec); // -> stnt1d_mz_p_bi_2
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_cst_cstnt_si_ctg(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>13)&3, N=INSWORD&1;
	if(!msz && !N && HasSME2() && HasSVE2p1()) return st1b_mz_p_bi(ctx, dec); // -> st1b_mz_p_bi_4
	if(!msz && N && HasSME2() && HasSVE2p1()) return stnt1b_mz_p_bi(ctx, dec); // -> stnt1b_mz_p_bi_4
	if(msz==1 && !N && HasSME2() && HasSVE2p1()) return st1h_mz_p_bi(ctx, dec); // -> st1h_mz_p_bi_4
	if(msz==1 && N && HasSME2() && HasSVE2p1()) return stnt1h_mz_p_bi(ctx, dec); // -> stnt1h_mz_p_bi_4
	if(msz==2 && !N && HasSME2() && HasSVE2p1()) return st1w_mz_p_bi(ctx, dec); // -> st1w_mz_p_bi_4
	if(msz==2 && N && HasSME2() && HasSVE2p1()) return stnt1w_mz_p_bi(ctx, dec); // -> stnt1w_mz_p_bi_4
	if(msz==3 && !N && HasSME2() && HasSVE2p1()) return st1d_mz_p_bi(ctx, dec); // -> st1d_mz_p_bi_4
	if(msz==3 && N && HasSME2() && HasSVE2p1()) return stnt1d_mz_p_bi(ctx, dec); // -> stnt1d_mz_p_bi_4
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_cld_cldnt_ss_nctg(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>13)&3, N=(INSWORD>>3)&1;
	if(!msz && !N && HasSME2()) return ld1b_mzx_p_br(ctx, dec); // -> ld1b_mzx_p_br_2x8
	if(!msz && N && HasSME2()) return ldnt1b_mzx_p_br(ctx, dec); // -> ldnt1b_mzx_p_br_2x8
	if(msz==1 && !N && HasSME2()) return ld1h_mzx_p_br(ctx, dec); // -> ld1h_mzx_p_br_2x8
	if(msz==1 && N && HasSME2()) return ldnt1h_mzx_p_br(ctx, dec); // -> ldnt1h_mzx_p_br_2x8
	if(msz==2 && !N && HasSME2()) return ld1w_mzx_p_br(ctx, dec); // -> ld1w_mzx_p_br_2x8
	if(msz==2 && N && HasSME2()) return ldnt1w_mzx_p_br(ctx, dec); // -> ldnt1w_mzx_p_br_2x8
	if(msz==3 && !N && HasSME2()) return ld1d_mzx_p_br(ctx, dec); // -> ld1d_mzx_p_br_2x8
	if(msz==3 && N && HasSME2()) return ldnt1d_mzx_p_br(ctx, dec); // -> ldnt1d_mzx_p_br_2x8
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_cld_cldnt_ss_nctg(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>13)&3, N=(INSWORD>>3)&1;
	if(!msz && !N && HasSME2()) return ld1b_mzx_p_br(ctx, dec); // -> ld1b_mzx_p_br_4x4
	if(!msz && N && HasSME2()) return ldnt1b_mzx_p_br(ctx, dec); // -> ldnt1b_mzx_p_br_4x4
	if(msz==1 && !N && HasSME2()) return ld1h_mzx_p_br(ctx, dec); // -> ld1h_mzx_p_br_4x4
	if(msz==1 && N && HasSME2()) return ldnt1h_mzx_p_br(ctx, dec); // -> ldnt1h_mzx_p_br_4x4
	if(msz==2 && !N && HasSME2()) return ld1w_mzx_p_br(ctx, dec); // -> ld1w_mzx_p_br_4x4
	if(msz==2 && N && HasSME2()) return ldnt1w_mzx_p_br(ctx, dec); // -> ldnt1w_mzx_p_br_4x4
	if(msz==3 && !N && HasSME2()) return ld1d_mzx_p_br(ctx, dec); // -> ld1d_mzx_p_br_4x4
	if(msz==3 && N && HasSME2()) return ldnt1d_mzx_p_br(ctx, dec); // -> ldnt1d_mzx_p_br_4x4
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_cst_cstnt_ss_nctg(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>13)&3, N=(INSWORD>>3)&1;
	if(!msz && !N && HasSME2()) return st1b_mzx_p_br(ctx, dec); // -> st1b_mzx_p_br_2x8
	if(!msz && N && HasSME2()) return stnt1b_mzx_p_br(ctx, dec); // -> stnt1b_mzx_p_br_2x8
	if(msz==1 && !N && HasSME2()) return st1h_mzx_p_br(ctx, dec); // -> st1h_mzx_p_br_2x8
	if(msz==1 && N && HasSME2()) return stnt1h_mzx_p_br(ctx, dec); // -> stnt1h_mzx_p_br_2x8
	if(msz==2 && !N && HasSME2()) return st1w_mzx_p_br(ctx, dec); // -> st1w_mzx_p_br_2x8
	if(msz==2 && N && HasSME2()) return stnt1w_mzx_p_br(ctx, dec); // -> stnt1w_mzx_p_br_2x8
	if(msz==3 && !N && HasSME2()) return st1d_mzx_p_br(ctx, dec); // -> st1d_mzx_p_br_2x8
	if(msz==3 && N && HasSME2()) return stnt1d_mzx_p_br(ctx, dec); // -> stnt1d_mzx_p_br_2x8
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_cst_cstnt_ss_nctg(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>13)&3, N=(INSWORD>>3)&1;
	if(!msz && !N && HasSME2()) return st1b_mzx_p_br(ctx, dec); // -> st1b_mzx_p_br_4x4
	if(!msz && N && HasSME2()) return stnt1b_mzx_p_br(ctx, dec); // -> stnt1b_mzx_p_br_4x4
	if(msz==1 && !N && HasSME2()) return st1h_mzx_p_br(ctx, dec); // -> st1h_mzx_p_br_4x4
	if(msz==1 && N && HasSME2()) return stnt1h_mzx_p_br(ctx, dec); // -> stnt1h_mzx_p_br_4x4
	if(msz==2 && !N && HasSME2()) return st1w_mzx_p_br(ctx, dec); // -> st1w_mzx_p_br_4x4
	if(msz==2 && N && HasSME2()) return stnt1w_mzx_p_br(ctx, dec); // -> stnt1w_mzx_p_br_4x4
	if(msz==3 && !N && HasSME2()) return st1d_mzx_p_br(ctx, dec); // -> st1d_mzx_p_br_4x4
	if(msz==3 && N && HasSME2()) return stnt1d_mzx_p_br(ctx, dec); // -> stnt1d_mzx_p_br_4x4
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_cld_cldnt_si_nctg(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>13)&3, N=(INSWORD>>3)&1;
	if(!msz && !N && HasSME2()) return ld1b_mzx_p_bi(ctx, dec); // -> ld1b_mzx_p_bi_2x8
	if(!msz && N && HasSME2()) return ldnt1b_mzx_p_bi(ctx, dec); // -> ldnt1b_mzx_p_bi_2x8
	if(msz==1 && !N && HasSME2()) return ld1h_mzx_p_bi(ctx, dec); // -> ld1h_mzx_p_bi_2x8
	if(msz==1 && N && HasSME2()) return ldnt1h_mzx_p_bi(ctx, dec); // -> ldnt1h_mzx_p_bi_2x8
	if(msz==2 && !N && HasSME2()) return ld1w_mzx_p_bi(ctx, dec); // -> ld1w_mzx_p_bi_2x8
	if(msz==2 && N && HasSME2()) return ldnt1w_mzx_p_bi(ctx, dec); // -> ldnt1w_mzx_p_bi_2x8
	if(msz==3 && !N && HasSME2()) return ld1d_mzx_p_bi(ctx, dec); // -> ld1d_mzx_p_bi_2x8
	if(msz==3 && N && HasSME2()) return ldnt1d_mzx_p_bi(ctx, dec); // -> ldnt1d_mzx_p_bi_2x8
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_cld_cldnt_si_nctg(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>13)&3, N=(INSWORD>>3)&1;
	if(!msz && !N && HasSME2()) return ld1b_mzx_p_bi(ctx, dec); // -> ld1b_mzx_p_bi_4x4
	if(!msz && N && HasSME2()) return ldnt1b_mzx_p_bi(ctx, dec); // -> ldnt1b_mzx_p_bi_4x4
	if(msz==1 && !N && HasSME2()) return ld1h_mzx_p_bi(ctx, dec); // -> ld1h_mzx_p_bi_4x4
	if(msz==1 && N && HasSME2()) return ldnt1h_mzx_p_bi(ctx, dec); // -> ldnt1h_mzx_p_bi_4x4
	if(msz==2 && !N && HasSME2()) return ld1w_mzx_p_bi(ctx, dec); // -> ld1w_mzx_p_bi_4x4
	if(msz==2 && N && HasSME2()) return ldnt1w_mzx_p_bi(ctx, dec); // -> ldnt1w_mzx_p_bi_4x4
	if(msz==3 && !N && HasSME2()) return ld1d_mzx_p_bi(ctx, dec); // -> ld1d_mzx_p_bi_4x4
	if(msz==3 && N && HasSME2()) return ldnt1d_mzx_p_bi(ctx, dec); // -> ldnt1d_mzx_p_bi_4x4
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_cst_cstnt_si_nctg(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>13)&3, N=(INSWORD>>3)&1;
	if(!msz && !N && HasSME2()) return st1b_mzx_p_bi(ctx, dec); // -> st1b_mzx_p_bi_2x8
	if(!msz && N && HasSME2()) return stnt1b_mzx_p_bi(ctx, dec); // -> stnt1b_mzx_p_bi_2x8
	if(msz==1 && !N && HasSME2()) return st1h_mzx_p_bi(ctx, dec); // -> st1h_mzx_p_bi_2x8
	if(msz==1 && N && HasSME2()) return stnt1h_mzx_p_bi(ctx, dec); // -> stnt1h_mzx_p_bi_2x8
	if(msz==2 && !N && HasSME2()) return st1w_mzx_p_bi(ctx, dec); // -> st1w_mzx_p_bi_2x8
	if(msz==2 && N && HasSME2()) return stnt1w_mzx_p_bi(ctx, dec); // -> stnt1w_mzx_p_bi_2x8
	if(msz==3 && !N && HasSME2()) return st1d_mzx_p_bi(ctx, dec); // -> st1d_mzx_p_bi_2x8
	if(msz==3 && N && HasSME2()) return stnt1d_mzx_p_bi(ctx, dec); // -> stnt1d_mzx_p_bi_2x8
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_cst_cstnt_si_nctg(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>13)&3, N=(INSWORD>>3)&1;
	if(!msz && !N && HasSME2()) return st1b_mzx_p_bi(ctx, dec); // -> st1b_mzx_p_bi_4x4
	if(!msz && N && HasSME2()) return stnt1b_mzx_p_bi(ctx, dec); // -> stnt1b_mzx_p_bi_4x4
	if(msz==1 && !N && HasSME2()) return st1h_mzx_p_bi(ctx, dec); // -> st1h_mzx_p_bi_4x4
	if(msz==1 && N && HasSME2()) return stnt1h_mzx_p_bi(ctx, dec); // -> stnt1h_mzx_p_bi_4x4
	if(msz==2 && !N && HasSME2()) return st1w_mzx_p_bi(ctx, dec); // -> st1w_mzx_p_bi_4x4
	if(msz==2 && N && HasSME2()) return stnt1w_mzx_p_bi(ctx, dec); // -> stnt1w_mzx_p_bi_4x4
	if(msz==3 && !N && HasSME2()) return st1d_mzx_p_bi(ctx, dec); // -> st1d_mzx_p_bi_4x4
	if(msz==3 && N && HasSME2()) return stnt1d_mzx_p_bi(ctx, dec); // -> stnt1d_mzx_p_bi_4x4
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_zz_za_mla_long_long_mm(context *ctx, Instruction *dec)
{
	uint32_t sz=(INSWORD>>22)&1, U=(INSWORD>>4)&1, S=(INSWORD>>3)&1, op=(INSWORD>>2)&1;
	if(!sz && !U && !S && op && HasSME2()) return usmlall_za_zzw(ctx, dec); // -> usmlall_za_zzw_s4x4
	if(!sz && !U && S && op) UNALLOCATED(ENC_UNALLOCATED_740_MORTLACH_MULTI4_ZZ_ZA_MLA_LONG_LONG_MM);
	if(!U && !S && !op && HasSME2()) return smlall_za_zzw(ctx, dec); // -> smlall_za_zzw_4x4
	if(!U && S && !op && HasSME2()) return smlsll_za_zzw(ctx, dec); // -> smlsll_za_zzw_4x4
	if(U && !S && !op && HasSME2()) return umlall_za_zzw(ctx, dec); // -> umlall_za_zzw_4x4
	if(U && S && !op && HasSME2()) return umlsll_za_zzw(ctx, dec); // -> umlsll_za_zzw_4x4
	if(!sz && U && op) UNALLOCATED(ENC_UNALLOCATED_739_MORTLACH_MULTI4_ZZ_ZA_MLA_LONG_LONG_MM);
	if(sz && op) UNALLOCATED(ENC_UNALLOCATED_738_MORTLACH_MULTI4_ZZ_ZA_MLA_LONG_LONG_MM);
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_zz_za_fp8_fma_long_long_mm(context *ctx, Instruction *dec)
{
	return fmlall_za32_z8z8w(ctx, dec);
}

int decode_iclass_mortlach_multi4_zz_za_fma_long_mm(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>4)&1, S=(INSWORD>>3)&1;
	if(!op && !S && HasSME2()) return fmlal_za_zzw(ctx, dec); // -> fmlal_za_zzw_4x4
	if(!op && S && HasSME2()) return fmlsl_za_zzw(ctx, dec); // -> fmlsl_za_zzw_4x4
	if(op && !S && HasSME2()) return bfmlal_za_zzw(ctx, dec); // -> bfmlal_za_zzw_4x4
	if(op && S && HasSME2()) return bfmlsl_za_zzw(ctx, dec); // -> bfmlsl_za_zzw_4x4
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_zz_za_fp8_fma_long_mm(context *ctx, Instruction *dec)
{
	return fmlal_za_z8z8w(ctx, dec);
}

int decode_iclass_mortlach_multi4_zz_za_mla_long_mm(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>4)&1, S=(INSWORD>>3)&1;
	if(!U && !S && HasSME2()) return smlal_za_zzw(ctx, dec); // -> smlal_za_zzw_4x4
	if(!U && S && HasSME2()) return smlsl_za_zzw(ctx, dec); // -> smlsl_za_zzw_4x4
	if(U && !S && HasSME2()) return umlal_za_zzw(ctx, dec); // -> umlal_za_zzw_4x4
	if(U && S && HasSME2()) return umlsl_za_zzw(ctx, dec); // -> umlsl_za_zzw_4x4
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_z_za_fpdot_mm(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>4)&3;
	if(!opc && HasSME2()) return fdot_za_zzw(ctx, dec); // -> fdot_za_zzw_4x4
	if(opc==1 && HasSME2()) return bfdot_za_zzw(ctx, dec); // -> bfdot_za_zzw_4x4
	if(opc==2 && HasSME_F8F16()) return fdot_za_z8z8w(ctx, dec); // -> fdot_za_z8z8w_4x4
	if(opc==3 && HasSME_F8F32()) return fdot_za32_z8z8w(ctx, dec); // -> fdot_za32_z8z8w_4x4
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_zz_za_f16_mm(context *ctx, Instruction *dec)
{
	uint32_t sz=(INSWORD>>22)&1, S=(INSWORD>>4)&1;
	if(!sz && !S && HasSME_F16F16()) return fmla_za_zzw(ctx, dec); // -> fmla_za_zzw_4x4_16
	if(!sz && S && HasSME_F16F16()) return fmls_za_zzw(ctx, dec); // -> fmls_za_zzw_4x4_16
	if(sz && !S && HasSME_B16B16()) return bfmla_za_zzw(ctx, dec); // -> bfmla_za_zzw_4x4_16
	if(sz && S && HasSME_B16B16()) return bfmls_za_zzw(ctx, dec); // -> bfmls_za_zzw_4x4_16
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_z_za_4way_dot_mm(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>4)&1;
	if(!U && HasSME2()) return sdot_za_zzw(ctx, dec); // -> sdot_za_zzw_4x4
	if(U && HasSME2()) return udot_za_zzw(ctx, dec); // -> udot_za_zzw_4x4
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_z_za_mixed_dot_mm(context *ctx, Instruction *dec)
{
	return usdot_za_zzw(ctx, dec);
}

int decode_iclass_mortlach_multi4_z_za_2way_dot_mm(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>4)&1;
	if(!U && HasSME2()) return sdot_za32_zzw(ctx, dec); // -> sdot_za32_zzw_4x4
	if(U && HasSME2()) return udot_za32_zzw(ctx, dec); // -> udot_za32_zzw_4x4
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_zz_za_float_mm(context *ctx, Instruction *dec)
{
	uint32_t S=(INSWORD>>3)&1;
	if(!S && HasSME2()) return fmla_za_zzw(ctx, dec); // -> fmla_za_zzw_4x4
	if(S && HasSME2()) return fmls_za_zzw(ctx, dec); // -> fmls_za_zzw_4x4
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_zz_za_int_mm(context *ctx, Instruction *dec)
{
	uint32_t S=(INSWORD>>3)&1;
	if(!S && HasSME2()) return add_za_zzw(ctx, dec); // -> add_za_zzw_4x4
	if(S && HasSME2()) return sub_za_zzw(ctx, dec); // -> sub_za_zzw_4x4
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_z_za_float_mm(context *ctx, Instruction *dec)
{
	uint32_t S=(INSWORD>>3)&1;
	if(!S && HasSME2()) return fadd_za_zw(ctx, dec); // -> fadd_za_zw_4x4
	if(S && HasSME2()) return fsub_za_zw(ctx, dec); // -> fsub_za_zw_4x4
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_z_za_int_mm(context *ctx, Instruction *dec)
{
	uint32_t S=(INSWORD>>3)&1;
	if(!S && HasSME2()) return add_za_zw(ctx, dec); // -> add_za_zw_4x4
	if(S && HasSME2()) return sub_za_zw(ctx, dec); // -> sub_za_zw_4x4
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_z_za_f16_mm(context *ctx, Instruction *dec)
{
	uint32_t sz=(INSWORD>>22)&1, S=(INSWORD>>3)&1;
	if(!sz && !S && HasSME_F16F16() && HasSME_F8F16()) return fadd_za_zw(ctx, dec); // -> fadd_za_zw_4x4_16
	if(!sz && S && HasSME_F16F16() && HasSME_F8F16()) return fsub_za_zw(ctx, dec); // -> fsub_za_zw_4x4_16
	if(sz && !S && HasSME_B16B16()) return bfadd_za_zw(ctx, dec); // -> bfadd_za_zw_4x4_16
	if(sz && S && HasSME_B16B16()) return bfsub_za_zw(ctx, dec); // -> bfsub_za_zw_4x4_16
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_zz_za_mla_long_long_mm(context *ctx, Instruction *dec)
{
	uint32_t sz=(INSWORD>>22)&1, U=(INSWORD>>4)&1, S=(INSWORD>>3)&1, op=(INSWORD>>2)&1;
	if(!sz && !U && !S && op && HasSME2()) return usmlall_za_zzw(ctx, dec); // -> usmlall_za_zzw_s2x2
	if(!sz && !U && S && op) UNALLOCATED(ENC_UNALLOCATED_743_MORTLACH_MULTI2_ZZ_ZA_MLA_LONG_LONG_MM);
	if(!U && !S && !op && HasSME2()) return smlall_za_zzw(ctx, dec); // -> smlall_za_zzw_2x2
	if(!U && S && !op && HasSME2()) return smlsll_za_zzw(ctx, dec); // -> smlsll_za_zzw_2x2
	if(U && !S && !op && HasSME2()) return umlall_za_zzw(ctx, dec); // -> umlall_za_zzw_2x2
	if(U && S && !op && HasSME2()) return umlsll_za_zzw(ctx, dec); // -> umlsll_za_zzw_2x2
	if(!sz && U && op) UNALLOCATED(ENC_UNALLOCATED_742_MORTLACH_MULTI2_ZZ_ZA_MLA_LONG_LONG_MM);
	if(sz && op) UNALLOCATED(ENC_UNALLOCATED_741_MORTLACH_MULTI2_ZZ_ZA_MLA_LONG_LONG_MM);
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_zz_za_fp8_fma_long_long_mm(context *ctx, Instruction *dec)
{
	return fmlall_za32_z8z8w(ctx, dec);
}

int decode_iclass_mortlach_multi2_zz_za_fma_long_mm(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>4)&1, S=(INSWORD>>3)&1;
	if(!op && !S && HasSME2()) return fmlal_za_zzw(ctx, dec); // -> fmlal_za_zzw_2x2
	if(!op && S && HasSME2()) return fmlsl_za_zzw(ctx, dec); // -> fmlsl_za_zzw_2x2
	if(op && !S && HasSME2()) return bfmlal_za_zzw(ctx, dec); // -> bfmlal_za_zzw_2x2
	if(op && S && HasSME2()) return bfmlsl_za_zzw(ctx, dec); // -> bfmlsl_za_zzw_2x2
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_zz_za_fp8_fma_long_mm(context *ctx, Instruction *dec)
{
	return fmlal_za_z8z8w(ctx, dec);
}

int decode_iclass_mortlach_multi2_zz_za_mla_long_mm(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>4)&1, S=(INSWORD>>3)&1;
	if(!U && !S && HasSME2()) return smlal_za_zzw(ctx, dec); // -> smlal_za_zzw_2x2
	if(!U && S && HasSME2()) return smlsl_za_zzw(ctx, dec); // -> smlsl_za_zzw_2x2
	if(U && !S && HasSME2()) return umlal_za_zzw(ctx, dec); // -> umlal_za_zzw_2x2
	if(U && S && HasSME2()) return umlsl_za_zzw(ctx, dec); // -> umlsl_za_zzw_2x2
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_z_za_fpdot_mm(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>4)&3;
	if(!opc && HasSME2()) return fdot_za_zzw(ctx, dec); // -> fdot_za_zzw_2x2
	if(opc==1 && HasSME2()) return bfdot_za_zzw(ctx, dec); // -> bfdot_za_zzw_2x2
	if(opc==2 && HasSME_F8F16()) return fdot_za_z8z8w(ctx, dec); // -> fdot_za_z8z8w_2x2
	if(opc==3 && HasSME_F8F32()) return fdot_za32_z8z8w(ctx, dec); // -> fdot_za32_z8z8w_2x2
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_zz_za_f16_mm(context *ctx, Instruction *dec)
{
	uint32_t sz=(INSWORD>>22)&1, S=(INSWORD>>4)&1;
	if(!sz && !S && HasSME_F16F16()) return fmla_za_zzw(ctx, dec); // -> fmla_za_zzw_2x2_16
	if(!sz && S && HasSME_F16F16()) return fmls_za_zzw(ctx, dec); // -> fmls_za_zzw_2x2_16
	if(sz && !S && HasSME_B16B16()) return bfmla_za_zzw(ctx, dec); // -> bfmla_za_zzw_2x2_16
	if(sz && S && HasSME_B16B16()) return bfmls_za_zzw(ctx, dec); // -> bfmls_za_zzw_2x2_16
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_z_za_4way_dot_mm(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>4)&1;
	if(!U && HasSME2()) return sdot_za_zzw(ctx, dec); // -> sdot_za_zzw_2x2
	if(U && HasSME2()) return udot_za_zzw(ctx, dec); // -> udot_za_zzw_2x2
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_z_za_mixed_dot_mm(context *ctx, Instruction *dec)
{
	return usdot_za_zzw(ctx, dec);
}

int decode_iclass_mortlach_multi2_z_za_2way_dot_mm(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>4)&1;
	if(!U && HasSME2()) return sdot_za32_zzw(ctx, dec); // -> sdot_za32_zzw_2x2
	if(U && HasSME2()) return udot_za32_zzw(ctx, dec); // -> udot_za32_zzw_2x2
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_zz_za_float_mm(context *ctx, Instruction *dec)
{
	uint32_t S=(INSWORD>>3)&1;
	if(!S && HasSME2()) return fmla_za_zzw(ctx, dec); // -> fmla_za_zzw_2x2
	if(S && HasSME2()) return fmls_za_zzw(ctx, dec); // -> fmls_za_zzw_2x2
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_zz_za_int_mm(context *ctx, Instruction *dec)
{
	uint32_t S=(INSWORD>>3)&1;
	if(!S && HasSME2()) return add_za_zzw(ctx, dec); // -> add_za_zzw_2x2
	if(S && HasSME2()) return sub_za_zzw(ctx, dec); // -> sub_za_zzw_2x2
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_z_za_float_mm(context *ctx, Instruction *dec)
{
	uint32_t S=(INSWORD>>3)&1;
	if(!S && HasSME2()) return fadd_za_zw(ctx, dec); // -> fadd_za_zw_2x2
	if(S && HasSME2()) return fsub_za_zw(ctx, dec); // -> fsub_za_zw_2x2
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_z_za_int_mm(context *ctx, Instruction *dec)
{
	uint32_t S=(INSWORD>>3)&1;
	if(!S && HasSME2()) return add_za_zw(ctx, dec); // -> add_za_zw_2x2
	if(S && HasSME2()) return sub_za_zw(ctx, dec); // -> sub_za_zw_2x2
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_z_za_f16_mm(context *ctx, Instruction *dec)
{
	uint32_t sz=(INSWORD>>22)&1, S=(INSWORD>>3)&1;
	if(!sz && !S && HasSME_F16F16() && HasSME_F8F16()) return fadd_za_zw(ctx, dec); // -> fadd_za_zw_2x2_16
	if(!sz && S && HasSME_F16F16() && HasSME_F8F16()) return fsub_za_zw(ctx, dec); // -> fsub_za_zw_2x2_16
	if(sz && !S && HasSME_B16B16()) return bfadd_za_zw(ctx, dec); // -> bfadd_za_zw_2x2_16
	if(sz && S && HasSME_B16B16()) return bfsub_za_zw(ctx, dec); // -> bfsub_za_zw_2x2_16
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_z_z_minmax_mm(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>5)&3, U=INSWORD&1;
	if(!opc && !U && HasSME2()) return smax_mz_zzw(ctx, dec); // -> smax_mz_zzw_4x4
	if(!opc && U && HasSME2()) return umax_mz_zzw(ctx, dec); // -> umax_mz_zzw_4x4
	if(opc==1 && !U && HasSME2()) return smin_mz_zzw(ctx, dec); // -> smin_mz_zzw_4x4
	if(opc==1 && U && HasSME2()) return umin_mz_zzw(ctx, dec); // -> umin_mz_zzw_4x4
	if((opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_744_MORTLACH_MULTI4_Z_Z_MINMAX_MM);
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_z_z_fminmax_mm(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, opc=(INSWORD>>5)&3, o2=INSWORD&1;
	if(!size && !opc && !o2 && HasSME2() && HasSVE_B16B16()) return bfmax_mz_zzw(ctx, dec); // -> bfmax_mz_zzw_4x4
	if(!size && !opc && o2 && HasSME2() && HasSVE_B16B16()) return bfmin_mz_zzw(ctx, dec); // -> bfmin_mz_zzw_4x4
	if(!size && opc==1 && !o2 && HasSME2() && HasSVE_B16B16()) return bfmaxnm_mz_zzw(ctx, dec); // -> bfmaxnm_mz_zzw_4x4
	if(!size && opc==1 && o2 && HasSME2() && HasSVE_B16B16()) return bfminnm_mz_zzw(ctx, dec); // -> bfminnm_mz_zzw_4x4
	if(size && !opc && !o2 && HasSME2()) return fmax_mz_zzw(ctx, dec); // -> fmax_mz_zzw_4x4
	if(size && !opc && o2 && HasSME2()) return fmin_mz_zzw(ctx, dec); // -> fmin_mz_zzw_4x4
	if(size && opc==1 && !o2 && HasSME2()) return fmaxnm_mz_zzw(ctx, dec); // -> fmaxnm_mz_zzw_4x4
	if(size && opc==1 && o2 && HasSME2()) return fminnm_mz_zzw(ctx, dec); // -> fminnm_mz_zzw_4x4
	if(opc==2 && !o2 && HasSME2() && HasFAMINMAX()) return famax_mz_zzw(ctx, dec); // -> famax_mz_zzw_4x4
	if(opc==2 && o2 && HasSME2() && HasFAMINMAX()) return famin_mz_zzw(ctx, dec); // -> famin_mz_zzw_4x4
	if(opc==3) UNALLOCATED(ENC_UNALLOCATED_745_MORTLACH_MULTI4_Z_Z_FMINMAX_MM);
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_z_z_fscale_mm(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, opc=(INSWORD>>5)&3, o2=INSWORD&1;
	if(!size && !opc && !o2 && HasSME2() && HasSVE_BFSCALE()) return bfscale_mz_zzw(ctx, dec); // -> bfscale_mz_zzw_4x4
	if(size && !opc && !o2 && HasSME2() && HasFP8()) return fscale_mz_zzw(ctx, dec); // -> fscale_mz_zzw_4x4
	if(!opc && o2) UNALLOCATED(ENC_UNALLOCATED_747_MORTLACH_MULTI4_Z_Z_FSCALE_MM);
	if(opc) UNALLOCATED(ENC_UNALLOCATED_746_MORTLACH_MULTI4_Z_Z_FSCALE_MM);
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_z_z_shift_mm(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>5)&7, U=INSWORD&1;
	if(opc==1 && !U && HasSME2()) return srshl_mz_zzw(ctx, dec); // -> srshl_mz_zzw_4x4
	if(opc==1 && U && HasSME2()) return urshl_mz_zzw(ctx, dec); // -> urshl_mz_zzw_4x4
	if(opc!=1) UNALLOCATED(ENC_UNALLOCATED_748_MORTLACH_MULTI4_Z_Z_SHIFT_MM);
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_z_z_minmax_mm(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>5)&3, U=INSWORD&1;
	if(!opc && !U && HasSME2()) return smax_mz_zzw(ctx, dec); // -> smax_mz_zzw_2x2
	if(!opc && U && HasSME2()) return umax_mz_zzw(ctx, dec); // -> umax_mz_zzw_2x2
	if(opc==1 && !U && HasSME2()) return smin_mz_zzw(ctx, dec); // -> smin_mz_zzw_2x2
	if(opc==1 && U && HasSME2()) return umin_mz_zzw(ctx, dec); // -> umin_mz_zzw_2x2
	if((opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_749_MORTLACH_MULTI2_Z_Z_MINMAX_MM);
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_z_z_fminmax_mm(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, opc=(INSWORD>>5)&3, o2=INSWORD&1;
	if(!size && !opc && !o2 && HasSME2() && HasSVE_B16B16()) return bfmax_mz_zzw(ctx, dec); // -> bfmax_mz_zzw_2x2
	if(!size && !opc && o2 && HasSME2() && HasSVE_B16B16()) return bfmin_mz_zzw(ctx, dec); // -> bfmin_mz_zzw_2x2
	if(!size && opc==1 && !o2 && HasSME2() && HasSVE_B16B16()) return bfmaxnm_mz_zzw(ctx, dec); // -> bfmaxnm_mz_zzw_2x2
	if(!size && opc==1 && o2 && HasSME2() && HasSVE_B16B16()) return bfminnm_mz_zzw(ctx, dec); // -> bfminnm_mz_zzw_2x2
	if(size && !opc && !o2 && HasSME2()) return fmax_mz_zzw(ctx, dec); // -> fmax_mz_zzw_2x2
	if(size && !opc && o2 && HasSME2()) return fmin_mz_zzw(ctx, dec); // -> fmin_mz_zzw_2x2
	if(size && opc==1 && !o2 && HasSME2()) return fmaxnm_mz_zzw(ctx, dec); // -> fmaxnm_mz_zzw_2x2
	if(size && opc==1 && o2 && HasSME2()) return fminnm_mz_zzw(ctx, dec); // -> fminnm_mz_zzw_2x2
	if(opc==2 && !o2 && HasSME2() && HasFAMINMAX()) return famax_mz_zzw(ctx, dec); // -> famax_mz_zzw_2x2
	if(opc==2 && o2 && HasSME2() && HasFAMINMAX()) return famin_mz_zzw(ctx, dec); // -> famin_mz_zzw_2x2
	if(opc==3) UNALLOCATED(ENC_UNALLOCATED_750_MORTLACH_MULTI2_Z_Z_FMINMAX_MM);
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_z_z_fscale_mm(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, opc=(INSWORD>>5)&3, o2=INSWORD&1;
	if(!size && !opc && !o2 && HasSME2() && HasSVE_BFSCALE()) return bfscale_mz_zzw(ctx, dec); // -> bfscale_mz_zzw_2x2
	if(size && !opc && !o2 && HasSME2() && HasFP8()) return fscale_mz_zzw(ctx, dec); // -> fscale_mz_zzw_2x2
	if(!opc && o2) UNALLOCATED(ENC_UNALLOCATED_752_MORTLACH_MULTI2_Z_Z_FSCALE_MM);
	if(opc) UNALLOCATED(ENC_UNALLOCATED_751_MORTLACH_MULTI2_Z_Z_FSCALE_MM);
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_z_z_shift_mm(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>5)&7, U=INSWORD&1;
	if(opc==1 && !U && HasSME2()) return srshl_mz_zzw(ctx, dec); // -> srshl_mz_zzw_2x2
	if(opc==1 && U && HasSME2()) return urshl_mz_zzw(ctx, dec); // -> urshl_mz_zzw_2x2
	if(opc!=1) UNALLOCATED(ENC_UNALLOCATED_753_MORTLACH_MULTI2_Z_Z_SHIFT_MM);
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_z_z_sqdmulh_mm(context *ctx, Instruction *dec)
{
	uint32_t op=INSWORD&1;
	if(!op && HasSME2()) return sqdmulh_mz_zzw(ctx, dec); // -> sqdmulh_mz_zzw_4x4
	if(op) UNALLOCATED(ENC_UNALLOCATED_754_MORTLACH_MULTI4_Z_Z_SQDMULH_MM);
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_z_z_sqdmulh_mm(context *ctx, Instruction *dec)
{
	uint32_t op=INSWORD&1;
	if(!op && HasSME2()) return sqdmulh_mz_zzw(ctx, dec); // -> sqdmulh_mz_zzw_2x2
	if(op) UNALLOCATED(ENC_UNALLOCATED_755_MORTLACH_MULTI2_Z_Z_SQDMULH_MM);
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_zz_za_mla_long_long_sm(context *ctx, Instruction *dec)
{
	uint32_t sz=(INSWORD>>22)&1, U=(INSWORD>>4)&1, S=(INSWORD>>3)&1, op=(INSWORD>>2)&1;
	if(!sz && !U && !S && op && HasSME2()) return usmlall_za_zzv(ctx, dec); // -> usmlall_za_zzv_s4x1
	if(!sz && U && !S && op && HasSME2()) return sumlall_za_zzv(ctx, dec); // -> sumlall_za_zzv_s4x1
	if(!U && !S && !op && HasSME2()) return smlall_za_zzv(ctx, dec); // -> smlall_za_zzv_4x1
	if(!U && S && !op && HasSME2()) return smlsll_za_zzv(ctx, dec); // -> smlsll_za_zzv_4x1
	if(U && !S && !op && HasSME2()) return umlall_za_zzv(ctx, dec); // -> umlall_za_zzv_4x1
	if(U && S && !op && HasSME2()) return umlsll_za_zzv(ctx, dec); // -> umlsll_za_zzv_4x1
	if(!sz && S && op) UNALLOCATED(ENC_UNALLOCATED_757_MORTLACH_MULTI4_ZZ_ZA_MLA_LONG_LONG_SM);
	if(sz && op) UNALLOCATED(ENC_UNALLOCATED_756_MORTLACH_MULTI4_ZZ_ZA_MLA_LONG_LONG_SM);
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_zz_za_fp8_fma_long_long_sm(context *ctx, Instruction *dec)
{
	return fmlall_za32_z8z8v(ctx, dec);
}

int decode_iclass_mortlach_multi1_zz_za_fp8_fma_long_long_sm(context *ctx, Instruction *dec)
{
	return fmlall_za32_z8z8v(ctx, dec);
}

int decode_iclass_mortlach_multi4_zz_za_fma_long_sm(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>4)&1, S=(INSWORD>>3)&1, o2=(INSWORD>>2)&1;
	if(!op && !S && !o2 && HasSME2()) return fmlal_za_zzv(ctx, dec); // -> fmlal_za_zzv_4x1
	if(!op && !S && o2 && HasSME_F8F16()) return fmlal_za_z8z8v(ctx, dec); // -> fmlal_za_z8z8v_4x1
	if(!op && S && !o2 && HasSME2()) return fmlsl_za_zzv(ctx, dec); // -> fmlsl_za_zzv_4x1
	if(!op && S && o2) UNALLOCATED(ENC_UNALLOCATED_759_MORTLACH_MULTI4_ZZ_ZA_FMA_LONG_SM);
	if(op && !S && !o2 && HasSME2()) return bfmlal_za_zzv(ctx, dec); // -> bfmlal_za_zzv_4x1
	if(op && S && !o2 && HasSME2()) return bfmlsl_za_zzv(ctx, dec); // -> bfmlsl_za_zzv_4x1
	if(op && o2) UNALLOCATED(ENC_UNALLOCATED_758_MORTLACH_MULTI4_ZZ_ZA_FMA_LONG_SM);
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_zz_za_mla_long_sm(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>4)&1, S=(INSWORD>>3)&1, op=(INSWORD>>2)&1;
	if(!U && !S && !op && HasSME2()) return smlal_za_zzv(ctx, dec); // -> smlal_za_zzv_4x1
	if(!U && S && !op && HasSME2()) return smlsl_za_zzv(ctx, dec); // -> smlsl_za_zzv_4x1
	if(U && !S && !op && HasSME2()) return umlal_za_zzv(ctx, dec); // -> umlal_za_zzv_4x1
	if(U && S && !op && HasSME2()) return umlsl_za_zzv(ctx, dec); // -> umlsl_za_zzv_4x1
	if(op) UNALLOCATED(ENC_UNALLOCATED_760_MORTLACH_MULTI4_ZZ_ZA_MLA_LONG_SM);
	UNMATCHED;
}

int decode_iclass_mortlach_multi1_zz_za_fp8_fma_long_sm(context *ctx, Instruction *dec)
{
	return fmlal_za_z8z8v(ctx, dec);
}

int decode_iclass_mortlach_multi4_z_za_fpdot_sm(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>3)&3;
	if(!opc && HasSME2()) return fdot_za_zzv(ctx, dec); // -> fdot_za_zzv_4x1
	if(opc==1 && HasSME_F8F16()) return fdot_za_z8z8v(ctx, dec); // -> fdot_za_z8z8v_4x1
	if(opc==2 && HasSME2()) return bfdot_za_zzv(ctx, dec); // -> bfdot_za_zzv_4x1
	if(opc==3 && HasSME_F8F32()) return fdot_za32_z8z8v(ctx, dec); // -> fdot_za32_z8z8v_4x1
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_z_za_4way_dot_sm(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>4)&1;
	if(!U && HasSME2()) return sdot_za_zzv(ctx, dec); // -> sdot_za_zzv_4x1
	if(U && HasSME2()) return udot_za_zzv(ctx, dec); // -> udot_za_zzv_4x1
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_z_za_mixed_dot_sm(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>4)&1;
	if(!U && HasSME2()) return usdot_za_zzv(ctx, dec); // -> usdot_za_zzv_s4x1
	if(U && HasSME2()) return sudot_za_zzv(ctx, dec); // -> sudot_za_zzv_s4x1
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_z_za_2way_dot_sm(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>4)&1;
	if(!U && HasSME2()) return sdot_za32_zzv(ctx, dec); // -> sdot_za32_zzv_4x1
	if(U && HasSME2()) return udot_za32_zzv(ctx, dec); // -> udot_za32_zzv_4x1
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_zz_za_float_sm(context *ctx, Instruction *dec)
{
	uint32_t S=(INSWORD>>3)&1;
	if(!S && HasSME2()) return fmla_za_zzv(ctx, dec); // -> fmla_za_zzv_4x1
	if(S && HasSME2()) return fmls_za_zzv(ctx, dec); // -> fmls_za_zzv_4x1
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_zz_za_int_sm(context *ctx, Instruction *dec)
{
	uint32_t S=(INSWORD>>3)&1;
	if(!S && HasSME2()) return add_za_zzv(ctx, dec); // -> add_za_zzv_4x1
	if(S && HasSME2()) return sub_za_zzv(ctx, dec); // -> sub_za_zzv_4x1
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_zz_za_f16_sm(context *ctx, Instruction *dec)
{
	uint32_t sz=(INSWORD>>22)&1, S=(INSWORD>>3)&1;
	if(!sz && !S && HasSME_F16F16()) return fmla_za_zzv(ctx, dec); // -> fmla_za_zzv_4x1_16
	if(!sz && S && HasSME_F16F16()) return fmls_za_zzv(ctx, dec); // -> fmls_za_zzv_4x1_16
	if(sz && !S && HasSME_B16B16()) return bfmla_za_zzv(ctx, dec); // -> bfmla_za_zzv_4x1_16
	if(sz && S && HasSME_B16B16()) return bfmls_za_zzv(ctx, dec); // -> bfmls_za_zzv_4x1_16
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_zz_za_mla_long_long_sm(context *ctx, Instruction *dec)
{
	uint32_t sz=(INSWORD>>22)&1, U=(INSWORD>>4)&1, S=(INSWORD>>3)&1, op=(INSWORD>>2)&1;
	if(!sz && !U && !S && op && HasSME2()) return usmlall_za_zzv(ctx, dec); // -> usmlall_za_zzv_s2x1
	if(!sz && U && !S && op && HasSME2()) return sumlall_za_zzv(ctx, dec); // -> sumlall_za_zzv_s2x1
	if(!U && !S && !op && HasSME2()) return smlall_za_zzv(ctx, dec); // -> smlall_za_zzv_2x1
	if(!U && S && !op && HasSME2()) return smlsll_za_zzv(ctx, dec); // -> smlsll_za_zzv_2x1
	if(U && !S && !op && HasSME2()) return umlall_za_zzv(ctx, dec); // -> umlall_za_zzv_2x1
	if(U && S && !op && HasSME2()) return umlsll_za_zzv(ctx, dec); // -> umlsll_za_zzv_2x1
	if(!sz && S && op) UNALLOCATED(ENC_UNALLOCATED_762_MORTLACH_MULTI2_ZZ_ZA_MLA_LONG_LONG_SM);
	if(sz && op) UNALLOCATED(ENC_UNALLOCATED_761_MORTLACH_MULTI2_ZZ_ZA_MLA_LONG_LONG_SM);
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_zz_za_fp8_fma_long_long_sm(context *ctx, Instruction *dec)
{
	return fmlall_za32_z8z8v(ctx, dec);
}

int decode_iclass_mortlach_multi1_zz_za_mla_long_long_sm(context *ctx, Instruction *dec)
{
	uint32_t sz=(INSWORD>>22)&1, U=(INSWORD>>4)&1, S=(INSWORD>>3)&1, op=(INSWORD>>2)&1;
	if(!sz && !U && !S && op && HasSME2()) return usmlall_za_zzv(ctx, dec); // -> usmlall_za_zzv_s
	if(!sz && !U && S && op) UNALLOCATED(ENC_UNALLOCATED_765_MORTLACH_MULTI1_ZZ_ZA_MLA_LONG_LONG_SM);
	if(!U && !S && !op && HasSME2()) return smlall_za_zzv(ctx, dec); // -> smlall_za_zzv_1
	if(!U && S && !op && HasSME2()) return smlsll_za_zzv(ctx, dec); // -> smlsll_za_zzv_1
	if(U && !S && !op && HasSME2()) return umlall_za_zzv(ctx, dec); // -> umlall_za_zzv_1
	if(U && S && !op && HasSME2()) return umlsll_za_zzv(ctx, dec); // -> umlsll_za_zzv_1
	if(!sz && U && op) UNALLOCATED(ENC_UNALLOCATED_764_MORTLACH_MULTI1_ZZ_ZA_MLA_LONG_LONG_SM);
	if(sz && op) UNALLOCATED(ENC_UNALLOCATED_763_MORTLACH_MULTI1_ZZ_ZA_MLA_LONG_LONG_SM);
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_zz_za_fma_long_sm(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>4)&1, S=(INSWORD>>3)&1, o2=(INSWORD>>2)&1;
	if(!op && !S && !o2 && HasSME2()) return fmlal_za_zzv(ctx, dec); // -> fmlal_za_zzv_2x1
	if(!op && !S && o2 && HasSME_F8F16()) return fmlal_za_z8z8v(ctx, dec); // -> fmlal_za_z8z8v_2x1
	if(!op && S && !o2 && HasSME2()) return fmlsl_za_zzv(ctx, dec); // -> fmlsl_za_zzv_2x1
	if(!op && S && o2) UNALLOCATED(ENC_UNALLOCATED_767_MORTLACH_MULTI2_ZZ_ZA_FMA_LONG_SM);
	if(op && !S && !o2 && HasSME2()) return bfmlal_za_zzv(ctx, dec); // -> bfmlal_za_zzv_2x1
	if(op && S && !o2 && HasSME2()) return bfmlsl_za_zzv(ctx, dec); // -> bfmlsl_za_zzv_2x1
	if(op && o2) UNALLOCATED(ENC_UNALLOCATED_766_MORTLACH_MULTI2_ZZ_ZA_FMA_LONG_SM);
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_zz_za_mla_long_sm(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>4)&1, S=(INSWORD>>3)&1, op=(INSWORD>>2)&1;
	if(!U && !S && !op && HasSME2()) return smlal_za_zzv(ctx, dec); // -> smlal_za_zzv_2x1
	if(!U && S && !op && HasSME2()) return smlsl_za_zzv(ctx, dec); // -> smlsl_za_zzv_2x1
	if(U && !S && !op && HasSME2()) return umlal_za_zzv(ctx, dec); // -> umlal_za_zzv_2x1
	if(U && S && !op && HasSME2()) return umlsl_za_zzv(ctx, dec); // -> umlsl_za_zzv_2x1
	if(op) UNALLOCATED(ENC_UNALLOCATED_768_MORTLACH_MULTI2_ZZ_ZA_MLA_LONG_SM);
	UNMATCHED;
}

int decode_iclass_mortlach_multi1_zz_za_fma_long_sm(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>4)&1, S=(INSWORD>>3)&1;
	if(!op && !S && HasSME2()) return fmlal_za_zzv(ctx, dec); // -> fmlal_za_zzv_1
	if(!op && S && HasSME2()) return fmlsl_za_zzv(ctx, dec); // -> fmlsl_za_zzv_1
	if(op && !S && HasSME2()) return bfmlal_za_zzv(ctx, dec); // -> bfmlal_za_zzv_1
	if(op && S && HasSME2()) return bfmlsl_za_zzv(ctx, dec); // -> bfmlsl_za_zzv_1
	UNMATCHED;
}

int decode_iclass_mortlach_multi1_zz_za_mla_long_sm(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>4)&1, S=(INSWORD>>3)&1;
	if(!U && !S && HasSME2()) return smlal_za_zzv(ctx, dec); // -> smlal_za_zzv_1
	if(!U && S && HasSME2()) return smlsl_za_zzv(ctx, dec); // -> smlsl_za_zzv_1
	if(U && !S && HasSME2()) return umlal_za_zzv(ctx, dec); // -> umlal_za_zzv_1
	if(U && S && HasSME2()) return umlsl_za_zzv(ctx, dec); // -> umlsl_za_zzv_1
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_z_za_fpdot_sm(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>3)&3;
	if(!opc && HasSME2()) return fdot_za_zzv(ctx, dec); // -> fdot_za_zzv_2x1
	if(opc==1 && HasSME_F8F16()) return fdot_za_z8z8v(ctx, dec); // -> fdot_za_z8z8v_2x1
	if(opc==2 && HasSME2()) return bfdot_za_zzv(ctx, dec); // -> bfdot_za_zzv_2x1
	if(opc==3 && HasSME_F8F32()) return fdot_za32_z8z8v(ctx, dec); // -> fdot_za32_z8z8v_2x1
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_z_za_4way_dot_sm(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>4)&1;
	if(!U && HasSME2()) return sdot_za_zzv(ctx, dec); // -> sdot_za_zzv_2x1
	if(U && HasSME2()) return udot_za_zzv(ctx, dec); // -> udot_za_zzv_2x1
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_z_za_mixed_dot_sm(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>4)&1;
	if(!U && HasSME2()) return usdot_za_zzv(ctx, dec); // -> usdot_za_zzv_s2x1
	if(U && HasSME2()) return sudot_za_zzv(ctx, dec); // -> sudot_za_zzv_s2x1
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_z_za_2way_dot_sm(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>4)&1;
	if(!U && HasSME2()) return sdot_za32_zzv(ctx, dec); // -> sdot_za32_zzv_2x1
	if(U && HasSME2()) return udot_za32_zzv(ctx, dec); // -> udot_za32_zzv_2x1
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_zz_za_float_sm(context *ctx, Instruction *dec)
{
	uint32_t S=(INSWORD>>3)&1;
	if(!S && HasSME2()) return fmla_za_zzv(ctx, dec); // -> fmla_za_zzv_2x1
	if(S && HasSME2()) return fmls_za_zzv(ctx, dec); // -> fmls_za_zzv_2x1
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_zz_za_int_sm(context *ctx, Instruction *dec)
{
	uint32_t S=(INSWORD>>3)&1;
	if(!S && HasSME2()) return add_za_zzv(ctx, dec); // -> add_za_zzv_2x1
	if(S && HasSME2()) return sub_za_zzv(ctx, dec); // -> sub_za_zzv_2x1
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_zz_za_f16_sm(context *ctx, Instruction *dec)
{
	uint32_t sz=(INSWORD>>22)&1, S=(INSWORD>>3)&1;
	if(!sz && !S && HasSME_F16F16()) return fmla_za_zzv(ctx, dec); // -> fmla_za_zzv_2x1_16
	if(!sz && S && HasSME_F16F16()) return fmls_za_zzv(ctx, dec); // -> fmls_za_zzv_2x1_16
	if(sz && !S && HasSME_B16B16()) return bfmla_za_zzv(ctx, dec); // -> bfmla_za_zzv_2x1_16
	if(sz && S && HasSME_B16B16()) return bfmls_za_zzv(ctx, dec); // -> bfmls_za_zzv_2x1_16
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_z_z_minmax_sm(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>5)&1, U=INSWORD&1;
	if(!op && !U && HasSME2()) return smax_mz_zzv(ctx, dec); // -> smax_mz_zzv_4x1
	if(!op && U && HasSME2()) return umax_mz_zzv(ctx, dec); // -> umax_mz_zzv_4x1
	if(op && !U && HasSME2()) return smin_mz_zzv(ctx, dec); // -> smin_mz_zzv_4x1
	if(op && U && HasSME2()) return umin_mz_zzv(ctx, dec); // -> umin_mz_zzv_4x1
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_z_z_fminmax_sm(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, op=(INSWORD>>5)&1, o2=INSWORD&1;
	if(!size && !op && !o2 && HasSME2() && HasSVE_B16B16()) return bfmax_mz_zzv(ctx, dec); // -> bfmax_mz_zzv_4x1
	if(!size && !op && o2 && HasSME2() && HasSVE_B16B16()) return bfmin_mz_zzv(ctx, dec); // -> bfmin_mz_zzv_4x1
	if(!size && op && !o2 && HasSME2() && HasSVE_B16B16()) return bfmaxnm_mz_zzv(ctx, dec); // -> bfmaxnm_mz_zzv_4x1
	if(!size && op && o2 && HasSME2() && HasSVE_B16B16()) return bfminnm_mz_zzv(ctx, dec); // -> bfminnm_mz_zzv_4x1
	if(size && !op && !o2 && HasSME2()) return fmax_mz_zzv(ctx, dec); // -> fmax_mz_zzv_4x1
	if(size && !op && o2 && HasSME2()) return fmin_mz_zzv(ctx, dec); // -> fmin_mz_zzv_4x1
	if(size && op && !o2 && HasSME2()) return fmaxnm_mz_zzv(ctx, dec); // -> fmaxnm_mz_zzv_4x1
	if(size && op && o2 && HasSME2()) return fminnm_mz_zzv(ctx, dec); // -> fminnm_mz_zzv_4x1
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_z_z_fscale_sm(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, op=INSWORD&1;
	if(!size && !op && HasSME2() && HasSVE_BFSCALE()) return bfscale_mz_zzv(ctx, dec); // -> bfscale_mz_zzv_4x1
	if(size && !op && HasSME2() && HasFP8()) return fscale_mz_zzv(ctx, dec); // -> fscale_mz_zzv_4x1
	if(op) UNALLOCATED(ENC_UNALLOCATED_769_MORTLACH_MULTI4_Z_Z_FSCALE_SM);
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_z_z_shift_sm(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>5)&7, U=INSWORD&1;
	if(opc==1 && !U && HasSME2()) return srshl_mz_zzv(ctx, dec); // -> srshl_mz_zzv_4x1
	if(opc==1 && U && HasSME2()) return urshl_mz_zzv(ctx, dec); // -> urshl_mz_zzv_4x1
	if(opc!=1) UNALLOCATED(ENC_UNALLOCATED_770_MORTLACH_MULTI4_Z_Z_SHIFT_SM);
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_z_z_add_sm(context *ctx, Instruction *dec)
{
	uint32_t op=INSWORD&1;
	if(!op && HasSME2()) return add_mz_zzv(ctx, dec); // -> add_mz_zzv_4x1
	if(op) UNALLOCATED(ENC_UNALLOCATED_771_MORTLACH_MULTI4_Z_Z_ADD_SM);
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_z_z_sqdmulh_sm(context *ctx, Instruction *dec)
{
	uint32_t op=INSWORD&1;
	if(!op && HasSME2()) return sqdmulh_mz_zzv(ctx, dec); // -> sqdmulh_mz_zzv_4x1
	if(op) UNALLOCATED(ENC_UNALLOCATED_772_MORTLACH_MULTI4_Z_Z_SQDMULH_SM);
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_z_z_minmax_sm(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>5)&1, U=INSWORD&1;
	if(!op && !U && HasSME2()) return smax_mz_zzv(ctx, dec); // -> smax_mz_zzv_2x1
	if(!op && U && HasSME2()) return umax_mz_zzv(ctx, dec); // -> umax_mz_zzv_2x1
	if(op && !U && HasSME2()) return smin_mz_zzv(ctx, dec); // -> smin_mz_zzv_2x1
	if(op && U && HasSME2()) return umin_mz_zzv(ctx, dec); // -> umin_mz_zzv_2x1
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_z_z_fminmax_sm(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, op=(INSWORD>>5)&1, o2=INSWORD&1;
	if(!size && !op && !o2 && HasSME2() && HasSVE_B16B16()) return bfmax_mz_zzv(ctx, dec); // -> bfmax_mz_zzv_2x1
	if(!size && !op && o2 && HasSME2() && HasSVE_B16B16()) return bfmin_mz_zzv(ctx, dec); // -> bfmin_mz_zzv_2x1
	if(!size && op && !o2 && HasSME2() && HasSVE_B16B16()) return bfmaxnm_mz_zzv(ctx, dec); // -> bfmaxnm_mz_zzv_2x1
	if(!size && op && o2 && HasSME2() && HasSVE_B16B16()) return bfminnm_mz_zzv(ctx, dec); // -> bfminnm_mz_zzv_2x1
	if(size && !op && !o2 && HasSME2()) return fmax_mz_zzv(ctx, dec); // -> fmax_mz_zzv_2x1
	if(size && !op && o2 && HasSME2()) return fmin_mz_zzv(ctx, dec); // -> fmin_mz_zzv_2x1
	if(size && op && !o2 && HasSME2()) return fmaxnm_mz_zzv(ctx, dec); // -> fmaxnm_mz_zzv_2x1
	if(size && op && o2 && HasSME2()) return fminnm_mz_zzv(ctx, dec); // -> fminnm_mz_zzv_2x1
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_z_z_fscale_sm(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, op=INSWORD&1;
	if(!size && !op && HasSME2() && HasSVE_BFSCALE()) return bfscale_mz_zzv(ctx, dec); // -> bfscale_mz_zzv_2x1
	if(size && !op && HasSME2() && HasFP8()) return fscale_mz_zzv(ctx, dec); // -> fscale_mz_zzv_2x1
	if(op) UNALLOCATED(ENC_UNALLOCATED_773_MORTLACH_MULTI2_Z_Z_FSCALE_SM);
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_z_z_shift_sm(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>5)&7, U=INSWORD&1;
	if(opc==1 && !U && HasSME2()) return srshl_mz_zzv(ctx, dec); // -> srshl_mz_zzv_2x1
	if(opc==1 && U && HasSME2()) return urshl_mz_zzv(ctx, dec); // -> urshl_mz_zzv_2x1
	if(opc!=1) UNALLOCATED(ENC_UNALLOCATED_774_MORTLACH_MULTI2_Z_Z_SHIFT_SM);
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_z_z_add_sm(context *ctx, Instruction *dec)
{
	uint32_t op=INSWORD&1;
	if(!op && HasSME2()) return add_mz_zzv(ctx, dec); // -> add_mz_zzv_2x1
	if(op) UNALLOCATED(ENC_UNALLOCATED_775_MORTLACH_MULTI2_Z_Z_ADD_SM);
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_z_z_sqdmulh_sm(context *ctx, Instruction *dec)
{
	uint32_t op=INSWORD&1;
	if(!op && HasSME2()) return sqdmulh_mz_zzv(ctx, dec); // -> sqdmulh_mz_zzv_2x1
	if(op) UNALLOCATED(ENC_UNALLOCATED_776_MORTLACH_MULTI2_Z_Z_SQDMULH_SM);
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_fclamp(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, op=INSWORD&1;
	if(!size && !op && HasSME2() && HasSVE_B16B16()) return bfclamp_mz_zz(ctx, dec); // -> bfclamp_mz_zz_2
	if(size && !op && HasSME2()) return fclamp_mz_zz(ctx, dec); // -> fclamp_mz_zz_2
	if(op) UNALLOCATED(ENC_UNALLOCATED_777_MORTLACH_MULTI2_FCLAMP);
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_clamp_int(context *ctx, Instruction *dec)
{
	uint32_t U=INSWORD&1;
	if(!U && HasSME2()) return sclamp_mz_zz(ctx, dec); // -> sclamp_mz_zz_2
	if(U && HasSME2()) return uclamp_mz_zz(ctx, dec); // -> uclamp_mz_zz_2
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_fclamp(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, op=INSWORD&1;
	if(!size && !op && HasSME2() && HasSVE_B16B16()) return bfclamp_mz_zz(ctx, dec); // -> bfclamp_mz_zz_4
	if(size && !op && HasSME2()) return fclamp_mz_zz(ctx, dec); // -> fclamp_mz_zz_4
	if(op) UNALLOCATED(ENC_UNALLOCATED_778_MORTLACH_MULTI4_FCLAMP);
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_clamp_int(context *ctx, Instruction *dec)
{
	uint32_t U=INSWORD&1;
	if(!U && HasSME2()) return sclamp_mz_zz(ctx, dec); // -> sclamp_mz_zz_4
	if(U && HasSME2()) return uclamp_mz_zz(ctx, dec); // -> uclamp_mz_zz_4
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_z_z_zip(context *ctx, Instruction *dec)
{
	uint32_t op=INSWORD&1;
	if(!op && HasSME2()) return zip_mz_zz(ctx, dec); // -> zip_mz_zz_2
	if(op && HasSME2()) return uzp_mz_zz(ctx, dec); // -> uzp_mz_zz_2
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_z_z_long_zip(context *ctx, Instruction *dec)
{
	uint32_t op=INSWORD&1;
	if(!op && HasSME2()) return zip_mz_zz(ctx, dec); // -> zip_mz_zz_2q
	if(op && HasSME2()) return uzp_mz_zz(ctx, dec); // -> uzp_mz_zz_2q
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_qrshr(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>20)&1, U=(INSWORD>>5)&1;
	if(!op && !U && HasSME2()) return sqrshr_z_mz2(ctx, dec); // -> sqrshr_z_mz2_
	if(!op && U && HasSME2()) return uqrshr_z_mz2(ctx, dec); // -> uqrshr_z_mz2_
	if(op && !U && HasSME2()) return sqrshru_z_mz2(ctx, dec); // -> sqrshru_z_mz2_
	if(op && U) UNALLOCATED(ENC_UNALLOCATED_779_MORTLACH_MULTI2_QRSHR);
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_qrshr(context *ctx, Instruction *dec)
{
	uint32_t N=(INSWORD>>10)&1, op=(INSWORD>>6)&1, U=(INSWORD>>5)&1;
	if(!N && !op && !U && HasSME2()) return sqrshr_z_mz4(ctx, dec); // -> sqrshr_z_mz4_
	if(!N && !op && U && HasSME2()) return uqrshr_z_mz4(ctx, dec); // -> uqrshr_z_mz4_
	if(!N && op && !U && HasSME2()) return sqrshru_z_mz4(ctx, dec); // -> sqrshru_z_mz4_
	if(N && !op && !U && HasSME2()) return sqrshrn_z_mz4(ctx, dec); // -> sqrshrn_z_mz4_
	if(N && !op && U && HasSME2()) return uqrshrn_z_mz4(ctx, dec); // -> uqrshrn_z_mz4_
	if(N && op && !U && HasSME2()) return sqrshrun_z_mz4(ctx, dec); // -> sqrshrun_z_mz4_
	if(op && U) UNALLOCATED(ENC_UNALLOCATED_780_MORTLACH_MULTI4_QRSHR);
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_narrow_fp_cvrt(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>22)&1, N=(INSWORD>>5)&1;
	if(!op && !N && HasSME2()) return fcvt_z_mz2(ctx, dec); // -> fcvt_z_mz2_
	if(!op && N && HasSME2()) return fcvtn_z_mz2(ctx, dec); // -> fcvtn_z_mz2_
	if(op && !N && HasSME2()) return bfcvt_z_mz2(ctx, dec); // -> bfcvt_z_mz2_
	if(op && N && HasSME2()) return bfcvtn_z_mz2(ctx, dec); // -> bfcvtn_z_mz2_
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_fpint_cvrt(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>5)&1;
	if(!U && HasSME2()) return fcvtzs_mz_z(ctx, dec); // -> fcvtzs_mz_z_2
	if(U && HasSME2()) return fcvtzu_mz_z(ctx, dec); // -> fcvtzu_mz_z_2
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_intfp_cvrt(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>5)&1;
	if(!U && HasSME2()) return scvtf_mz_z(ctx, dec); // -> scvtf_mz_z_2
	if(U && HasSME2()) return ucvtf_mz_z(ctx, dec); // -> ucvtf_mz_z_2
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_narrow_int_cvrt(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>22)&1, U=(INSWORD>>5)&1;
	if(!op && !U && HasSME2()) return sqcvt_z_mz2(ctx, dec); // -> sqcvt_z_mz2_
	if(!op && U && HasSME2()) return uqcvt_z_mz2(ctx, dec); // -> uqcvt_z_mz2_
	if(op && !U && HasSME2()) return sqcvtu_z_mz2(ctx, dec); // -> sqcvtu_z_mz2_
	if(op && U) UNALLOCATED(ENC_UNALLOCATED_781_MORTLACH_MULTI2_NARROW_INT_CVRT);
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_narrow_fp8_cvrt(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>22)&1;
	if(!op && HasSME2() && HasFP8()) return fcvt_z8_mz2(ctx, dec); // -> fcvt_z8_mz2_
	if(op && HasSME2() && HasFP8()) return bfcvt_z8_mz2(ctx, dec); // -> bfcvt_z8_mz2_
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_wide_int(context *ctx, Instruction *dec)
{
	uint32_t U=INSWORD&1;
	if(!U && HasSME2()) return sunpk_mz_z(ctx, dec); // -> sunpk_mz_z_2
	if(U && HasSME2()) return uunpk_mz_z(ctx, dec); // -> uunpk_mz_z_2
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_wide_fp8_cvrt(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>22)&3, L=INSWORD&1;
	if(!opc && !L && HasSME2() && HasFP8()) return f1cvt_mz2_z8(ctx, dec); // -> f1cvt_mz2_z8_
	if(!opc && L && HasSME2() && HasFP8()) return f1cvtl_mz2_z8(ctx, dec); // -> f1cvtl_mz2_z8_
	if(opc==1 && !L && HasSME2() && HasFP8()) return bf1cvt_mz2_z8(ctx, dec); // -> bf1cvt_mz2_z8_
	if(opc==1 && L && HasSME2() && HasFP8()) return bf1cvtl_mz2_z8(ctx, dec); // -> bf1cvtl_mz2_z8_
	if(opc==2 && !L && HasSME2() && HasFP8()) return f1cvt_mz2_z8(ctx, dec); // -> f2cvt_mz2_z8_
	if(opc==2 && L && HasSME2() && HasFP8()) return f1cvtl_mz2_z8(ctx, dec); // -> f2cvtl_mz2_z8_
	if(opc==3 && !L && HasSME2() && HasFP8()) return bf1cvt_mz2_z8(ctx, dec); // -> bf2cvt_mz2_z8_
	if(opc==3 && L && HasSME2() && HasFP8()) return bf1cvtl_mz2_z8(ctx, dec); // -> bf2cvtl_mz2_z8_
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_frint(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, opc=(INSWORD>>16)&7;
	if(size==2 && !opc && HasSME2()) return frintn_mz_z(ctx, dec); // -> frintn_mz_z_2
	if(size==2 && opc==1 && HasSME2()) return frintp_mz_z(ctx, dec); // -> frintp_mz_z_2
	if(size==2 && opc==2 && HasSME2()) return frintm_mz_z(ctx, dec); // -> frintm_mz_z_2
	if(size==2 && opc==3) UNALLOCATED(ENC_UNALLOCATED_784_MORTLACH_MULTI2_FRINT);
	if(size==2 && opc==4 && HasSME2()) return frinta_mz_z(ctx, dec); // -> frinta_mz_z_2
	if(size==2 && opc==5) UNALLOCATED(ENC_UNALLOCATED_785_MORTLACH_MULTI2_FRINT);
	if(size==2 && (opc&6)==6) UNALLOCATED(ENC_UNALLOCATED_783_MORTLACH_MULTI2_FRINT);
	if(size!=2) UNALLOCATED(ENC_UNALLOCATED_782_MORTLACH_MULTI2_FRINT);
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_wide_fp_cvrt(context *ctx, Instruction *dec)
{
	uint32_t L=INSWORD&1;
	if(!L && HasSME_F16F16()) return fcvt_mz2_z(ctx, dec); // -> fcvt_mz2_z_
	if(L && HasSME_F16F16()) return fcvtl_mz2_z(ctx, dec); // -> fcvtl_mz2_z_
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_fpint_cvrt(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>5)&1;
	if(!U && HasSME2()) return fcvtzs_mz_z(ctx, dec); // -> fcvtzs_mz_z_4
	if(U && HasSME2()) return fcvtzu_mz_z(ctx, dec); // -> fcvtzu_mz_z_4
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_intfp_cvrt(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>5)&1;
	if(!U && HasSME2()) return scvtf_mz_z(ctx, dec); // -> scvtf_mz_z_4
	if(U && HasSME2()) return ucvtf_mz_z(ctx, dec); // -> ucvtf_mz_z_4
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_narrow_int_cvrt(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>22)&1, N=(INSWORD>>6)&1, U=(INSWORD>>5)&1;
	if(!op && !N && !U && HasSME2()) return sqcvt_z_mz4(ctx, dec); // -> sqcvt_z_mz4_
	if(!op && !N && U && HasSME2()) return uqcvt_z_mz4(ctx, dec); // -> uqcvt_z_mz4_
	if(!op && N && !U && HasSME2()) return sqcvtn_z_mz4(ctx, dec); // -> sqcvtn_z_mz4_
	if(!op && N && U && HasSME2()) return uqcvtn_z_mz4(ctx, dec); // -> uqcvtn_z_mz4_
	if(op && !N && !U && HasSME2()) return sqcvtu_z_mz4(ctx, dec); // -> sqcvtu_z_mz4_
	if(op && N && !U && HasSME2()) return sqcvtun_z_mz4(ctx, dec); // -> sqcvtun_z_mz4_
	if(op && U) UNALLOCATED(ENC_UNALLOCATED_786_MORTLACH_MULTI4_NARROW_INT_CVRT);
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_narrow_fp8_cvrt(context *ctx, Instruction *dec)
{
	uint32_t N=(INSWORD>>5)&1;
	if(!N && HasSME2() && HasFP8()) return fcvt_z8_mz4(ctx, dec); // -> fcvt_z8_mz4_
	if(N && HasSME2() && HasFP8()) return fcvtn_z8_mz4(ctx, dec); // -> fcvtn_z8_mz4_
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_wide_int(context *ctx, Instruction *dec)
{
	uint32_t U=INSWORD&1;
	if(!U && HasSME2()) return sunpk_mz_z(ctx, dec); // -> sunpk_mz_z_4
	if(U && HasSME2()) return uunpk_mz_z(ctx, dec); // -> uunpk_mz_z_4
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_z_z_zip(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>1)&1;
	if(!op && HasSME2()) return zip_mz_z(ctx, dec); // -> zip_mz_z_4
	if(op && HasSME2()) return uzp_mz_z(ctx, dec); // -> uzp_mz_z_4
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_z_z_long_zip(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>1)&1;
	if(!op && HasSME2()) return zip_mz_z(ctx, dec); // -> zip_mz_z_4q
	if(op && HasSME2()) return uzp_mz_z(ctx, dec); // -> uzp_mz_z_4q
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_frint(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, opc=(INSWORD>>16)&7;
	if(size==2 && !opc && HasSME2()) return frintn_mz_z(ctx, dec); // -> frintn_mz_z_4
	if(size==2 && opc==1 && HasSME2()) return frintp_mz_z(ctx, dec); // -> frintp_mz_z_4
	if(size==2 && opc==2 && HasSME2()) return frintm_mz_z(ctx, dec); // -> frintm_mz_z_4
	if(size==2 && opc==3) UNALLOCATED(ENC_UNALLOCATED_789_MORTLACH_MULTI4_FRINT);
	if(size==2 && opc==4 && HasSME2()) return frinta_mz_z(ctx, dec); // -> frinta_mz_z_4
	if(size==2 && opc==5) UNALLOCATED(ENC_UNALLOCATED_790_MORTLACH_MULTI4_FRINT);
	if(size==2 && (opc&6)==6) UNALLOCATED(ENC_UNALLOCATED_788_MORTLACH_MULTI4_FRINT);
	if(size!=2) UNALLOCATED(ENC_UNALLOCATED_787_MORTLACH_MULTI4_FRINT);
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_select_int(context *ctx, Instruction *dec)
{
	return sel_mz_p_zz(ctx, dec);
}

int decode_iclass_mortlach_multi4_select_int(context *ctx, Instruction *dec)
{
	return sel_mz_p_zz(ctx, dec);
}

int decode_iclass_mortlach_multi_zero(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>15)&7, opc2=INSWORD&7;
	if(opc==6 && !(opc2&6) && HasSME2p1()) return zero_za4_ri(ctx, dec); // -> zero_za4_ri_2
	if(opc==7 && !(opc2&6) && HasSME2p1()) return zero_za4_ri(ctx, dec); // -> zero_za4_ri_4
	if(opc==2 && !(opc2&4) && HasSME2p1()) return zero_za2_ri(ctx, dec); // -> zero_za2_ri_2
	if(opc==3 && !(opc2&4) && HasSME2p1()) return zero_za2_ri(ctx, dec); // -> zero_za2_ri_4
	if(opc==5 && !(opc2&4) && HasSME2p1()) return zero_za4_ri(ctx, dec); // -> zero_za4_ri_1
	if(opc==5 && (opc2&4)==4) UNALLOCATED(ENC_UNALLOCATED_792_MORTLACH_MULTI_ZERO);
	if((opc&6)==6 && (opc2&6)==2) UNALLOCATED(ENC_UNALLOCATED_793_MORTLACH_MULTI_ZERO);
	if(!opc && HasSME2p1()) return zero_za1_ri(ctx, dec); // -> zero_za1_ri_2
	if(opc==1 && HasSME2p1()) return zero_za2_ri(ctx, dec); // -> zero_za2_ri_1
	if(opc==4 && HasSME2p1()) return zero_za1_ri(ctx, dec); // -> zero_za1_ri_4
	if((opc&2)==2 && (opc2&4)==4) UNALLOCATED(ENC_UNALLOCATED_791_MORTLACH_MULTI_ZERO);
	UNMATCHED;
}

int decode_iclass_mortlach_multi2_fmul_sm(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3;
	if(!size && HasSME2() && HasSVE_BFSCALE()) return bfmul_mz_zzv(ctx, dec); // -> bfmul_mz_zzv_2x1
	if(size && HasSME2p2()) return fmul_mz_zzv(ctx, dec); // -> fmul_mz_zzv_2x1
	UNMATCHED;
}

int decode_iclass_mortlach_multi4_fmul_sm(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3;
	if(!size && HasSME2() && HasSVE_BFSCALE()) return bfmul_mz_zzv(ctx, dec); // -> bfmul_mz_zzv_4x1
	if(size && HasSME2p2()) return fmul_mz_zzv(ctx, dec); // -> fmul_mz_zzv_4x1
	UNMATCHED;
}

int decode_iclass_mortlach_bini32_prod(context *ctx, Instruction *dec)
{
	uint32_t S=(INSWORD>>4)&1;
	if(!S && HasSME2()) return bmopa_za_pp_zz(ctx, dec); // -> bmopa_za_pp_zz_32
	if(S && HasSME2()) return bmops_za_pp_zz(ctx, dec); // -> bmops_za_pp_zz_32
	UNMATCHED;
}

int decode_iclass_mortlach_f8f16_prod(context *ctx, Instruction *dec)
{
	return fmopa_za16_pp_z8z8(ctx, dec);
}

int decode_iclass_mortlach_f16f16_prod(context *ctx, Instruction *dec)
{
	uint32_t S=(INSWORD>>4)&1;
	if(!S && HasSME_F16F16()) return fmopa_za_pp_zz(ctx, dec); // -> fmopa_za_pp_zz_16
	if(S && HasSME_F16F16()) return fmops_za_pp_zz(ctx, dec); // -> fmops_za_pp_zz_16
	UNMATCHED;
}

int decode_iclass_mortlach_b16b16_prod(context *ctx, Instruction *dec)
{
	uint32_t S=(INSWORD>>4)&1;
	if(!S && HasSME_B16B16()) return bfmopa_za_pp_zz(ctx, dec); // -> bfmopa_za_pp_zz_16
	if(S && HasSME_B16B16()) return bfmops_za_pp_zz(ctx, dec); // -> bfmops_za_pp_zz_16
	UNMATCHED;
}

int decode_iclass_mortlach_f32f32_prod4(context *ctx, Instruction *dec)
{
	uint32_t M=(INSWORD>>20)&1, N=(INSWORD>>9)&1, S=(INSWORD>>4)&1;
	if(!M && !N && !S && HasSME_MOP4()) return fmop4a_za_zz(ctx, dec); // -> fmop4a_za_zz_s1x1
	if(!M && !N && S && HasSME_MOP4()) return fmop4s_za_zz(ctx, dec); // -> fmop4s_za_zz_s1x1
	if(!M && N && !S && HasSME_MOP4()) return fmop4a_za_zz(ctx, dec); // -> fmop4a_za_zz_s2x1
	if(!M && N && S && HasSME_MOP4()) return fmop4s_za_zz(ctx, dec); // -> fmop4s_za_zz_s2x1
	if(M && !N && !S && HasSME_MOP4()) return fmop4a_za_zz(ctx, dec); // -> fmop4a_za_zz_s1x2
	if(M && !N && S && HasSME_MOP4()) return fmop4s_za_zz(ctx, dec); // -> fmop4s_za_zz_s1x2
	if(M && N && !S && HasSME_MOP4()) return fmop4a_za_zz(ctx, dec); // -> fmop4a_za_zz_s2x2
	if(M && N && S && HasSME_MOP4()) return fmop4s_za_zz(ctx, dec); // -> fmop4s_za_zz_s2x2
	UNMATCHED;
}

int decode_iclass_mortlach_f8f32_prod4(context *ctx, Instruction *dec)
{
	uint32_t M=(INSWORD>>20)&1, N=(INSWORD>>9)&1;
	if(!M && !N && HasSME_MOP4() && HasSME_F8F32()) return fmop4a_za32_z8z8(ctx, dec); // -> fmop4a_za32_z8z8_b1x1
	if(!M && N && HasSME_MOP4() && HasSME_F8F32()) return fmop4a_za32_z8z8(ctx, dec); // -> fmop4a_za32_z8z8_b2x1
	if(M && !N && HasSME_MOP4() && HasSME_F8F32()) return fmop4a_za32_z8z8(ctx, dec); // -> fmop4a_za32_z8z8_b1x2
	if(M && N && HasSME_MOP4() && HasSME_F8F32()) return fmop4a_za32_z8z8(ctx, dec); // -> fmop4a_za32_z8z8_b2x2
	UNMATCHED;
}

int decode_iclass_mortlach_b16f32_prod4(context *ctx, Instruction *dec)
{
	uint32_t M=(INSWORD>>20)&1, N=(INSWORD>>9)&1, S=(INSWORD>>4)&1;
	if(!M && !N && !S && HasSME_MOP4()) return bfmop4a_za32_zz(ctx, dec); // -> bfmop4a_za32_zz_h1x1
	if(!M && !N && S && HasSME_MOP4()) return bfmop4s_za32_zz(ctx, dec); // -> bfmop4s_za32_zz_h1x1
	if(!M && N && !S && HasSME_MOP4()) return bfmop4a_za32_zz(ctx, dec); // -> bfmop4a_za32_zz_h2x1
	if(!M && N && S && HasSME_MOP4()) return bfmop4s_za32_zz(ctx, dec); // -> bfmop4s_za32_zz_h2x1
	if(M && !N && !S && HasSME_MOP4()) return bfmop4a_za32_zz(ctx, dec); // -> bfmop4a_za32_zz_h1x2
	if(M && !N && S && HasSME_MOP4()) return bfmop4s_za32_zz(ctx, dec); // -> bfmop4s_za32_zz_h1x2
	if(M && N && !S && HasSME_MOP4()) return bfmop4a_za32_zz(ctx, dec); // -> bfmop4a_za32_zz_h2x2
	if(M && N && S && HasSME_MOP4()) return bfmop4s_za32_zz(ctx, dec); // -> bfmop4s_za32_zz_h2x2
	UNMATCHED;
}

int decode_iclass_mortlach_f16f32_prod4(context *ctx, Instruction *dec)
{
	uint32_t M=(INSWORD>>20)&1, N=(INSWORD>>9)&1, S=(INSWORD>>4)&1;
	if(!M && !N && !S && HasSME_MOP4()) return fmop4a_za32_zz(ctx, dec); // -> fmop4a_za32_zz_h1x1
	if(!M && !N && S && HasSME_MOP4()) return fmop4s_za32_zz(ctx, dec); // -> fmop4s_za32_zz_h1x1
	if(!M && N && !S && HasSME_MOP4()) return fmop4a_za32_zz(ctx, dec); // -> fmop4a_za32_zz_h2x1
	if(!M && N && S && HasSME_MOP4()) return fmop4s_za32_zz(ctx, dec); // -> fmop4s_za32_zz_h2x1
	if(M && !N && !S && HasSME_MOP4()) return fmop4a_za32_zz(ctx, dec); // -> fmop4a_za32_zz_h1x2
	if(M && !N && S && HasSME_MOP4()) return fmop4s_za32_zz(ctx, dec); // -> fmop4s_za32_zz_h1x2
	if(M && N && !S && HasSME_MOP4()) return fmop4a_za32_zz(ctx, dec); // -> fmop4a_za32_zz_h2x2
	if(M && N && S && HasSME_MOP4()) return fmop4s_za32_zz(ctx, dec); // -> fmop4s_za32_zz_h2x2
	UNMATCHED;
}

int decode_iclass_mortlach_i8i32_prod4(context *ctx, Instruction *dec)
{
	uint32_t u0=(INSWORD>>24)&1, u1=(INSWORD>>21)&1, M=(INSWORD>>20)&1, N=(INSWORD>>9)&1, S=(INSWORD>>4)&1;
	if(!u0 && !u1 && !M && !N && !S && HasSME_MOP4()) return smop4a_za_zz(ctx, dec); // -> smop4a_za_zz_b1x1
	if(!u0 && !u1 && !M && !N && S && HasSME_MOP4()) return smop4s_za_zz(ctx, dec); // -> smop4s_za_zz_b1x1
	if(!u0 && !u1 && !M && N && !S && HasSME_MOP4()) return smop4a_za_zz(ctx, dec); // -> smop4a_za_zz_b2x1
	if(!u0 && !u1 && !M && N && S && HasSME_MOP4()) return smop4s_za_zz(ctx, dec); // -> smop4s_za_zz_b2x1
	if(!u0 && !u1 && M && !N && !S && HasSME_MOP4()) return smop4a_za_zz(ctx, dec); // -> smop4a_za_zz_b1x2
	if(!u0 && !u1 && M && !N && S && HasSME_MOP4()) return smop4s_za_zz(ctx, dec); // -> smop4s_za_zz_b1x2
	if(!u0 && !u1 && M && N && !S && HasSME_MOP4()) return smop4a_za_zz(ctx, dec); // -> smop4a_za_zz_b2x2
	if(!u0 && !u1 && M && N && S && HasSME_MOP4()) return smop4s_za_zz(ctx, dec); // -> smop4s_za_zz_b2x2
	if(!u0 && u1 && !M && !N && !S && HasSME_MOP4()) return sumop4a_za_zz(ctx, dec); // -> sumop4a_za_zz_b1x1
	if(!u0 && u1 && !M && !N && S && HasSME_MOP4()) return sumop4s_za_zz(ctx, dec); // -> sumop4s_za_zz_b1x1
	if(!u0 && u1 && !M && N && !S && HasSME_MOP4()) return sumop4a_za_zz(ctx, dec); // -> sumop4a_za_zz_b2x1
	if(!u0 && u1 && !M && N && S && HasSME_MOP4()) return sumop4s_za_zz(ctx, dec); // -> sumop4s_za_zz_b2x1
	if(!u0 && u1 && M && !N && !S && HasSME_MOP4()) return sumop4a_za_zz(ctx, dec); // -> sumop4a_za_zz_b1x2
	if(!u0 && u1 && M && !N && S && HasSME_MOP4()) return sumop4s_za_zz(ctx, dec); // -> sumop4s_za_zz_b1x2
	if(!u0 && u1 && M && N && !S && HasSME_MOP4()) return sumop4a_za_zz(ctx, dec); // -> sumop4a_za_zz_b2x2
	if(!u0 && u1 && M && N && S && HasSME_MOP4()) return sumop4s_za_zz(ctx, dec); // -> sumop4s_za_zz_b2x2
	if(u0 && !u1 && !M && !N && !S && HasSME_MOP4()) return usmop4a_za_zz(ctx, dec); // -> usmop4a_za_zz_b1x1
	if(u0 && !u1 && !M && !N && S && HasSME_MOP4()) return usmop4s_za_zz(ctx, dec); // -> usmop4s_za_zz_b1x1
	if(u0 && !u1 && !M && N && !S && HasSME_MOP4()) return usmop4a_za_zz(ctx, dec); // -> usmop4a_za_zz_b2x1
	if(u0 && !u1 && !M && N && S && HasSME_MOP4()) return usmop4s_za_zz(ctx, dec); // -> usmop4s_za_zz_b2x1
	if(u0 && !u1 && M && !N && !S && HasSME_MOP4()) return usmop4a_za_zz(ctx, dec); // -> usmop4a_za_zz_b1x2
	if(u0 && !u1 && M && !N && S && HasSME_MOP4()) return usmop4s_za_zz(ctx, dec); // -> usmop4s_za_zz_b1x2
	if(u0 && !u1 && M && N && !S && HasSME_MOP4()) return usmop4a_za_zz(ctx, dec); // -> usmop4a_za_zz_b2x2
	if(u0 && !u1 && M && N && S && HasSME_MOP4()) return usmop4s_za_zz(ctx, dec); // -> usmop4s_za_zz_b2x2
	if(u0 && u1 && !M && !N && !S && HasSME_MOP4()) return umop4a_za_zz(ctx, dec); // -> umop4a_za_zz_b1x1
	if(u0 && u1 && !M && !N && S && HasSME_MOP4()) return umop4s_za_zz(ctx, dec); // -> umop4s_za_zz_b1x1
	if(u0 && u1 && !M && N && !S && HasSME_MOP4()) return umop4a_za_zz(ctx, dec); // -> umop4a_za_zz_b2x1
	if(u0 && u1 && !M && N && S && HasSME_MOP4()) return umop4s_za_zz(ctx, dec); // -> umop4s_za_zz_b2x1
	if(u0 && u1 && M && !N && !S && HasSME_MOP4()) return umop4a_za_zz(ctx, dec); // -> umop4a_za_zz_b1x2
	if(u0 && u1 && M && !N && S && HasSME_MOP4()) return umop4s_za_zz(ctx, dec); // -> umop4s_za_zz_b1x2
	if(u0 && u1 && M && N && !S && HasSME_MOP4()) return umop4a_za_zz(ctx, dec); // -> umop4a_za_zz_b2x2
	if(u0 && u1 && M && N && S && HasSME_MOP4()) return umop4s_za_zz(ctx, dec); // -> umop4s_za_zz_b2x2
	UNMATCHED;
}

int decode_iclass_mortlach_f8f16_prod4(context *ctx, Instruction *dec)
{
	uint32_t M=(INSWORD>>20)&1, N=(INSWORD>>9)&1;
	if(!M && !N && HasSME_MOP4() && HasSME_F8F16()) return fmop4a_za16_z8z8(ctx, dec); // -> fmop4a_za16_z8z8_b1x1
	if(!M && N && HasSME_MOP4() && HasSME_F8F16()) return fmop4a_za16_z8z8(ctx, dec); // -> fmop4a_za16_z8z8_b2x1
	if(M && !N && HasSME_MOP4() && HasSME_F8F16()) return fmop4a_za16_z8z8(ctx, dec); // -> fmop4a_za16_z8z8_b1x2
	if(M && N && HasSME_MOP4() && HasSME_F8F16()) return fmop4a_za16_z8z8(ctx, dec); // -> fmop4a_za16_z8z8_b2x2
	UNMATCHED;
}

int decode_iclass_mortlach_f16f16_prod4(context *ctx, Instruction *dec)
{
	uint32_t M=(INSWORD>>20)&1, N=(INSWORD>>9)&1, S=(INSWORD>>4)&1;
	if(!M && !N && !S && HasSME_MOP4() && HasSME_F16F16()) return fmop4a_za_zz(ctx, dec); // -> fmop4a_za_zz_h1x1
	if(!M && !N && S && HasSME_MOP4() && HasSME_F16F16()) return fmop4s_za_zz(ctx, dec); // -> fmop4s_za_zz_h1x1
	if(!M && N && !S && HasSME_MOP4() && HasSME_F16F16()) return fmop4a_za_zz(ctx, dec); // -> fmop4a_za_zz_h2x1
	if(!M && N && S && HasSME_MOP4() && HasSME_F16F16()) return fmop4s_za_zz(ctx, dec); // -> fmop4s_za_zz_h2x1
	if(M && !N && !S && HasSME_MOP4() && HasSME_F16F16()) return fmop4a_za_zz(ctx, dec); // -> fmop4a_za_zz_h1x2
	if(M && !N && S && HasSME_MOP4() && HasSME_F16F16()) return fmop4s_za_zz(ctx, dec); // -> fmop4s_za_zz_h1x2
	if(M && N && !S && HasSME_MOP4() && HasSME_F16F16()) return fmop4a_za_zz(ctx, dec); // -> fmop4a_za_zz_h2x2
	if(M && N && S && HasSME_MOP4() && HasSME_F16F16()) return fmop4s_za_zz(ctx, dec); // -> fmop4s_za_zz_h2x2
	UNMATCHED;
}

int decode_iclass_mortlach_b16b16_prod4(context *ctx, Instruction *dec)
{
	uint32_t M=(INSWORD>>20)&1, N=(INSWORD>>9)&1, S=(INSWORD>>4)&1;
	if(!M && !N && !S && HasSME_MOP4() && HasSME_B16B16()) return bfmop4a_za_zz(ctx, dec); // -> bfmop4a_za_zz_h1x1
	if(!M && !N && S && HasSME_MOP4() && HasSME_B16B16()) return bfmop4s_za_zz(ctx, dec); // -> bfmop4s_za_zz_h1x1
	if(!M && N && !S && HasSME_MOP4() && HasSME_B16B16()) return bfmop4a_za_zz(ctx, dec); // -> bfmop4a_za_zz_h2x1
	if(!M && N && S && HasSME_MOP4() && HasSME_B16B16()) return bfmop4s_za_zz(ctx, dec); // -> bfmop4s_za_zz_h2x1
	if(M && !N && !S && HasSME_MOP4() && HasSME_B16B16()) return bfmop4a_za_zz(ctx, dec); // -> bfmop4a_za_zz_h1x2
	if(M && !N && S && HasSME_MOP4() && HasSME_B16B16()) return bfmop4s_za_zz(ctx, dec); // -> bfmop4s_za_zz_h1x2
	if(M && N && !S && HasSME_MOP4() && HasSME_B16B16()) return bfmop4a_za_zz(ctx, dec); // -> bfmop4a_za_zz_h2x2
	if(M && N && S && HasSME_MOP4() && HasSME_B16B16()) return bfmop4s_za_zz(ctx, dec); // -> bfmop4s_za_zz_h2x2
	UNMATCHED;
}

int decode_iclass_mortlach_i16i32_prod4(context *ctx, Instruction *dec)
{
	uint32_t u0=(INSWORD>>24)&1, M=(INSWORD>>20)&1, N=(INSWORD>>9)&1, S=(INSWORD>>4)&1;
	if(!u0 && !M && !N && !S && HasSME_MOP4()) return smop4a_za32_zz(ctx, dec); // -> smop4a_za32_zz_h1x1
	if(!u0 && !M && !N && S && HasSME_MOP4()) return smop4s_za32_zz(ctx, dec); // -> smop4s_za32_zz_h1x1
	if(!u0 && !M && N && !S && HasSME_MOP4()) return smop4a_za32_zz(ctx, dec); // -> smop4a_za32_zz_h2x1
	if(!u0 && !M && N && S && HasSME_MOP4()) return smop4s_za32_zz(ctx, dec); // -> smop4s_za32_zz_h2x1
	if(!u0 && M && !N && !S && HasSME_MOP4()) return smop4a_za32_zz(ctx, dec); // -> smop4a_za32_zz_h1x2
	if(!u0 && M && !N && S && HasSME_MOP4()) return smop4s_za32_zz(ctx, dec); // -> smop4s_za32_zz_h1x2
	if(!u0 && M && N && !S && HasSME_MOP4()) return smop4a_za32_zz(ctx, dec); // -> smop4a_za32_zz_h2x2
	if(!u0 && M && N && S && HasSME_MOP4()) return smop4s_za32_zz(ctx, dec); // -> smop4s_za32_zz_h2x2
	if(u0 && !M && !N && !S && HasSME_MOP4()) return umop4a_za32_zz(ctx, dec); // -> umop4a_za32_zz_h1x1
	if(u0 && !M && !N && S && HasSME_MOP4()) return umop4s_za32_zz(ctx, dec); // -> umop4s_za32_zz_h1x1
	if(u0 && !M && N && !S && HasSME_MOP4()) return umop4a_za32_zz(ctx, dec); // -> umop4a_za32_zz_h2x1
	if(u0 && !M && N && S && HasSME_MOP4()) return umop4s_za32_zz(ctx, dec); // -> umop4s_za32_zz_h2x1
	if(u0 && M && !N && !S && HasSME_MOP4()) return umop4a_za32_zz(ctx, dec); // -> umop4a_za32_zz_h1x2
	if(u0 && M && !N && S && HasSME_MOP4()) return umop4s_za32_zz(ctx, dec); // -> umop4s_za32_zz_h1x2
	if(u0 && M && N && !S && HasSME_MOP4()) return umop4a_za32_zz(ctx, dec); // -> umop4a_za32_zz_h2x2
	if(u0 && M && N && S && HasSME_MOP4()) return umop4s_za32_zz(ctx, dec); // -> umop4s_za32_zz_h2x2
	UNMATCHED;
}

int decode_iclass_mortlach_f64f64_prod4(context *ctx, Instruction *dec)
{
	uint32_t M=(INSWORD>>20)&1, N=(INSWORD>>9)&1, S=(INSWORD>>4)&1;
	if(!M && !N && !S && HasSME_MOP4() && HasSME_F64F64()) return fmop4a_za_zz(ctx, dec); // -> fmop4a_za_zz_d1x1
	if(!M && !N && S && HasSME_MOP4() && HasSME_F64F64()) return fmop4s_za_zz(ctx, dec); // -> fmop4s_za_zz_d1x1
	if(!M && N && !S && HasSME_MOP4() && HasSME_F64F64()) return fmop4a_za_zz(ctx, dec); // -> fmop4a_za_zz_d2x1
	if(!M && N && S && HasSME_MOP4() && HasSME_F64F64()) return fmop4s_za_zz(ctx, dec); // -> fmop4s_za_zz_d2x1
	if(M && !N && !S && HasSME_MOP4() && HasSME_F64F64()) return fmop4a_za_zz(ctx, dec); // -> fmop4a_za_zz_d1x2
	if(M && !N && S && HasSME_MOP4() && HasSME_F64F64()) return fmop4s_za_zz(ctx, dec); // -> fmop4s_za_zz_d1x2
	if(M && N && !S && HasSME_MOP4() && HasSME_F64F64()) return fmop4a_za_zz(ctx, dec); // -> fmop4a_za_zz_d2x2
	if(M && N && S && HasSME_MOP4() && HasSME_F64F64()) return fmop4s_za_zz(ctx, dec); // -> fmop4s_za_zz_d2x2
	UNMATCHED;
}

int decode_iclass_mortlach_i16i64_prod4(context *ctx, Instruction *dec)
{
	uint32_t u0=(INSWORD>>24)&1, u1=(INSWORD>>21)&1, M=(INSWORD>>20)&1, N=(INSWORD>>9)&1, S=(INSWORD>>4)&1;
	if(!u0 && !u1 && !M && !N && !S && HasSME_MOP4() && HasSME_I16I64()) return smop4a_za_zz(ctx, dec); // -> smop4a_za_zz_h1x1
	if(!u0 && !u1 && !M && !N && S && HasSME_MOP4() && HasSME_I16I64()) return smop4s_za_zz(ctx, dec); // -> smop4s_za_zz_h1x1
	if(!u0 && !u1 && !M && N && !S && HasSME_MOP4() && HasSME_I16I64()) return smop4a_za_zz(ctx, dec); // -> smop4a_za_zz_h2x1
	if(!u0 && !u1 && !M && N && S && HasSME_MOP4() && HasSME_I16I64()) return smop4s_za_zz(ctx, dec); // -> smop4s_za_zz_h2x1
	if(!u0 && !u1 && M && !N && !S && HasSME_MOP4() && HasSME_I16I64()) return smop4a_za_zz(ctx, dec); // -> smop4a_za_zz_h1x2
	if(!u0 && !u1 && M && !N && S && HasSME_MOP4() && HasSME_I16I64()) return smop4s_za_zz(ctx, dec); // -> smop4s_za_zz_h1x2
	if(!u0 && !u1 && M && N && !S && HasSME_MOP4() && HasSME_I16I64()) return smop4a_za_zz(ctx, dec); // -> smop4a_za_zz_h2x2
	if(!u0 && !u1 && M && N && S && HasSME_MOP4() && HasSME_I16I64()) return smop4s_za_zz(ctx, dec); // -> smop4s_za_zz_h2x2
	if(!u0 && u1 && !M && !N && !S && HasSME_MOP4() && HasSME_I16I64()) return sumop4a_za_zz(ctx, dec); // -> sumop4a_za_zz_h1x1
	if(!u0 && u1 && !M && !N && S && HasSME_MOP4() && HasSME_I16I64()) return sumop4s_za_zz(ctx, dec); // -> sumop4s_za_zz_h1x1
	if(!u0 && u1 && !M && N && !S && HasSME_MOP4() && HasSME_I16I64()) return sumop4a_za_zz(ctx, dec); // -> sumop4a_za_zz_h2x1
	if(!u0 && u1 && !M && N && S && HasSME_MOP4() && HasSME_I16I64()) return sumop4s_za_zz(ctx, dec); // -> sumop4s_za_zz_h2x1
	if(!u0 && u1 && M && !N && !S && HasSME_MOP4() && HasSME_I16I64()) return sumop4a_za_zz(ctx, dec); // -> sumop4a_za_zz_h1x2
	if(!u0 && u1 && M && !N && S && HasSME_MOP4() && HasSME_I16I64()) return sumop4s_za_zz(ctx, dec); // -> sumop4s_za_zz_h1x2
	if(!u0 && u1 && M && N && !S && HasSME_MOP4() && HasSME_I16I64()) return sumop4a_za_zz(ctx, dec); // -> sumop4a_za_zz_h2x2
	if(!u0 && u1 && M && N && S && HasSME_MOP4() && HasSME_I16I64()) return sumop4s_za_zz(ctx, dec); // -> sumop4s_za_zz_h2x2
	if(u0 && !u1 && !M && !N && !S && HasSME_MOP4() && HasSME_I16I64()) return usmop4a_za_zz(ctx, dec); // -> usmop4a_za_zz_h1x1
	if(u0 && !u1 && !M && !N && S && HasSME_MOP4() && HasSME_I16I64()) return usmop4s_za_zz(ctx, dec); // -> usmop4s_za_zz_h1x1
	if(u0 && !u1 && !M && N && !S && HasSME_MOP4() && HasSME_I16I64()) return usmop4a_za_zz(ctx, dec); // -> usmop4a_za_zz_h2x1
	if(u0 && !u1 && !M && N && S && HasSME_MOP4() && HasSME_I16I64()) return usmop4s_za_zz(ctx, dec); // -> usmop4s_za_zz_h2x1
	if(u0 && !u1 && M && !N && !S && HasSME_MOP4() && HasSME_I16I64()) return usmop4a_za_zz(ctx, dec); // -> usmop4a_za_zz_h1x2
	if(u0 && !u1 && M && !N && S && HasSME_MOP4() && HasSME_I16I64()) return usmop4s_za_zz(ctx, dec); // -> usmop4s_za_zz_h1x2
	if(u0 && !u1 && M && N && !S && HasSME_MOP4() && HasSME_I16I64()) return usmop4a_za_zz(ctx, dec); // -> usmop4a_za_zz_h2x2
	if(u0 && !u1 && M && N && S && HasSME_MOP4() && HasSME_I16I64()) return usmop4s_za_zz(ctx, dec); // -> usmop4s_za_zz_h2x2
	if(u0 && u1 && !M && !N && !S && HasSME_MOP4() && HasSME_I16I64()) return umop4a_za_zz(ctx, dec); // -> umop4a_za_zz_h1x1
	if(u0 && u1 && !M && !N && S && HasSME_MOP4() && HasSME_I16I64()) return umop4s_za_zz(ctx, dec); // -> umop4s_za_zz_h1x1
	if(u0 && u1 && !M && N && !S && HasSME_MOP4() && HasSME_I16I64()) return umop4a_za_zz(ctx, dec); // -> umop4a_za_zz_h2x1
	if(u0 && u1 && !M && N && S && HasSME_MOP4() && HasSME_I16I64()) return umop4s_za_zz(ctx, dec); // -> umop4s_za_zz_h2x1
	if(u0 && u1 && M && !N && !S && HasSME_MOP4() && HasSME_I16I64()) return umop4a_za_zz(ctx, dec); // -> umop4a_za_zz_h1x2
	if(u0 && u1 && M && !N && S && HasSME_MOP4() && HasSME_I16I64()) return umop4s_za_zz(ctx, dec); // -> umop4s_za_zz_h1x2
	if(u0 && u1 && M && N && !S && HasSME_MOP4() && HasSME_I16I64()) return umop4a_za_zz(ctx, dec); // -> umop4a_za_zz_h2x2
	if(u0 && u1 && M && N && S && HasSME_MOP4() && HasSME_I16I64()) return umop4s_za_zz(ctx, dec); // -> umop4s_za_zz_h2x2
	UNMATCHED;
}

int decode_iclass_mortlach_f32f32_1in2ss_prod(context *ctx, Instruction *dec)
{
	return ftmopa_za_zzzi(ctx, dec);
}

int decode_iclass_mortlach_f8f32_2in4ss_prod(context *ctx, Instruction *dec)
{
	return ftmopa_za32_z8z8zi(ctx, dec);
}

int decode_iclass_mortlach_b16f32_2in4ss_prod(context *ctx, Instruction *dec)
{
	return bftmopa_za32_zzzi(ctx, dec);
}

int decode_iclass_mortlach_f16f32_2in4ss_prod(context *ctx, Instruction *dec)
{
	return ftmopa_za32_zzzi(ctx, dec);
}

int decode_iclass_mortlach_i8i32_2in4ss_prod(context *ctx, Instruction *dec)
{
	uint32_t u0=(INSWORD>>24)&1, u1=(INSWORD>>21)&1;
	if(!u0 && !u1 && HasSME_TMOP()) return stmopa_za_zzzi(ctx, dec); // -> stmopa_za_zzzi_b2x1
	if(!u0 && u1 && HasSME_TMOP()) return sutmopa_za_zzzi(ctx, dec); // -> sutmopa_za_zzzi_b2x1
	if(u0 && !u1 && HasSME_TMOP()) return ustmopa_za_zzzi(ctx, dec); // -> ustmopa_za_zzzi_b2x1
	if(u0 && u1 && HasSME_TMOP()) return utmopa_za_zzzi(ctx, dec); // -> utmopa_za_zzzi_b2x1
	UNMATCHED;
}

int decode_iclass_mortlach_f8f16_2in4ss_prod(context *ctx, Instruction *dec)
{
	return ftmopa_za16_z8z8zi(ctx, dec);
}

int decode_iclass_mortlach_f16f16_1in2ss_prod(context *ctx, Instruction *dec)
{
	return ftmopa_za_zzzi(ctx, dec);
}

int decode_iclass_mortlach_b16b16_1in2ss_prod(context *ctx, Instruction *dec)
{
	return bftmopa_za_zzzi(ctx, dec);
}

int decode_iclass_mortlach_i16i32_2in4ss_prod(context *ctx, Instruction *dec)
{
	uint32_t u0=(INSWORD>>24)&1;
	if(!u0 && HasSME_TMOP()) return stmopa_za32_zzzi(ctx, dec); // -> stmopa_za32_zzzi_h2x1
	if(u0 && HasSME_TMOP()) return utmopa_za32_zzzi(ctx, dec); // -> utmopa_za32_zzzi_h2x1
	UNMATCHED;
}

int decode_iclass_mortlach_zero_zt(context *ctx, Instruction *dec)
{
	uint32_t op0=(INSWORD>>4)&0x3fff, opc=INSWORD&15;
	if(!op0 && opc==1 && HasSME2()) return zero_zt_i(ctx, dec); // -> zero_zt_i_
	if(!op0 && opc!=1) UNALLOCATED(ENC_UNALLOCATED_795_MORTLACH_ZERO_ZT);
	if(op0) UNALLOCATED(ENC_UNALLOCATED_794_MORTLACH_ZERO_ZT);
	UNMATCHED;
}

int decode_iclass_sve_int_bin_cons_misc_0_a(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>22)&3;
	if(!opc && HasSVE()) return adr_z_az(ctx, dec); // -> adr_z_az_d_s32_scaled
	if(opc==1 && HasSVE()) return adr_z_az(ctx, dec); // -> adr_z_az_d_u32_scaled
	if((opc&2)==2 && HasSVE()) return adr_z_az(ctx, dec); // -> adr_z_az_sd_same_scaled
	UNMATCHED;
}

int decode_iclass_sve_int_log_imm(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>22)&3;
	if(!opc && HasSVE() && HasSME()) return orr_z_zi(ctx, dec); // -> orr_z_zi_
	if(opc==1 && HasSVE() && HasSME()) return eor_z_zi(ctx, dec); // -> eor_z_zi_
	if(opc==2 && HasSVE() && HasSME()) return and_z_zi(ctx, dec); // -> and_z_zi_
	UNMATCHED;
}

int decode_iclass_sve_int_dup_mask_imm(context *ctx, Instruction *dec)
{
	return dupm_z_i(ctx, dec);
}

int decode_iclass_sve_int_bin_cons_log(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>22)&3;
	if(!opc && HasSVE() && HasSME()) return and_z_zz(ctx, dec); // -> and_z_zz_
	if(opc==1 && HasSVE() && HasSME()) return orr_z_zz(ctx, dec); // -> orr_z_zz_
	if(opc==2 && HasSVE() && HasSME()) return eor_z_zz(ctx, dec); // -> eor_z_zz_
	if(opc==3 && HasSVE() && HasSME()) return bic_z_zz(ctx, dec); // -> bic_z_zz_
	UNMATCHED;
}

int decode_iclass_sve_int_rotate_imm(context *ctx, Instruction *dec)
{
	return xar_z_zzi(ctx, dec);
}

int decode_iclass_sve_int_tern_log(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>22)&3, o2=(INSWORD>>10)&1;
	if(!opc && !o2 && HasSVE2() && HasSME()) return eor3_z_zzz(ctx, dec); // -> eor3_z_zzz_
	if(!opc && o2 && HasSVE2() && HasSME()) return bsl_z_zzz(ctx, dec); // -> bsl_z_zzz_
	if(opc==1 && !o2 && HasSVE2() && HasSME()) return bcax_z_zzz(ctx, dec); // -> bcax_z_zzz_
	if(opc==1 && o2 && HasSVE2() && HasSME()) return bsl1n_z_zzz(ctx, dec); // -> bsl1n_z_zzz_
	if(opc==2 && o2 && HasSVE2() && HasSME()) return bsl2n_z_zzz(ctx, dec); // -> bsl2n_z_zzz_
	if(opc==3 && o2 && HasSVE2() && HasSME()) return nbsl_z_zzz(ctx, dec); // -> nbsl_z_zzz_
	if((opc&2)==2 && !o2) UNALLOCATED(ENC_UNALLOCATED_487_SVE_INT_TERN_LOG);
	UNMATCHED;
}

int decode_iclass_sve_int_bin_pred_shift_0(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>18)&3, L=(INSWORD>>17)&1, U=(INSWORD>>16)&1;
	if(!opc && !L && !U && HasSVE() && HasSME()) return asr_z_p_zi(ctx, dec); // -> asr_z_p_zi_
	if(!opc && !L && U && HasSVE() && HasSME()) return lsr_z_p_zi(ctx, dec); // -> lsr_z_p_zi_
	if(!opc && L && !U) UNALLOCATED(ENC_UNALLOCATED_489_SVE_INT_BIN_PRED_SHIFT_0);
	if(!opc && L && U && HasSVE() && HasSME()) return lsl_z_p_zi(ctx, dec); // -> lsl_z_p_zi_
	if(opc==1 && !L && !U && HasSVE() && HasSME()) return asrd_z_p_zi(ctx, dec); // -> asrd_z_p_zi_
	if(opc==1 && !L && U) UNALLOCATED(ENC_UNALLOCATED_490_SVE_INT_BIN_PRED_SHIFT_0);
	if(opc==1 && L && !U && HasSVE2() && HasSME()) return sqshl_z_p_zi(ctx, dec); // -> sqshl_z_p_zi_
	if(opc==1 && L && U && HasSVE2() && HasSME()) return uqshl_z_p_zi(ctx, dec); // -> uqshl_z_p_zi_
	if(opc==3 && !L && !U && HasSVE2() && HasSME()) return srshr_z_p_zi(ctx, dec); // -> srshr_z_p_zi_
	if(opc==3 && !L && U && HasSVE2() && HasSME()) return urshr_z_p_zi(ctx, dec); // -> urshr_z_p_zi_
	if(opc==3 && L && !U) UNALLOCATED(ENC_UNALLOCATED_491_SVE_INT_BIN_PRED_SHIFT_0);
	if(opc==3 && L && U && HasSVE2() && HasSME()) return sqshlu_z_p_zi(ctx, dec); // -> sqshlu_z_p_zi_
	if(opc==2) UNALLOCATED(ENC_UNALLOCATED_488_SVE_INT_BIN_PRED_SHIFT_0);
	UNMATCHED;
}

int decode_iclass_sve_int_bin_pred_shift_1(context *ctx, Instruction *dec)
{
	uint32_t R=(INSWORD>>18)&1, L=(INSWORD>>17)&1, U=(INSWORD>>16)&1;
	if(!R && !L && !U && HasSVE() && HasSME()) return asr_z_p_zz(ctx, dec); // -> asr_z_p_zz_
	if(!R && !L && U && HasSVE() && HasSME()) return lsr_z_p_zz(ctx, dec); // -> lsr_z_p_zz_
	if(!R && L && U && HasSVE() && HasSME()) return lsl_z_p_zz(ctx, dec); // -> lsl_z_p_zz_
	if(R && !L && !U && HasSVE() && HasSME()) return asrr_z_p_zz(ctx, dec); // -> asrr_z_p_zz_
	if(R && !L && U && HasSVE() && HasSME()) return lsrr_z_p_zz(ctx, dec); // -> lsrr_z_p_zz_
	if(R && L && U && HasSVE() && HasSME()) return lslr_z_p_zz(ctx, dec); // -> lslr_z_p_zz_
	if(L && !U) UNALLOCATED(ENC_UNALLOCATED_492_SVE_INT_BIN_PRED_SHIFT_1);
	UNMATCHED;
}

int decode_iclass_sve_int_bin_pred_shift_2(context *ctx, Instruction *dec)
{
	uint32_t R=(INSWORD>>18)&1, L=(INSWORD>>17)&1, U=(INSWORD>>16)&1;
	if(!R && !L && !U && HasSVE() && HasSME()) return asr_z_p_zw(ctx, dec); // -> asr_z_p_zw_
	if(!R && !L && U && HasSVE() && HasSME()) return lsr_z_p_zw(ctx, dec); // -> lsr_z_p_zw_
	if(!R && L && !U) UNALLOCATED(ENC_UNALLOCATED_494_SVE_INT_BIN_PRED_SHIFT_2);
	if(!R && L && U && HasSVE() && HasSME()) return lsl_z_p_zw(ctx, dec); // -> lsl_z_p_zw_
	if(R) UNALLOCATED(ENC_UNALLOCATED_493_SVE_INT_BIN_PRED_SHIFT_2);
	UNMATCHED;
}

int decode_iclass_sve_int_bin_cons_shift_a(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>10)&3;
	if(!opc && HasSVE() && HasSME()) return asr_z_zw(ctx, dec); // -> asr_z_zw_
	if(opc==1 && HasSVE() && HasSME()) return lsr_z_zw(ctx, dec); // -> lsr_z_zw_
	if(opc==2) UNALLOCATED(ENC_UNALLOCATED_495_SVE_INT_BIN_CONS_SHIFT_A);
	if(opc==3 && HasSVE() && HasSME()) return lsl_z_zw(ctx, dec); // -> lsl_z_zw_
	UNMATCHED;
}

int decode_iclass_sve_int_bin_cons_shift_b(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>10)&3;
	if(!opc && HasSVE() && HasSME()) return asr_z_zi(ctx, dec); // -> asr_z_zi_
	if(opc==1 && HasSVE() && HasSME()) return lsr_z_zi(ctx, dec); // -> lsr_z_zi_
	if(opc==2) UNALLOCATED(ENC_UNALLOCATED_496_SVE_INT_BIN_CONS_SHIFT_B);
	if(opc==3 && HasSVE() && HasSME()) return lsl_z_zi(ctx, dec); // -> lsl_z_zi_
	UNMATCHED;
}

int decode_iclass_sve_int_countvlv0(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, D=(INSWORD>>11)&1, U=(INSWORD>>10)&1;
	if(size==1 && !D && !U && HasSVE() && HasSME()) return sqinch_z_zs(ctx, dec); // -> sqinch_z_zs_
	if(size==1 && !D && U && HasSVE() && HasSME()) return uqinch_z_zs(ctx, dec); // -> uqinch_z_zs_
	if(size==1 && D && !U && HasSVE() && HasSME()) return sqdech_z_zs(ctx, dec); // -> sqdech_z_zs_
	if(size==1 && D && U && HasSVE() && HasSME()) return uqdech_z_zs(ctx, dec); // -> uqdech_z_zs_
	if(size==2 && !D && !U && HasSVE() && HasSME()) return sqincw_z_zs(ctx, dec); // -> sqincw_z_zs_
	if(size==2 && !D && U && HasSVE() && HasSME()) return uqincw_z_zs(ctx, dec); // -> uqincw_z_zs_
	if(size==2 && D && !U && HasSVE() && HasSME()) return sqdecw_z_zs(ctx, dec); // -> sqdecw_z_zs_
	if(size==2 && D && U && HasSVE() && HasSME()) return uqdecw_z_zs(ctx, dec); // -> uqdecw_z_zs_
	if(size==3 && !D && !U && HasSVE() && HasSME()) return sqincd_z_zs(ctx, dec); // -> sqincd_z_zs_
	if(size==3 && !D && U && HasSVE() && HasSME()) return uqincd_z_zs(ctx, dec); // -> uqincd_z_zs_
	if(size==3 && D && !U && HasSVE() && HasSME()) return sqdecd_z_zs(ctx, dec); // -> sqdecd_z_zs_
	if(size==3 && D && U && HasSVE() && HasSME()) return uqdecd_z_zs(ctx, dec); // -> uqdecd_z_zs_
	if(!size) UNALLOCATED(ENC_UNALLOCATED_497_SVE_INT_COUNTVLV0);
	UNMATCHED;
}

int decode_iclass_sve_int_countvlv1(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, D=(INSWORD>>10)&1;
	if(size==1 && !D && HasSVE() && HasSME()) return incd_z_zs(ctx, dec); // -> inch_z_zs_
	if(size==1 && D && HasSVE() && HasSME()) return decd_z_zs(ctx, dec); // -> dech_z_zs_
	if(size==2 && !D && HasSVE() && HasSME()) return incd_z_zs(ctx, dec); // -> incw_z_zs_
	if(size==2 && D && HasSVE() && HasSME()) return decd_z_zs(ctx, dec); // -> decw_z_zs_
	if(size==3 && !D && HasSVE() && HasSME()) return incd_z_zs(ctx, dec); // -> incd_z_zs_
	if(size==3 && D && HasSVE() && HasSME()) return decd_z_zs(ctx, dec); // -> decd_z_zs_
	if(!size) UNALLOCATED(ENC_UNALLOCATED_498_SVE_INT_COUNTVLV1);
	UNMATCHED;
}

int decode_iclass_sve_int_count(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, op=(INSWORD>>10)&1;
	if(!size && !op && HasSVE() && HasSME()) return cntb_r_s(ctx, dec); // -> cntb_r_s_
	if(size==1 && !op && HasSVE() && HasSME()) return cntb_r_s(ctx, dec); // -> cnth_r_s_
	if(size==2 && !op && HasSVE() && HasSME()) return cntb_r_s(ctx, dec); // -> cntw_r_s_
	if(size==3 && !op && HasSVE() && HasSME()) return cntb_r_s(ctx, dec); // -> cntd_r_s_
	if(op) UNALLOCATED(ENC_UNALLOCATED_499_SVE_INT_COUNT);
	UNMATCHED;
}

int decode_iclass_sve_int_pred_pattern_a(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, D=(INSWORD>>10)&1;
	if(!size && !D && HasSVE() && HasSME()) return incb_r_rs(ctx, dec); // -> incb_r_rs_
	if(!size && D && HasSVE() && HasSME()) return decb_r_rs(ctx, dec); // -> decb_r_rs_
	if(size==1 && !D && HasSVE() && HasSME()) return incb_r_rs(ctx, dec); // -> inch_r_rs_
	if(size==1 && D && HasSVE() && HasSME()) return decb_r_rs(ctx, dec); // -> dech_r_rs_
	if(size==2 && !D && HasSVE() && HasSME()) return incb_r_rs(ctx, dec); // -> incw_r_rs_
	if(size==2 && D && HasSVE() && HasSME()) return decb_r_rs(ctx, dec); // -> decw_r_rs_
	if(size==3 && !D && HasSVE() && HasSME()) return incb_r_rs(ctx, dec); // -> incd_r_rs_
	if(size==3 && D && HasSVE() && HasSME()) return decb_r_rs(ctx, dec); // -> decd_r_rs_
	UNMATCHED;
}

int decode_iclass_sve_int_pred_pattern_b(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, sf=(INSWORD>>20)&1, D=(INSWORD>>11)&1, U=(INSWORD>>10)&1;
	if(!size && !sf && !D && !U && HasSVE() && HasSME()) return sqincb_r_rs(ctx, dec); // -> sqincb_r_rs_sx
	if(!size && !sf && !D && U && HasSVE() && HasSME()) return uqincb_r_rs(ctx, dec); // -> uqincb_r_rs_uw
	if(!size && !sf && D && !U && HasSVE() && HasSME()) return sqdecb_r_rs(ctx, dec); // -> sqdecb_r_rs_sx
	if(!size && !sf && D && U && HasSVE() && HasSME()) return uqdecb_r_rs(ctx, dec); // -> uqdecb_r_rs_uw
	if(!size && sf && !D && !U && HasSVE() && HasSME()) return sqincb_r_rs(ctx, dec); // -> sqincb_r_rs_x
	if(!size && sf && !D && U && HasSVE() && HasSME()) return uqincb_r_rs(ctx, dec); // -> uqincb_r_rs_x
	if(!size && sf && D && !U && HasSVE() && HasSME()) return sqdecb_r_rs(ctx, dec); // -> sqdecb_r_rs_x
	if(!size && sf && D && U && HasSVE() && HasSME()) return uqdecb_r_rs(ctx, dec); // -> uqdecb_r_rs_x
	if(size==1 && !sf && !D && !U && HasSVE() && HasSME()) return sqinch_r_rs(ctx, dec); // -> sqinch_r_rs_sx
	if(size==1 && !sf && !D && U && HasSVE() && HasSME()) return uqinch_r_rs(ctx, dec); // -> uqinch_r_rs_uw
	if(size==1 && !sf && D && !U && HasSVE() && HasSME()) return sqdech_r_rs(ctx, dec); // -> sqdech_r_rs_sx
	if(size==1 && !sf && D && U && HasSVE() && HasSME()) return uqdech_r_rs(ctx, dec); // -> uqdech_r_rs_uw
	if(size==1 && sf && !D && !U && HasSVE() && HasSME()) return sqinch_r_rs(ctx, dec); // -> sqinch_r_rs_x
	if(size==1 && sf && !D && U && HasSVE() && HasSME()) return uqinch_r_rs(ctx, dec); // -> uqinch_r_rs_x
	if(size==1 && sf && D && !U && HasSVE() && HasSME()) return sqdech_r_rs(ctx, dec); // -> sqdech_r_rs_x
	if(size==1 && sf && D && U && HasSVE() && HasSME()) return uqdech_r_rs(ctx, dec); // -> uqdech_r_rs_x
	if(size==2 && !sf && !D && !U && HasSVE() && HasSME()) return sqincw_r_rs(ctx, dec); // -> sqincw_r_rs_sx
	if(size==2 && !sf && !D && U && HasSVE() && HasSME()) return uqincw_r_rs(ctx, dec); // -> uqincw_r_rs_uw
	if(size==2 && !sf && D && !U && HasSVE() && HasSME()) return sqdecw_r_rs(ctx, dec); // -> sqdecw_r_rs_sx
	if(size==2 && !sf && D && U && HasSVE() && HasSME()) return uqdecw_r_rs(ctx, dec); // -> uqdecw_r_rs_uw
	if(size==2 && sf && !D && !U && HasSVE() && HasSME()) return sqincw_r_rs(ctx, dec); // -> sqincw_r_rs_x
	if(size==2 && sf && !D && U && HasSVE() && HasSME()) return uqincw_r_rs(ctx, dec); // -> uqincw_r_rs_x
	if(size==2 && sf && D && !U && HasSVE() && HasSME()) return sqdecw_r_rs(ctx, dec); // -> sqdecw_r_rs_x
	if(size==2 && sf && D && U && HasSVE() && HasSME()) return uqdecw_r_rs(ctx, dec); // -> uqdecw_r_rs_x
	if(size==3 && !sf && !D && !U && HasSVE() && HasSME()) return sqincd_r_rs(ctx, dec); // -> sqincd_r_rs_sx
	if(size==3 && !sf && !D && U && HasSVE() && HasSME()) return uqincd_r_rs(ctx, dec); // -> uqincd_r_rs_uw
	if(size==3 && !sf && D && !U && HasSVE() && HasSME()) return sqdecd_r_rs(ctx, dec); // -> sqdecd_r_rs_sx
	if(size==3 && !sf && D && U && HasSVE() && HasSME()) return uqdecd_r_rs(ctx, dec); // -> uqdecd_r_rs_uw
	if(size==3 && sf && !D && !U && HasSVE() && HasSME()) return sqincd_r_rs(ctx, dec); // -> sqincd_r_rs_x
	if(size==3 && sf && !D && U && HasSVE() && HasSME()) return uqincd_r_rs(ctx, dec); // -> uqincd_r_rs_x
	if(size==3 && sf && D && !U && HasSVE() && HasSME()) return sqdecd_r_rs(ctx, dec); // -> sqdecd_r_rs_x
	if(size==3 && sf && D && U && HasSVE() && HasSME()) return uqdecd_r_rs(ctx, dec); // -> uqdecd_r_rs_x
	UNMATCHED;
}

int decode_iclass_sve_fp_clamp(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3;
	if(!size && HasSVE_B16B16()) return bfclamp_z_zz(ctx, dec); // -> bfclamp_z_zz_
	if(size && HasSME2() && HasSVE2p1()) return fclamp_z_zz(ctx, dec); // -> fclamp_z_zz_
	UNMATCHED;
}

int decode_iclass_sve_int_count_v_sat(context *ctx, Instruction *dec)
{
	uint32_t D=(INSWORD>>17)&1, U=(INSWORD>>16)&1, opc=(INSWORD>>9)&3;
	if(!D && !U && !opc && HasSVE() && HasSME()) return sqincp_z_p_z(ctx, dec); // -> sqincp_z_p_z_
	if(!D && U && !opc && HasSVE() && HasSME()) return uqincp_z_p_z(ctx, dec); // -> uqincp_z_p_z_
	if(D && !U && !opc && HasSVE() && HasSME()) return sqdecp_z_p_z(ctx, dec); // -> sqdecp_z_p_z_
	if(D && U && !opc && HasSVE() && HasSME()) return uqdecp_z_p_z(ctx, dec); // -> uqdecp_z_p_z_
	if(opc) UNALLOCATED(ENC_UNALLOCATED_500_SVE_INT_COUNT_V_SAT);
	UNMATCHED;
}

int decode_iclass_sve_int_count_v(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>17)&1, D=(INSWORD>>16)&1, opc2=(INSWORD>>9)&3;
	if(!op && !D && !opc2 && HasSVE() && HasSME()) return incp_z_p_z(ctx, dec); // -> incp_z_p_z_
	if(!op && D && !opc2 && HasSVE() && HasSME()) return decp_z_p_z(ctx, dec); // -> decp_z_p_z_
	if(!op && opc2) UNALLOCATED(ENC_UNALLOCATED_502_SVE_INT_COUNT_V);
	if(op) UNALLOCATED(ENC_UNALLOCATED_501_SVE_INT_COUNT_V);
	UNMATCHED;
}

int decode_iclass_sve_int_count_r_sat(context *ctx, Instruction *dec)
{
	uint32_t D=(INSWORD>>17)&1, U=(INSWORD>>16)&1, sf=(INSWORD>>10)&1, op=(INSWORD>>9)&1;
	if(!D && !U && !sf && !op && HasSVE() && HasSME()) return sqincp_r_p_r(ctx, dec); // -> sqincp_r_p_r_sx
	if(!D && !U && sf && !op && HasSVE() && HasSME()) return sqincp_r_p_r(ctx, dec); // -> sqincp_r_p_r_x
	if(!D && U && !sf && !op && HasSVE() && HasSME()) return uqincp_r_p_r(ctx, dec); // -> uqincp_r_p_r_uw
	if(!D && U && sf && !op && HasSVE() && HasSME()) return uqincp_r_p_r(ctx, dec); // -> uqincp_r_p_r_x
	if(D && !U && !sf && !op && HasSVE() && HasSME()) return sqdecp_r_p_r(ctx, dec); // -> sqdecp_r_p_r_sx
	if(D && !U && sf && !op && HasSVE() && HasSME()) return sqdecp_r_p_r(ctx, dec); // -> sqdecp_r_p_r_x
	if(D && U && !sf && !op && HasSVE() && HasSME()) return uqdecp_r_p_r(ctx, dec); // -> uqdecp_r_p_r_uw
	if(D && U && sf && !op && HasSVE() && HasSME()) return uqdecp_r_p_r(ctx, dec); // -> uqdecp_r_p_r_x
	if(op) UNALLOCATED(ENC_UNALLOCATED_503_SVE_INT_COUNT_R_SAT);
	UNMATCHED;
}

int decode_iclass_sve_int_count_r(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>17)&1, D=(INSWORD>>16)&1, opc2=(INSWORD>>9)&3;
	if(!op && !D && !opc2 && HasSVE() && HasSME()) return incp_r_p_r(ctx, dec); // -> incp_r_p_r_
	if(!op && D && !opc2 && HasSVE() && HasSME()) return decp_r_p_r(ctx, dec); // -> decp_r_p_r_
	if(!op && opc2) UNALLOCATED(ENC_UNALLOCATED_505_SVE_INT_COUNT_R);
	if(op) UNALLOCATED(ENC_UNALLOCATED_504_SVE_INT_COUNT_R);
	UNMATCHED;
}

int decode_iclass_sve_int_index_ii(context *ctx, Instruction *dec)
{
	return index_z_ii(ctx, dec);
}

int decode_iclass_sve_int_index_ri(context *ctx, Instruction *dec)
{
	return index_z_ri(ctx, dec);
}

int decode_iclass_sve_int_index_ir(context *ctx, Instruction *dec)
{
	return index_z_ir(ctx, dec);
}

int decode_iclass_sve_int_index_rr(context *ctx, Instruction *dec)
{
	return index_z_rr(ctx, dec);
}

int decode_iclass_sve_int_bin_cons_arit_0(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, opc=(INSWORD>>10)&7;
	if(size==3 && opc==2 && HasSVE() && HasCPA()) return addpt_z_zz(ctx, dec); // -> addpt_z_zz_
	if(size==3 && opc==3 && HasSVE() && HasCPA()) return subpt_z_zz(ctx, dec); // -> subpt_z_zz_
	if(size!=3 && (opc&6)==2) UNALLOCATED(ENC_UNALLOCATED_506_SVE_INT_BIN_CONS_ARIT_0);
	if(!opc && HasSVE() && HasSME()) return add_z_zz(ctx, dec); // -> add_z_zz_
	if(opc==1 && HasSVE() && HasSME()) return sub_z_zz(ctx, dec); // -> sub_z_zz_
	if(opc==4 && HasSVE() && HasSME()) return sqadd_z_zz(ctx, dec); // -> sqadd_z_zz_
	if(opc==5 && HasSVE() && HasSME()) return uqadd_z_zz(ctx, dec); // -> uqadd_z_zz_
	if(opc==6 && HasSVE() && HasSME()) return sqsub_z_zz(ctx, dec); // -> sqsub_z_zz_
	if(opc==7 && HasSVE() && HasSME()) return uqsub_z_zz(ctx, dec); // -> uqsub_z_zz_
	UNMATCHED;
}

int decode_iclass_sve_int_bin_pred_arit_0(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, opc=(INSWORD>>16)&7;
	if(size==3 && opc==4 && HasSVE() && HasCPA()) return addpt_z_p_zz(ctx, dec); // -> addpt_z_p_zz_
	if(size==3 && opc==5 && HasSVE() && HasCPA()) return subpt_z_p_zz(ctx, dec); // -> subpt_z_p_zz_
	if(size==3 && (opc&6)==6) UNALLOCATED(ENC_UNALLOCATED_509_SVE_INT_BIN_PRED_ARIT_0);
	if(!opc && HasSVE() && HasSME()) return add_z_p_zz(ctx, dec); // -> add_z_p_zz_
	if(opc==1 && HasSVE() && HasSME()) return sub_z_p_zz(ctx, dec); // -> sub_z_p_zz_
	if(opc==2) UNALLOCATED(ENC_UNALLOCATED_508_SVE_INT_BIN_PRED_ARIT_0);
	if(opc==3 && HasSVE() && HasSME()) return subr_z_p_zz(ctx, dec); // -> subr_z_p_zz_
	if(size!=3 && (opc&4)==4) UNALLOCATED(ENC_UNALLOCATED_507_SVE_INT_BIN_PRED_ARIT_0);
	UNMATCHED;
}

int decode_iclass_sve_int_bin_pred_arit_1(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>17)&3, U=(INSWORD>>16)&1;
	if(!opc && !U && HasSVE() && HasSME()) return smax_z_p_zz(ctx, dec); // -> smax_z_p_zz_
	if(!opc && U && HasSVE() && HasSME()) return umax_z_p_zz(ctx, dec); // -> umax_z_p_zz_
	if(opc==1 && !U && HasSVE() && HasSME()) return smin_z_p_zz(ctx, dec); // -> smin_z_p_zz_
	if(opc==1 && U && HasSVE() && HasSME()) return umin_z_p_zz(ctx, dec); // -> umin_z_p_zz_
	if(opc==2 && !U && HasSVE() && HasSME()) return sabd_z_p_zz(ctx, dec); // -> sabd_z_p_zz_
	if(opc==2 && U && HasSVE() && HasSME()) return uabd_z_p_zz(ctx, dec); // -> uabd_z_p_zz_
	if(opc==3) UNALLOCATED(ENC_UNALLOCATED_510_SVE_INT_BIN_PRED_ARIT_1);
	UNMATCHED;
}

int decode_iclass_sve_int_bin_pred_arit_2(context *ctx, Instruction *dec)
{
	uint32_t H=(INSWORD>>17)&1, U=(INSWORD>>16)&1;
	if(!H && !U && HasSVE() && HasSME()) return mul_z_p_zz(ctx, dec); // -> mul_z_p_zz_
	if(!H && U) UNALLOCATED(ENC_UNALLOCATED_511_SVE_INT_BIN_PRED_ARIT_2);
	if(H && !U && HasSVE() && HasSME()) return smulh_z_p_zz(ctx, dec); // -> smulh_z_p_zz_
	if(H && U && HasSVE() && HasSME()) return umulh_z_p_zz(ctx, dec); // -> umulh_z_p_zz_
	UNMATCHED;
}

int decode_iclass_sve_int_bin_pred_div(context *ctx, Instruction *dec)
{
	uint32_t R=(INSWORD>>17)&1, U=(INSWORD>>16)&1;
	if(!R && !U && HasSVE() && HasSME()) return sdiv_z_p_zz(ctx, dec); // -> sdiv_z_p_zz_
	if(!R && U && HasSVE() && HasSME()) return udiv_z_p_zz(ctx, dec); // -> udiv_z_p_zz_
	if(R && !U && HasSVE() && HasSME()) return sdivr_z_p_zz(ctx, dec); // -> sdivr_z_p_zz_
	if(R && U && HasSVE() && HasSME()) return udivr_z_p_zz(ctx, dec); // -> udivr_z_p_zz_
	UNMATCHED;
}

int decode_iclass_sve_int_bin_pred_log(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&7;
	if(!opc && HasSVE() && HasSME()) return orr_z_p_zz(ctx, dec); // -> orr_z_p_zz_
	if(opc==1 && HasSVE() && HasSME()) return eor_z_p_zz(ctx, dec); // -> eor_z_p_zz_
	if(opc==2 && HasSVE() && HasSME()) return and_z_p_zz(ctx, dec); // -> and_z_p_zz_
	if(opc==3 && HasSVE() && HasSME()) return bic_z_p_zz(ctx, dec); // -> bic_z_p_zz_
	if((opc&4)==4) UNALLOCATED(ENC_UNALLOCATED_512_SVE_INT_BIN_PRED_LOG);
	UNMATCHED;
}

int decode_iclass_sve_int_while_rr(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>11)&1, lt=(INSWORD>>10)&1, eq=(INSWORD>>4)&1;
	if(!U && !lt && !eq && HasSVE2() && HasSME()) return whilege_p_p_rr(ctx, dec); // -> whilege_p_p_rr_
	if(!U && !lt && eq && HasSVE2() && HasSME()) return whilegt_p_p_rr(ctx, dec); // -> whilegt_p_p_rr_
	if(!U && lt && !eq && HasSVE() && HasSME()) return whilelt_p_p_rr(ctx, dec); // -> whilelt_p_p_rr_
	if(!U && lt && eq && HasSVE() && HasSME()) return whilele_p_p_rr(ctx, dec); // -> whilele_p_p_rr_
	if(U && !lt && !eq && HasSVE2() && HasSME()) return whilehs_p_p_rr(ctx, dec); // -> whilehs_p_p_rr_
	if(U && !lt && eq && HasSVE2() && HasSME()) return whilehi_p_p_rr(ctx, dec); // -> whilehi_p_p_rr_
	if(U && lt && !eq && HasSVE() && HasSME()) return whilelo_p_p_rr(ctx, dec); // -> whilelo_p_p_rr_
	if(U && lt && eq && HasSVE() && HasSME()) return whilels_p_p_rr(ctx, dec); // -> whilels_p_p_rr_
	UNMATCHED;
}

int decode_iclass_sve_int_cterm(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>23)&1, ne=(INSWORD>>4)&1;
	if(op && !ne && HasSVE() && HasSME()) return ctermeq_rr(ctx, dec); // -> ctermeq_rr_
	if(op && ne && HasSVE() && HasSME()) return ctermeq_rr(ctx, dec); // -> ctermne_rr_
	if(!op) UNALLOCATED(ENC_UNALLOCATED_513_SVE_INT_CTERM);
	UNMATCHED;
}

int decode_iclass_sve_int_whilenc(context *ctx, Instruction *dec)
{
	uint32_t rw=(INSWORD>>4)&1;
	if(!rw && HasSVE2() && HasSME()) return whilewr_p_rr(ctx, dec); // -> whilewr_p_rr_
	if(rw && HasSVE2() && HasSME()) return whilerw_p_rr(ctx, dec); // -> whilerw_p_rr_
	UNMATCHED;
}

int decode_iclass_sve_int_scmp_vi(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>15)&1, o2=(INSWORD>>13)&1, ne=(INSWORD>>4)&1;
	if(!op && !o2 && !ne && HasSVE() && HasSME()) return cmpeq_p_p_zi(ctx, dec); // -> cmpge_p_p_zi_
	if(!op && !o2 && ne && HasSVE() && HasSME()) return cmpeq_p_p_zi(ctx, dec); // -> cmpgt_p_p_zi_
	if(!op && o2 && !ne && HasSVE() && HasSME()) return cmpeq_p_p_zi(ctx, dec); // -> cmplt_p_p_zi_
	if(!op && o2 && ne && HasSVE() && HasSME()) return cmpeq_p_p_zi(ctx, dec); // -> cmple_p_p_zi_
	if(op && !o2 && !ne && HasSVE() && HasSME()) return cmpeq_p_p_zi(ctx, dec); // -> cmpeq_p_p_zi_
	if(op && !o2 && ne && HasSVE() && HasSME()) return cmpeq_p_p_zi(ctx, dec); // -> cmpne_p_p_zi_
	if(op && o2) UNALLOCATED(ENC_UNALLOCATED_514_SVE_INT_SCMP_VI);
	UNMATCHED;
}

int decode_iclass_sve_int_ucmp_vi(context *ctx, Instruction *dec)
{
	uint32_t lt=(INSWORD>>13)&1, ne=(INSWORD>>4)&1;
	if(!lt && !ne && HasSVE() && HasSME()) return cmpeq_p_p_zi(ctx, dec); // -> cmphs_p_p_zi_
	if(!lt && ne && HasSVE() && HasSME()) return cmpeq_p_p_zi(ctx, dec); // -> cmphi_p_p_zi_
	if(lt && !ne && HasSVE() && HasSME()) return cmpeq_p_p_zi(ctx, dec); // -> cmplo_p_p_zi_
	if(lt && ne && HasSVE() && HasSME()) return cmpeq_p_p_zi(ctx, dec); // -> cmpls_p_p_zi_
	UNMATCHED;
}

int decode_iclass_sve_int_cmp_0(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>15)&1, o2=(INSWORD>>13)&1, ne=(INSWORD>>4)&1;
	if(!op && !o2 && !ne && HasSVE() && HasSME()) return cmpeq_p_p_zz(ctx, dec); // -> cmphs_p_p_zz_
	if(!op && !o2 && ne && HasSVE() && HasSME()) return cmpeq_p_p_zz(ctx, dec); // -> cmphi_p_p_zz_
	if(!op && o2 && !ne && HasSVE() && HasSME()) return cmpeq_p_p_zw(ctx, dec); // -> cmpeq_p_p_zw_
	if(!op && o2 && ne && HasSVE() && HasSME()) return cmpeq_p_p_zw(ctx, dec); // -> cmpne_p_p_zw_
	if(op && !o2 && !ne && HasSVE() && HasSME()) return cmpeq_p_p_zz(ctx, dec); // -> cmpge_p_p_zz_
	if(op && !o2 && ne && HasSVE() && HasSME()) return cmpeq_p_p_zz(ctx, dec); // -> cmpgt_p_p_zz_
	if(op && o2 && !ne && HasSVE() && HasSME()) return cmpeq_p_p_zz(ctx, dec); // -> cmpeq_p_p_zz_
	if(op && o2 && ne && HasSVE() && HasSME()) return cmpeq_p_p_zz(ctx, dec); // -> cmpne_p_p_zz_
	UNMATCHED;
}

int decode_iclass_sve_int_cmp_1(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>15)&1, lt=(INSWORD>>13)&1, ne=(INSWORD>>4)&1;
	if(!U && !lt && !ne && HasSVE() && HasSME()) return cmpeq_p_p_zw(ctx, dec); // -> cmpge_p_p_zw_
	if(!U && !lt && ne && HasSVE() && HasSME()) return cmpeq_p_p_zw(ctx, dec); // -> cmpgt_p_p_zw_
	if(!U && lt && !ne && HasSVE() && HasSME()) return cmpeq_p_p_zw(ctx, dec); // -> cmplt_p_p_zw_
	if(!U && lt && ne && HasSVE() && HasSME()) return cmpeq_p_p_zw(ctx, dec); // -> cmple_p_p_zw_
	if(U && !lt && !ne && HasSVE() && HasSME()) return cmpeq_p_p_zw(ctx, dec); // -> cmphs_p_p_zw_
	if(U && !lt && ne && HasSVE() && HasSME()) return cmpeq_p_p_zw(ctx, dec); // -> cmphi_p_p_zw_
	if(U && lt && !ne && HasSVE() && HasSME()) return cmpeq_p_p_zw(ctx, dec); // -> cmplo_p_p_zw_
	if(U && lt && ne && HasSVE() && HasSME()) return cmpeq_p_p_zw(ctx, dec); // -> cmpls_p_p_zw_
	UNMATCHED;
}

int decode_iclass_sve_int_bin_cons_misc_0_b(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>10)&1;
	if(!op && HasSVE()) return ftssel_z_zz(ctx, dec); // -> ftssel_z_zz_
	if(op) UNALLOCATED(ENC_UNALLOCATED_515_SVE_INT_BIN_CONS_MISC_0_B);
	UNMATCHED;
}

int decode_iclass_sve_int_bin_cons_misc_0_c(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&0x1f;
	if(!opc && HasSVE() && HasSSVE_FEXPA()) return fexpa_z_z(ctx, dec); // -> fexpa_z_z_
	if(opc) UNALLOCATED(ENC_UNALLOCATED_516_SVE_INT_BIN_CONS_MISC_0_C);
	UNMATCHED;
}

int decode_iclass_sve_int_bin_cons_misc_0_d(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>22)&3, opc2=(INSWORD>>16)&0x1f;
	if(!opc && !opc2 && HasSVE() && HasSME()) return movprfx_z_z(ctx, dec); // -> movprfx_z_z_
	if(!opc && opc2) UNALLOCATED(ENC_UNALLOCATED_518_SVE_INT_BIN_CONS_MISC_0_D);
	if(opc) UNALLOCATED(ENC_UNALLOCATED_517_SVE_INT_BIN_CONS_MISC_0_D);
	UNMATCHED;
}

int decode_iclass_sve_int_mlas_vvv_pred(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>13)&1;
	if(!op && HasSVE() && HasSME()) return mla_z_p_zzz(ctx, dec); // -> mla_z_p_zzz_
	if(op && HasSVE() && HasSME()) return mls_z_p_zzz(ctx, dec); // -> mls_z_p_zzz_
	UNMATCHED;
}

int decode_iclass_sve_int_mladdsub_vvv_pred(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>13)&1;
	if(!op && HasSVE() && HasSME()) return mad_z_p_zzz(ctx, dec); // -> mad_z_p_zzz_
	if(op && HasSVE() && HasSME()) return msb_z_p_zzz(ctx, dec); // -> msb_z_p_zzz_
	UNMATCHED;
}

int decode_iclass_sve_intx_dot(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, U=(INSWORD>>10)&1;
	if(size==1 && !U && HasSVE2p3() && HasSME2p3()) return sdot_z32_zzz(ctx, dec); // -> sdot_z16_zzz_h
	if(size==1 && U && HasSVE2p3() && HasSME2p3()) return udot_z32_zzz(ctx, dec); // -> udot_z16_zzz_h
	if(!size) UNALLOCATED(ENC_UNALLOCATED_519_SVE_INTX_DOT);
	if((size&2)==2 && !U && HasSVE() && HasSME()) return sdot_z_zzz(ctx, dec); // -> sdot_z_zzz_
	if((size&2)==2 && U && HasSVE() && HasSME()) return udot_z_zzz(ctx, dec); // -> udot_z_zzz_
	UNMATCHED;
}

int decode_iclass_sve_intx_qdmlalbt(context *ctx, Instruction *dec)
{
	uint32_t S=(INSWORD>>10)&1;
	if(!S && HasSVE2() && HasSME()) return sqdmlalbt_z_zzz(ctx, dec); // -> sqdmlalbt_z_zzz_
	if(S && HasSVE2() && HasSME()) return sqdmlslbt_z_zzz(ctx, dec); // -> sqdmlslbt_z_zzz_
	UNMATCHED;
}

int decode_iclass_sve_intx_cdot(context *ctx, Instruction *dec)
{
	return cdot_z_zzz(ctx, dec);
}

int decode_iclass_sve_intx_cmla(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>12)&1;
	if(!op && HasSVE2() && HasSME()) return cmla_z_zzz(ctx, dec); // -> cmla_z_zzz_
	if(op && HasSVE2() && HasSME()) return sqrdcmlah_z_zzz(ctx, dec); // -> sqrdcmlah_z_zzz_
	UNMATCHED;
}

int decode_iclass_sve_intx_mlal_long(context *ctx, Instruction *dec)
{
	uint32_t S=(INSWORD>>12)&1, U=(INSWORD>>11)&1, T=(INSWORD>>10)&1;
	if(!S && !U && !T && HasSVE2() && HasSME()) return smlalb_z_zzz(ctx, dec); // -> smlalb_z_zzz_
	if(!S && !U && T && HasSVE2() && HasSME()) return smlalt_z_zzz(ctx, dec); // -> smlalt_z_zzz_
	if(!S && U && !T && HasSVE2() && HasSME()) return umlalb_z_zzz(ctx, dec); // -> umlalb_z_zzz_
	if(!S && U && T && HasSVE2() && HasSME()) return umlalt_z_zzz(ctx, dec); // -> umlalt_z_zzz_
	if(S && !U && !T && HasSVE2() && HasSME()) return smlslb_z_zzz(ctx, dec); // -> smlslb_z_zzz_
	if(S && !U && T && HasSVE2() && HasSME()) return smlslt_z_zzz(ctx, dec); // -> smlslt_z_zzz_
	if(S && U && !T && HasSVE2() && HasSME()) return umlslb_z_zzz(ctx, dec); // -> umlslb_z_zzz_
	if(S && U && T && HasSVE2() && HasSME()) return umlslt_z_zzz(ctx, dec); // -> umlslt_z_zzz_
	UNMATCHED;
}

int decode_iclass_sve_intx_qdmlal_long(context *ctx, Instruction *dec)
{
	uint32_t S=(INSWORD>>11)&1, T=(INSWORD>>10)&1;
	if(!S && !T && HasSVE2() && HasSME()) return sqdmlalb_z_zzz(ctx, dec); // -> sqdmlalb_z_zzz_
	if(!S && T && HasSVE2() && HasSME()) return sqdmlalt_z_zzz(ctx, dec); // -> sqdmlalt_z_zzz_
	if(S && !T && HasSVE2() && HasSME()) return sqdmlslb_z_zzz(ctx, dec); // -> sqdmlslb_z_zzz_
	if(S && T && HasSVE2() && HasSME()) return sqdmlslt_z_zzz(ctx, dec); // -> sqdmlslt_z_zzz_
	UNMATCHED;
}

int decode_iclass_sve_intx_qrdmlah(context *ctx, Instruction *dec)
{
	uint32_t S=(INSWORD>>10)&1;
	if(!S && HasSVE2() && HasSME()) return sqrdmlah_z_zzz(ctx, dec); // -> sqrdmlah_z_zzz_
	if(S && HasSVE2() && HasSME()) return sqrdmlsh_z_zzz(ctx, dec); // -> sqrdmlsh_z_zzz_
	UNMATCHED;
}

int decode_iclass_sve_intx_mixed_dot(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3;
	if(size==2 && HasSVE() && HasI8MM() && HasSME() && HasI8MM()) return usdot_z_zzz(ctx, dec); // -> usdot_z_zzz_s
	if(size!=2) UNALLOCATED(ENC_UNALLOCATED_520_SVE_INTX_MIXED_DOT);
	UNMATCHED;
}

int decode_iclass_sve_int_reduce_0(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>17)&1, U=(INSWORD>>16)&1;
	if(!op && !U && HasSVE() && HasSME()) return saddv_r_p_z(ctx, dec); // -> saddv_r_p_z_
	if(!op && U && HasSVE() && HasSME()) return uaddv_r_p_z(ctx, dec); // -> uaddv_r_p_z_
	if(op) UNALLOCATED(ENC_UNALLOCATED_521_SVE_INT_REDUCE_0);
	UNMATCHED;
}

int decode_iclass_sve_int_reduce_0q(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>17)&1, U=(INSWORD>>16)&1;
	if(!op && !U) UNALLOCATED(ENC_UNALLOCATED_523_SVE_INT_REDUCE_0Q);
	if(!op && U && HasSVE2p1() && HasSME2p1()) return addqv_z_p_z(ctx, dec); // -> addqv_z_p_z_
	if(op) UNALLOCATED(ENC_UNALLOCATED_522_SVE_INT_REDUCE_0Q);
	UNMATCHED;
}

int decode_iclass_sve_int_reduce_1(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>17)&1, U=(INSWORD>>16)&1;
	if(!op && !U && HasSVE() && HasSME()) return smaxv_r_p_z(ctx, dec); // -> smaxv_r_p_z_
	if(!op && U && HasSVE() && HasSME()) return umaxv_r_p_z(ctx, dec); // -> umaxv_r_p_z_
	if(op && !U && HasSVE() && HasSME()) return sminv_r_p_z(ctx, dec); // -> sminv_r_p_z_
	if(op && U && HasSVE() && HasSME()) return uminv_r_p_z(ctx, dec); // -> uminv_r_p_z_
	UNMATCHED;
}

int decode_iclass_sve_int_reduce_1q(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>17)&1, U=(INSWORD>>16)&1;
	if(!op && !U && HasSVE2p1() && HasSME2p1()) return smaxqv_z_p_z(ctx, dec); // -> smaxqv_z_p_z_
	if(!op && U && HasSVE2p1() && HasSME2p1()) return umaxqv_z_p_z(ctx, dec); // -> umaxqv_z_p_z_
	if(op && !U && HasSVE2p1() && HasSME2p1()) return sminqv_z_p_z(ctx, dec); // -> sminqv_z_p_z_
	if(op && U && HasSVE2p1() && HasSME2p1()) return uminqv_z_p_z(ctx, dec); // -> uminqv_z_p_z_
	UNMATCHED;
}

int decode_iclass_sve_int_movprfx_pred(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>17)&3;
	if(!opc && HasSVE() && HasSME()) return movprfx_z_p_z(ctx, dec); // -> movprfx_z_p_z_
	if(opc) UNALLOCATED(ENC_UNALLOCATED_524_SVE_INT_MOVPRFX_PRED);
	UNMATCHED;
}

int decode_iclass_sve_int_reduce_2(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&3;
	if(!opc && HasSVE() && HasSME()) return orv_r_p_z(ctx, dec); // -> orv_r_p_z_
	if(opc==1 && HasSVE() && HasSME()) return eorv_r_p_z(ctx, dec); // -> eorv_r_p_z_
	if(opc==2 && HasSVE() && HasSME()) return andv_r_p_z(ctx, dec); // -> andv_r_p_z_
	if(opc==3) UNALLOCATED(ENC_UNALLOCATED_525_SVE_INT_REDUCE_2);
	UNMATCHED;
}

int decode_iclass_sve_int_reduce_2q(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&3;
	if(!opc && HasSVE2p1() && HasSME2p1()) return orqv_z_p_z(ctx, dec); // -> orqv_z_p_z_
	if(opc==1 && HasSVE2p1() && HasSME2p1()) return eorqv_z_p_z(ctx, dec); // -> eorqv_z_p_z_
	if(opc==2 && HasSVE2p1() && HasSME2p1()) return andqv_z_p_z(ctx, dec); // -> andqv_z_p_z_
	if(opc==3) UNALLOCATED(ENC_UNALLOCATED_526_SVE_INT_REDUCE_2Q);
	UNMATCHED;
}

int decode_iclass_sve_int_un_pred_arit_0(context *ctx, Instruction *dec)
{
	uint32_t M=(INSWORD>>20)&1, opc=(INSWORD>>16)&7;
	if(!M && !opc && HasSVE2p2() && HasSME2p2()) return sxtb_z_p_z(ctx, dec); // -> sxtb_z_p_z_z
	if(!M && opc==1 && HasSVE2p2() && HasSME2p2()) return uxtb_z_p_z(ctx, dec); // -> uxtb_z_p_z_z
	if(!M && opc==2 && HasSVE2p2() && HasSME2p2()) return sxtb_z_p_z(ctx, dec); // -> sxth_z_p_z_z
	if(!M && opc==3 && HasSVE2p2() && HasSME2p2()) return uxtb_z_p_z(ctx, dec); // -> uxth_z_p_z_z
	if(!M && opc==4 && HasSVE2p2() && HasSME2p2()) return sxtb_z_p_z(ctx, dec); // -> sxtw_z_p_z_z
	if(!M && opc==5 && HasSVE2p2() && HasSME2p2()) return uxtb_z_p_z(ctx, dec); // -> uxtw_z_p_z_z
	if(!M && opc==6 && HasSVE2p2() && HasSME2p2()) return abs_z_p_z(ctx, dec); // -> abs_z_p_z_z
	if(!M && opc==7 && HasSVE2p2() && HasSME2p2()) return neg_z_p_z(ctx, dec); // -> neg_z_p_z_z
	if(M && !opc && HasSVE() && HasSME()) return sxtb_z_p_z(ctx, dec); // -> sxtb_z_p_z_m
	if(M && opc==1 && HasSVE() && HasSME()) return uxtb_z_p_z(ctx, dec); // -> uxtb_z_p_z_m
	if(M && opc==2 && HasSVE() && HasSME()) return sxtb_z_p_z(ctx, dec); // -> sxth_z_p_z_m
	if(M && opc==3 && HasSVE() && HasSME()) return uxtb_z_p_z(ctx, dec); // -> uxth_z_p_z_m
	if(M && opc==4 && HasSVE() && HasSME()) return sxtb_z_p_z(ctx, dec); // -> sxtw_z_p_z_m
	if(M && opc==5 && HasSVE() && HasSME()) return uxtb_z_p_z(ctx, dec); // -> uxtw_z_p_z_m
	if(M && opc==6 && HasSVE() && HasSME()) return abs_z_p_z(ctx, dec); // -> abs_z_p_z_m
	if(M && opc==7 && HasSVE() && HasSME()) return neg_z_p_z(ctx, dec); // -> neg_z_p_z_m
	UNMATCHED;
}

int decode_iclass_sve_int_un_pred_arit_1(context *ctx, Instruction *dec)
{
	uint32_t M=(INSWORD>>20)&1, opc=(INSWORD>>16)&7;
	if(!M && !opc && HasSVE2p2() && HasSME2p2()) return cls_z_p_z(ctx, dec); // -> cls_z_p_z_z
	if(!M && opc==1 && HasSVE2p2() && HasSME2p2()) return clz_z_p_z(ctx, dec); // -> clz_z_p_z_z
	if(!M && opc==2 && HasSVE2p2() && HasSME2p2()) return cnt_z_p_z(ctx, dec); // -> cnt_z_p_z_z
	if(!M && opc==3 && HasSVE2p2() && HasSME2p2()) return cnot_z_p_z(ctx, dec); // -> cnot_z_p_z_z
	if(!M && opc==4 && HasSVE2p2() && HasSME2p2()) return fabs_z_p_z(ctx, dec); // -> fabs_z_p_z_z
	if(!M && opc==5 && HasSVE2p2() && HasSME2p2()) return fneg_z_p_z(ctx, dec); // -> fneg_z_p_z_z
	if(!M && opc==6 && HasSVE2p2() && HasSME2p2()) return not_z_p_z(ctx, dec); // -> not_z_p_z_z
	if(M && !opc && HasSVE() && HasSME()) return cls_z_p_z(ctx, dec); // -> cls_z_p_z_m
	if(M && opc==1 && HasSVE() && HasSME()) return clz_z_p_z(ctx, dec); // -> clz_z_p_z_m
	if(M && opc==2 && HasSVE() && HasSME()) return cnt_z_p_z(ctx, dec); // -> cnt_z_p_z_m
	if(M && opc==3 && HasSVE() && HasSME()) return cnot_z_p_z(ctx, dec); // -> cnot_z_p_z_m
	if(M && opc==4 && HasSVE() && HasSME()) return fabs_z_p_z(ctx, dec); // -> fabs_z_p_z_m
	if(M && opc==5 && HasSVE() && HasSME()) return fneg_z_p_z(ctx, dec); // -> fneg_z_p_z_m
	if(M && opc==6 && HasSVE() && HasSME()) return not_z_p_z(ctx, dec); // -> not_z_p_z_m
	if(opc==7) UNALLOCATED(ENC_UNALLOCATED_527_SVE_INT_UN_PRED_ARIT_1);
	UNMATCHED;
}

int decode_iclass_sve_int_dup_imm_pred(context *ctx, Instruction *dec)
{
	uint32_t M=(INSWORD>>14)&1;
	if(!M && HasSVE() && HasSME()) return cpy_z_o_i(ctx, dec); // -> cpy_z_o_i_
	if(M && HasSVE() && HasSME()) return cpy_z_p_i(ctx, dec); // -> cpy_z_p_i_
	UNMATCHED;
}

int decode_iclass_sve_int_dup_fpimm_pred(context *ctx, Instruction *dec)
{
	return fcpy_z_p_i(ctx, dec);
}

int decode_iclass_sve_int_arith_imm0(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&7;
	if(!opc && HasSVE() && HasSME()) return add_z_zi(ctx, dec); // -> add_z_zi_
	if(opc==1 && HasSVE() && HasSME()) return sub_z_zi(ctx, dec); // -> sub_z_zi_
	if(opc==2) UNALLOCATED(ENC_UNALLOCATED_528_SVE_INT_ARITH_IMM0);
	if(opc==3 && HasSVE() && HasSME()) return subr_z_zi(ctx, dec); // -> subr_z_zi_
	if(opc==4 && HasSVE() && HasSME()) return sqadd_z_zi(ctx, dec); // -> sqadd_z_zi_
	if(opc==5 && HasSVE() && HasSME()) return uqadd_z_zi(ctx, dec); // -> uqadd_z_zi_
	if(opc==6 && HasSVE() && HasSME()) return sqsub_z_zi(ctx, dec); // -> sqsub_z_zi_
	if(opc==7 && HasSVE() && HasSME()) return uqsub_z_zi(ctx, dec); // -> uqsub_z_zi_
	UNMATCHED;
}

int decode_iclass_sve_int_arith_imm1(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&7, o2=(INSWORD>>13)&1;
	if(!opc && !o2 && HasSVE() && HasSME()) return smax_z_zi(ctx, dec); // -> smax_z_zi_
	if(opc==1 && !o2 && HasSVE() && HasSME()) return umax_z_zi(ctx, dec); // -> umax_z_zi_
	if(opc==2 && !o2 && HasSVE() && HasSME()) return smin_z_zi(ctx, dec); // -> smin_z_zi_
	if(opc==3 && !o2 && HasSVE() && HasSME()) return umin_z_zi(ctx, dec); // -> umin_z_zi_
	if(!(opc&4) && o2) UNALLOCATED(ENC_UNALLOCATED_530_SVE_INT_ARITH_IMM1);
	if((opc&4)==4) UNALLOCATED(ENC_UNALLOCATED_529_SVE_INT_ARITH_IMM1);
	UNMATCHED;
}

int decode_iclass_sve_int_arith_imm2(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&7, o2=(INSWORD>>13)&1;
	if(!opc && !o2 && HasSVE() && HasSME()) return mul_z_zi(ctx, dec); // -> mul_z_zi_
	if(!opc && o2) UNALLOCATED(ENC_UNALLOCATED_532_SVE_INT_ARITH_IMM2);
	if(opc) UNALLOCATED(ENC_UNALLOCATED_531_SVE_INT_ARITH_IMM2);
	UNMATCHED;
}

int decode_iclass_sve_int_dup_imm(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>17)&3;
	if(!opc && HasSVE() && HasSME()) return dup_z_i(ctx, dec); // -> dup_z_i_
	if(opc) UNALLOCATED(ENC_UNALLOCATED_533_SVE_INT_DUP_IMM);
	UNMATCHED;
}

int decode_iclass_sve_int_dup_fpimm(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>17)&3, o2=(INSWORD>>13)&1;
	if(!opc && !o2 && HasSVE() && HasSME()) return fdup_z_i(ctx, dec); // -> fdup_z_i_
	if(!opc && o2) UNALLOCATED(ENC_UNALLOCATED_535_SVE_INT_DUP_FPIMM);
	if(opc) UNALLOCATED(ENC_UNALLOCATED_534_SVE_INT_DUP_FPIMM);
	UNMATCHED;
}

int decode_iclass_sve_mem_32b_gld_vs(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>23)&3, U=(INSWORD>>14)&1, ff=(INSWORD>>13)&1;
	if(!opc && !U && !ff && HasSVE()) return ld1sb_z_p_bz(ctx, dec); // -> ld1sb_z_p_bz_s_x32_unscaled
	if(!opc && !U && ff && HasSVE()) return ldff1sb_z_p_bz(ctx, dec); // -> ldff1sb_z_p_bz_s_x32_unscaled
	if(!opc && U && !ff && HasSVE()) return ld1b_z_p_bz(ctx, dec); // -> ld1b_z_p_bz_s_x32_unscaled
	if(!opc && U && ff && HasSVE()) return ldff1b_z_p_bz(ctx, dec); // -> ldff1b_z_p_bz_s_x32_unscaled
	if(opc==1 && !U && !ff && HasSVE()) return ld1sh_z_p_bz(ctx, dec); // -> ld1sh_z_p_bz_s_x32_unscaled
	if(opc==1 && !U && ff && HasSVE()) return ldff1sh_z_p_bz(ctx, dec); // -> ldff1sh_z_p_bz_s_x32_unscaled
	if(opc==1 && U && !ff && HasSVE()) return ld1h_z_p_bz(ctx, dec); // -> ld1h_z_p_bz_s_x32_unscaled
	if(opc==1 && U && ff && HasSVE()) return ldff1h_z_p_bz(ctx, dec); // -> ldff1h_z_p_bz_s_x32_unscaled
	if(opc==2 && U && !ff && HasSVE()) return ld1w_z_p_bz(ctx, dec); // -> ld1w_z_p_bz_s_x32_unscaled
	if(opc==2 && U && ff && HasSVE()) return ldff1w_z_p_bz(ctx, dec); // -> ldff1w_z_p_bz_s_x32_unscaled
	if(opc==2 && !U) UNALLOCATED(ENC_UNALLOCATED_536_SVE_MEM_32B_GLD_VS);
	UNMATCHED;
}

int decode_iclass_sve_mem_32b_prfm_sv(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>13)&3;
	if(!msz && HasSVE()) return prfb_i_p_bz(ctx, dec); // -> prfb_i_p_bz_s_x32_scaled
	if(msz==1 && HasSVE()) return prfh_i_p_bz(ctx, dec); // -> prfh_i_p_bz_s_x32_scaled
	if(msz==2 && HasSVE()) return prfw_i_p_bz(ctx, dec); // -> prfw_i_p_bz_s_x32_scaled
	if(msz==3 && HasSVE()) return prfd_i_p_bz(ctx, dec); // -> prfd_i_p_bz_s_x32_scaled
	UNMATCHED;
}

int decode_iclass_sve_mem_32b_gld_sv_a(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>14)&1, ff=(INSWORD>>13)&1;
	if(!U && !ff && HasSVE()) return ld1sh_z_p_bz(ctx, dec); // -> ld1sh_z_p_bz_s_x32_scaled
	if(!U && ff && HasSVE()) return ldff1sh_z_p_bz(ctx, dec); // -> ldff1sh_z_p_bz_s_x32_scaled
	if(U && !ff && HasSVE()) return ld1h_z_p_bz(ctx, dec); // -> ld1h_z_p_bz_s_x32_scaled
	if(U && ff && HasSVE()) return ldff1h_z_p_bz(ctx, dec); // -> ldff1h_z_p_bz_s_x32_scaled
	UNMATCHED;
}

int decode_iclass_sve_mem_32b_gld_sv_b(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>14)&1, ff=(INSWORD>>13)&1;
	if(U && !ff && HasSVE()) return ld1w_z_p_bz(ctx, dec); // -> ld1w_z_p_bz_s_x32_scaled
	if(U && ff && HasSVE()) return ldff1w_z_p_bz(ctx, dec); // -> ldff1w_z_p_bz_s_x32_scaled
	if(!U) UNALLOCATED(ENC_UNALLOCATED_537_SVE_MEM_32B_GLD_SV_B);
	UNMATCHED;
}

int decode_iclass_sve_mem_32b_pfill(context *ctx, Instruction *dec)
{
	return ldr_p_bi(ctx, dec);
}

int decode_iclass_sve_mem_32b_fill(context *ctx, Instruction *dec)
{
	return ldr_z_bi(ctx, dec);
}

int decode_iclass_sve_mem_prfm_si(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>13)&3;
	if(!msz && HasSVE() && HasSME()) return prfb_i_p_bi(ctx, dec); // -> prfb_i_p_bi_s
	if(msz==1 && HasSVE() && HasSME()) return prfh_i_p_bi(ctx, dec); // -> prfh_i_p_bi_s
	if(msz==2 && HasSVE() && HasSME()) return prfw_i_p_bi(ctx, dec); // -> prfw_i_p_bi_s
	if(msz==3 && HasSVE() && HasSME()) return prfd_i_p_bi(ctx, dec); // -> prfd_i_p_bi_s
	UNMATCHED;
}

int decode_iclass_sve_mem_32b_gldnt_vs(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3, U=(INSWORD>>13)&1;
	if(!msz && !U && HasSVE2()) return ldnt1sb_z_p_ar(ctx, dec); // -> ldnt1sb_z_p_ar_s_x32_unscaled
	if(!msz && U && HasSVE2()) return ldnt1b_z_p_ar(ctx, dec); // -> ldnt1b_z_p_ar_s_x32_unscaled
	if(msz==1 && !U && HasSVE2()) return ldnt1sh_z_p_ar(ctx, dec); // -> ldnt1sh_z_p_ar_s_x32_unscaled
	if(msz==1 && U && HasSVE2()) return ldnt1h_z_p_ar(ctx, dec); // -> ldnt1h_z_p_ar_s_x32_unscaled
	if(msz==2 && !U) UNALLOCATED(ENC_UNALLOCATED_539_SVE_MEM_32B_GLDNT_VS);
	if(msz==2 && U && HasSVE2()) return ldnt1w_z_p_ar(ctx, dec); // -> ldnt1w_z_p_ar_s_x32_unscaled
	if(msz==3) UNALLOCATED(ENC_UNALLOCATED_538_SVE_MEM_32B_GLDNT_VS);
	UNMATCHED;
}

int decode_iclass_sve_mem_prfm_ss(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3, Rm=(INSWORD>>16)&0x1f;
	if(!msz && Rm!=0x1f && HasSVE() && HasSME()) return prfb_i_p_br(ctx, dec); // -> prfb_i_p_br_s
	if(msz==1 && Rm!=0x1f && HasSVE() && HasSME()) return prfh_i_p_br(ctx, dec); // -> prfh_i_p_br_s
	if(msz==2 && Rm!=0x1f && HasSVE() && HasSME()) return prfw_i_p_br(ctx, dec); // -> prfw_i_p_br_s
	if(msz==3 && Rm!=0x1f && HasSVE() && HasSME()) return prfd_i_p_br(ctx, dec); // -> prfd_i_p_br_s
	if(Rm==0x1f) UNALLOCATED(ENC_UNALLOCATED_540_SVE_MEM_PRFM_SS);
	UNMATCHED;
}

int decode_iclass_sve_mem_32b_prfm_vi(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3;
	if(!msz && HasSVE()) return prfb_i_p_ai(ctx, dec); // -> prfb_i_p_ai_s
	if(msz==1 && HasSVE()) return prfh_i_p_ai(ctx, dec); // -> prfh_i_p_ai_s
	if(msz==2 && HasSVE()) return prfw_i_p_ai(ctx, dec); // -> prfw_i_p_ai_s
	if(msz==3 && HasSVE()) return prfd_i_p_ai(ctx, dec); // -> prfd_i_p_ai_s
	UNMATCHED;
}

int decode_iclass_sve_mem_32b_gld_vi(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3, U=(INSWORD>>14)&1, ff=(INSWORD>>13)&1;
	if(!msz && !U && !ff && HasSVE()) return ld1sb_z_p_ai(ctx, dec); // -> ld1sb_z_p_ai_s
	if(!msz && !U && ff && HasSVE()) return ldff1sb_z_p_ai(ctx, dec); // -> ldff1sb_z_p_ai_s
	if(!msz && U && !ff && HasSVE()) return ld1b_z_p_ai(ctx, dec); // -> ld1b_z_p_ai_s
	if(!msz && U && ff && HasSVE()) return ldff1b_z_p_ai(ctx, dec); // -> ldff1b_z_p_ai_s
	if(msz==1 && !U && !ff && HasSVE()) return ld1sh_z_p_ai(ctx, dec); // -> ld1sh_z_p_ai_s
	if(msz==1 && !U && ff && HasSVE()) return ldff1sh_z_p_ai(ctx, dec); // -> ldff1sh_z_p_ai_s
	if(msz==1 && U && !ff && HasSVE()) return ld1h_z_p_ai(ctx, dec); // -> ld1h_z_p_ai_s
	if(msz==1 && U && ff && HasSVE()) return ldff1h_z_p_ai(ctx, dec); // -> ldff1h_z_p_ai_s
	if(msz==2 && U && !ff && HasSVE()) return ld1w_z_p_ai(ctx, dec); // -> ld1w_z_p_ai_s
	if(msz==2 && U && ff && HasSVE()) return ldff1w_z_p_ai(ctx, dec); // -> ldff1w_z_p_ai_s
	if(msz==2 && !U) UNALLOCATED(ENC_UNALLOCATED_542_SVE_MEM_32B_GLD_VI);
	if(msz==3) UNALLOCATED(ENC_UNALLOCATED_541_SVE_MEM_32B_GLD_VI);
	UNMATCHED;
}

int decode_iclass_sve_mem_ld_dup(context *ctx, Instruction *dec)
{
	uint32_t dtypeh=(INSWORD>>23)&3, dtypel=(INSWORD>>13)&3;
	if(!dtypeh && !dtypel && HasSVE() && HasSME()) return ld1rb_z_p_bi(ctx, dec); // -> ld1rb_z_p_bi_u8
	if(!dtypeh && dtypel==1 && HasSVE() && HasSME()) return ld1rb_z_p_bi(ctx, dec); // -> ld1rb_z_p_bi_u16
	if(!dtypeh && dtypel==2 && HasSVE() && HasSME()) return ld1rb_z_p_bi(ctx, dec); // -> ld1rb_z_p_bi_u32
	if(!dtypeh && dtypel==3 && HasSVE() && HasSME()) return ld1rb_z_p_bi(ctx, dec); // -> ld1rb_z_p_bi_u64
	if(dtypeh==1 && !dtypel && HasSVE() && HasSME()) return ld1rsw_z_p_bi(ctx, dec); // -> ld1rsw_z_p_bi_s64
	if(dtypeh==1 && dtypel==1 && HasSVE() && HasSME()) return ld1rh_z_p_bi(ctx, dec); // -> ld1rh_z_p_bi_u16
	if(dtypeh==1 && dtypel==2 && HasSVE() && HasSME()) return ld1rh_z_p_bi(ctx, dec); // -> ld1rh_z_p_bi_u32
	if(dtypeh==1 && dtypel==3 && HasSVE() && HasSME()) return ld1rh_z_p_bi(ctx, dec); // -> ld1rh_z_p_bi_u64
	if(dtypeh==2 && !dtypel && HasSVE() && HasSME()) return ld1rsh_z_p_bi(ctx, dec); // -> ld1rsh_z_p_bi_s64
	if(dtypeh==2 && dtypel==1 && HasSVE() && HasSME()) return ld1rsh_z_p_bi(ctx, dec); // -> ld1rsh_z_p_bi_s32
	if(dtypeh==2 && dtypel==2 && HasSVE() && HasSME()) return ld1rw_z_p_bi(ctx, dec); // -> ld1rw_z_p_bi_u32
	if(dtypeh==2 && dtypel==3 && HasSVE() && HasSME()) return ld1rw_z_p_bi(ctx, dec); // -> ld1rw_z_p_bi_u64
	if(dtypeh==3 && !dtypel && HasSVE() && HasSME()) return ld1rsb_z_p_bi(ctx, dec); // -> ld1rsb_z_p_bi_s64
	if(dtypeh==3 && dtypel==1 && HasSVE() && HasSME()) return ld1rsb_z_p_bi(ctx, dec); // -> ld1rsb_z_p_bi_s32
	if(dtypeh==3 && dtypel==2 && HasSVE() && HasSME()) return ld1rsb_z_p_bi(ctx, dec); // -> ld1rsb_z_p_bi_s16
	if(dtypeh==3 && dtypel==3 && HasSVE() && HasSME()) return ld1rd_z_p_bi(ctx, dec); // -> ld1rd_z_p_bi_u64
	UNMATCHED;
}

int decode_iclass_sve_mem_64b_gld_vs(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3, U=(INSWORD>>14)&1, ff=(INSWORD>>13)&1;
	if(!msz && !U && !ff && HasSVE()) return ld1sb_z_p_bz(ctx, dec); // -> ld1sb_z_p_bz_d_x32_unscaled
	if(!msz && !U && ff && HasSVE()) return ldff1sb_z_p_bz(ctx, dec); // -> ldff1sb_z_p_bz_d_x32_unscaled
	if(!msz && U && !ff && HasSVE()) return ld1b_z_p_bz(ctx, dec); // -> ld1b_z_p_bz_d_x32_unscaled
	if(!msz && U && ff && HasSVE()) return ldff1b_z_p_bz(ctx, dec); // -> ldff1b_z_p_bz_d_x32_unscaled
	if(msz==1 && !U && !ff && HasSVE()) return ld1sh_z_p_bz(ctx, dec); // -> ld1sh_z_p_bz_d_x32_unscaled
	if(msz==1 && !U && ff && HasSVE()) return ldff1sh_z_p_bz(ctx, dec); // -> ldff1sh_z_p_bz_d_x32_unscaled
	if(msz==1 && U && !ff && HasSVE()) return ld1h_z_p_bz(ctx, dec); // -> ld1h_z_p_bz_d_x32_unscaled
	if(msz==1 && U && ff && HasSVE()) return ldff1h_z_p_bz(ctx, dec); // -> ldff1h_z_p_bz_d_x32_unscaled
	if(msz==2 && !U && !ff && HasSVE()) return ld1sw_z_p_bz(ctx, dec); // -> ld1sw_z_p_bz_d_x32_unscaled
	if(msz==2 && !U && ff && HasSVE()) return ldff1sw_z_p_bz(ctx, dec); // -> ldff1sw_z_p_bz_d_x32_unscaled
	if(msz==2 && U && !ff && HasSVE()) return ld1w_z_p_bz(ctx, dec); // -> ld1w_z_p_bz_d_x32_unscaled
	if(msz==2 && U && ff && HasSVE()) return ldff1w_z_p_bz(ctx, dec); // -> ldff1w_z_p_bz_d_x32_unscaled
	if(msz==3 && U && !ff && HasSVE()) return ld1d_z_p_bz(ctx, dec); // -> ld1d_z_p_bz_d_x32_unscaled
	if(msz==3 && U && ff && HasSVE()) return ldff1d_z_p_bz(ctx, dec); // -> ldff1d_z_p_bz_d_x32_unscaled
	if(msz==3 && !U) UNALLOCATED(ENC_UNALLOCATED_543_SVE_MEM_64B_GLD_VS);
	UNMATCHED;
}

int decode_iclass_sve_mem_64b_prfm_sv(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>13)&3;
	if(!msz && HasSVE()) return prfb_i_p_bz(ctx, dec); // -> prfb_i_p_bz_d_x32_scaled
	if(msz==1 && HasSVE()) return prfh_i_p_bz(ctx, dec); // -> prfh_i_p_bz_d_x32_scaled
	if(msz==2 && HasSVE()) return prfw_i_p_bz(ctx, dec); // -> prfw_i_p_bz_d_x32_scaled
	if(msz==3 && HasSVE()) return prfd_i_p_bz(ctx, dec); // -> prfd_i_p_bz_d_x32_scaled
	UNMATCHED;
}

int decode_iclass_sve_mem_64b_gld_sv(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>23)&3, U=(INSWORD>>14)&1, ff=(INSWORD>>13)&1;
	if(opc==1 && !U && !ff && HasSVE()) return ld1sh_z_p_bz(ctx, dec); // -> ld1sh_z_p_bz_d_x32_scaled
	if(opc==1 && !U && ff && HasSVE()) return ldff1sh_z_p_bz(ctx, dec); // -> ldff1sh_z_p_bz_d_x32_scaled
	if(opc==1 && U && !ff && HasSVE()) return ld1h_z_p_bz(ctx, dec); // -> ld1h_z_p_bz_d_x32_scaled
	if(opc==1 && U && ff && HasSVE()) return ldff1h_z_p_bz(ctx, dec); // -> ldff1h_z_p_bz_d_x32_scaled
	if(opc==2 && !U && !ff && HasSVE()) return ld1sw_z_p_bz(ctx, dec); // -> ld1sw_z_p_bz_d_x32_scaled
	if(opc==2 && !U && ff && HasSVE()) return ldff1sw_z_p_bz(ctx, dec); // -> ldff1sw_z_p_bz_d_x32_scaled
	if(opc==2 && U && !ff && HasSVE()) return ld1w_z_p_bz(ctx, dec); // -> ld1w_z_p_bz_d_x32_scaled
	if(opc==2 && U && ff && HasSVE()) return ldff1w_z_p_bz(ctx, dec); // -> ldff1w_z_p_bz_d_x32_scaled
	if(opc==3 && U && !ff && HasSVE()) return ld1d_z_p_bz(ctx, dec); // -> ld1d_z_p_bz_d_x32_scaled
	if(opc==3 && U && ff && HasSVE()) return ldff1d_z_p_bz(ctx, dec); // -> ldff1d_z_p_bz_d_x32_scaled
	if(opc==3 && !U) UNALLOCATED(ENC_UNALLOCATED_544_SVE_MEM_64B_GLD_SV);
	UNMATCHED;
}

int decode_iclass_sve_mem_64b_gldnt_vs(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3, U=(INSWORD>>14)&1;
	if(!msz && !U && HasSVE2()) return ldnt1sb_z_p_ar(ctx, dec); // -> ldnt1sb_z_p_ar_d_64_unscaled
	if(!msz && U && HasSVE2()) return ldnt1b_z_p_ar(ctx, dec); // -> ldnt1b_z_p_ar_d_64_unscaled
	if(msz==1 && !U && HasSVE2()) return ldnt1sh_z_p_ar(ctx, dec); // -> ldnt1sh_z_p_ar_d_64_unscaled
	if(msz==1 && U && HasSVE2()) return ldnt1h_z_p_ar(ctx, dec); // -> ldnt1h_z_p_ar_d_64_unscaled
	if(msz==2 && !U && HasSVE2()) return ldnt1sw_z_p_ar(ctx, dec); // -> ldnt1sw_z_p_ar_d_64_unscaled
	if(msz==2 && U && HasSVE2()) return ldnt1w_z_p_ar(ctx, dec); // -> ldnt1w_z_p_ar_d_64_unscaled
	if(msz==3 && !U) UNALLOCATED(ENC_UNALLOCATED_545_SVE_MEM_64B_GLDNT_VS);
	if(msz==3 && U && HasSVE2()) return ldnt1d_z_p_ar(ctx, dec); // -> ldnt1d_z_p_ar_d_64_unscaled
	UNMATCHED;
}

int decode_iclass_sve_mem_64b_prfm_vi(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3;
	if(!msz && HasSVE()) return prfb_i_p_ai(ctx, dec); // -> prfb_i_p_ai_d
	if(msz==1 && HasSVE()) return prfh_i_p_ai(ctx, dec); // -> prfh_i_p_ai_d
	if(msz==2 && HasSVE()) return prfw_i_p_ai(ctx, dec); // -> prfw_i_p_ai_d
	if(msz==3 && HasSVE()) return prfd_i_p_ai(ctx, dec); // -> prfd_i_p_ai_d
	UNMATCHED;
}

int decode_iclass_sve_mem_64b_gldq_vs(context *ctx, Instruction *dec)
{
	return ld1q_z_p_ar(ctx, dec);
}

int decode_iclass_sve_mem_64b_gld_vi(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3, U=(INSWORD>>14)&1, ff=(INSWORD>>13)&1;
	if(!msz && !U && !ff && HasSVE()) return ld1sb_z_p_ai(ctx, dec); // -> ld1sb_z_p_ai_d
	if(!msz && !U && ff && HasSVE()) return ldff1sb_z_p_ai(ctx, dec); // -> ldff1sb_z_p_ai_d
	if(!msz && U && !ff && HasSVE()) return ld1b_z_p_ai(ctx, dec); // -> ld1b_z_p_ai_d
	if(!msz && U && ff && HasSVE()) return ldff1b_z_p_ai(ctx, dec); // -> ldff1b_z_p_ai_d
	if(msz==1 && !U && !ff && HasSVE()) return ld1sh_z_p_ai(ctx, dec); // -> ld1sh_z_p_ai_d
	if(msz==1 && !U && ff && HasSVE()) return ldff1sh_z_p_ai(ctx, dec); // -> ldff1sh_z_p_ai_d
	if(msz==1 && U && !ff && HasSVE()) return ld1h_z_p_ai(ctx, dec); // -> ld1h_z_p_ai_d
	if(msz==1 && U && ff && HasSVE()) return ldff1h_z_p_ai(ctx, dec); // -> ldff1h_z_p_ai_d
	if(msz==2 && !U && !ff && HasSVE()) return ld1sw_z_p_ai(ctx, dec); // -> ld1sw_z_p_ai_d
	if(msz==2 && !U && ff && HasSVE()) return ldff1sw_z_p_ai(ctx, dec); // -> ldff1sw_z_p_ai_d
	if(msz==2 && U && !ff && HasSVE()) return ld1w_z_p_ai(ctx, dec); // -> ld1w_z_p_ai_d
	if(msz==2 && U && ff && HasSVE()) return ldff1w_z_p_ai(ctx, dec); // -> ldff1w_z_p_ai_d
	if(msz==3 && U && !ff && HasSVE()) return ld1d_z_p_ai(ctx, dec); // -> ld1d_z_p_ai_d
	if(msz==3 && U && ff && HasSVE()) return ldff1d_z_p_ai(ctx, dec); // -> ldff1d_z_p_ai_d
	if(msz==3 && !U) UNALLOCATED(ENC_UNALLOCATED_546_SVE_MEM_64B_GLD_VI);
	UNMATCHED;
}

int decode_iclass_sve_mem_64b_gld_vs2(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3, U=(INSWORD>>14)&1, ff=(INSWORD>>13)&1;
	if(!msz && !U && !ff && HasSVE()) return ld1sb_z_p_bz(ctx, dec); // -> ld1sb_z_p_bz_d_64_unscaled
	if(!msz && !U && ff && HasSVE()) return ldff1sb_z_p_bz(ctx, dec); // -> ldff1sb_z_p_bz_d_64_unscaled
	if(!msz && U && !ff && HasSVE()) return ld1b_z_p_bz(ctx, dec); // -> ld1b_z_p_bz_d_64_unscaled
	if(!msz && U && ff && HasSVE()) return ldff1b_z_p_bz(ctx, dec); // -> ldff1b_z_p_bz_d_64_unscaled
	if(msz==1 && !U && !ff && HasSVE()) return ld1sh_z_p_bz(ctx, dec); // -> ld1sh_z_p_bz_d_64_unscaled
	if(msz==1 && !U && ff && HasSVE()) return ldff1sh_z_p_bz(ctx, dec); // -> ldff1sh_z_p_bz_d_64_unscaled
	if(msz==1 && U && !ff && HasSVE()) return ld1h_z_p_bz(ctx, dec); // -> ld1h_z_p_bz_d_64_unscaled
	if(msz==1 && U && ff && HasSVE()) return ldff1h_z_p_bz(ctx, dec); // -> ldff1h_z_p_bz_d_64_unscaled
	if(msz==2 && !U && !ff && HasSVE()) return ld1sw_z_p_bz(ctx, dec); // -> ld1sw_z_p_bz_d_64_unscaled
	if(msz==2 && !U && ff && HasSVE()) return ldff1sw_z_p_bz(ctx, dec); // -> ldff1sw_z_p_bz_d_64_unscaled
	if(msz==2 && U && !ff && HasSVE()) return ld1w_z_p_bz(ctx, dec); // -> ld1w_z_p_bz_d_64_unscaled
	if(msz==2 && U && ff && HasSVE()) return ldff1w_z_p_bz(ctx, dec); // -> ldff1w_z_p_bz_d_64_unscaled
	if(msz==3 && U && !ff && HasSVE()) return ld1d_z_p_bz(ctx, dec); // -> ld1d_z_p_bz_d_64_unscaled
	if(msz==3 && U && ff && HasSVE()) return ldff1d_z_p_bz(ctx, dec); // -> ldff1d_z_p_bz_d_64_unscaled
	if(msz==3 && !U) UNALLOCATED(ENC_UNALLOCATED_547_SVE_MEM_64B_GLD_VS2);
	UNMATCHED;
}

int decode_iclass_sve_mem_64b_prfm_sv2(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>13)&3;
	if(!msz && HasSVE()) return prfb_i_p_bz(ctx, dec); // -> prfb_i_p_bz_d_64_scaled
	if(msz==1 && HasSVE()) return prfh_i_p_bz(ctx, dec); // -> prfh_i_p_bz_d_64_scaled
	if(msz==2 && HasSVE()) return prfw_i_p_bz(ctx, dec); // -> prfw_i_p_bz_d_64_scaled
	if(msz==3 && HasSVE()) return prfd_i_p_bz(ctx, dec); // -> prfd_i_p_bz_d_64_scaled
	UNMATCHED;
}

int decode_iclass_sve_mem_64b_gld_sv2(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>23)&3, U=(INSWORD>>14)&1, ff=(INSWORD>>13)&1;
	if(opc==1 && !U && !ff && HasSVE()) return ld1sh_z_p_bz(ctx, dec); // -> ld1sh_z_p_bz_d_64_scaled
	if(opc==1 && !U && ff && HasSVE()) return ldff1sh_z_p_bz(ctx, dec); // -> ldff1sh_z_p_bz_d_64_scaled
	if(opc==1 && U && !ff && HasSVE()) return ld1h_z_p_bz(ctx, dec); // -> ld1h_z_p_bz_d_64_scaled
	if(opc==1 && U && ff && HasSVE()) return ldff1h_z_p_bz(ctx, dec); // -> ldff1h_z_p_bz_d_64_scaled
	if(opc==2 && !U && !ff && HasSVE()) return ld1sw_z_p_bz(ctx, dec); // -> ld1sw_z_p_bz_d_64_scaled
	if(opc==2 && !U && ff && HasSVE()) return ldff1sw_z_p_bz(ctx, dec); // -> ldff1sw_z_p_bz_d_64_scaled
	if(opc==2 && U && !ff && HasSVE()) return ld1w_z_p_bz(ctx, dec); // -> ld1w_z_p_bz_d_64_scaled
	if(opc==2 && U && ff && HasSVE()) return ldff1w_z_p_bz(ctx, dec); // -> ldff1w_z_p_bz_d_64_scaled
	if(opc==3 && U && !ff && HasSVE()) return ld1d_z_p_bz(ctx, dec); // -> ld1d_z_p_bz_d_64_scaled
	if(opc==3 && U && ff && HasSVE()) return ldff1d_z_p_bz(ctx, dec); // -> ldff1d_z_p_bz_d_64_scaled
	if(opc==3 && !U) UNALLOCATED(ENC_UNALLOCATED_548_SVE_MEM_64B_GLD_SV2);
	UNMATCHED;
}

int decode_iclass_sve_mem_ldqr_ss(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3, ssz=(INSWORD>>21)&3, Rm=(INSWORD>>16)&0x1f;
	if(!msz && !ssz && Rm!=0x1f && HasSVE() && HasSME()) return ld1rqb_z_p_br(ctx, dec); // -> ld1rqb_z_p_br_contiguous
	if(!msz && ssz==1 && Rm!=0x1f && HasF64MM()) return ld1rob_z_p_br(ctx, dec); // -> ld1rob_z_p_br_contiguous
	if(msz==1 && !ssz && Rm!=0x1f && HasSVE() && HasSME()) return ld1rqh_z_p_br(ctx, dec); // -> ld1rqh_z_p_br_contiguous
	if(msz==1 && ssz==1 && Rm!=0x1f && HasF64MM()) return ld1roh_z_p_br(ctx, dec); // -> ld1roh_z_p_br_contiguous
	if(msz==2 && !ssz && Rm!=0x1f && HasSVE() && HasSME()) return ld1rqw_z_p_br(ctx, dec); // -> ld1rqw_z_p_br_contiguous
	if(msz==2 && ssz==1 && Rm!=0x1f && HasF64MM()) return ld1row_z_p_br(ctx, dec); // -> ld1row_z_p_br_contiguous
	if(msz==3 && !ssz && Rm!=0x1f && HasSVE() && HasSME()) return ld1rqd_z_p_br(ctx, dec); // -> ld1rqd_z_p_br_contiguous
	if(msz==3 && ssz==1 && Rm!=0x1f && HasF64MM()) return ld1rod_z_p_br(ctx, dec); // -> ld1rod_z_p_br_contiguous
	if(!(ssz&2) && Rm==0x1f) UNALLOCATED(ENC_UNALLOCATED_550_SVE_MEM_LDQR_SS);
	if((ssz&2)==2) UNALLOCATED(ENC_UNALLOCATED_549_SVE_MEM_LDQR_SS);
	UNMATCHED;
}

int decode_iclass_sve_mem_ldqr_si(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3, ssz=(INSWORD>>21)&3;
	if(!msz && !ssz && HasSVE() && HasSME()) return ld1rqb_z_p_bi(ctx, dec); // -> ld1rqb_z_p_bi_u8
	if(!msz && ssz==1 && HasF64MM()) return ld1rob_z_p_bi(ctx, dec); // -> ld1rob_z_p_bi_u8
	if(msz==1 && !ssz && HasSVE() && HasSME()) return ld1rqh_z_p_bi(ctx, dec); // -> ld1rqh_z_p_bi_u16
	if(msz==1 && ssz==1 && HasF64MM()) return ld1roh_z_p_bi(ctx, dec); // -> ld1roh_z_p_bi_u16
	if(msz==2 && !ssz && HasSVE() && HasSME()) return ld1rqw_z_p_bi(ctx, dec); // -> ld1rqw_z_p_bi_u32
	if(msz==2 && ssz==1 && HasF64MM()) return ld1row_z_p_bi(ctx, dec); // -> ld1row_z_p_bi_u32
	if(msz==3 && !ssz && HasSVE() && HasSME()) return ld1rqd_z_p_bi(ctx, dec); // -> ld1rqd_z_p_bi_u64
	if(msz==3 && ssz==1 && HasF64MM()) return ld1rod_z_p_bi(ctx, dec); // -> ld1rod_z_p_bi_u64
	if((ssz&2)==2) UNALLOCATED(ENC_UNALLOCATED_551_SVE_MEM_LDQR_SI);
	UNMATCHED;
}

int decode_iclass_sve_mem_cld_si_q(context *ctx, Instruction *dec)
{
	uint32_t dtype=(INSWORD>>23)&3;
	if(dtype==2 && HasSVE2p1()) return ld1w_z_p_bi(ctx, dec); // -> ld1w_z_p_bi_u128
	if(dtype==3 && HasSVE2p1()) return ld1d_z_p_bi(ctx, dec); // -> ld1d_z_p_bi_u128
	if(!(dtype&2)) UNALLOCATED(ENC_UNALLOCATED_552_SVE_MEM_CLD_SI_Q);
	UNMATCHED;
}

int decode_iclass_sve_mem_cld_ss(context *ctx, Instruction *dec)
{
	uint32_t dtype=(INSWORD>>21)&15, Rm=(INSWORD>>16)&0x1f;
	if(!dtype && Rm!=0x1f && HasSVE() && HasSME()) return ld1b_z_p_br(ctx, dec); // -> ld1b_z_p_br_u8
	if(dtype==1 && Rm!=0x1f && HasSVE() && HasSME()) return ld1b_z_p_br(ctx, dec); // -> ld1b_z_p_br_u16
	if(dtype==2 && Rm!=0x1f && HasSVE() && HasSME()) return ld1b_z_p_br(ctx, dec); // -> ld1b_z_p_br_u32
	if(dtype==3 && Rm!=0x1f && HasSVE() && HasSME()) return ld1b_z_p_br(ctx, dec); // -> ld1b_z_p_br_u64
	if(dtype==4 && Rm!=0x1f && HasSVE() && HasSME()) return ld1sw_z_p_br(ctx, dec); // -> ld1sw_z_p_br_s64
	if(dtype==5 && Rm!=0x1f && HasSVE() && HasSME()) return ld1h_z_p_br(ctx, dec); // -> ld1h_z_p_br_u16
	if(dtype==6 && Rm!=0x1f && HasSVE() && HasSME()) return ld1h_z_p_br(ctx, dec); // -> ld1h_z_p_br_u32
	if(dtype==7 && Rm!=0x1f && HasSVE() && HasSME()) return ld1h_z_p_br(ctx, dec); // -> ld1h_z_p_br_u64
	if(dtype==8 && Rm!=0x1f && HasSVE() && HasSME()) return ld1sh_z_p_br(ctx, dec); // -> ld1sh_z_p_br_s64
	if(dtype==9 && Rm!=0x1f && HasSVE() && HasSME()) return ld1sh_z_p_br(ctx, dec); // -> ld1sh_z_p_br_s32
	if(dtype==10 && Rm!=0x1f && HasSVE() && HasSME()) return ld1w_z_p_br(ctx, dec); // -> ld1w_z_p_br_u32
	if(dtype==11 && Rm!=0x1f && HasSVE() && HasSME()) return ld1w_z_p_br(ctx, dec); // -> ld1w_z_p_br_u64
	if(dtype==12 && Rm!=0x1f && HasSVE() && HasSME()) return ld1sb_z_p_br(ctx, dec); // -> ld1sb_z_p_br_s64
	if(dtype==13 && Rm!=0x1f && HasSVE() && HasSME()) return ld1sb_z_p_br(ctx, dec); // -> ld1sb_z_p_br_s32
	if(dtype==14 && Rm!=0x1f && HasSVE() && HasSME()) return ld1sb_z_p_br(ctx, dec); // -> ld1sb_z_p_br_s16
	if(dtype==15 && Rm!=0x1f && HasSVE() && HasSME()) return ld1d_z_p_br(ctx, dec); // -> ld1d_z_p_br_u64
	if(Rm==0x1f) UNALLOCATED(ENC_UNALLOCATED_553_SVE_MEM_CLD_SS);
	UNMATCHED;
}

int decode_iclass_sve_mem_cldff_ss(context *ctx, Instruction *dec)
{
	uint32_t dtype=(INSWORD>>21)&15;
	if(!dtype && HasSVE()) return ldff1b_z_p_br(ctx, dec); // -> ldff1b_z_p_br_u8
	if(dtype==1 && HasSVE()) return ldff1b_z_p_br(ctx, dec); // -> ldff1b_z_p_br_u16
	if(dtype==2 && HasSVE()) return ldff1b_z_p_br(ctx, dec); // -> ldff1b_z_p_br_u32
	if(dtype==3 && HasSVE()) return ldff1b_z_p_br(ctx, dec); // -> ldff1b_z_p_br_u64
	if(dtype==4 && HasSVE()) return ldff1sw_z_p_br(ctx, dec); // -> ldff1sw_z_p_br_s64
	if(dtype==5 && HasSVE()) return ldff1h_z_p_br(ctx, dec); // -> ldff1h_z_p_br_u16
	if(dtype==6 && HasSVE()) return ldff1h_z_p_br(ctx, dec); // -> ldff1h_z_p_br_u32
	if(dtype==7 && HasSVE()) return ldff1h_z_p_br(ctx, dec); // -> ldff1h_z_p_br_u64
	if(dtype==8 && HasSVE()) return ldff1sh_z_p_br(ctx, dec); // -> ldff1sh_z_p_br_s64
	if(dtype==9 && HasSVE()) return ldff1sh_z_p_br(ctx, dec); // -> ldff1sh_z_p_br_s32
	if(dtype==10 && HasSVE()) return ldff1w_z_p_br(ctx, dec); // -> ldff1w_z_p_br_u32
	if(dtype==11 && HasSVE()) return ldff1w_z_p_br(ctx, dec); // -> ldff1w_z_p_br_u64
	if(dtype==12 && HasSVE()) return ldff1sb_z_p_br(ctx, dec); // -> ldff1sb_z_p_br_s64
	if(dtype==13 && HasSVE()) return ldff1sb_z_p_br(ctx, dec); // -> ldff1sb_z_p_br_s32
	if(dtype==14 && HasSVE()) return ldff1sb_z_p_br(ctx, dec); // -> ldff1sb_z_p_br_s16
	if(dtype==15 && HasSVE()) return ldff1d_z_p_br(ctx, dec); // -> ldff1d_z_p_br_u64
	UNMATCHED;
}

int decode_iclass_sve_mem_cld_ss_q(context *ctx, Instruction *dec)
{
	uint32_t dtype=(INSWORD>>23)&3, Rm=(INSWORD>>16)&0x1f;
	if(dtype==2 && Rm!=0x1f && HasSVE2p1()) return ld1w_z_p_br(ctx, dec); // -> ld1w_z_p_br_u128
	if(dtype==3 && Rm!=0x1f && HasSVE2p1()) return ld1d_z_p_br(ctx, dec); // -> ld1d_z_p_br_u128
	if((dtype&2)==2 && Rm==0x1f) UNALLOCATED(ENC_UNALLOCATED_555_SVE_MEM_CLD_SS_Q);
	if(!(dtype&2)) UNALLOCATED(ENC_UNALLOCATED_554_SVE_MEM_CLD_SS_Q);
	UNMATCHED;
}

int decode_iclass_sve_mem_eldq_ss(context *ctx, Instruction *dec)
{
	uint32_t num=(INSWORD>>23)&3, Rm=(INSWORD>>16)&0x1f;
	if(num==1 && Rm!=0x1f && HasSVE2p1() && HasSME2p1()) return ld2q_z_p_br(ctx, dec); // -> ld2q_z_p_br_contiguous
	if(num==2 && Rm!=0x1f && HasSVE2p1() && HasSME2p1()) return ld3q_z_p_br(ctx, dec); // -> ld3q_z_p_br_contiguous
	if(num==3 && Rm!=0x1f && HasSVE2p1() && HasSME2p1()) return ld4q_z_p_br(ctx, dec); // -> ld4q_z_p_br_contiguous
	if(num && Rm==0x1f) UNALLOCATED(ENC_UNALLOCATED_557_SVE_MEM_ELDQ_SS);
	if(!num) UNALLOCATED(ENC_UNALLOCATED_556_SVE_MEM_ELDQ_SS);
	UNMATCHED;
}

int decode_iclass_sve_mem_cld_si(context *ctx, Instruction *dec)
{
	uint32_t dtype=(INSWORD>>21)&15;
	if(!dtype && HasSVE() && HasSME()) return ld1b_z_p_bi(ctx, dec); // -> ld1b_z_p_bi_u8
	if(dtype==1 && HasSVE() && HasSME()) return ld1b_z_p_bi(ctx, dec); // -> ld1b_z_p_bi_u16
	if(dtype==2 && HasSVE() && HasSME()) return ld1b_z_p_bi(ctx, dec); // -> ld1b_z_p_bi_u32
	if(dtype==3 && HasSVE() && HasSME()) return ld1b_z_p_bi(ctx, dec); // -> ld1b_z_p_bi_u64
	if(dtype==4 && HasSVE() && HasSME()) return ld1sw_z_p_bi(ctx, dec); // -> ld1sw_z_p_bi_s64
	if(dtype==5 && HasSVE() && HasSME()) return ld1h_z_p_bi(ctx, dec); // -> ld1h_z_p_bi_u16
	if(dtype==6 && HasSVE() && HasSME()) return ld1h_z_p_bi(ctx, dec); // -> ld1h_z_p_bi_u32
	if(dtype==7 && HasSVE() && HasSME()) return ld1h_z_p_bi(ctx, dec); // -> ld1h_z_p_bi_u64
	if(dtype==8 && HasSVE() && HasSME()) return ld1sh_z_p_bi(ctx, dec); // -> ld1sh_z_p_bi_s64
	if(dtype==9 && HasSVE() && HasSME()) return ld1sh_z_p_bi(ctx, dec); // -> ld1sh_z_p_bi_s32
	if(dtype==10 && HasSVE() && HasSME()) return ld1w_z_p_bi(ctx, dec); // -> ld1w_z_p_bi_u32
	if(dtype==11 && HasSVE() && HasSME()) return ld1w_z_p_bi(ctx, dec); // -> ld1w_z_p_bi_u64
	if(dtype==12 && HasSVE() && HasSME()) return ld1sb_z_p_bi(ctx, dec); // -> ld1sb_z_p_bi_s64
	if(dtype==13 && HasSVE() && HasSME()) return ld1sb_z_p_bi(ctx, dec); // -> ld1sb_z_p_bi_s32
	if(dtype==14 && HasSVE() && HasSME()) return ld1sb_z_p_bi(ctx, dec); // -> ld1sb_z_p_bi_s16
	if(dtype==15 && HasSVE() && HasSME()) return ld1d_z_p_bi(ctx, dec); // -> ld1d_z_p_bi_u64
	UNMATCHED;
}

int decode_iclass_sve_mem_cldnf_si(context *ctx, Instruction *dec)
{
	uint32_t dtype=(INSWORD>>21)&15;
	if(!dtype && HasSVE()) return ldnf1b_z_p_bi(ctx, dec); // -> ldnf1b_z_p_bi_u8
	if(dtype==1 && HasSVE()) return ldnf1b_z_p_bi(ctx, dec); // -> ldnf1b_z_p_bi_u16
	if(dtype==2 && HasSVE()) return ldnf1b_z_p_bi(ctx, dec); // -> ldnf1b_z_p_bi_u32
	if(dtype==3 && HasSVE()) return ldnf1b_z_p_bi(ctx, dec); // -> ldnf1b_z_p_bi_u64
	if(dtype==4 && HasSVE()) return ldnf1sw_z_p_bi(ctx, dec); // -> ldnf1sw_z_p_bi_s64
	if(dtype==5 && HasSVE()) return ldnf1h_z_p_bi(ctx, dec); // -> ldnf1h_z_p_bi_u16
	if(dtype==6 && HasSVE()) return ldnf1h_z_p_bi(ctx, dec); // -> ldnf1h_z_p_bi_u32
	if(dtype==7 && HasSVE()) return ldnf1h_z_p_bi(ctx, dec); // -> ldnf1h_z_p_bi_u64
	if(dtype==8 && HasSVE()) return ldnf1sh_z_p_bi(ctx, dec); // -> ldnf1sh_z_p_bi_s64
	if(dtype==9 && HasSVE()) return ldnf1sh_z_p_bi(ctx, dec); // -> ldnf1sh_z_p_bi_s32
	if(dtype==10 && HasSVE()) return ldnf1w_z_p_bi(ctx, dec); // -> ldnf1w_z_p_bi_u32
	if(dtype==11 && HasSVE()) return ldnf1w_z_p_bi(ctx, dec); // -> ldnf1w_z_p_bi_u64
	if(dtype==12 && HasSVE()) return ldnf1sb_z_p_bi(ctx, dec); // -> ldnf1sb_z_p_bi_s64
	if(dtype==13 && HasSVE()) return ldnf1sb_z_p_bi(ctx, dec); // -> ldnf1sb_z_p_bi_s32
	if(dtype==14 && HasSVE()) return ldnf1sb_z_p_bi(ctx, dec); // -> ldnf1sb_z_p_bi_s16
	if(dtype==15 && HasSVE()) return ldnf1d_z_p_bi(ctx, dec); // -> ldnf1d_z_p_bi_u64
	UNMATCHED;
}

int decode_iclass_sve_mem_cldnt_ss(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3, Rm=(INSWORD>>16)&0x1f;
	if(!msz && Rm!=0x1f && HasSVE() && HasSME()) return ldnt1b_z_p_br(ctx, dec); // -> ldnt1b_z_p_br_contiguous
	if(msz==1 && Rm!=0x1f && HasSVE() && HasSME()) return ldnt1h_z_p_br(ctx, dec); // -> ldnt1h_z_p_br_contiguous
	if(msz==2 && Rm!=0x1f && HasSVE() && HasSME()) return ldnt1w_z_p_br(ctx, dec); // -> ldnt1w_z_p_br_contiguous
	if(msz==3 && Rm!=0x1f && HasSVE() && HasSME()) return ldnt1d_z_p_br(ctx, dec); // -> ldnt1d_z_p_br_contiguous
	if(Rm==0x1f) UNALLOCATED(ENC_UNALLOCATED_558_SVE_MEM_CLDNT_SS);
	UNMATCHED;
}

int decode_iclass_sve_mem_eld_ss(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3, opc=(INSWORD>>21)&3, Rm=(INSWORD>>16)&0x1f;
	if(!msz && opc==1 && Rm!=0x1f && HasSVE() && HasSME()) return ld2b_z_p_br(ctx, dec); // -> ld2b_z_p_br_contiguous
	if(!msz && opc==2 && Rm!=0x1f && HasSVE() && HasSME()) return ld3b_z_p_br(ctx, dec); // -> ld3b_z_p_br_contiguous
	if(!msz && opc==3 && Rm!=0x1f && HasSVE() && HasSME()) return ld4b_z_p_br(ctx, dec); // -> ld4b_z_p_br_contiguous
	if(msz==1 && opc==1 && Rm!=0x1f && HasSVE() && HasSME()) return ld2h_z_p_br(ctx, dec); // -> ld2h_z_p_br_contiguous
	if(msz==1 && opc==2 && Rm!=0x1f && HasSVE() && HasSME()) return ld3h_z_p_br(ctx, dec); // -> ld3h_z_p_br_contiguous
	if(msz==1 && opc==3 && Rm!=0x1f && HasSVE() && HasSME()) return ld4h_z_p_br(ctx, dec); // -> ld4h_z_p_br_contiguous
	if(msz==2 && opc==1 && Rm!=0x1f && HasSVE() && HasSME()) return ld2w_z_p_br(ctx, dec); // -> ld2w_z_p_br_contiguous
	if(msz==2 && opc==2 && Rm!=0x1f && HasSVE() && HasSME()) return ld3w_z_p_br(ctx, dec); // -> ld3w_z_p_br_contiguous
	if(msz==2 && opc==3 && Rm!=0x1f && HasSVE() && HasSME()) return ld4w_z_p_br(ctx, dec); // -> ld4w_z_p_br_contiguous
	if(msz==3 && opc==1 && Rm!=0x1f && HasSVE() && HasSME()) return ld2d_z_p_br(ctx, dec); // -> ld2d_z_p_br_contiguous
	if(msz==3 && opc==2 && Rm!=0x1f && HasSVE() && HasSME()) return ld3d_z_p_br(ctx, dec); // -> ld3d_z_p_br_contiguous
	if(msz==3 && opc==3 && Rm!=0x1f && HasSVE() && HasSME()) return ld4d_z_p_br(ctx, dec); // -> ld4d_z_p_br_contiguous
	if(opc && Rm==0x1f) UNALLOCATED(ENC_UNALLOCATED_559_SVE_MEM_ELD_SS);
	UNMATCHED;
}

int decode_iclass_sve_mem_cldnt_si(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3;
	if(!msz && HasSVE() && HasSME()) return ldnt1b_z_p_bi(ctx, dec); // -> ldnt1b_z_p_bi_contiguous
	if(msz==1 && HasSVE() && HasSME()) return ldnt1h_z_p_bi(ctx, dec); // -> ldnt1h_z_p_bi_contiguous
	if(msz==2 && HasSVE() && HasSME()) return ldnt1w_z_p_bi(ctx, dec); // -> ldnt1w_z_p_bi_contiguous
	if(msz==3 && HasSVE() && HasSME()) return ldnt1d_z_p_bi(ctx, dec); // -> ldnt1d_z_p_bi_contiguous
	UNMATCHED;
}

int decode_iclass_sve_mem_eld_si(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3, opc=(INSWORD>>21)&3;
	if(!msz && opc==1 && HasSVE() && HasSME()) return ld2b_z_p_bi(ctx, dec); // -> ld2b_z_p_bi_contiguous
	if(!msz && opc==2 && HasSVE() && HasSME()) return ld3b_z_p_bi(ctx, dec); // -> ld3b_z_p_bi_contiguous
	if(!msz && opc==3 && HasSVE() && HasSME()) return ld4b_z_p_bi(ctx, dec); // -> ld4b_z_p_bi_contiguous
	if(msz==1 && opc==1 && HasSVE() && HasSME()) return ld2h_z_p_bi(ctx, dec); // -> ld2h_z_p_bi_contiguous
	if(msz==1 && opc==2 && HasSVE() && HasSME()) return ld3h_z_p_bi(ctx, dec); // -> ld3h_z_p_bi_contiguous
	if(msz==1 && opc==3 && HasSVE() && HasSME()) return ld4h_z_p_bi(ctx, dec); // -> ld4h_z_p_bi_contiguous
	if(msz==2 && opc==1 && HasSVE() && HasSME()) return ld2w_z_p_bi(ctx, dec); // -> ld2w_z_p_bi_contiguous
	if(msz==2 && opc==2 && HasSVE() && HasSME()) return ld3w_z_p_bi(ctx, dec); // -> ld3w_z_p_bi_contiguous
	if(msz==2 && opc==3 && HasSVE() && HasSME()) return ld4w_z_p_bi(ctx, dec); // -> ld4w_z_p_bi_contiguous
	if(msz==3 && opc==1 && HasSVE() && HasSME()) return ld2d_z_p_bi(ctx, dec); // -> ld2d_z_p_bi_contiguous
	if(msz==3 && opc==2 && HasSVE() && HasSME()) return ld3d_z_p_bi(ctx, dec); // -> ld3d_z_p_bi_contiguous
	if(msz==3 && opc==3 && HasSVE() && HasSME()) return ld4d_z_p_bi(ctx, dec); // -> ld4d_z_p_bi_contiguous
	UNMATCHED;
}

int decode_iclass_sve_mem_eldq_si(context *ctx, Instruction *dec)
{
	uint32_t num=(INSWORD>>23)&3;
	if(!num) UNALLOCATED(ENC_UNALLOCATED_560_SVE_MEM_ELDQ_SI);
	if(num==1 && HasSVE2p1() && HasSME2p1()) return ld2q_z_p_bi(ctx, dec); // -> ld2q_z_p_bi_contiguous
	if(num==2 && HasSVE2p1() && HasSME2p1()) return ld3q_z_p_bi(ctx, dec); // -> ld3q_z_p_bi_contiguous
	if(num==3 && HasSVE2p1() && HasSME2p1()) return ld4q_z_p_bi(ctx, dec); // -> ld4q_z_p_bi_contiguous
	UNMATCHED;
}

int decode_iclass_sve_mem_estq_si(context *ctx, Instruction *dec)
{
	uint32_t num=(INSWORD>>22)&3;
	if(!num) UNALLOCATED(ENC_UNALLOCATED_561_SVE_MEM_ESTQ_SI);
	if(num==1 && HasSVE2p1() && HasSME2p1()) return st2q_z_p_bi(ctx, dec); // -> st2q_z_p_bi_contiguous
	if(num==2 && HasSVE2p1() && HasSME2p1()) return st3q_z_p_bi(ctx, dec); // -> st3q_z_p_bi_contiguous
	if(num==3 && HasSVE2p1() && HasSME2p1()) return st4q_z_p_bi(ctx, dec); // -> st4q_z_p_bi_contiguous
	UNMATCHED;
}

int decode_iclass_sve_mem_estq_ss(context *ctx, Instruction *dec)
{
	uint32_t num=(INSWORD>>22)&3, Rm=(INSWORD>>16)&0x1f;
	if(num==1 && Rm!=0x1f && HasSVE2p1() && HasSME2p1()) return st2q_z_p_br(ctx, dec); // -> st2q_z_p_br_contiguous
	if(num==2 && Rm!=0x1f && HasSVE2p1() && HasSME2p1()) return st3q_z_p_br(ctx, dec); // -> st3q_z_p_br_contiguous
	if(num==3 && Rm!=0x1f && HasSVE2p1() && HasSME2p1()) return st4q_z_p_br(ctx, dec); // -> st4q_z_p_br_contiguous
	if(num && Rm==0x1f) UNALLOCATED(ENC_UNALLOCATED_563_SVE_MEM_ESTQ_SS);
	if(!num) UNALLOCATED(ENC_UNALLOCATED_562_SVE_MEM_ESTQ_SS);
	UNMATCHED;
}

int decode_iclass_sve_mem_pspill(context *ctx, Instruction *dec)
{
	return str_p_bi(ctx, dec);
}

int decode_iclass_sve_mem_cst_ss(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>22)&7, o2=(INSWORD>>21)&1, Rm=(INSWORD>>16)&0x1f;
	if(opc==4 && !o2 && Rm==0x1f) UNALLOCATED(ENC_UNALLOCATED_567_SVE_MEM_CST_SS);
	if(opc==4 && !o2 && Rm!=0x1f && HasSVE2p1()) return st1w_z_p_br(ctx, dec); // -> st1w_z_p_br_u128
	if(opc==7 && !o2 && Rm!=0x1f && HasSVE2p1()) return st1d_z_p_br(ctx, dec); // -> st1d_z_p_br_u128
	if(opc==7 && o2 && Rm!=0x1f && HasSVE() && HasSME()) return st1d_z_p_br(ctx, dec); // -> st1d_z_p_br_
	if(opc==5 && Rm!=0x1f && HasSVE() && HasSME()) return st1w_z_p_br(ctx, dec); // -> st1w_z_p_br_
	if(!(opc&5) && Rm==0x1f) UNALLOCATED(ENC_UNALLOCATED_566_SVE_MEM_CST_SS);
	if(!(opc&6) && Rm!=0x1f && HasSVE() && HasSME()) return st1b_z_p_br(ctx, dec); // -> st1b_z_p_br_
	if((opc&6)==2 && Rm!=0x1f && HasSVE() && HasSME()) return st1h_z_p_br(ctx, dec); // -> st1h_z_p_br_
	if(opc&1 && Rm==0x1f) UNALLOCATED(ENC_UNALLOCATED_565_SVE_MEM_CST_SS);
	if(opc==4 && o2) UNALLOCATED(ENC_UNALLOCATED_564_SVE_MEM_CST_SS);
	UNMATCHED;
}

int decode_iclass_sve_mem_spill(context *ctx, Instruction *dec)
{
	return str_z_bi(ctx, dec);
}

int decode_iclass_sve_mem_cst_si(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3, opc=(INSWORD>>21)&3;
	if(msz==2 && !opc && HasSVE2p1()) return st1w_z_p_bi(ctx, dec); // -> st1w_z_p_bi_u128
	if(msz==2 && opc==1) UNALLOCATED(ENC_UNALLOCATED_569_SVE_MEM_CST_SI);
	if(msz==3 && opc==2 && HasSVE2p1()) return st1d_z_p_bi(ctx, dec); // -> st1d_z_p_bi_u128
	if(msz==3 && opc==3 && HasSVE() && HasSME()) return st1d_z_p_bi(ctx, dec); // -> st1d_z_p_bi_
	if(msz==2 && (opc&2)==2 && HasSVE() && HasSME()) return st1w_z_p_bi(ctx, dec); // -> st1w_z_p_bi_
	if(msz==3 && !(opc&2)) UNALLOCATED(ENC_UNALLOCATED_568_SVE_MEM_CST_SI);
	if(!msz && HasSVE() && HasSME()) return st1b_z_p_bi(ctx, dec); // -> st1b_z_p_bi_
	if(msz==1 && HasSVE() && HasSME()) return st1h_z_p_bi(ctx, dec); // -> st1h_z_p_bi_
	UNMATCHED;
}

int decode_iclass_sve_mem_cstnt_si(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3;
	if(!msz && HasSVE() && HasSME()) return stnt1b_z_p_bi(ctx, dec); // -> stnt1b_z_p_bi_contiguous
	if(msz==1 && HasSVE() && HasSME()) return stnt1h_z_p_bi(ctx, dec); // -> stnt1h_z_p_bi_contiguous
	if(msz==2 && HasSVE() && HasSME()) return stnt1w_z_p_bi(ctx, dec); // -> stnt1w_z_p_bi_contiguous
	if(msz==3 && HasSVE() && HasSME()) return stnt1d_z_p_bi(ctx, dec); // -> stnt1d_z_p_bi_contiguous
	UNMATCHED;
}

int decode_iclass_sve_mem_est_si(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3, opc=(INSWORD>>21)&3;
	if(!msz && opc==1 && HasSVE() && HasSME()) return st2b_z_p_bi(ctx, dec); // -> st2b_z_p_bi_contiguous
	if(!msz && opc==2 && HasSVE() && HasSME()) return st3b_z_p_bi(ctx, dec); // -> st3b_z_p_bi_contiguous
	if(!msz && opc==3 && HasSVE() && HasSME()) return st4b_z_p_bi(ctx, dec); // -> st4b_z_p_bi_contiguous
	if(msz==1 && opc==1 && HasSVE() && HasSME()) return st2h_z_p_bi(ctx, dec); // -> st2h_z_p_bi_contiguous
	if(msz==1 && opc==2 && HasSVE() && HasSME()) return st3h_z_p_bi(ctx, dec); // -> st3h_z_p_bi_contiguous
	if(msz==1 && opc==3 && HasSVE() && HasSME()) return st4h_z_p_bi(ctx, dec); // -> st4h_z_p_bi_contiguous
	if(msz==2 && opc==1 && HasSVE() && HasSME()) return st2w_z_p_bi(ctx, dec); // -> st2w_z_p_bi_contiguous
	if(msz==2 && opc==2 && HasSVE() && HasSME()) return st3w_z_p_bi(ctx, dec); // -> st3w_z_p_bi_contiguous
	if(msz==2 && opc==3 && HasSVE() && HasSME()) return st4w_z_p_bi(ctx, dec); // -> st4w_z_p_bi_contiguous
	if(msz==3 && opc==1 && HasSVE() && HasSME()) return st2d_z_p_bi(ctx, dec); // -> st2d_z_p_bi_contiguous
	if(msz==3 && opc==2 && HasSVE() && HasSME()) return st3d_z_p_bi(ctx, dec); // -> st3d_z_p_bi_contiguous
	if(msz==3 && opc==3 && HasSVE() && HasSME()) return st4d_z_p_bi(ctx, dec); // -> st4d_z_p_bi_contiguous
	UNMATCHED;
}

int decode_iclass_sve_mem_cstnt_ss(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3, Rm=(INSWORD>>16)&0x1f;
	if(!msz && Rm!=0x1f && HasSVE() && HasSME()) return stnt1b_z_p_br(ctx, dec); // -> stnt1b_z_p_br_contiguous
	if(msz==1 && Rm!=0x1f && HasSVE() && HasSME()) return stnt1h_z_p_br(ctx, dec); // -> stnt1h_z_p_br_contiguous
	if(msz==2 && Rm!=0x1f && HasSVE() && HasSME()) return stnt1w_z_p_br(ctx, dec); // -> stnt1w_z_p_br_contiguous
	if(msz==3 && Rm!=0x1f && HasSVE() && HasSME()) return stnt1d_z_p_br(ctx, dec); // -> stnt1d_z_p_br_contiguous
	if(Rm==0x1f) UNALLOCATED(ENC_UNALLOCATED_570_SVE_MEM_CSTNT_SS);
	UNMATCHED;
}

int decode_iclass_sve_mem_est_ss(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3, opc=(INSWORD>>21)&3, Rm=(INSWORD>>16)&0x1f;
	if(!msz && opc==1 && Rm!=0x1f && HasSVE() && HasSME()) return st2b_z_p_br(ctx, dec); // -> st2b_z_p_br_contiguous
	if(!msz && opc==2 && Rm!=0x1f && HasSVE() && HasSME()) return st3b_z_p_br(ctx, dec); // -> st3b_z_p_br_contiguous
	if(!msz && opc==3 && Rm!=0x1f && HasSVE() && HasSME()) return st4b_z_p_br(ctx, dec); // -> st4b_z_p_br_contiguous
	if(msz==1 && opc==1 && Rm!=0x1f && HasSVE() && HasSME()) return st2h_z_p_br(ctx, dec); // -> st2h_z_p_br_contiguous
	if(msz==1 && opc==2 && Rm!=0x1f && HasSVE() && HasSME()) return st3h_z_p_br(ctx, dec); // -> st3h_z_p_br_contiguous
	if(msz==1 && opc==3 && Rm!=0x1f && HasSVE() && HasSME()) return st4h_z_p_br(ctx, dec); // -> st4h_z_p_br_contiguous
	if(msz==2 && opc==1 && Rm!=0x1f && HasSVE() && HasSME()) return st2w_z_p_br(ctx, dec); // -> st2w_z_p_br_contiguous
	if(msz==2 && opc==2 && Rm!=0x1f && HasSVE() && HasSME()) return st3w_z_p_br(ctx, dec); // -> st3w_z_p_br_contiguous
	if(msz==2 && opc==3 && Rm!=0x1f && HasSVE() && HasSME()) return st4w_z_p_br(ctx, dec); // -> st4w_z_p_br_contiguous
	if(msz==3 && opc==1 && Rm!=0x1f && HasSVE() && HasSME()) return st2d_z_p_br(ctx, dec); // -> st2d_z_p_br_contiguous
	if(msz==3 && opc==2 && Rm!=0x1f && HasSVE() && HasSME()) return st3d_z_p_br(ctx, dec); // -> st3d_z_p_br_contiguous
	if(msz==3 && opc==3 && Rm!=0x1f && HasSVE() && HasSME()) return st4d_z_p_br(ctx, dec); // -> st4d_z_p_br_contiguous
	if(opc && Rm==0x1f) UNALLOCATED(ENC_UNALLOCATED_571_SVE_MEM_EST_SS);
	UNMATCHED;
}

int decode_iclass_sve_mem_sstnt_64b_vs(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3;
	if(!msz && HasSVE2()) return stnt1b_z_p_ar(ctx, dec); // -> stnt1b_z_p_ar_d_64_unscaled
	if(msz==1 && HasSVE2()) return stnt1h_z_p_ar(ctx, dec); // -> stnt1h_z_p_ar_d_64_unscaled
	if(msz==2 && HasSVE2()) return stnt1w_z_p_ar(ctx, dec); // -> stnt1w_z_p_ar_d_64_unscaled
	if(msz==3 && HasSVE2()) return stnt1d_z_p_ar(ctx, dec); // -> stnt1d_z_p_ar_d_64_unscaled
	UNMATCHED;
}

int decode_iclass_sve_mem_sstnt_32b_vs(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3;
	if(!msz && HasSVE2()) return stnt1b_z_p_ar(ctx, dec); // -> stnt1b_z_p_ar_s_x32_unscaled
	if(msz==1 && HasSVE2()) return stnt1h_z_p_ar(ctx, dec); // -> stnt1h_z_p_ar_s_x32_unscaled
	if(msz==2 && HasSVE2()) return stnt1w_z_p_ar(ctx, dec); // -> stnt1w_z_p_ar_s_x32_unscaled
	if(msz==3) UNALLOCATED(ENC_UNALLOCATED_572_SVE_MEM_SSTNT_32B_VS);
	UNMATCHED;
}

int decode_iclass_sve_mem_sstq_64b_vs(context *ctx, Instruction *dec)
{
	return st1q_z_p_ar(ctx, dec);
}

int decode_iclass_sve_mem_sst_vs2(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3;
	if(!msz && HasSVE()) return st1b_z_p_bz(ctx, dec); // -> st1b_z_p_bz_d_64_unscaled
	if(msz==1 && HasSVE()) return st1h_z_p_bz(ctx, dec); // -> st1h_z_p_bz_d_64_unscaled
	if(msz==2 && HasSVE()) return st1w_z_p_bz(ctx, dec); // -> st1w_z_p_bz_d_64_unscaled
	if(msz==3 && HasSVE()) return st1d_z_p_bz(ctx, dec); // -> st1d_z_p_bz_d_64_unscaled
	UNMATCHED;
}

int decode_iclass_sve_mem_sst_sv2(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3;
	if(!msz) UNALLOCATED(ENC_UNALLOCATED_573_SVE_MEM_SST_SV2);
	if(msz==1 && HasSVE()) return st1h_z_p_bz(ctx, dec); // -> st1h_z_p_bz_d_64_scaled
	if(msz==2 && HasSVE()) return st1w_z_p_bz(ctx, dec); // -> st1w_z_p_bz_d_64_scaled
	if(msz==3 && HasSVE()) return st1d_z_p_bz(ctx, dec); // -> st1d_z_p_bz_d_64_scaled
	UNMATCHED;
}

int decode_iclass_sve_mem_sst_vi_a(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3;
	if(!msz && HasSVE()) return st1b_z_p_ai(ctx, dec); // -> st1b_z_p_ai_d
	if(msz==1 && HasSVE()) return st1h_z_p_ai(ctx, dec); // -> st1h_z_p_ai_d
	if(msz==2 && HasSVE()) return st1w_z_p_ai(ctx, dec); // -> st1w_z_p_ai_d
	if(msz==3 && HasSVE()) return st1d_z_p_ai(ctx, dec); // -> st1d_z_p_ai_d
	UNMATCHED;
}

int decode_iclass_sve_mem_sst_vi_b(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3;
	if(!msz && HasSVE()) return st1b_z_p_ai(ctx, dec); // -> st1b_z_p_ai_s
	if(msz==1 && HasSVE()) return st1h_z_p_ai(ctx, dec); // -> st1h_z_p_ai_s
	if(msz==2 && HasSVE()) return st1w_z_p_ai(ctx, dec); // -> st1w_z_p_ai_s
	if(msz==3) UNALLOCATED(ENC_UNALLOCATED_574_SVE_MEM_SST_VI_B);
	UNMATCHED;
}

int decode_iclass_sve_mem_sst_vs_a(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3;
	if(!msz && HasSVE()) return st1b_z_p_bz(ctx, dec); // -> st1b_z_p_bz_d_x32_unscaled
	if(msz==1 && HasSVE()) return st1h_z_p_bz(ctx, dec); // -> st1h_z_p_bz_d_x32_unscaled
	if(msz==2 && HasSVE()) return st1w_z_p_bz(ctx, dec); // -> st1w_z_p_bz_d_x32_unscaled
	if(msz==3 && HasSVE()) return st1d_z_p_bz(ctx, dec); // -> st1d_z_p_bz_d_x32_unscaled
	UNMATCHED;
}

int decode_iclass_sve_mem_sst_vs_b(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3;
	if(!msz && HasSVE()) return st1b_z_p_bz(ctx, dec); // -> st1b_z_p_bz_s_x32_unscaled
	if(msz==1 && HasSVE()) return st1h_z_p_bz(ctx, dec); // -> st1h_z_p_bz_s_x32_unscaled
	if(msz==2 && HasSVE()) return st1w_z_p_bz(ctx, dec); // -> st1w_z_p_bz_s_x32_unscaled
	if(msz==3) UNALLOCATED(ENC_UNALLOCATED_575_SVE_MEM_SST_VS_B);
	UNMATCHED;
}

int decode_iclass_sve_mem_sst_sv_a(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3;
	if(!msz) UNALLOCATED(ENC_UNALLOCATED_576_SVE_MEM_SST_SV_A);
	if(msz==1 && HasSVE()) return st1h_z_p_bz(ctx, dec); // -> st1h_z_p_bz_d_x32_scaled
	if(msz==2 && HasSVE()) return st1w_z_p_bz(ctx, dec); // -> st1w_z_p_bz_d_x32_scaled
	if(msz==3 && HasSVE()) return st1d_z_p_bz(ctx, dec); // -> st1d_z_p_bz_d_x32_scaled
	UNMATCHED;
}

int decode_iclass_sve_mem_sst_sv_b(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3;
	if(!msz) UNALLOCATED(ENC_UNALLOCATED_577_SVE_MEM_SST_SV_B);
	if(msz==1 && HasSVE()) return st1h_z_p_bz(ctx, dec); // -> st1h_z_p_bz_s_x32_scaled
	if(msz==2 && HasSVE()) return st1w_z_p_bz(ctx, dec); // -> st1w_z_p_bz_s_x32_scaled
	if(msz==3) UNALLOCATED(ENC_UNALLOCATED_578_SVE_MEM_SST_SV_B);
	UNMATCHED;
}

int decode_iclass_sve_intx_clong(context *ctx, Instruction *dec)
{
	uint32_t S=(INSWORD>>11)&1, tb=(INSWORD>>10)&1;
	if(!S && !tb && HasSVE2() && HasSME()) return saddlbt_z_zz(ctx, dec); // -> saddlbt_z_zz_
	if(!S && tb) UNALLOCATED(ENC_UNALLOCATED_579_SVE_INTX_CLONG);
	if(S && !tb && HasSVE2() && HasSME()) return ssublbt_z_zz(ctx, dec); // -> ssublbt_z_zz_
	if(S && tb && HasSVE2() && HasSME()) return ssubltb_z_zz(ctx, dec); // -> ssubltb_z_zz_
	UNMATCHED;
}

int decode_iclass_sve_intx_eorx(context *ctx, Instruction *dec)
{
	uint32_t tb=(INSWORD>>10)&1;
	if(!tb && HasSVE2() && HasSME()) return eorbt_z_zz(ctx, dec); // -> eorbt_z_zz_
	if(tb && HasSVE2() && HasSME()) return eortb_z_zz(ctx, dec); // -> eortb_z_zz_
	UNMATCHED;
}

int decode_iclass_sve_intx_mmla(context *ctx, Instruction *dec)
{
	uint32_t uns=(INSWORD>>22)&3;
	if(!uns && HasSVE() && HasI8MM()) return smmla_z_zzz(ctx, dec); // -> smmla_z_zzz_
	if(uns==1) UNALLOCATED(ENC_UNALLOCATED_580_SVE_INTX_MMLA);
	if(uns==2 && HasSVE() && HasI8MM()) return usmmla_z_zzz(ctx, dec); // -> usmmla_z_zzz_
	if(uns==3 && HasSVE() && HasI8MM()) return ummla_z_zzz(ctx, dec); // -> ummla_z_zzz_
	UNMATCHED;
}

int decode_iclass_sve_intx_shift_long(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>11)&1, T=(INSWORD>>10)&1;
	if(!U && !T && HasSVE2() && HasSME()) return sshllb_z_zi(ctx, dec); // -> sshllb_z_zi_
	if(!U && T && HasSVE2() && HasSME()) return sshllt_z_zi(ctx, dec); // -> sshllt_z_zi_
	if(U && !T && HasSVE2() && HasSME()) return ushllb_z_zi(ctx, dec); // -> ushllb_z_zi_
	if(U && T && HasSVE2() && HasSME()) return ushllt_z_zi(ctx, dec); // -> ushllt_z_zi_
	UNMATCHED;
}

int decode_iclass_sve_intx_perm_bit(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>10)&3;
	if(!opc && HasSVE_BitPerm()) return bext_z_zz(ctx, dec); // -> bext_z_zz_
	if(opc==1 && HasSVE_BitPerm()) return bdep_z_zz(ctx, dec); // -> bdep_z_zz_
	if(opc==2 && HasSVE_BitPerm()) return bgrp_z_zz(ctx, dec); // -> bgrp_z_zz_
	if(opc==3) UNALLOCATED(ENC_UNALLOCATED_581_SVE_INTX_PERM_BIT);
	UNMATCHED;
}

int decode_iclass_sve_intx_dot_by_indexed_elem(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, U=(INSWORD>>10)&1;
	if(size==2 && !U && HasSVE() && HasSME()) return sdot_z_zzzi(ctx, dec); // -> sdot_z_zzzi_s
	if(size==2 && U && HasSVE() && HasSME()) return udot_z_zzzi(ctx, dec); // -> udot_z_zzzi_s
	if(size==3 && !U && HasSVE() && HasSME()) return sdot_z_zzzi(ctx, dec); // -> sdot_z_zzzi_d
	if(size==3 && U && HasSVE() && HasSME()) return udot_z_zzzi(ctx, dec); // -> udot_z_zzzi_d
	if(!(size&2) && !U && HasSVE2p3() && HasSME2p3()) return sdot_z32_zzzi(ctx, dec); // -> sdot_z16_zzzi_h
	if(!(size&2) && U && HasSVE2p3() && HasSME2p3()) return udot_z32_zzzi(ctx, dec); // -> udot_z16_zzzi_h
	UNMATCHED;
}

int decode_iclass_sve_intx_mla_by_indexed_elem(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, S=(INSWORD>>10)&1;
	if(size==2 && !S && HasSVE2() && HasSME()) return mla_z_zzzi(ctx, dec); // -> mla_z_zzzi_s
	if(size==2 && S && HasSVE2() && HasSME()) return mls_z_zzzi(ctx, dec); // -> mls_z_zzzi_s
	if(size==3 && !S && HasSVE2() && HasSME()) return mla_z_zzzi(ctx, dec); // -> mla_z_zzzi_d
	if(size==3 && S && HasSVE2() && HasSME()) return mls_z_zzzi(ctx, dec); // -> mls_z_zzzi_d
	if(!(size&2) && !S && HasSVE2() && HasSME()) return mla_z_zzzi(ctx, dec); // -> mla_z_zzzi_h
	if(!(size&2) && S && HasSVE2() && HasSME()) return mls_z_zzzi(ctx, dec); // -> mls_z_zzzi_h
	UNMATCHED;
}

int decode_iclass_sve_intx_qrdmlah_by_indexed_elem(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, S=(INSWORD>>10)&1;
	if(size==2 && !S && HasSVE2() && HasSME()) return sqrdmlah_z_zzzi(ctx, dec); // -> sqrdmlah_z_zzzi_s
	if(size==2 && S && HasSVE2() && HasSME()) return sqrdmlsh_z_zzzi(ctx, dec); // -> sqrdmlsh_z_zzzi_s
	if(size==3 && !S && HasSVE2() && HasSME()) return sqrdmlah_z_zzzi(ctx, dec); // -> sqrdmlah_z_zzzi_d
	if(size==3 && S && HasSVE2() && HasSME()) return sqrdmlsh_z_zzzi(ctx, dec); // -> sqrdmlsh_z_zzzi_d
	if(!(size&2) && !S && HasSVE2() && HasSME()) return sqrdmlah_z_zzzi(ctx, dec); // -> sqrdmlah_z_zzzi_h
	if(!(size&2) && S && HasSVE2() && HasSME()) return sqrdmlsh_z_zzzi(ctx, dec); // -> sqrdmlsh_z_zzzi_h
	UNMATCHED;
}

int decode_iclass_sve_intx_mixed_dot_by_indexed_elem(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, U=(INSWORD>>10)&1;
	if(size==2 && !U && HasSVE() && HasI8MM() && HasSME() && HasI8MM()) return usdot_z_zzzi(ctx, dec); // -> usdot_z_zzzi_s
	if(size==2 && U && HasSVE() && HasI8MM() && HasSME() && HasI8MM()) return sudot_z_zzzi(ctx, dec); // -> sudot_z_zzzi_s
	if(size!=2) UNALLOCATED(ENC_UNALLOCATED_582_SVE_INTX_MIXED_DOT_BY_INDEXED_ELEM);
	UNMATCHED;
}

int decode_iclass_sve_intx_qdmla_long_by_indexed_elem(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, S=(INSWORD>>12)&1, T=(INSWORD>>10)&1;
	if(size==2 && !S && !T && HasSVE2() && HasSME()) return sqdmlalb_z_zzzi(ctx, dec); // -> sqdmlalb_z_zzzi_s
	if(size==2 && !S && T && HasSVE2() && HasSME()) return sqdmlalt_z_zzzi(ctx, dec); // -> sqdmlalt_z_zzzi_s
	if(size==2 && S && !T && HasSVE2() && HasSME()) return sqdmlslb_z_zzzi(ctx, dec); // -> sqdmlslb_z_zzzi_s
	if(size==2 && S && T && HasSVE2() && HasSME()) return sqdmlslt_z_zzzi(ctx, dec); // -> sqdmlslt_z_zzzi_s
	if(size==3 && !S && !T && HasSVE2() && HasSME()) return sqdmlalb_z_zzzi(ctx, dec); // -> sqdmlalb_z_zzzi_d
	if(size==3 && !S && T && HasSVE2() && HasSME()) return sqdmlalt_z_zzzi(ctx, dec); // -> sqdmlalt_z_zzzi_d
	if(size==3 && S && !T && HasSVE2() && HasSME()) return sqdmlslb_z_zzzi(ctx, dec); // -> sqdmlslb_z_zzzi_d
	if(size==3 && S && T && HasSVE2() && HasSME()) return sqdmlslt_z_zzzi(ctx, dec); // -> sqdmlslt_z_zzzi_d
	if(!(size&2)) UNALLOCATED(ENC_UNALLOCATED_583_SVE_INTX_QDMLA_LONG_BY_INDEXED_ELEM);
	UNMATCHED;
}

int decode_iclass_sve_intx_cdot_by_indexed_elem(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3;
	if(size==2 && HasSVE2() && HasSME()) return cdot_z_zzzi(ctx, dec); // -> cdot_z_zzzi_s
	if(size==3 && HasSVE2() && HasSME()) return cdot_z_zzzi(ctx, dec); // -> cdot_z_zzzi_d
	if(!(size&2)) UNALLOCATED(ENC_UNALLOCATED_584_SVE_INTX_CDOT_BY_INDEXED_ELEM);
	UNMATCHED;
}

int decode_iclass_sve_intx_cmla_by_indexed_elem(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3;
	if(size==2 && HasSVE2() && HasSME()) return cmla_z_zzzi(ctx, dec); // -> cmla_z_zzzi_h
	if(size==3 && HasSVE2() && HasSME()) return cmla_z_zzzi(ctx, dec); // -> cmla_z_zzzi_s
	if(!(size&2)) UNALLOCATED(ENC_UNALLOCATED_585_SVE_INTX_CMLA_BY_INDEXED_ELEM);
	UNMATCHED;
}

int decode_iclass_sve_intx_qrdcmla_by_indexed_elem(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3;
	if(size==2 && HasSVE2() && HasSME()) return sqrdcmlah_z_zzzi(ctx, dec); // -> sqrdcmlah_z_zzzi_h
	if(size==3 && HasSVE2() && HasSME()) return sqrdcmlah_z_zzzi(ctx, dec); // -> sqrdcmlah_z_zzzi_s
	if(!(size&2)) UNALLOCATED(ENC_UNALLOCATED_586_SVE_INTX_QRDCMLA_BY_INDEXED_ELEM);
	UNMATCHED;
}

int decode_iclass_sve_intx_mla_long_by_indexed_elem(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, S=(INSWORD>>13)&1, U=(INSWORD>>12)&1, T=(INSWORD>>10)&1;
	if(size==2 && !S && !U && !T && HasSVE2() && HasSME()) return smlalb_z_zzzi(ctx, dec); // -> smlalb_z_zzzi_s
	if(size==2 && !S && !U && T && HasSVE2() && HasSME()) return smlalt_z_zzzi(ctx, dec); // -> smlalt_z_zzzi_s
	if(size==2 && !S && U && !T && HasSVE2() && HasSME()) return umlalb_z_zzzi(ctx, dec); // -> umlalb_z_zzzi_s
	if(size==2 && !S && U && T && HasSVE2() && HasSME()) return umlalt_z_zzzi(ctx, dec); // -> umlalt_z_zzzi_s
	if(size==2 && S && !U && !T && HasSVE2() && HasSME()) return smlslb_z_zzzi(ctx, dec); // -> smlslb_z_zzzi_s
	if(size==2 && S && !U && T && HasSVE2() && HasSME()) return smlslt_z_zzzi(ctx, dec); // -> smlslt_z_zzzi_s
	if(size==2 && S && U && !T && HasSVE2() && HasSME()) return umlslb_z_zzzi(ctx, dec); // -> umlslb_z_zzzi_s
	if(size==2 && S && U && T && HasSVE2() && HasSME()) return umlslt_z_zzzi(ctx, dec); // -> umlslt_z_zzzi_s
	if(size==3 && !S && !U && !T && HasSVE2() && HasSME()) return smlalb_z_zzzi(ctx, dec); // -> smlalb_z_zzzi_d
	if(size==3 && !S && !U && T && HasSVE2() && HasSME()) return smlalt_z_zzzi(ctx, dec); // -> smlalt_z_zzzi_d
	if(size==3 && !S && U && !T && HasSVE2() && HasSME()) return umlalb_z_zzzi(ctx, dec); // -> umlalb_z_zzzi_d
	if(size==3 && !S && U && T && HasSVE2() && HasSME()) return umlalt_z_zzzi(ctx, dec); // -> umlalt_z_zzzi_d
	if(size==3 && S && !U && !T && HasSVE2() && HasSME()) return smlslb_z_zzzi(ctx, dec); // -> smlslb_z_zzzi_d
	if(size==3 && S && !U && T && HasSVE2() && HasSME()) return smlslt_z_zzzi(ctx, dec); // -> smlslt_z_zzzi_d
	if(size==3 && S && U && !T && HasSVE2() && HasSME()) return umlslb_z_zzzi(ctx, dec); // -> umlslb_z_zzzi_d
	if(size==3 && S && U && T && HasSVE2() && HasSME()) return umlslt_z_zzzi(ctx, dec); // -> umlslt_z_zzzi_d
	if(!(size&2)) UNALLOCATED(ENC_UNALLOCATED_587_SVE_INTX_MLA_LONG_BY_INDEXED_ELEM);
	UNMATCHED;
}

int decode_iclass_sve_intx_mul_long_by_indexed_elem(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, U=(INSWORD>>12)&1, T=(INSWORD>>10)&1;
	if(size==2 && !U && !T && HasSVE2() && HasSME()) return smullb_z_zzi(ctx, dec); // -> smullb_z_zzi_s
	if(size==2 && !U && T && HasSVE2() && HasSME()) return smullt_z_zzi(ctx, dec); // -> smullt_z_zzi_s
	if(size==2 && U && !T && HasSVE2() && HasSME()) return umullb_z_zzi(ctx, dec); // -> umullb_z_zzi_s
	if(size==2 && U && T && HasSVE2() && HasSME()) return umullt_z_zzi(ctx, dec); // -> umullt_z_zzi_s
	if(size==3 && !U && !T && HasSVE2() && HasSME()) return smullb_z_zzi(ctx, dec); // -> smullb_z_zzi_d
	if(size==3 && !U && T && HasSVE2() && HasSME()) return smullt_z_zzi(ctx, dec); // -> smullt_z_zzi_d
	if(size==3 && U && !T && HasSVE2() && HasSME()) return umullb_z_zzi(ctx, dec); // -> umullb_z_zzi_d
	if(size==3 && U && T && HasSVE2() && HasSME()) return umullt_z_zzi(ctx, dec); // -> umullt_z_zzi_d
	if(!(size&2)) UNALLOCATED(ENC_UNALLOCATED_588_SVE_INTX_MUL_LONG_BY_INDEXED_ELEM);
	UNMATCHED;
}

int decode_iclass_sve_intx_qdmul_long_by_indexed_elem(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, T=(INSWORD>>10)&1;
	if(size==2 && !T && HasSVE2() && HasSME()) return sqdmullb_z_zzi(ctx, dec); // -> sqdmullb_z_zzi_s
	if(size==2 && T && HasSVE2() && HasSME()) return sqdmullt_z_zzi(ctx, dec); // -> sqdmullt_z_zzi_s
	if(size==3 && !T && HasSVE2() && HasSME()) return sqdmullb_z_zzi(ctx, dec); // -> sqdmullb_z_zzi_d
	if(size==3 && T && HasSVE2() && HasSME()) return sqdmullt_z_zzi(ctx, dec); // -> sqdmullt_z_zzi_d
	if(!(size&2)) UNALLOCATED(ENC_UNALLOCATED_589_SVE_INTX_QDMUL_LONG_BY_INDEXED_ELEM);
	UNMATCHED;
}

int decode_iclass_sve_intx_qdmulh_by_indexed_elem(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, R=(INSWORD>>10)&1;
	if(size==2 && !R && HasSVE2() && HasSME()) return sqdmulh_z_zzi(ctx, dec); // -> sqdmulh_z_zzi_s
	if(size==2 && R && HasSVE2() && HasSME()) return sqrdmulh_z_zzi(ctx, dec); // -> sqrdmulh_z_zzi_s
	if(size==3 && !R && HasSVE2() && HasSME()) return sqdmulh_z_zzi(ctx, dec); // -> sqdmulh_z_zzi_d
	if(size==3 && R && HasSVE2() && HasSME()) return sqrdmulh_z_zzi(ctx, dec); // -> sqrdmulh_z_zzi_d
	if(!(size&2) && !R && HasSVE2() && HasSME()) return sqdmulh_z_zzi(ctx, dec); // -> sqdmulh_z_zzi_h
	if(!(size&2) && R && HasSVE2() && HasSME()) return sqrdmulh_z_zzi(ctx, dec); // -> sqrdmulh_z_zzi_h
	UNMATCHED;
}

int decode_iclass_sve_intx_mul_by_indexed_elem(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3;
	if(size==2 && HasSVE2() && HasSME()) return mul_z_zzi(ctx, dec); // -> mul_z_zzi_s
	if(size==3 && HasSVE2() && HasSME()) return mul_z_zzi(ctx, dec); // -> mul_z_zzi_d
	if(!(size&2) && HasSVE2() && HasSME()) return mul_z_zzi(ctx, dec); // -> mul_z_zzi_h
	UNMATCHED;
}

int decode_iclass_sve_int_break(context *ctx, Instruction *dec)
{
	uint32_t B=(INSWORD>>23)&1, S=(INSWORD>>22)&1, M=(INSWORD>>4)&1;
	if(!B && S && !M && HasSVE() && HasSME()) return brkas_p_p_p(ctx, dec); // -> brkas_p_p_p_z
	if(B && S && !M && HasSVE() && HasSME()) return brkbs_p_p_p(ctx, dec); // -> brkbs_p_p_p_z
	if(S && M) UNALLOCATED(ENC_UNALLOCATED_590_SVE_INT_BREAK);
	if(!B && !S && HasSVE() && HasSME()) return brka_p_p_p(ctx, dec); // -> brka_p_p_p_
	if(B && !S && HasSVE() && HasSME()) return brkb_p_p_p(ctx, dec); // -> brkb_p_p_p_
	UNMATCHED;
}

int decode_iclass_sve_int_brkn(context *ctx, Instruction *dec)
{
	uint32_t S=(INSWORD>>22)&1;
	if(!S && HasSVE() && HasSME()) return brkn_p_p_pp(ctx, dec); // -> brkn_p_p_pp_
	if(S && HasSVE() && HasSME()) return brkns_p_p_pp(ctx, dec); // -> brkns_p_p_pp_
	UNMATCHED;
}

int decode_iclass_sve_int_perm_bin_perm_pp(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>11)&3, H=(INSWORD>>10)&1;
	if(!opc && !H && HasSVE() && HasSME()) return zip1_p_pp(ctx, dec); // -> zip1_p_pp_
	if(!opc && H && HasSVE() && HasSME()) return zip1_p_pp(ctx, dec); // -> zip2_p_pp_
	if(opc==1 && !H && HasSVE() && HasSME()) return uzp1_p_pp(ctx, dec); // -> uzp1_p_pp_
	if(opc==1 && H && HasSVE() && HasSME()) return uzp1_p_pp(ctx, dec); // -> uzp2_p_pp_
	if(opc==2 && !H && HasSVE() && HasSME()) return trn1_p_pp(ctx, dec); // -> trn1_p_pp_
	if(opc==2 && H && HasSVE() && HasSME()) return trn1_p_pp(ctx, dec); // -> trn2_p_pp_
	if(opc==3) UNALLOCATED(ENC_UNALLOCATED_591_SVE_INT_PERM_BIN_PERM_PP);
	UNMATCHED;
}

int decode_iclass_sve_int_perm_punpk(context *ctx, Instruction *dec)
{
	uint32_t H=(INSWORD>>16)&1;
	if(!H && HasSVE() && HasSME()) return punpkhi_p_p(ctx, dec); // -> punpklo_p_p_
	if(H && HasSVE() && HasSME()) return punpkhi_p_p(ctx, dec); // -> punpkhi_p_p_
	UNMATCHED;
}

int decode_iclass_sve_int_perm_reverse_p(context *ctx, Instruction *dec)
{
	return rev_p_p(ctx, dec);
}

int decode_iclass_sve_int_perm_extract_i(context *ctx, Instruction *dec)
{
	return ext_z_zi(ctx, dec);
}

int decode_iclass_sve_intx_perm_extract_i(context *ctx, Instruction *dec)
{
	return ext_z_zi(ctx, dec);
}

int decode_iclass_sve_int_perm_dup_i(context *ctx, Instruction *dec)
{
	return dup_z_zi(ctx, dec);
}

int decode_iclass_sve_int_perm_bin_perm_zz(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>10)&7;
	if(!opc && HasSVE() && HasSME()) return zip1_z_zz(ctx, dec); // -> zip1_z_zz_
	if(opc==1 && HasSVE() && HasSME()) return zip1_z_zz(ctx, dec); // -> zip2_z_zz_
	if(opc==2 && HasSVE() && HasSME()) return uzp1_z_zz(ctx, dec); // -> uzp1_z_zz_
	if(opc==3 && HasSVE() && HasSME()) return uzp1_z_zz(ctx, dec); // -> uzp2_z_zz_
	if(opc==4 && HasSVE() && HasSME()) return trn1_z_zz(ctx, dec); // -> trn1_z_zz_
	if(opc==5 && HasSVE() && HasSME()) return trn1_z_zz(ctx, dec); // -> trn2_z_zz_
	if((opc&6)==6) UNALLOCATED(ENC_UNALLOCATED_592_SVE_INT_PERM_BIN_PERM_ZZ);
	UNMATCHED;
}

int decode_iclass_sve_int_perm_dupq_i(context *ctx, Instruction *dec)
{
	return dupq_z_zi(ctx, dec);
}

int decode_iclass_sve_int_perm_extq(context *ctx, Instruction *dec)
{
	return extq_z_zi(ctx, dec);
}

int decode_iclass_sve_int_perm_cpy_v(context *ctx, Instruction *dec)
{
	return cpy_z_p_v(ctx, dec);
}

int decode_iclass_sve_int_perm_compact(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3;
	if(!(size&2) && HasSVE2p2() && HasSME2p2()) return compact_z_p_z(ctx, dec); // -> compact_z_p_z_s
	if((size&2)==2 && HasSVE() && HasSME2p2()) return compact_z_p_z(ctx, dec); // -> compact_z_p_z_
	UNMATCHED;
}

int decode_iclass_sve_int_perm_last_v(context *ctx, Instruction *dec)
{
	uint32_t B=(INSWORD>>16)&1;
	if(!B && HasSVE() && HasSME()) return lasta_v_p_z(ctx, dec); // -> lasta_v_p_z_
	if(B && HasSVE() && HasSME()) return lastb_v_p_z(ctx, dec); // -> lastb_v_p_z_
	UNMATCHED;
}

int decode_iclass_sve_int_perm_rev(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&3, Z=(INSWORD>>13)&1;
	if(!opc && !Z && HasSVE() && HasSME()) return revb_z_z(ctx, dec); // -> revb_z_z_m
	if(!opc && Z && HasSVE2p2() && HasSME2p2()) return revb_z_z(ctx, dec); // -> revb_z_z_z
	if(opc==1 && !Z && HasSVE() && HasSME()) return revb_z_z(ctx, dec); // -> revh_z_z_m
	if(opc==1 && Z && HasSVE2p2() && HasSME2p2()) return revb_z_z(ctx, dec); // -> revh_z_z_z
	if(opc==2 && !Z && HasSVE() && HasSME()) return revb_z_z(ctx, dec); // -> revw_z_z_m
	if(opc==2 && Z && HasSVE2p2() && HasSME2p2()) return revb_z_z(ctx, dec); // -> revw_z_z_z
	if(opc==3 && !Z && HasSVE() && HasSME()) return rbit_z_p_z(ctx, dec); // -> rbit_z_p_z_m
	if(opc==3 && Z && HasSVE2p2() && HasSME2p2()) return rbit_z_p_z(ctx, dec); // -> rbit_z_p_z_z
	UNMATCHED;
}

int decode_iclass_sve_int_perm_clast_zz(context *ctx, Instruction *dec)
{
	uint32_t B=(INSWORD>>16)&1;
	if(!B && HasSVE() && HasSME()) return clasta_z_p_zz(ctx, dec); // -> clasta_z_p_zz_
	if(B && HasSVE() && HasSME()) return clastb_z_p_zz(ctx, dec); // -> clastb_z_p_zz_
	UNMATCHED;
}

int decode_iclass_sve_int_perm_clast_vz(context *ctx, Instruction *dec)
{
	uint32_t B=(INSWORD>>16)&1;
	if(!B && HasSVE() && HasSME()) return clasta_v_p_z(ctx, dec); // -> clasta_v_p_z_
	if(B && HasSVE() && HasSME()) return clastb_v_p_z(ctx, dec); // -> clastb_v_p_z_
	UNMATCHED;
}

int decode_iclass_sve_int_perm_splice(context *ctx, Instruction *dec)
{
	return splice_z_p_zz(ctx, dec);
}

int decode_iclass_sve_intx_perm_splice(context *ctx, Instruction *dec)
{
	return splice_z_p_zz(ctx, dec);
}

int decode_iclass_sve_int_perm_last_r(context *ctx, Instruction *dec)
{
	uint32_t B=(INSWORD>>16)&1;
	if(!B && HasSVE() && HasSME()) return lasta_r_p_z(ctx, dec); // -> lasta_r_p_z_
	if(B && HasSVE() && HasSME()) return lastb_r_p_z(ctx, dec); // -> lastb_r_p_z_
	UNMATCHED;
}

int decode_iclass_sve_int_perm_cpy_r(context *ctx, Instruction *dec)
{
	return cpy_z_p_r(ctx, dec);
}

int decode_iclass_sve_int_perm_clast_rz(context *ctx, Instruction *dec)
{
	uint32_t B=(INSWORD>>16)&1;
	if(!B && HasSVE() && HasSME()) return clasta_r_p_z(ctx, dec); // -> clasta_r_p_z_
	if(B && HasSVE() && HasSME()) return clastb_r_p_z(ctx, dec); // -> clastb_r_p_z_
	UNMATCHED;
}

int decode_iclass_sve_int_perm_revd(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, Z=(INSWORD>>13)&1;
	if(!size && !Z && HasSME() && HasSVE2p1()) return revd_z_p_z(ctx, dec); // -> revd_z_p_z_m
	if(!size && Z && HasSVE2p2() && HasSME2p2()) return revd_z_p_z(ctx, dec); // -> revd_z_p_z_z
	if(size) UNALLOCATED(ENC_UNALLOCATED_593_SVE_INT_PERM_REVD);
	UNMATCHED;
}

int decode_iclass_sve_int_perm_expand(context *ctx, Instruction *dec)
{
	return expand_z_p_z(ctx, dec);
}

int decode_iclass_sve_int_perm_bin_long_perm_zz(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>11)&3, H=(INSWORD>>10)&1;
	if(!opc && !H && HasF64MM()) return zip1_z_zz(ctx, dec); // -> zip1_z_zz_q
	if(!opc && H && HasF64MM()) return zip1_z_zz(ctx, dec); // -> zip2_z_zz_q
	if(opc==1 && !H && HasF64MM()) return uzp1_z_zz(ctx, dec); // -> uzp1_z_zz_q
	if(opc==1 && H && HasF64MM()) return uzp1_z_zz(ctx, dec); // -> uzp2_z_zz_q
	if(opc==3 && !H && HasF64MM()) return trn1_z_zz(ctx, dec); // -> trn1_z_zz_q
	if(opc==3 && H && HasF64MM()) return trn1_z_zz(ctx, dec); // -> trn2_z_zz_q
	if(opc==2) UNALLOCATED(ENC_UNALLOCATED_594_SVE_INT_PERM_BIN_LONG_PERM_ZZ);
	UNMATCHED;
}

int decode_iclass_sve_int_perm_tbxquads(context *ctx, Instruction *dec)
{
	return tbxq_z_zz(ctx, dec);
}

int decode_iclass_sve_int_perm_tbl_3src(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>10)&1;
	if(!op && HasSVE2() && HasSME()) return tbl_z_zz(ctx, dec); // -> tbl_z_zz_2
	if(op && HasSVE2() && HasSME()) return tbx_z_zz(ctx, dec); // -> tbx_z_zz_
	UNMATCHED;
}

int decode_iclass_sve_int_perm_binquads(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>10)&7;
	if(!opc && HasSVE2p1() && HasSME2p1()) return zipq1_z_zz(ctx, dec); // -> zipq1_z_zz_
	if(opc==1 && HasSVE2p1() && HasSME2p1()) return zipq2_z_zz(ctx, dec); // -> zipq2_z_zz_
	if(opc==2 && HasSVE2p1() && HasSME2p1()) return uzpq1_z_zz(ctx, dec); // -> uzpq1_z_zz_
	if(opc==3 && HasSVE2p1() && HasSME2p1()) return uzpq2_z_zz(ctx, dec); // -> uzpq2_z_zz_
	if(opc==6 && HasSVE2p1() && HasSME2p1()) return tblq_z_zz(ctx, dec); // -> tblq_z_zz_
	if(opc==7) UNALLOCATED(ENC_UNALLOCATED_596_SVE_INT_PERM_BINQUADS);
	if((opc&6)==4) UNALLOCATED(ENC_UNALLOCATED_595_SVE_INT_PERM_BINQUADS);
	UNMATCHED;
}

int decode_iclass_sve_int_perm_tbl(context *ctx, Instruction *dec)
{
	return tbl_z_zz(ctx, dec);
}

int decode_iclass_sve_int_perm_dup_r(context *ctx, Instruction *dec)
{
	return dup_z_r(ctx, dec);
}

int decode_iclass_sve_int_perm_insrs(context *ctx, Instruction *dec)
{
	return insr_z_r(ctx, dec);
}

int decode_iclass_sve_int_mov_v2p(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>22)&3, opc2=(INSWORD>>17)&3;
	if(!opc && !opc2) UNALLOCATED(ENC_UNALLOCATED_597_SVE_INT_MOV_V2P);
	if(!opc && opc2==1 && HasSVE2p1() && HasSME2p1()) return pmov_p_zi(ctx, dec); // -> pmov_p_zi_b
	if(!opc && (opc2&2)==2 && HasSVE2p1() && HasSME2p1()) return pmov_p_zi(ctx, dec); // -> pmov_p_zi_h
	if(opc==1 && HasSVE2p1() && HasSME2p1()) return pmov_p_zi(ctx, dec); // -> pmov_p_zi_s
	if((opc&2)==2 && HasSVE2p1() && HasSME2p1()) return pmov_p_zi(ctx, dec); // -> pmov_p_zi_d
	UNMATCHED;
}

int decode_iclass_sve_int_mov_p2v(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>22)&3, opc2=(INSWORD>>17)&3;
	if(!opc && !opc2) UNALLOCATED(ENC_UNALLOCATED_598_SVE_INT_MOV_P2V);
	if(!opc && opc2==1 && HasSVE2p1() && HasSME2p1()) return pmov_z_pi(ctx, dec); // -> pmov_z_pi_b
	if(!opc && (opc2&2)==2 && HasSVE2p1() && HasSME2p1()) return pmov_z_pi(ctx, dec); // -> pmov_z_pi_h
	if(opc==1 && HasSVE2p1() && HasSME2p1()) return pmov_z_pi(ctx, dec); // -> pmov_z_pi_s
	if((opc&2)==2 && HasSVE2p1() && HasSME2p1()) return pmov_z_pi(ctx, dec); // -> pmov_z_pi_d
	UNMATCHED;
}

int decode_iclass_sve_int_perm_unpk(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>17)&1, H=(INSWORD>>16)&1;
	if(!U && !H && HasSVE() && HasSME()) return sunpkhi_z_z(ctx, dec); // -> sunpklo_z_z_
	if(!U && H && HasSVE() && HasSME()) return sunpkhi_z_z(ctx, dec); // -> sunpkhi_z_z_
	if(U && !H && HasSVE() && HasSME()) return uunpkhi_z_z(ctx, dec); // -> uunpklo_z_z_
	if(U && H && HasSVE() && HasSME()) return uunpkhi_z_z(ctx, dec); // -> uunpkhi_z_z_
	UNMATCHED;
}

int decode_iclass_sve_int_perm_insrv(context *ctx, Instruction *dec)
{
	return insr_z_v(ctx, dec);
}

int decode_iclass_sve_int_perm_reverse_z(context *ctx, Instruction *dec)
{
	return rev_z_z(ctx, dec);
}

int decode_iclass_sve_int_pcount_pred(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&7;
	if(!opc && HasSVE() && HasSME()) return cntp_r_p_p(ctx, dec); // -> cntp_r_p_p_
	if(opc==1 && HasSVE2p2() && HasSME2p2()) return firstp_r_p_p(ctx, dec); // -> firstp_r_p_p_
	if(opc==2 && HasSVE2p2() && HasSME2p2()) return lastp_r_p_p(ctx, dec); // -> lastp_r_p_p_
	if(opc==3) UNALLOCATED(ENC_UNALLOCATED_600_SVE_INT_PCOUNT_PRED);
	if((opc&4)==4) UNALLOCATED(ENC_UNALLOCATED_599_SVE_INT_PCOUNT_PRED);
	UNMATCHED;
}

int decode_iclass_sve_int_pcount_pn(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&7;
	if(!opc && HasSME2() && HasSVE2p1()) return cntp_r_pn(ctx, dec); // -> cntp_r_pn_
	if(opc) UNALLOCATED(ENC_UNALLOCATED_601_SVE_INT_PCOUNT_PN);
	UNMATCHED;
}

int decode_iclass_sve_int_pred_log(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>23)&1, S=(INSWORD>>22)&1, o2=(INSWORD>>9)&1, o3=(INSWORD>>4)&1;
	if(!op && !S && !o2 && !o3 && HasSVE() && HasSME()) return and_p_p_pp(ctx, dec); // -> and_p_p_pp_z
	if(!op && !S && !o2 && o3 && HasSVE() && HasSME()) return bic_p_p_pp(ctx, dec); // -> bic_p_p_pp_z
	if(!op && !S && o2 && !o3 && HasSVE() && HasSME()) return eor_p_p_pp(ctx, dec); // -> eor_p_p_pp_z
	if(!op && !S && o2 && o3 && HasSVE() && HasSME()) return sel_p_p_pp(ctx, dec); // -> sel_p_p_pp_
	if(!op && S && !o2 && !o3 && HasSVE() && HasSME()) return ands_p_p_pp(ctx, dec); // -> ands_p_p_pp_z
	if(!op && S && !o2 && o3 && HasSVE() && HasSME()) return bics_p_p_pp(ctx, dec); // -> bics_p_p_pp_z
	if(!op && S && o2 && !o3 && HasSVE() && HasSME()) return eors_p_p_pp(ctx, dec); // -> eors_p_p_pp_z
	if(!op && S && o2 && o3) UNALLOCATED(ENC_UNALLOCATED_602_SVE_INT_PRED_LOG);
	if(op && !S && !o2 && !o3 && HasSVE() && HasSME()) return orr_p_p_pp(ctx, dec); // -> orr_p_p_pp_z
	if(op && !S && !o2 && o3 && HasSVE() && HasSME()) return orn_p_p_pp(ctx, dec); // -> orn_p_p_pp_z
	if(op && !S && o2 && !o3 && HasSVE() && HasSME()) return nor_p_p_pp(ctx, dec); // -> nor_p_p_pp_z
	if(op && !S && o2 && o3 && HasSVE() && HasSME()) return nand_p_p_pp(ctx, dec); // -> nand_p_p_pp_z
	if(op && S && !o2 && !o3 && HasSVE() && HasSME()) return orrs_p_p_pp(ctx, dec); // -> orrs_p_p_pp_z
	if(op && S && !o2 && o3 && HasSVE() && HasSME()) return orns_p_p_pp(ctx, dec); // -> orns_p_p_pp_z
	if(op && S && o2 && !o3 && HasSVE() && HasSME()) return nors_p_p_pp(ctx, dec); // -> nors_p_p_pp_z
	if(op && S && o2 && o3 && HasSVE() && HasSME()) return nands_p_p_pp(ctx, dec); // -> nands_p_p_pp_z
	UNMATCHED;
}

int decode_iclass_sve_int_ptest(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>23)&1, S=(INSWORD>>22)&1, opc2=INSWORD&15;
	if(!op && S && !opc2 && HasSVE() && HasSME()) return ptest_p_p(ctx, dec); // -> ptest__p_p_
	if(!op && S && opc2) UNALLOCATED(ENC_UNALLOCATED_605_SVE_INT_PTEST);
	if(!op && !S) UNALLOCATED(ENC_UNALLOCATED_604_SVE_INT_PTEST);
	if(op) UNALLOCATED(ENC_UNALLOCATED_603_SVE_INT_PTEST);
	UNMATCHED;
}

int decode_iclass_sve_int_pfirst(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>23)&1, S=(INSWORD>>22)&1;
	if(!op && !S) UNALLOCATED(ENC_UNALLOCATED_607_SVE_INT_PFIRST);
	if(!op && S && HasSVE() && HasSME()) return pfirst_p_p_p(ctx, dec); // -> pfirst_p_p_p_
	if(op) UNALLOCATED(ENC_UNALLOCATED_606_SVE_INT_PFIRST);
	UNMATCHED;
}

int decode_iclass_sve_int_pnext(context *ctx, Instruction *dec)
{
	return pnext_p_p_p(ctx, dec);
}

int decode_iclass_sve_int_ptrue(context *ctx, Instruction *dec)
{
	uint32_t S=(INSWORD>>16)&1;
	if(!S && HasSVE() && HasSME()) return ptrue_p_s(ctx, dec); // -> ptrue_p_s_
	if(S && HasSVE() && HasSME()) return ptrues_p_s(ctx, dec); // -> ptrues_p_s_
	UNMATCHED;
}

int decode_iclass_sve_int_pfalse(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>23)&1, S=(INSWORD>>22)&1;
	if(!op && !S && HasSVE() && HasSME()) return pfalse_p(ctx, dec); // -> pfalse_p_
	if(!op && S) UNALLOCATED(ENC_UNALLOCATED_609_SVE_INT_PFALSE);
	if(op) UNALLOCATED(ENC_UNALLOCATED_608_SVE_INT_PFALSE);
	UNMATCHED;
}

int decode_iclass_sve_int_rdffr(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>23)&1, S=(INSWORD>>22)&1;
	if(!op && !S && HasSVE()) return rdffr_p_p_f(ctx, dec); // -> rdffr_p_p_f_
	if(!op && S && HasSVE()) return rdffrs_p_p_f(ctx, dec); // -> rdffrs_p_p_f_
	if(op) UNALLOCATED(ENC_UNALLOCATED_610_SVE_INT_RDFFR);
	UNMATCHED;
}

int decode_iclass_sve_int_rdffr_2(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>23)&1, S=(INSWORD>>22)&1;
	if(!op && !S && HasSVE()) return rdffr_p_f(ctx, dec); // -> rdffr_p_f_
	if(!op && S) UNALLOCATED(ENC_UNALLOCATED_612_SVE_INT_RDFFR_2);
	if(op) UNALLOCATED(ENC_UNALLOCATED_611_SVE_INT_RDFFR_2);
	UNMATCHED;
}

int decode_iclass_sve_int_pred_dup(context *ctx, Instruction *dec)
{
	uint32_t S=(INSWORD>>9)&1;
	if(!S && HasSME() && HasSVE2p1()) return psel_p_ppi(ctx, dec); // -> psel_p_ppi_
	if(S) UNALLOCATED(ENC_UNALLOCATED_613_SVE_INT_PRED_DUP);
	UNMATCHED;
}

int decode_iclass_sve_int_brkp(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>23)&1, S=(INSWORD>>22)&1, B=(INSWORD>>4)&1;
	if(!op && !S && !B && HasSVE() && HasSME()) return brkpa_p_p_pp(ctx, dec); // -> brkpa_p_p_pp_
	if(!op && !S && B && HasSVE() && HasSME()) return brkpb_p_p_pp(ctx, dec); // -> brkpb_p_p_pp_
	if(!op && S && !B && HasSVE() && HasSME()) return brkpas_p_p_pp(ctx, dec); // -> brkpas_p_p_pp_
	if(!op && S && B && HasSVE() && HasSME()) return brkpbs_p_p_pp(ctx, dec); // -> brkpbs_p_p_pp_
	if(op) UNALLOCATED(ENC_UNALLOCATED_614_SVE_INT_BRKP);
	UNMATCHED;
}

int decode_iclass_sve_int_while_rr_pn(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>11)&1, lt=(INSWORD>>10)&1, eq=(INSWORD>>3)&1;
	if(!U && !lt && !eq && HasSME2() && HasSVE2p1()) return whilege_pn_rr(ctx, dec); // -> whilege_pn_rr_
	if(!U && !lt && eq && HasSME2() && HasSVE2p1()) return whilegt_pn_rr(ctx, dec); // -> whilegt_pn_rr_
	if(!U && lt && !eq && HasSME2() && HasSVE2p1()) return whilelt_pn_rr(ctx, dec); // -> whilelt_pn_rr_
	if(!U && lt && eq && HasSME2() && HasSVE2p1()) return whilele_pn_rr(ctx, dec); // -> whilele_pn_rr_
	if(U && !lt && !eq && HasSME2() && HasSVE2p1()) return whilehs_pn_rr(ctx, dec); // -> whilehs_pn_rr_
	if(U && !lt && eq && HasSME2() && HasSVE2p1()) return whilehi_pn_rr(ctx, dec); // -> whilehi_pn_rr_
	if(U && lt && !eq && HasSME2() && HasSVE2p1()) return whilelo_pn_rr(ctx, dec); // -> whilelo_pn_rr_
	if(U && lt && eq && HasSME2() && HasSVE2p1()) return whilels_pn_rr(ctx, dec); // -> whilels_pn_rr_
	UNMATCHED;
}

int decode_iclass_sve_int_while_rr_pair(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>11)&1, lt=(INSWORD>>10)&1, eq=INSWORD&1;
	if(!U && !lt && !eq && HasSME2() && HasSVE2p1()) return whilege_pp_rr(ctx, dec); // -> whilege_pp_rr_
	if(!U && !lt && eq && HasSME2() && HasSVE2p1()) return whilegt_pp_rr(ctx, dec); // -> whilegt_pp_rr_
	if(!U && lt && !eq && HasSME2() && HasSVE2p1()) return whilelt_pp_rr(ctx, dec); // -> whilelt_pp_rr_
	if(!U && lt && eq && HasSME2() && HasSVE2p1()) return whilele_pp_rr(ctx, dec); // -> whilele_pp_rr_
	if(U && !lt && !eq && HasSME2() && HasSVE2p1()) return whilehs_pp_rr(ctx, dec); // -> whilehs_pp_rr_
	if(U && !lt && eq && HasSME2() && HasSVE2p1()) return whilehi_pp_rr(ctx, dec); // -> whilehi_pp_rr_
	if(U && lt && !eq && HasSME2() && HasSVE2p1()) return whilelo_pp_rr(ctx, dec); // -> whilelo_pp_rr_
	if(U && lt && eq && HasSME2() && HasSVE2p1()) return whilels_pp_rr(ctx, dec); // -> whilels_pp_rr_
	UNMATCHED;
}

int decode_iclass_sve_int_ctr_to_mask(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>8)&7;
	if((opc&6)==4 && HasSME2() && HasSVE2p1()) return pext_pp_rr(ctx, dec); // -> pext_pp_rr_
	if((opc&6)==6) UNALLOCATED(ENC_UNALLOCATED_615_SVE_INT_CTR_TO_MASK);
	if(!(opc&4) && HasSME2() && HasSVE2p1()) return pext_pn_rr(ctx, dec); // -> pext_pn_rr_
	UNMATCHED;
}

int decode_iclass_sve_int_pn_ptrue(context *ctx, Instruction *dec)
{
	return ptrue_pn_i(ctx, dec);
}

int decode_iclass_sve_int_arith_vl(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>22)&1;
	if(!op && HasSVE() && HasSME()) return addvl_r_ri(ctx, dec); // -> addvl_r_ri_
	if(op && HasSVE() && HasSME()) return addpl_r_ri(ctx, dec); // -> addpl_r_ri_
	UNMATCHED;
}

int decode_iclass_sve_int_arith_svl(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>22)&1;
	if(!op && HasSME()) return addsvl_r_ri(ctx, dec); // -> addsvl_r_ri_
	if(op && HasSME()) return addspl_r_ri(ctx, dec); // -> addspl_r_ri_
	UNMATCHED;
}

int decode_iclass_sve_int_read_vl_a(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>22)&1, opc2=(INSWORD>>16)&0x1f;
	if(!op && opc2==0x1f && HasSVE() && HasSME()) return rdvl_r_i(ctx, dec); // -> rdvl_r_i_
	if(!op && opc2!=0x1f) UNALLOCATED(ENC_UNALLOCATED_617_SVE_INT_READ_VL_A);
	if(op) UNALLOCATED(ENC_UNALLOCATED_616_SVE_INT_READ_VL_A);
	UNMATCHED;
}

int decode_iclass_sve_int_read_svl_a(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>22)&1, opc2=(INSWORD>>16)&0x1f;
	if(!op && opc2==0x1f && HasSME()) return rdsvl_r_i(ctx, dec); // -> rdsvl_r_i_
	if(!op && opc2!=0x1f) UNALLOCATED(ENC_UNALLOCATED_619_SVE_INT_READ_SVL_A);
	if(op) UNALLOCATED(ENC_UNALLOCATED_618_SVE_INT_READ_SVL_A);
	UNMATCHED;
}

int decode_iclass_sve_int_sel_vvv(context *ctx, Instruction *dec)
{
	return sel_z_p_zz(ctx, dec);
}

int decode_iclass_sve_int_wrffr(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>22)&3;
	if(!opc && HasSVE()) return wrffr_f_p(ctx, dec); // -> wrffr_f_p_
	if(opc) UNALLOCATED(ENC_UNALLOCATED_620_SVE_INT_WRFFR);
	UNMATCHED;
}

int decode_iclass_sve_int_setffr(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>22)&3;
	if(!opc && HasSVE()) return setffr_f(ctx, dec); // -> setffr_f_
	if(opc) UNALLOCATED(ENC_UNALLOCATED_621_SVE_INT_SETFFR);
	UNMATCHED;
}

int decode_iclass_sve_fp_2op_p_vd(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&3;
	if(!opc && HasSVE()) return fadda_v_p_z(ctx, dec); // -> fadda_v_p_z_
	if(opc) UNALLOCATED(ENC_UNALLOCATED_622_SVE_FP_2OP_P_VD);
	UNMATCHED;
}

int decode_iclass_sve_fp_2op_p_zds(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, opc=(INSWORD>>16)&15;
	if(!size && !opc && HasSVE_B16B16()) return bfadd_z_p_zz(ctx, dec); // -> bfadd_z_p_zz_
	if(!size && opc==1 && HasSVE_B16B16()) return bfsub_z_p_zz(ctx, dec); // -> bfsub_z_p_zz_
	if(!size && opc==2 && HasSVE_B16B16()) return bfmul_z_p_zz(ctx, dec); // -> bfmul_z_p_zz_
	if(!size && opc==4 && HasSVE_B16B16()) return bfmaxnm_z_p_zz(ctx, dec); // -> bfmaxnm_z_p_zz_
	if(!size && opc==5 && HasSVE_B16B16()) return bfminnm_z_p_zz(ctx, dec); // -> bfminnm_z_p_zz_
	if(!size && opc==6 && HasSVE_B16B16()) return bfmax_z_p_zz(ctx, dec); // -> bfmax_z_p_zz_
	if(!size && opc==7 && HasSVE_B16B16()) return bfmin_z_p_zz(ctx, dec); // -> bfmin_z_p_zz_
	if(!size && opc==9 && HasSVE_BFSCALE()) return bfscale_z_p_zz(ctx, dec); // -> bfscale_z_p_zz_
	if(size && !opc && HasSVE() && HasSME()) return fadd_z_p_zz(ctx, dec); // -> fadd_z_p_zz_
	if(size && opc==1 && HasSVE() && HasSME()) return fsub_z_p_zz(ctx, dec); // -> fsub_z_p_zz_
	if(size && opc==2 && HasSVE() && HasSME()) return fmul_z_p_zz(ctx, dec); // -> fmul_z_p_zz_
	if(size && opc==4 && HasSVE() && HasSME()) return fmaxnm_z_p_zz(ctx, dec); // -> fmaxnm_z_p_zz_
	if(size && opc==5 && HasSVE() && HasSME()) return fminnm_z_p_zz(ctx, dec); // -> fminnm_z_p_zz_
	if(size && opc==6 && HasSVE() && HasSME()) return fmax_z_p_zz(ctx, dec); // -> fmax_z_p_zz_
	if(size && opc==7 && HasSVE() && HasSME()) return fmin_z_p_zz(ctx, dec); // -> fmin_z_p_zz_
	if(size && opc==9 && HasSVE() && HasSME()) return fscale_z_p_zz(ctx, dec); // -> fscale_z_p_zz_
	if(opc==3 && HasSVE() && HasSME()) return fsubr_z_p_zz(ctx, dec); // -> fsubr_z_p_zz_
	if(opc==8 && HasSVE() && HasSME()) return fabd_z_p_zz(ctx, dec); // -> fabd_z_p_zz_
	if(opc==10 && HasSVE() && HasSME()) return fmulx_z_p_zz(ctx, dec); // -> fmulx_z_p_zz_
	if(opc==11) UNALLOCATED(ENC_UNALLOCATED_623_SVE_FP_2OP_P_ZDS);
	if(opc==12 && HasSVE() && HasSME()) return fdivr_z_p_zz(ctx, dec); // -> fdivr_z_p_zz_
	if(opc==13 && HasSVE() && HasSME()) return fdiv_z_p_zz(ctx, dec); // -> fdiv_z_p_zz_
	if(opc==14 && HasSVE2() && HasFAMINMAX() && HasSME2() && HasFAMINMAX()) return famax_z_p_zz(ctx, dec); // -> famax_z_p_zz_
	if(opc==15 && HasSVE2() && HasFAMINMAX() && HasSME2() && HasFAMINMAX()) return famin_z_p_zz(ctx, dec); // -> famin_z_p_zz_
	UNMATCHED;
}

int decode_iclass_sve_fp_ftmad(context *ctx, Instruction *dec)
{
	return ftmad_z_zzi(ctx, dec);
}

int decode_iclass_sve_fp_2op_i_p_zds(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&7;
	if(!opc && HasSVE() && HasSME()) return fadd_z_p_zs(ctx, dec); // -> fadd_z_p_zs_
	if(opc==1 && HasSVE() && HasSME()) return fsub_z_p_zs(ctx, dec); // -> fsub_z_p_zs_
	if(opc==2 && HasSVE() && HasSME()) return fmul_z_p_zs(ctx, dec); // -> fmul_z_p_zs_
	if(opc==3 && HasSVE() && HasSME()) return fsubr_z_p_zs(ctx, dec); // -> fsubr_z_p_zs_
	if(opc==4 && HasSVE() && HasSME()) return fmaxnm_z_p_zs(ctx, dec); // -> fmaxnm_z_p_zs_
	if(opc==5 && HasSVE() && HasSME()) return fminnm_z_p_zs(ctx, dec); // -> fminnm_z_p_zs_
	if(opc==6 && HasSVE() && HasSME()) return fmax_z_p_zs(ctx, dec); // -> fmax_z_p_zs_
	if(opc==7 && HasSVE() && HasSME()) return fmin_z_p_zs(ctx, dec); // -> fmin_z_p_zs_
	UNMATCHED;
}

int decode_iclass_sve_fp_3op_u_zd(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, opc=(INSWORD>>10)&7;
	if(!size && !opc && HasSVE_B16B16()) return bfadd_z_zz(ctx, dec); // -> bfadd_z_zz_
	if(!size && opc==1 && HasSVE_B16B16()) return bfsub_z_zz(ctx, dec); // -> bfsub_z_zz_
	if(!size && opc==2 && HasSVE_B16B16()) return bfmul_z_zz(ctx, dec); // -> bfmul_z_zz_
	if(size && !opc && HasSVE() && HasSME()) return fadd_z_zz(ctx, dec); // -> fadd_z_zz_
	if(size && opc==1 && HasSVE() && HasSME()) return fsub_z_zz(ctx, dec); // -> fsub_z_zz_
	if(size && opc==2 && HasSVE() && HasSME()) return fmul_z_zz(ctx, dec); // -> fmul_z_zz_
	if(opc==3 && HasSVE()) return ftsmul_z_zz(ctx, dec); // -> ftsmul_z_zz_
	if(opc==6 && HasSVE() && HasSME()) return frecps_z_zz(ctx, dec); // -> frecps_z_zz_
	if(opc==7 && HasSVE() && HasSME()) return frsqrts_z_zz(ctx, dec); // -> frsqrts_z_zz_
	if((opc&6)==4) UNALLOCATED(ENC_UNALLOCATED_624_SVE_FP_3OP_U_ZD);
	UNMATCHED;
}

int decode_iclass_sve_fp_3op_p_pd(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>15)&1, o2=(INSWORD>>13)&1, o3=(INSWORD>>4)&1;
	if(!op && !o2 && !o3 && HasSVE() && HasSME()) return fcmeq_p_p_zz(ctx, dec); // -> fcmge_p_p_zz_
	if(!op && !o2 && o3 && HasSVE() && HasSME()) return fcmeq_p_p_zz(ctx, dec); // -> fcmgt_p_p_zz_
	if(!op && o2 && !o3 && HasSVE() && HasSME()) return fcmeq_p_p_zz(ctx, dec); // -> fcmeq_p_p_zz_
	if(!op && o2 && o3 && HasSVE() && HasSME()) return fcmeq_p_p_zz(ctx, dec); // -> fcmne_p_p_zz_
	if(op && !o2 && !o3 && HasSVE() && HasSME()) return fcmeq_p_p_zz(ctx, dec); // -> fcmuo_p_p_zz_
	if(op && !o2 && o3 && HasSVE() && HasSME()) return facge_p_p_zz(ctx, dec); // -> facge_p_p_zz_
	if(op && o2 && !o3) UNALLOCATED(ENC_UNALLOCATED_625_SVE_FP_3OP_P_PD);
	if(op && o2 && o3 && HasSVE() && HasSME()) return facge_p_p_zz(ctx, dec); // -> facgt_p_p_zz_
	UNMATCHED;
}

int decode_iclass_sve_fp_2op_p_pd(context *ctx, Instruction *dec)
{
	uint32_t eq=(INSWORD>>17)&1, lt=(INSWORD>>16)&1, ne=(INSWORD>>4)&1;
	if(!eq && !lt && !ne && HasSVE() && HasSME()) return fcmeq_p_p_z0(ctx, dec); // -> fcmge_p_p_z0_
	if(!eq && !lt && ne && HasSVE() && HasSME()) return fcmeq_p_p_z0(ctx, dec); // -> fcmgt_p_p_z0_
	if(!eq && lt && !ne && HasSVE() && HasSME()) return fcmeq_p_p_z0(ctx, dec); // -> fcmlt_p_p_z0_
	if(!eq && lt && ne && HasSVE() && HasSME()) return fcmeq_p_p_z0(ctx, dec); // -> fcmle_p_p_z0_
	if(eq && !lt && !ne && HasSVE() && HasSME()) return fcmeq_p_p_z0(ctx, dec); // -> fcmeq_p_p_z0_
	if(eq && lt && !ne && HasSVE() && HasSME()) return fcmeq_p_p_z0(ctx, dec); // -> fcmne_p_p_z0_
	if(eq && ne) UNALLOCATED(ENC_UNALLOCATED_626_SVE_FP_2OP_P_PD);
	UNMATCHED;
}

int decode_iclass_sve_fp_fcadd(context *ctx, Instruction *dec)
{
	return fcadd_z_p_zz(ctx, dec);
}

int decode_iclass_sve_fp_fcmla_by_indexed_elem(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3;
	if(size==2 && HasSVE() && HasSME()) return fcmla_z_zzzi(ctx, dec); // -> fcmla_z_zzzi_h
	if(size==3 && HasSVE() && HasSME()) return fcmla_z_zzzi(ctx, dec); // -> fcmla_z_zzzi_s
	if(!(size&2)) UNALLOCATED(ENC_UNALLOCATED_627_SVE_FP_FCMLA_BY_INDEXED_ELEM);
	UNMATCHED;
}

int decode_iclass_sve_fp_fcmla(context *ctx, Instruction *dec)
{
	return fcmla_z_p_zzz(ctx, dec);
}

int decode_iclass_sve_fp_fcvt2z(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>22)&3, opc2=(INSWORD>>16)&3;
	if(!opc && opc2==2 && HasSVE2p2() && HasSME2p2()) return fcvtxnt_z_p_z(ctx, dec); // -> fcvtxnt_z_p_z_d2sz
	if(opc==2 && !opc2 && HasSVE2p2() && HasSME2p2()) return fcvtnt_z_p_z(ctx, dec); // -> fcvtnt_z_p_z_s2hz
	if(opc==2 && opc2==1 && HasSVE2p2() && HasSME2p2()) return fcvtlt_z_p_z(ctx, dec); // -> fcvtlt_z_p_z_h2sz
	if(opc==2 && opc2==2 && HasSVE2p2() && HasSME2p2()) return bfcvtnt_z_p_z(ctx, dec); // -> bfcvtnt_z_p_z_s2bfz
	if(opc==3 && opc2==2 && HasSVE2p2() && HasSME2p2()) return fcvtnt_z_p_z(ctx, dec); // -> fcvtnt_z_p_z_d2sz
	if(opc==3 && opc2==3 && HasSVE2p2() && HasSME2p2()) return fcvtlt_z_p_z(ctx, dec); // -> fcvtlt_z_p_z_s2dz
	if(!(opc&1) && opc2==3) UNALLOCATED(ENC_UNALLOCATED_631_SVE_FP_FCVT2Z);
	if(!opc && !(opc2&2)) UNALLOCATED(ENC_UNALLOCATED_629_SVE_FP_FCVT2Z);
	if(opc==3 && !(opc2&2)) UNALLOCATED(ENC_UNALLOCATED_630_SVE_FP_FCVT2Z);
	if(opc==1) UNALLOCATED(ENC_UNALLOCATED_628_SVE_FP_FCVT2Z);
	UNMATCHED;
}

int decode_iclass_sve_fp_fcvt2(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>22)&3, opc2=(INSWORD>>16)&3;
	if(!opc && opc2==2 && HasSVE2() && HasSME()) return fcvtxnt_z_p_z(ctx, dec); // -> fcvtxnt_z_p_z_d2s
	if(opc==2 && !opc2 && HasSVE2() && HasSME()) return fcvtnt_z_p_z(ctx, dec); // -> fcvtnt_z_p_z_s2h
	if(opc==2 && opc2==1 && HasSVE2() && HasSME()) return fcvtlt_z_p_z(ctx, dec); // -> fcvtlt_z_p_z_h2s
	if(opc==2 && opc2==2 && HasSVE() && HasBF16() && HasSME() && HasBF16()) return bfcvtnt_z_p_z(ctx, dec); // -> bfcvtnt_z_p_z_s2bf
	if(opc==3 && opc2==2 && HasSVE2() && HasSME()) return fcvtnt_z_p_z(ctx, dec); // -> fcvtnt_z_p_z_d2s
	if(opc==3 && opc2==3 && HasSVE2() && HasSME()) return fcvtlt_z_p_z(ctx, dec); // -> fcvtlt_z_p_z_s2d
	if(!(opc&1) && opc2==3) UNALLOCATED(ENC_UNALLOCATED_635_SVE_FP_FCVT2);
	if(!opc && !(opc2&2)) UNALLOCATED(ENC_UNALLOCATED_633_SVE_FP_FCVT2);
	if(opc==3 && !(opc2&2)) UNALLOCATED(ENC_UNALLOCATED_634_SVE_FP_FCVT2);
	if(opc==1) UNALLOCATED(ENC_UNALLOCATED_632_SVE_FP_FCVT2);
	UNMATCHED;
}

int decode_iclass_sve_fp_fast_red(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&7;
	if(!opc && HasSVE() && HasSME()) return faddv_v_p_z(ctx, dec); // -> faddv_v_p_z_
	if(opc==1) UNALLOCATED(ENC_UNALLOCATED_637_SVE_FP_FAST_RED);
	if(opc==4 && HasSVE() && HasSME()) return fmaxnmv_v_p_z(ctx, dec); // -> fmaxnmv_v_p_z_
	if(opc==5 && HasSVE() && HasSME()) return fminnmv_v_p_z(ctx, dec); // -> fminnmv_v_p_z_
	if(opc==6 && HasSVE() && HasSME()) return fmaxv_v_p_z(ctx, dec); // -> fmaxv_v_p_z_
	if(opc==7 && HasSVE() && HasSME()) return fminv_v_p_z(ctx, dec); // -> fminv_v_p_z_
	if((opc&6)==2) UNALLOCATED(ENC_UNALLOCATED_636_SVE_FP_FAST_RED);
	UNMATCHED;
}

int decode_iclass_sve_fp_fast_redq(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&7;
	if(!opc && HasSVE2p1() && HasSME2p1()) return faddqv_z_p_z(ctx, dec); // -> faddqv_z_p_z_
	if(opc==1) UNALLOCATED(ENC_UNALLOCATED_639_SVE_FP_FAST_REDQ);
	if(opc==4 && HasSVE2p1() && HasSME2p1()) return fmaxnmqv_z_p_z(ctx, dec); // -> fmaxnmqv_z_p_z_
	if(opc==5 && HasSVE2p1() && HasSME2p1()) return fminnmqv_z_p_z(ctx, dec); // -> fminnmqv_z_p_z_
	if(opc==6 && HasSVE2p1() && HasSME2p1()) return fmaxqv_z_p_z(ctx, dec); // -> fmaxqv_z_p_z_
	if(opc==7 && HasSVE2p1() && HasSME2p1()) return fminqv_z_p_z(ctx, dec); // -> fminqv_z_p_z_
	if((opc&6)==2) UNALLOCATED(ENC_UNALLOCATED_638_SVE_FP_FAST_REDQ);
	UNMATCHED;
}

int decode_iclass_sve_fp_fmmla(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>22)&3;
	if(!opc && HasSVE_F16F32MM()) return fmmla_z32_zzz(ctx, dec); // -> fmmla_z32_zzz_h
	if(opc==1 && HasSVE() && HasBF16()) return bfmmla_z_zzz(ctx, dec); // -> bfmmla_z_zzz_
	if(opc==2 && HasF32MM()) return fmmla_z_zzz(ctx, dec); // -> fmmla_z_zzz_s
	if(opc==3 && HasF64MM()) return fmmla_z_zzz(ctx, dec); // -> fmmla_z_zzz_d
	UNMATCHED;
}

int decode_iclass_sve_fp_fmul_by_indexed_elem(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, o2=(INSWORD>>11)&1;
	if(size==2 && !o2 && HasSVE() && HasSME()) return fmul_z_zzi(ctx, dec); // -> fmul_z_zzi_s
	if(size==3 && !o2 && HasSVE() && HasSME()) return fmul_z_zzi(ctx, dec); // -> fmul_z_zzi_d
	if(!(size&2) && !o2 && HasSVE() && HasSME()) return fmul_z_zzi(ctx, dec); // -> fmul_z_zzi_h
	if(!(size&2) && o2 && HasSVE_B16B16()) return bfmul_z_zzi(ctx, dec); // -> bfmul_z_zzi_h
	if((size&2)==2 && o2) UNALLOCATED(ENC_UNALLOCATED_640_SVE_FP_FMUL_BY_INDEXED_ELEM);
	UNMATCHED;
}

int decode_iclass_sve_fp_3op_p_zds_a(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, opc=(INSWORD>>13)&3;
	if(!size && !opc && HasSVE_B16B16()) return bfmla_z_p_zzz(ctx, dec); // -> bfmla_z_p_zzz_
	if(!size && opc==1 && HasSVE_B16B16()) return bfmls_z_p_zzz(ctx, dec); // -> bfmls_z_p_zzz_
	if(size && !opc && HasSVE() && HasSME()) return fmla_z_p_zzz(ctx, dec); // -> fmla_z_p_zzz_
	if(size && opc==1 && HasSVE() && HasSME()) return fmls_z_p_zzz(ctx, dec); // -> fmls_z_p_zzz_
	if(size && opc==2 && HasSVE() && HasSME()) return fnmla_z_p_zzz(ctx, dec); // -> fnmla_z_p_zzz_
	if(size && opc==3 && HasSVE() && HasSME()) return fnmls_z_p_zzz(ctx, dec); // -> fnmls_z_p_zzz_
	if(!size && (opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_641_SVE_FP_3OP_P_ZDS_A);
	UNMATCHED;
}

int decode_iclass_sve_fp_3op_p_zds_b(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>13)&3;
	if(!opc && HasSVE() && HasSME()) return fmad_z_p_zzz(ctx, dec); // -> fmad_z_p_zzz_
	if(opc==1 && HasSVE() && HasSME()) return fmsb_z_p_zzz(ctx, dec); // -> fmsb_z_p_zzz_
	if(opc==2 && HasSVE() && HasSME()) return fnmad_z_p_zzz(ctx, dec); // -> fnmad_z_p_zzz_
	if(opc==3 && HasSVE() && HasSME()) return fnmsb_z_p_zzz(ctx, dec); // -> fnmsb_z_p_zzz_
	UNMATCHED;
}

int decode_iclass_sve_fp_fma_by_indexed_elem(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, o2=(INSWORD>>11)&1, op=(INSWORD>>10)&1;
	if(size==2 && !o2 && !op && HasSVE() && HasSME()) return fmla_z_zzzi(ctx, dec); // -> fmla_z_zzzi_s
	if(size==2 && !o2 && op && HasSVE() && HasSME()) return fmls_z_zzzi(ctx, dec); // -> fmls_z_zzzi_s
	if(size==3 && !o2 && !op && HasSVE() && HasSME()) return fmla_z_zzzi(ctx, dec); // -> fmla_z_zzzi_d
	if(size==3 && !o2 && op && HasSVE() && HasSME()) return fmls_z_zzzi(ctx, dec); // -> fmls_z_zzzi_d
	if(!(size&2) && !o2 && !op && HasSVE() && HasSME()) return fmla_z_zzzi(ctx, dec); // -> fmla_z_zzzi_h
	if(!(size&2) && !o2 && op && HasSVE() && HasSME()) return fmls_z_zzzi(ctx, dec); // -> fmls_z_zzzi_h
	if(!(size&2) && o2 && !op && HasSVE_B16B16()) return bfmla_z_zzzi(ctx, dec); // -> bfmla_z_zzzi_h
	if(!(size&2) && o2 && op && HasSVE_B16B16()) return bfmls_z_zzzi(ctx, dec); // -> bfmls_z_zzzi_h
	if((size&2)==2 && o2) UNALLOCATED(ENC_UNALLOCATED_642_SVE_FP_FMA_BY_INDEXED_ELEM);
	UNMATCHED;
}

int decode_iclass_sve_fp_2op_p_zd_a(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&7;
	if(!opc && HasSVE() && HasSME()) return frinta_z_p_z(ctx, dec); // -> frintn_z_p_z_m
	if(opc==1 && HasSVE() && HasSME()) return frinta_z_p_z(ctx, dec); // -> frintp_z_p_z_m
	if(opc==2 && HasSVE() && HasSME()) return frinta_z_p_z(ctx, dec); // -> frintm_z_p_z_m
	if(opc==3 && HasSVE() && HasSME()) return frinta_z_p_z(ctx, dec); // -> frintz_z_p_z_m
	if(opc==4 && HasSVE() && HasSME()) return frinta_z_p_z(ctx, dec); // -> frinta_z_p_z_m
	if(opc==5) UNALLOCATED(ENC_UNALLOCATED_643_SVE_FP_2OP_P_ZD_A);
	if(opc==6 && HasSVE() && HasSME()) return frinta_z_p_z(ctx, dec); // -> frintx_z_p_z_m
	if(opc==7 && HasSVE() && HasSME()) return frinta_z_p_z(ctx, dec); // -> frinti_z_p_z_m
	UNMATCHED;
}

int decode_iclass_sve_fp_2op_p_zd_b_0(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>22)&3, opc2=(INSWORD>>16)&3;
	if(!opc && opc2==2 && HasSVE2() && HasSME()) return fcvtx_z_p_z(ctx, dec); // -> fcvtx_z_p_z_d2s
	if(opc==2 && !opc2 && HasSVE() && HasSME()) return fcvt_z_p_z(ctx, dec); // -> fcvt_z_p_z_s2h
	if(opc==2 && opc2==1 && HasSVE() && HasSME()) return fcvt_z_p_z(ctx, dec); // -> fcvt_z_p_z_h2s
	if(opc==2 && opc2==2 && HasSVE() && HasBF16() && HasSME() && HasBF16()) return bfcvt_z_p_z(ctx, dec); // -> bfcvt_z_p_z_s2bf
	if(opc==3 && !opc2 && HasSVE() && HasSME()) return fcvt_z_p_z(ctx, dec); // -> fcvt_z_p_z_d2h
	if(opc==3 && opc2==1 && HasSVE() && HasSME()) return fcvt_z_p_z(ctx, dec); // -> fcvt_z_p_z_h2d
	if(opc==3 && opc2==2 && HasSVE() && HasSME()) return fcvt_z_p_z(ctx, dec); // -> fcvt_z_p_z_d2s
	if(opc==3 && opc2==3 && HasSVE() && HasSME()) return fcvt_z_p_z(ctx, dec); // -> fcvt_z_p_z_s2d
	if(!(opc&1) && opc2==3) UNALLOCATED(ENC_UNALLOCATED_646_SVE_FP_2OP_P_ZD_B_0);
	if(!opc && !(opc2&2)) UNALLOCATED(ENC_UNALLOCATED_645_SVE_FP_2OP_P_ZD_B_0);
	if(opc==1) UNALLOCATED(ENC_UNALLOCATED_644_SVE_FP_2OP_P_ZD_B_0);
	UNMATCHED;
}

int decode_iclass_sve_fp_2op_p_zd_b_1(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&3;
	if(!opc && HasSVE() && HasSME()) return frecpx_z_p_z(ctx, dec); // -> frecpx_z_p_z_m
	if(opc==1 && HasSVE() && HasSME()) return fsqrt_z_p_z(ctx, dec); // -> fsqrt_z_p_z_m
	if((opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_647_SVE_FP_2OP_P_ZD_B_1);
	UNMATCHED;
}

int decode_iclass_sve_fp_2op_p_zd_c(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>22)&3, opc2=(INSWORD>>17)&3, U=(INSWORD>>16)&1;
	if(opc==1 && opc2==1 && !U && HasSVE() && HasSME()) return scvtf_z_p_z(ctx, dec); // -> scvtf_z_p_z_h2fp16
	if(opc==1 && opc2==1 && U && HasSVE() && HasSME()) return ucvtf_z_p_z(ctx, dec); // -> ucvtf_z_p_z_h2fp16
	if(opc==1 && opc2==2 && !U && HasSVE() && HasSME()) return scvtf_z_p_z(ctx, dec); // -> scvtf_z_p_z_w2fp16
	if(opc==1 && opc2==2 && U && HasSVE() && HasSME()) return ucvtf_z_p_z(ctx, dec); // -> ucvtf_z_p_z_w2fp16
	if(opc==1 && opc2==3 && !U && HasSVE() && HasSME()) return scvtf_z_p_z(ctx, dec); // -> scvtf_z_p_z_x2fp16
	if(opc==1 && opc2==3 && U && HasSVE() && HasSME()) return ucvtf_z_p_z(ctx, dec); // -> ucvtf_z_p_z_x2fp16
	if(opc==2 && opc2==2 && !U && HasSVE() && HasSME()) return scvtf_z_p_z(ctx, dec); // -> scvtf_z_p_z_w2s
	if(opc==2 && opc2==2 && U && HasSVE() && HasSME()) return ucvtf_z_p_z(ctx, dec); // -> ucvtf_z_p_z_w2s
	if(opc==3 && !opc2 && !U && HasSVE() && HasSME()) return scvtf_z_p_z(ctx, dec); // -> scvtf_z_p_z_w2d
	if(opc==3 && !opc2 && U && HasSVE() && HasSME()) return ucvtf_z_p_z(ctx, dec); // -> ucvtf_z_p_z_w2d
	if(opc==3 && opc2==2 && !U && HasSVE() && HasSME()) return scvtf_z_p_z(ctx, dec); // -> scvtf_z_p_z_x2s
	if(opc==3 && opc2==2 && U && HasSVE() && HasSME()) return ucvtf_z_p_z(ctx, dec); // -> ucvtf_z_p_z_x2s
	if(opc==3 && opc2==3 && !U && HasSVE() && HasSME()) return scvtf_z_p_z(ctx, dec); // -> scvtf_z_p_z_x2d
	if(opc==3 && opc2==3 && U && HasSVE() && HasSME()) return ucvtf_z_p_z(ctx, dec); // -> ucvtf_z_p_z_x2d
	if(!opc && !(opc2&2) && !U && HasSVE2p2() && HasSME2p2()) return frint32z_z_p_z(ctx, dec); // -> frint32z_z_p_z_m
	if(!opc && !(opc2&2) && U && HasSVE2p2() && HasSME2p2()) return frint32x_z_p_z(ctx, dec); // -> frint32x_z_p_z_m
	if(!opc && (opc2&2)==2 && !U && HasSVE2p2() && HasSME2p2()) return frint64z_z_p_z(ctx, dec); // -> frint64z_z_p_z_m
	if(!opc && (opc2&2)==2 && U && HasSVE2p2() && HasSME2p2()) return frint64x_z_p_z(ctx, dec); // -> frint64x_z_p_z_m
	if(opc==1 && !opc2) UNALLOCATED(ENC_UNALLOCATED_649_SVE_FP_2OP_P_ZD_C);
	if(opc==2 && opc2!=2) UNALLOCATED(ENC_UNALLOCATED_648_SVE_FP_2OP_P_ZD_C);
	if(opc==3 && opc2==1) UNALLOCATED(ENC_UNALLOCATED_650_SVE_FP_2OP_P_ZD_C);
	UNMATCHED;
}

int decode_iclass_sve_fp_2op_p_zd_d(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>22)&3, opc2=(INSWORD>>17)&3, U=(INSWORD>>16)&1;
	if(opc==1 && opc2==1 && !U && HasSVE() && HasSME()) return fcvtzs_z_p_z(ctx, dec); // -> fcvtzs_z_p_z_fp162h
	if(opc==1 && opc2==1 && U && HasSVE() && HasSME()) return fcvtzu_z_p_z(ctx, dec); // -> fcvtzu_z_p_z_fp162h
	if(opc==1 && opc2==2 && !U && HasSVE() && HasSME()) return fcvtzs_z_p_z(ctx, dec); // -> fcvtzs_z_p_z_fp162w
	if(opc==1 && opc2==2 && U && HasSVE() && HasSME()) return fcvtzu_z_p_z(ctx, dec); // -> fcvtzu_z_p_z_fp162w
	if(opc==1 && opc2==3 && !U && HasSVE() && HasSME()) return fcvtzs_z_p_z(ctx, dec); // -> fcvtzs_z_p_z_fp162x
	if(opc==1 && opc2==3 && U && HasSVE() && HasSME()) return fcvtzu_z_p_z(ctx, dec); // -> fcvtzu_z_p_z_fp162x
	if(opc==2 && opc2==2 && !U && HasSVE() && HasSME()) return fcvtzs_z_p_z(ctx, dec); // -> fcvtzs_z_p_z_s2w
	if(opc==2 && opc2==2 && U && HasSVE() && HasSME()) return fcvtzu_z_p_z(ctx, dec); // -> fcvtzu_z_p_z_s2w
	if(opc==3 && !opc2 && !U && HasSVE() && HasSME()) return fcvtzs_z_p_z(ctx, dec); // -> fcvtzs_z_p_z_d2w
	if(opc==3 && !opc2 && U && HasSVE() && HasSME()) return fcvtzu_z_p_z(ctx, dec); // -> fcvtzu_z_p_z_d2w
	if(opc==3 && opc2==2 && !U && HasSVE() && HasSME()) return fcvtzs_z_p_z(ctx, dec); // -> fcvtzs_z_p_z_s2x
	if(opc==3 && opc2==2 && U && HasSVE() && HasSME()) return fcvtzu_z_p_z(ctx, dec); // -> fcvtzu_z_p_z_s2x
	if(opc==3 && opc2==3 && !U && HasSVE() && HasSME()) return fcvtzs_z_p_z(ctx, dec); // -> fcvtzs_z_p_z_d2x
	if(opc==3 && opc2==3 && U && HasSVE() && HasSME()) return fcvtzu_z_p_z(ctx, dec); // -> fcvtzu_z_p_z_d2x
	if(opc==1 && !opc2) UNALLOCATED(ENC_UNALLOCATED_653_SVE_FP_2OP_P_ZD_D);
	if(opc==2 && opc2!=2) UNALLOCATED(ENC_UNALLOCATED_652_SVE_FP_2OP_P_ZD_D);
	if(opc==3 && opc2==1) UNALLOCATED(ENC_UNALLOCATED_654_SVE_FP_2OP_P_ZD_D);
	if(!opc && !U && HasSVE2() && HasSME()) return flogb_z_p_z(ctx, dec); // -> flogb_z_p_z_m
	if(!opc && U) UNALLOCATED(ENC_UNALLOCATED_651_SVE_FP_2OP_P_ZD_D);
	UNMATCHED;
}

int decode_iclass_sve_fp8_fcvt_wide(context *ctx, Instruction *dec)
{
	uint32_t L=(INSWORD>>16)&1, opc=(INSWORD>>10)&3;
	if(!L && !opc && HasSVE2() && HasFP8() && HasSME2() && HasFP8()) return f1cvt_z_z8(ctx, dec); // -> f1cvt_z_z8_b2h
	if(!L && opc==1 && HasSVE2() && HasFP8() && HasSME2() && HasFP8()) return f1cvt_z_z8(ctx, dec); // -> f2cvt_z_z8_b2h
	if(!L && opc==2 && HasSVE2() && HasFP8() && HasSME2() && HasFP8()) return bf1cvt_z_z8(ctx, dec); // -> bf1cvt_z_z8_b2bf
	if(!L && opc==3 && HasSVE2() && HasFP8() && HasSME2() && HasFP8()) return bf1cvt_z_z8(ctx, dec); // -> bf2cvt_z_z8_b2bf
	if(L && !opc && HasSVE2() && HasFP8() && HasSME2() && HasFP8()) return f1cvtlt_z_z8(ctx, dec); // -> f1cvtlt_z_z8_b2h
	if(L && opc==1 && HasSVE2() && HasFP8() && HasSME2() && HasFP8()) return f1cvtlt_z_z8(ctx, dec); // -> f2cvtlt_z_z8_b2h
	if(L && opc==2 && HasSVE2() && HasFP8() && HasSME2() && HasFP8()) return bf1cvtlt_z_z8(ctx, dec); // -> bf1cvtlt_z_z8_b2bf
	if(L && opc==3 && HasSVE2() && HasFP8() && HasSME2() && HasFP8()) return bf1cvtlt_z_z8(ctx, dec); // -> bf2cvtlt_z_z8_b2bf
	UNMATCHED;
}

int decode_iclass_sve_fp8_fcvt_narrow(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>10)&3;
	if(!opc && HasSVE2() && HasFP8() && HasSME2() && HasFP8()) return fcvtn_z8_mz2(ctx, dec); // -> fcvtn_z8_mz2_h2b
	if(opc==1 && HasSVE2() && HasFP8() && HasSME2() && HasFP8()) return fcvtnb_z8_mz2(ctx, dec); // -> fcvtnb_z8_mz2_s2b
	if(opc==2 && HasSVE2() && HasFP8() && HasSME2() && HasFP8()) return bfcvtn_z8_mz2(ctx, dec); // -> bfcvtn_z8_mz2_bf2b
	if(opc==3 && HasSVE2() && HasFP8() && HasSME2() && HasFP8()) return fcvtnt_z8_mz2(ctx, dec); // -> fcvtnt_z8_mz2_s2b
	UNMATCHED;
}

int decode_iclass_sve_fp_ucvtf_wide(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>10)&3;
	if(!opc && HasSVE2p3() && HasSME2p3()) return scvtf_z_z(ctx, dec); // -> scvtf_z_z_
	if(opc==1 && HasSVE2p3() && HasSME2p3()) return ucvtf_z_z(ctx, dec); // -> ucvtf_z_z_
	if(opc==2 && HasSVE2p3() && HasSME2p3()) return scvtflt_z_z(ctx, dec); // -> scvtflt_z_z_
	if(opc==3 && HasSVE2p3() && HasSME2p3()) return ucvtflt_z_z(ctx, dec); // -> ucvtflt_z_z_
	UNMATCHED;
}

int decode_iclass_sve_fp_fcvtzu_narrow(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>10)&1;
	if(!op && HasSVE2p3() && HasSME2p3()) return fcvtzsn_z_mz2(ctx, dec); // -> fcvtzsn_z_mz2_
	if(op && HasSVE2p3() && HasSME2p3()) return fcvtzun_z_mz2(ctx, dec); // -> fcvtzun_z_mz2_
	UNMATCHED;
}

int decode_iclass_sve_fp_2op_u_zd(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>16)&1;
	if(!op && HasSVE() && HasSME()) return frecpe_z_z(ctx, dec); // -> frecpe_z_z_
	if(op && HasSVE() && HasSME()) return frsqrte_z_z(ctx, dec); // -> frsqrte_z_z_
	UNMATCHED;
}

int decode_iclass_sve_fp_fdot(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>22)&1, o2=(INSWORD>>10)&1;
	if(!op && !o2 && HasSME2() && HasSVE2p1()) return fdot_z_zzz(ctx, dec); // -> fdot_z_zzz_
	if(!op && o2 && HasSSVE_FP8DOT2() && HasSVE2() && HasFP8DOT2()) return fdot_z_zz8z8(ctx, dec); // -> fdot_z_zz8z8_
	if(op && !o2 && HasSVE() && HasBF16() && HasSME() && HasBF16()) return bfdot_z_zzz(ctx, dec); // -> bfdot_z_zzz_
	if(op && o2 && HasSSVE_FP8DOT4() && HasSVE2() && HasFP8DOT4()) return fdot_z32_zz8z8(ctx, dec); // -> fdot_z32_zz8z8_
	UNMATCHED;
}

int decode_iclass_sve_fp_fma_long(context *ctx, Instruction *dec)
{
	uint32_t o2=(INSWORD>>22)&1, op=(INSWORD>>13)&1, T=(INSWORD>>10)&1;
	if(!o2 && !op && !T && HasSVE2() && HasSME()) return fmlalb_z_zzz(ctx, dec); // -> fmlalb_z_zzz_
	if(!o2 && !op && T && HasSVE2() && HasSME()) return fmlalt_z_zzz(ctx, dec); // -> fmlalt_z_zzz_
	if(!o2 && op && !T && HasSVE2() && HasSME()) return fmlslb_z_zzz(ctx, dec); // -> fmlslb_z_zzz_
	if(!o2 && op && T && HasSVE2() && HasSME()) return fmlslt_z_zzz(ctx, dec); // -> fmlslt_z_zzz_
	if(o2 && !op && !T && HasSVE() && HasBF16() && HasSME() && HasBF16()) return bfmlalb_z_zzz(ctx, dec); // -> bfmlalb_z_zzz_
	if(o2 && !op && T && HasSVE() && HasBF16() && HasSME() && HasBF16()) return bfmlalt_z_zzz(ctx, dec); // -> bfmlalt_z_zzz_
	if(o2 && op && !T && HasSME2() && HasSVE2p1()) return bfmlslb_z_zzz(ctx, dec); // -> bfmlslb_z_zzz_
	if(o2 && op && T && HasSME2() && HasSVE2p1()) return bfmlslt_z_zzz(ctx, dec); // -> bfmlslt_z_zzz_
	UNMATCHED;
}

int decode_iclass_sve_fp_fdot_by_indexed_elem(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>22)&1, opc2=(INSWORD>>10)&3;
	if(!op && !opc2 && HasSME2() && HasSVE2p1()) return fdot_z_zzzi(ctx, dec); // -> fdot_z_zzzi_
	if(!op && opc2==2) UNALLOCATED(ENC_UNALLOCATED_656_SVE_FP_FDOT_BY_INDEXED_ELEM);
	if(op && !opc2 && HasSVE() && HasBF16() && HasSME() && HasBF16()) return bfdot_z_zzzi(ctx, dec); // -> bfdot_z_zzzi_
	if(op && opc2==1 && HasSSVE_FP8DOT4() && HasSVE2() && HasFP8DOT4()) return fdot_z32_zz8z8i(ctx, dec); // -> fdot_z32_zz8z8i_
	if(!op && opc2&1 && HasSSVE_FP8DOT2() && HasSVE2() && HasFP8DOT2()) return fdot_z_zz8z8i(ctx, dec); // -> fdot_z_zz8z8i_
	if(op && (opc2&2)==2) UNALLOCATED(ENC_UNALLOCATED_655_SVE_FP_FDOT_BY_INDEXED_ELEM);
	UNMATCHED;
}

int decode_iclass_sve_fp_fma_long_by_indexed_elem(context *ctx, Instruction *dec)
{
	uint32_t o2=(INSWORD>>22)&1, op=(INSWORD>>13)&1, T=(INSWORD>>10)&1;
	if(!o2 && !op && !T && HasSVE2() && HasSME()) return fmlalb_z_zzzi(ctx, dec); // -> fmlalb_z_zzzi_s
	if(!o2 && !op && T && HasSVE2() && HasSME()) return fmlalt_z_zzzi(ctx, dec); // -> fmlalt_z_zzzi_s
	if(!o2 && op && !T && HasSVE2() && HasSME()) return fmlslb_z_zzzi(ctx, dec); // -> fmlslb_z_zzzi_s
	if(!o2 && op && T && HasSVE2() && HasSME()) return fmlslt_z_zzzi(ctx, dec); // -> fmlslt_z_zzzi_s
	if(o2 && !op && !T && HasSVE() && HasBF16() && HasSME() && HasBF16()) return bfmlalb_z_zzzi(ctx, dec); // -> bfmlalb_z_zzzi_
	if(o2 && !op && T && HasSVE() && HasBF16() && HasSME() && HasBF16()) return bfmlalt_z_zzzi(ctx, dec); // -> bfmlalt_z_zzzi_
	if(o2 && op && !T && HasSME2() && HasSVE2p1()) return bfmlslb_z_zzzi(ctx, dec); // -> bfmlslb_z_zzzi_
	if(o2 && op && T && HasSME2() && HasSVE2p1()) return bfmlslt_z_zzzi(ctx, dec); // -> bfmlslt_z_zzzi_
	UNMATCHED;
}

int decode_iclass_sve_intx_clamp(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>10)&1;
	if(!U && HasSME() && HasSVE2p1()) return sclamp_z_zz(ctx, dec); // -> sclamp_z_zz_
	if(U && HasSME() && HasSVE2p1()) return uclamp_z_zz(ctx, dec); // -> uclamp_z_zz_
	UNMATCHED;
}

int decode_iclass_sve_intx_dot2(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>10)&1;
	if(!U && HasSME2() && HasSVE2p1()) return sdot_z32_zzz(ctx, dec); // -> sdot_z32_zzz_
	if(U && HasSME2() && HasSVE2p1()) return udot_z32_zzz(ctx, dec); // -> udot_z32_zzz_
	UNMATCHED;
}

int decode_iclass_sve_intx_dot2_by_indexed_elem(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>10)&1;
	if(!U && HasSME2() && HasSVE2p1()) return sdot_z32_zzzi(ctx, dec); // -> sdot_z32_zzzi_
	if(U && HasSME2() && HasSVE2p1()) return udot_z32_zzzi(ctx, dec); // -> udot_z32_zzzi_
	UNMATCHED;
}

int decode_iclass_sve_intx_aba_long(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>11)&1, T=(INSWORD>>10)&1;
	if(!U && !T && HasSVE2() && HasSME()) return sabalb_z_zzz(ctx, dec); // -> sabalb_z_zzz_
	if(!U && T && HasSVE2() && HasSME()) return sabalt_z_zzz(ctx, dec); // -> sabalt_z_zzz_
	if(U && !T && HasSVE2() && HasSME()) return uabalb_z_zzz(ctx, dec); // -> uabalb_z_zzz_
	if(U && T && HasSVE2() && HasSME()) return uabalt_z_zzz(ctx, dec); // -> uabalt_z_zzz_
	UNMATCHED;
}

int decode_iclass_sve_intx_adc_long(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, T=(INSWORD>>10)&1;
	if(!(size&2) && !T && HasSVE2() && HasSME()) return adclb_z_zzz(ctx, dec); // -> adclb_z_zzz_
	if(!(size&2) && T && HasSVE2() && HasSME()) return adclt_z_zzz(ctx, dec); // -> adclt_z_zzz_
	if((size&2)==2 && !T && HasSVE2() && HasSME()) return sbclb_z_zzz(ctx, dec); // -> sbclb_z_zzz_
	if((size&2)==2 && T && HasSVE2() && HasSME()) return sbclt_z_zzz(ctx, dec); // -> sbclt_z_zzz_
	UNMATCHED;
}

int decode_iclass_sve_intx_cadd(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>16)&1;
	if(!op && HasSVE2() && HasSME()) return cadd_z_zz(ctx, dec); // -> cadd_z_zz_
	if(op && HasSVE2() && HasSME()) return sqcadd_z_zz(ctx, dec); // -> sqcadd_z_zz_
	UNMATCHED;
}

int decode_iclass_sve_intx_sra(context *ctx, Instruction *dec)
{
	uint32_t R=(INSWORD>>11)&1, U=(INSWORD>>10)&1;
	if(!R && !U && HasSVE2() && HasSME()) return ssra_z_zi(ctx, dec); // -> ssra_z_zi_
	if(!R && U && HasSVE2() && HasSME()) return usra_z_zi(ctx, dec); // -> usra_z_zi_
	if(R && !U && HasSVE2() && HasSME()) return srsra_z_zi(ctx, dec); // -> srsra_z_zi_
	if(R && U && HasSVE2() && HasSME()) return ursra_z_zi(ctx, dec); // -> ursra_z_zi_
	UNMATCHED;
}

int decode_iclass_sve_intx_shift_insert(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>10)&1;
	if(!op && HasSVE2() && HasSME()) return sri_z_zzi(ctx, dec); // -> sri_z_zzi_
	if(op && HasSVE2() && HasSME()) return sli_z_zzi(ctx, dec); // -> sli_z_zzi_
	UNMATCHED;
}

int decode_iclass_sve_intx_aba(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>10)&1;
	if(!U && HasSVE2() && HasSME()) return saba_z_zzz(ctx, dec); // -> saba_z_zzz_
	if(U && HasSVE2() && HasSME()) return uaba_z_zzz(ctx, dec); // -> uaba_z_zzz_
	UNMATCHED;
}

int decode_iclass_sve_crypto_unary(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, op=(INSWORD>>10)&1;
	if(!size && !op && HasSVE_AES()) return aesmc_z_z(ctx, dec); // -> aesmc_z_z_
	if(!size && op && HasSVE_AES()) return aesimc_z_z(ctx, dec); // -> aesimc_z_z_
	if(size) UNALLOCATED(ENC_UNALLOCATED_657_SVE_CRYPTO_UNARY);
	UNMATCHED;
}

int decode_iclass_sve_crypto_binary_dest(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, op=(INSWORD>>16)&1, o2=(INSWORD>>10)&1;
	if(!size && !op && !o2 && HasSVE_AES()) return aese_z_zz(ctx, dec); // -> aese_z_zz_
	if(!size && !op && o2 && HasSVE_AES()) return aesd_z_zz(ctx, dec); // -> aesd_z_zz_
	if(!size && op && !o2 && HasSVE_SM4()) return sm4e_z_zz(ctx, dec); // -> sm4e_z_zz_
	if(!size && op && o2) UNALLOCATED(ENC_UNALLOCATED_659_SVE_CRYPTO_BINARY_DEST);
	if(size) UNALLOCATED(ENC_UNALLOCATED_658_SVE_CRYPTO_BINARY_DEST);
	UNMATCHED;
}

int decode_iclass_sve_crypto_binary_multi2(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, op=(INSWORD>>16)&1, o2=(INSWORD>>10)&1, o3=INSWORD&1;
	if(!size && !op && !o2 && !o3 && HasSVE_AES2()) return aese_mz_zzi(ctx, dec); // -> aese_mz_zzi_2x1
	if(!size && !op && o2 && !o3 && HasSVE_AES2()) return aesd_mz_zzi(ctx, dec); // -> aesd_mz_zzi_2x1
	if(!size && op && !o2 && !o3 && HasSVE_AES2()) return aesemc_mz_zzi(ctx, dec); // -> aesemc_mz_zzi_2x1
	if(!size && op && o2 && !o3 && HasSVE_AES2()) return aesdimc_mz_zzi(ctx, dec); // -> aesdimc_mz_zzi_2x1
	if(!size && o3) UNALLOCATED(ENC_UNALLOCATED_661_SVE_CRYPTO_BINARY_MULTI2);
	if(size) UNALLOCATED(ENC_UNALLOCATED_660_SVE_CRYPTO_BINARY_MULTI2);
	UNMATCHED;
}

int decode_iclass_sve_crypto_binary_multi4(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, op=(INSWORD>>16)&1, o2=(INSWORD>>10)&1, opc3=INSWORD&3;
	if(!size && !op && !o2 && !opc3 && HasSVE_AES2()) return aese_mz_zzi(ctx, dec); // -> aese_mz_zzi_4x1
	if(!size && !op && o2 && !opc3 && HasSVE_AES2()) return aesd_mz_zzi(ctx, dec); // -> aesd_mz_zzi_4x1
	if(!size && op && !o2 && !opc3 && HasSVE_AES2()) return aesemc_mz_zzi(ctx, dec); // -> aesemc_mz_zzi_4x1
	if(!size && op && o2 && !opc3 && HasSVE_AES2()) return aesdimc_mz_zzi(ctx, dec); // -> aesdimc_mz_zzi_4x1
	if(!size && opc3) UNALLOCATED(ENC_UNALLOCATED_663_SVE_CRYPTO_BINARY_MULTI4);
	if(size) UNALLOCATED(ENC_UNALLOCATED_662_SVE_CRYPTO_BINARY_MULTI4);
	UNMATCHED;
}

int decode_iclass_sve_crypto_binary_const(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, op=(INSWORD>>10)&1;
	if(!size && !op && HasSVE_SM4()) return sm4ekey_z_zz(ctx, dec); // -> sm4ekey_z_zz_
	if(!size && op && HasSVE_SHA3()) return rax1_z_zz(ctx, dec); // -> rax1_z_zz_
	if(size) UNALLOCATED(ENC_UNALLOCATED_664_SVE_CRYPTO_BINARY_CONST);
	UNMATCHED;
}

int decode_iclass_sve_crypto_pmull_multi(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3;
	if(!size && HasSVE_AES2()) return pmull_mz_zzw(ctx, dec); // -> pmull_mz_zzw_1x2
	if(size) UNALLOCATED(ENC_UNALLOCATED_665_SVE_CRYPTO_PMULL_MULTI);
	UNMATCHED;
}

int decode_iclass_sve_crypto_pmlal_multi(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3;
	if(!size && HasSVE_AES2()) return pmlal_mz_zzzw(ctx, dec); // -> pmlal_mz_zzzw_1x2
	if(size) UNALLOCATED(ENC_UNALLOCATED_666_SVE_CRYPTO_PMLAL_MULTI);
	UNMATCHED;
}

int decode_iclass_sve_fp8_fma_long_by_indexed_elem(context *ctx, Instruction *dec)
{
	uint32_t T=(INSWORD>>23)&1;
	if(!T && HasSSVE_FP8FMA() && HasSVE2() && HasFP8FMA()) return fmlalb_z_z8z8z8i(ctx, dec); // -> fmlalb_z_z8z8z8i_
	if(T && HasSSVE_FP8FMA() && HasSVE2() && HasFP8FMA()) return fmlalt_z_z8z8z8i(ctx, dec); // -> fmlalt_z_z8z8z8i_
	UNMATCHED;
}

int decode_iclass_sve_fp8_fma_long_long_by_indexed_elem(context *ctx, Instruction *dec)
{
	uint32_t TT=(INSWORD>>22)&3;
	if(!TT && HasSSVE_FP8FMA() && HasSVE2() && HasFP8FMA()) return fmlallbb_z32_z8z8z8i(ctx, dec); // -> fmlallbb_z32_z8z8z8i_
	if(TT==1 && HasSSVE_FP8FMA() && HasSVE2() && HasFP8FMA()) return fmlallbt_z32_z8z8z8i(ctx, dec); // -> fmlallbt_z32_z8z8z8i_
	if(TT==2 && HasSSVE_FP8FMA() && HasSVE2() && HasFP8FMA()) return fmlalltb_z32_z8z8z8i(ctx, dec); // -> fmlalltb_z32_z8z8z8i_
	if(TT==3 && HasSSVE_FP8FMA() && HasSVE2() && HasFP8FMA()) return fmlalltt_z32_z8z8z8i(ctx, dec); // -> fmlalltt_z32_z8z8z8i_
	UNMATCHED;
}

int decode_iclass_sve_fp8_fmmla(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>22)&1;
	if(!op && HasSVE2() && HasF8F32MM()) return fmmla_z32_zz8z8(ctx, dec); // -> fmmla_z32_zz8z8_
	if(op && HasSVE2() && HasF8F16MM()) return fmmla_z16_zz8z8(ctx, dec); // -> fmmla_z16_zz8z8_
	UNMATCHED;
}

int decode_iclass_sve_fp8_fma_long_long(context *ctx, Instruction *dec)
{
	uint32_t TT=(INSWORD>>12)&3;
	if(!TT && HasSSVE_FP8FMA() && HasSVE2() && HasFP8FMA()) return fmlallbb_z32_z8z8z8(ctx, dec); // -> fmlallbb_z32_z8z8z8_
	if(TT==1 && HasSSVE_FP8FMA() && HasSVE2() && HasFP8FMA()) return fmlallbt_z32_z8z8z8(ctx, dec); // -> fmlallbt_z32_z8z8z8_
	if(TT==2 && HasSSVE_FP8FMA() && HasSVE2() && HasFP8FMA()) return fmlalltb_z32_z8z8z8(ctx, dec); // -> fmlalltb_z32_z8z8z8_
	if(TT==3 && HasSSVE_FP8FMA() && HasSVE2() && HasFP8FMA()) return fmlalltt_z32_z8z8z8(ctx, dec); // -> fmlalltt_z32_z8z8z8_
	UNMATCHED;
}

int decode_iclass_sve_fp8_fma_long(context *ctx, Instruction *dec)
{
	uint32_t T=(INSWORD>>12)&1;
	if(!T && HasSSVE_FP8FMA() && HasSVE2() && HasFP8FMA()) return fmlalb_z_z8z8z8(ctx, dec); // -> fmlalb_z_z8z8z8_
	if(T && HasSSVE_FP8FMA() && HasSVE2() && HasFP8FMA()) return fmlalt_z_z8z8z8(ctx, dec); // -> fmlalt_z_z8z8z8_
	UNMATCHED;
}

int decode_iclass_sve_intx_histseg(context *ctx, Instruction *dec)
{
	return histseg_z_zz(ctx, dec);
}

int decode_iclass_sve_intx_lut2_8(context *ctx, Instruction *dec)
{
	return luti2_z_zz(ctx, dec);
}

int decode_iclass_sve_intx_lut2_16(context *ctx, Instruction *dec)
{
	return luti2_z_zz(ctx, dec);
}

int decode_iclass_sve_intx_lut4_8(context *ctx, Instruction *dec)
{
	return luti4_z_zz(ctx, dec);
}

int decode_iclass_sve_intx_lut4_16(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>11)&1;
	if(!op && HasSVE2() && HasLUT() && HasSME2() && HasLUT()) return luti4_z_zz(ctx, dec); // -> luti4_z_zz_2x16
	if(op && HasSVE2() && HasLUT() && HasSME2() && HasLUT()) return luti4_z_zz(ctx, dec); // -> luti4_z_zz_1x16
	UNMATCHED;
}

int decode_iclass_sve_intx_lut6_8(context *ctx, Instruction *dec)
{
	return luti6_z_zzz(ctx, dec);
}

int decode_iclass_sve_intx_lut6_16(context *ctx, Instruction *dec)
{
	return luti6_z_z2zz(ctx, dec);
}

int decode_iclass_sve_intx_bin_pred_shift_sat_round(context *ctx, Instruction *dec)
{
	uint32_t Q=(INSWORD>>19)&1, R=(INSWORD>>18)&1, N=(INSWORD>>17)&1, U=(INSWORD>>16)&1;
	if(!Q && !R && N && !U && HasSVE2() && HasSME()) return srshl_z_p_zz(ctx, dec); // -> srshl_z_p_zz_
	if(!Q && !R && N && U && HasSVE2() && HasSME()) return urshl_z_p_zz(ctx, dec); // -> urshl_z_p_zz_
	if(!Q && R && N && !U && HasSVE2() && HasSME()) return srshlr_z_p_zz(ctx, dec); // -> srshlr_z_p_zz_
	if(!Q && R && N && U && HasSVE2() && HasSME()) return urshlr_z_p_zz(ctx, dec); // -> urshlr_z_p_zz_
	if(Q && !R && !N && !U && HasSVE2() && HasSME()) return sqshl_z_p_zz(ctx, dec); // -> sqshl_z_p_zz_
	if(Q && !R && !N && U && HasSVE2() && HasSME()) return uqshl_z_p_zz(ctx, dec); // -> uqshl_z_p_zz_
	if(Q && !R && N && !U && HasSVE2() && HasSME()) return sqrshl_z_p_zz(ctx, dec); // -> sqrshl_z_p_zz_
	if(Q && !R && N && U && HasSVE2() && HasSME()) return uqrshl_z_p_zz(ctx, dec); // -> uqrshl_z_p_zz_
	if(Q && R && !N && !U && HasSVE2() && HasSME()) return sqshlr_z_p_zz(ctx, dec); // -> sqshlr_z_p_zz_
	if(Q && R && !N && U && HasSVE2() && HasSME()) return uqshlr_z_p_zz(ctx, dec); // -> uqshlr_z_p_zz_
	if(Q && R && N && !U && HasSVE2() && HasSME()) return sqrshlr_z_p_zz(ctx, dec); // -> sqrshlr_z_p_zz_
	if(Q && R && N && U && HasSVE2() && HasSME()) return uqrshlr_z_p_zz(ctx, dec); // -> uqrshlr_z_p_zz_
	if(!Q && !N) UNALLOCATED(ENC_UNALLOCATED_667_SVE_INTX_BIN_PRED_SHIFT_SAT_ROUND);
	UNMATCHED;
}

int decode_iclass_sve_intx_pred_arith_unary(context *ctx, Instruction *dec)
{
	uint32_t Q=(INSWORD>>19)&1, Z=(INSWORD>>17)&1, op=(INSWORD>>16)&1;
	if(!Q && !Z && !op && HasSVE2() && HasSME()) return urecpe_z_p_z(ctx, dec); // -> urecpe_z_p_z_m
	if(!Q && !Z && op && HasSVE2() && HasSME()) return ursqrte_z_p_z(ctx, dec); // -> ursqrte_z_p_z_m
	if(!Q && Z && !op && HasSVE2p2() && HasSME2p2()) return urecpe_z_p_z(ctx, dec); // -> urecpe_z_p_z_z
	if(!Q && Z && op && HasSVE2p2() && HasSME2p2()) return ursqrte_z_p_z(ctx, dec); // -> ursqrte_z_p_z_z
	if(Q && !Z && !op && HasSVE2() && HasSME()) return sqabs_z_p_z(ctx, dec); // -> sqabs_z_p_z_m
	if(Q && !Z && op && HasSVE2() && HasSME()) return sqneg_z_p_z(ctx, dec); // -> sqneg_z_p_z_m
	if(Q && Z && !op && HasSVE2p2() && HasSME2p2()) return sqabs_z_p_z(ctx, dec); // -> sqabs_z_p_z_z
	if(Q && Z && op && HasSVE2p2() && HasSME2p2()) return sqneg_z_p_z(ctx, dec); // -> sqneg_z_p_z_z
	UNMATCHED;
}

int decode_iclass_sve_intx_accumulate_long_pairs(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>16)&1;
	if(!U && HasSVE2() && HasSME()) return sadalp_z_p_z(ctx, dec); // -> sadalp_z_p_z_
	if(U && HasSVE2() && HasSME()) return uadalp_z_p_z(ctx, dec); // -> uadalp_z_p_z_
	UNMATCHED;
}

int decode_iclass_sve_intx_pred_arith_binary(context *ctx, Instruction *dec)
{
	uint32_t R=(INSWORD>>18)&1, S=(INSWORD>>17)&1, U=(INSWORD>>16)&1;
	if(!R && !S && !U && HasSVE2() && HasSME()) return shadd_z_p_zz(ctx, dec); // -> shadd_z_p_zz_
	if(!R && !S && U && HasSVE2() && HasSME()) return uhadd_z_p_zz(ctx, dec); // -> uhadd_z_p_zz_
	if(!R && S && !U && HasSVE2() && HasSME()) return shsub_z_p_zz(ctx, dec); // -> shsub_z_p_zz_
	if(!R && S && U && HasSVE2() && HasSME()) return uhsub_z_p_zz(ctx, dec); // -> uhsub_z_p_zz_
	if(R && !S && !U && HasSVE2() && HasSME()) return srhadd_z_p_zz(ctx, dec); // -> srhadd_z_p_zz_
	if(R && !S && U && HasSVE2() && HasSME()) return urhadd_z_p_zz(ctx, dec); // -> urhadd_z_p_zz_
	if(R && S && !U && HasSVE2() && HasSME()) return shsubr_z_p_zz(ctx, dec); // -> shsubr_z_p_zz_
	if(R && S && U && HasSVE2() && HasSME()) return uhsubr_z_p_zz(ctx, dec); // -> uhsubr_z_p_zz_
	UNMATCHED;
}

int decode_iclass_sve_intx_arith_binary_pairs(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>17)&3, U=(INSWORD>>16)&1;
	if(!opc && !U && HasSVE2p3() && HasSME2p3()) return subp_z_p_zz(ctx, dec); // -> subp_z_p_zz_
	if(!opc && U && HasSVE2() && HasSME()) return addp_z_p_zz(ctx, dec); // -> addp_z_p_zz_
	if(opc==2 && !U && HasSVE2() && HasSME()) return smaxp_z_p_zz(ctx, dec); // -> smaxp_z_p_zz_
	if(opc==2 && U && HasSVE2() && HasSME()) return umaxp_z_p_zz(ctx, dec); // -> umaxp_z_p_zz_
	if(opc==3 && !U && HasSVE2() && HasSME()) return sminp_z_p_zz(ctx, dec); // -> sminp_z_p_zz_
	if(opc==3 && U && HasSVE2() && HasSME()) return uminp_z_p_zz(ctx, dec); // -> uminp_z_p_zz_
	if(opc==1) UNALLOCATED(ENC_UNALLOCATED_668_SVE_INTX_ARITH_BINARY_PAIRS);
	UNMATCHED;
}

int decode_iclass_sve_intx_pred_arith_binary_sat(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>18)&1, S=(INSWORD>>17)&1, U=(INSWORD>>16)&1;
	if(!op && !S && !U && HasSVE2() && HasSME()) return sqadd_z_p_zz(ctx, dec); // -> sqadd_z_p_zz_
	if(!op && !S && U && HasSVE2() && HasSME()) return uqadd_z_p_zz(ctx, dec); // -> uqadd_z_p_zz_
	if(!op && S && !U && HasSVE2() && HasSME()) return sqsub_z_p_zz(ctx, dec); // -> sqsub_z_p_zz_
	if(!op && S && U && HasSVE2() && HasSME()) return uqsub_z_p_zz(ctx, dec); // -> uqsub_z_p_zz_
	if(op && !S && !U && HasSVE2() && HasSME()) return suqadd_z_p_zz(ctx, dec); // -> suqadd_z_p_zz_
	if(op && !S && U && HasSVE2() && HasSME()) return usqadd_z_p_zz(ctx, dec); // -> usqadd_z_p_zz_
	if(op && S && !U && HasSVE2() && HasSME()) return sqsubr_z_p_zz(ctx, dec); // -> sqsubr_z_p_zz_
	if(op && S && U && HasSVE2() && HasSME()) return uqsubr_z_p_zz(ctx, dec); // -> uqsubr_z_p_zz_
	UNMATCHED;
}

int decode_iclass_sve_int_mul_b(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, opc=(INSWORD>>10)&3;
	if(!size && opc==1 && HasSVE2() && HasSME()) return pmul_z_zz(ctx, dec); // -> pmul_z_zz_
	if(size && opc==1) UNALLOCATED(ENC_UNALLOCATED_669_SVE_INT_MUL_B);
	if(!opc && HasSVE2() && HasSME()) return mul_z_zz(ctx, dec); // -> mul_z_zz_
	if(opc==2 && HasSVE2() && HasSME()) return smulh_z_zz(ctx, dec); // -> smulh_z_zz_
	if(opc==3 && HasSVE2() && HasSME()) return umulh_z_zz(ctx, dec); // -> umulh_z_zz_
	UNMATCHED;
}

int decode_iclass_sve_int_sqdmulh(context *ctx, Instruction *dec)
{
	uint32_t R=(INSWORD>>10)&1;
	if(!R && HasSVE2() && HasSME()) return sqdmulh_z_zz(ctx, dec); // -> sqdmulh_z_zz_
	if(R && HasSVE2() && HasSME()) return sqrdmulh_z_zz(ctx, dec); // -> sqrdmulh_z_zz_
	UNMATCHED;
}

int decode_iclass_sve_int_addqp(context *ctx, Instruction *dec)
{
	return addqp_z_zz(ctx, dec);
}

int decode_iclass_sve_int_addsubp(context *ctx, Instruction *dec)
{
	return addsubp_z_zz(ctx, dec);
}

int decode_iclass_sve_intx_shift_narrow(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>13)&1, U=(INSWORD>>12)&1, R=(INSWORD>>11)&1, T=(INSWORD>>10)&1;
	if(!op && !U && !R && !T && HasSVE2() && HasSME()) return sqshrunb_z_zi(ctx, dec); // -> sqshrunb_z_zi_
	if(!op && !U && !R && T && HasSVE2() && HasSME()) return sqshrunt_z_zi(ctx, dec); // -> sqshrunt_z_zi_
	if(!op && !U && R && !T && HasSVE2() && HasSME()) return sqrshrunb_z_zi(ctx, dec); // -> sqrshrunb_z_zi_
	if(!op && !U && R && T && HasSVE2() && HasSME()) return sqrshrunt_z_zi(ctx, dec); // -> sqrshrunt_z_zi_
	if(!op && U && !R && !T && HasSVE2() && HasSME()) return shrnb_z_zi(ctx, dec); // -> shrnb_z_zi_
	if(!op && U && !R && T && HasSVE2() && HasSME()) return shrnt_z_zi(ctx, dec); // -> shrnt_z_zi_
	if(!op && U && R && !T && HasSVE2() && HasSME()) return rshrnb_z_zi(ctx, dec); // -> rshrnb_z_zi_
	if(!op && U && R && T && HasSVE2() && HasSME()) return rshrnt_z_zi(ctx, dec); // -> rshrnt_z_zi_
	if(op && !U && !R && !T && HasSVE2() && HasSME()) return sqshrnb_z_zi(ctx, dec); // -> sqshrnb_z_zi_
	if(op && !U && !R && T && HasSVE2() && HasSME()) return sqshrnt_z_zi(ctx, dec); // -> sqshrnt_z_zi_
	if(op && !U && R && !T && HasSVE2() && HasSME()) return sqrshrnb_z_zi(ctx, dec); // -> sqrshrnb_z_zi_
	if(op && !U && R && T && HasSVE2() && HasSME()) return sqrshrnt_z_zi(ctx, dec); // -> sqrshrnt_z_zi_
	if(op && U && !R && !T && HasSVE2() && HasSME()) return uqshrnb_z_zi(ctx, dec); // -> uqshrnb_z_zi_
	if(op && U && !R && T && HasSVE2() && HasSME()) return uqshrnt_z_zi(ctx, dec); // -> uqshrnt_z_zi_
	if(op && U && R && !T && HasSVE2() && HasSME()) return uqrshrnb_z_zi(ctx, dec); // -> uqrshrnb_z_zi_
	if(op && U && R && T && HasSVE2() && HasSME()) return uqrshrnt_z_zi(ctx, dec); // -> uqrshrnt_z_zi_
	UNMATCHED;
}

int decode_iclass_sve_intx_multi_shift_narrow(context *ctx, Instruction *dec)
{
	uint32_t op0=(INSWORD>>22)&1, opc=(INSWORD>>16)&0x1f, op1=(INSWORD>>13)&1, U=(INSWORD>>12)&1, R=(INSWORD>>11)&1;
	if(!op0 && (opc&0x18)==8 && !op1 && !U && R && HasSVE2p3() && HasSME2p3()) return sqrshrun_z_mz2(ctx, dec); // -> sqrshrun_z_mz2_b
	if(!op0 && (opc&0x18)==8 && op1 && !U && R && HasSVE2p3() && HasSME2p3()) return sqrshrn_z_mz2(ctx, dec); // -> sqrshrn_z_mz2_b
	if(!op0 && (opc&0x18)==8 && op1 && U && R && HasSVE2p3() && HasSME2p3()) return uqrshrn_z_mz2(ctx, dec); // -> uqrshrn_z_mz2_b
	if(!op0 && (opc&0x18)==0x10 && !op1 && U && R) UNALLOCATED(ENC_UNALLOCATED_674_SVE_INTX_MULTI_SHIFT_NARROW);
	if(!op0 && (opc&8)==8 && !op1 && U && R) UNALLOCATED(ENC_UNALLOCATED_673_SVE_INTX_MULTI_SHIFT_NARROW);
	if(!op0 && (opc&0x10)==0x10 && !op1 && !U && R && HasSME2() && HasSVE2p1()) return sqrshrun_z_mz2(ctx, dec); // -> sqrshrun_z_mz2_
	if(!op0 && (opc&0x10)==0x10 && op1 && !U && R && HasSME2() && HasSVE2p1()) return sqrshrn_z_mz2(ctx, dec); // -> sqrshrn_z_mz2_
	if(!op0 && (opc&0x10)==0x10 && op1 && U && R && HasSME2() && HasSVE2p1()) return uqrshrn_z_mz2(ctx, dec); // -> uqrshrn_z_mz2_
	if(!op0 && !op1 && !U && !R && HasSVE2p3() && HasSME2p3()) return sqshrn_z_mz2(ctx, dec); // -> sqshrn_z_mz2_
	if(!op0 && !op1 && U && !R && HasSVE2p3() && HasSME2p3()) return uqshrn_z_mz2(ctx, dec); // -> uqshrn_z_mz2_
	if(!op0 && op1 && !U && !R && HasSVE2p3() && HasSME2p3()) return sqshrun_z_mz2(ctx, dec); // -> sqshrun_z_mz2_
	if(!op0 && op1 && U && !R) UNALLOCATED(ENC_UNALLOCATED_672_SVE_INTX_MULTI_SHIFT_NARROW);
	if(!op0 && !(opc&0x18) && R) UNALLOCATED(ENC_UNALLOCATED_671_SVE_INTX_MULTI_SHIFT_NARROW);
	if(op0) UNALLOCATED(ENC_UNALLOCATED_670_SVE_INTX_MULTI_SHIFT_NARROW);
	UNMATCHED;
}

int decode_iclass_sve_intx_extract_narrow(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>11)&3, T=(INSWORD>>10)&1;
	if(!opc && !T && HasSVE2() && HasSME()) return sqxtnb_z_zz(ctx, dec); // -> sqxtnb_z_zz_
	if(!opc && T && HasSVE2() && HasSME()) return sqxtnt_z_zz(ctx, dec); // -> sqxtnt_z_zz_
	if(opc==1 && !T && HasSVE2() && HasSME()) return uqxtnb_z_zz(ctx, dec); // -> uqxtnb_z_zz_
	if(opc==1 && T && HasSVE2() && HasSME()) return uqxtnt_z_zz(ctx, dec); // -> uqxtnt_z_zz_
	if(opc==2 && !T && HasSVE2() && HasSME()) return sqxtunb_z_zz(ctx, dec); // -> sqxtunb_z_zz_
	if(opc==2 && T && HasSVE2() && HasSME()) return sqxtunt_z_zz(ctx, dec); // -> sqxtunt_z_zz_
	if(opc==3) UNALLOCATED(ENC_UNALLOCATED_675_SVE_INTX_EXTRACT_NARROW);
	UNMATCHED;
}

int decode_iclass_sve_intx_multi_extract_narrow(context *ctx, Instruction *dec)
{
	uint32_t tszh=(INSWORD>>22)&1, tszl=(INSWORD>>19)&3, opc=(INSWORD>>11)&3;
	if(!tszh && tszl==2 && !opc && HasSME2() && HasSVE2p1()) return sqcvtn_z_mz2(ctx, dec); // -> sqcvtn_z_mz2_
	if(!tszh && tszl==2 && opc==1 && HasSME2() && HasSVE2p1()) return uqcvtn_z_mz2(ctx, dec); // -> uqcvtn_z_mz2_
	if(!tszh && tszl==2 && opc==2 && HasSME2() && HasSVE2p1()) return sqcvtun_z_mz2(ctx, dec); // -> sqcvtun_z_mz2_
	if(!tszh && tszl==2 && opc==3) UNALLOCATED(ENC_UNALLOCATED_678_SVE_INTX_MULTI_EXTRACT_NARROW);
	if(!tszh && tszl!=2) UNALLOCATED(ENC_UNALLOCATED_677_SVE_INTX_MULTI_EXTRACT_NARROW);
	if(tszh) UNALLOCATED(ENC_UNALLOCATED_676_SVE_INTX_MULTI_EXTRACT_NARROW);
	UNMATCHED;
}

int decode_iclass_sve_intx_arith_narrow(context *ctx, Instruction *dec)
{
	uint32_t S=(INSWORD>>12)&1, R=(INSWORD>>11)&1, T=(INSWORD>>10)&1;
	if(!S && !R && !T && HasSVE2() && HasSME()) return addhnb_z_zz(ctx, dec); // -> addhnb_z_zz_
	if(!S && !R && T && HasSVE2() && HasSME()) return addhnt_z_zz(ctx, dec); // -> addhnt_z_zz_
	if(!S && R && !T && HasSVE2() && HasSME()) return raddhnb_z_zz(ctx, dec); // -> raddhnb_z_zz_
	if(!S && R && T && HasSVE2() && HasSME()) return raddhnt_z_zz(ctx, dec); // -> raddhnt_z_zz_
	if(S && !R && !T && HasSVE2() && HasSME()) return subhnb_z_zz(ctx, dec); // -> subhnb_z_zz_
	if(S && !R && T && HasSVE2() && HasSME()) return subhnt_z_zz(ctx, dec); // -> subhnt_z_zz_
	if(S && R && !T && HasSVE2() && HasSME()) return rsubhnb_z_zz(ctx, dec); // -> rsubhnb_z_zz_
	if(S && R && T && HasSVE2() && HasSME()) return rsubhnt_z_zz(ctx, dec); // -> rsubhnt_z_zz_
	UNMATCHED;
}

int decode_iclass_sve_intx_match(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>4)&1;
	if(!op && HasSVE2()) return match_p_p_zz(ctx, dec); // -> match_p_p_zz_
	if(op && HasSVE2()) return nmatch_p_p_zz(ctx, dec); // -> nmatch_p_p_zz_
	UNMATCHED;
}

int decode_iclass_sve_intx_cons_arith_long(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>13)&1, S=(INSWORD>>12)&1, U=(INSWORD>>11)&1, T=(INSWORD>>10)&1;
	if(!op && !S && !U && !T && HasSVE2() && HasSME()) return saddlb_z_zz(ctx, dec); // -> saddlb_z_zz_
	if(!op && !S && !U && T && HasSVE2() && HasSME()) return saddlt_z_zz(ctx, dec); // -> saddlt_z_zz_
	if(!op && !S && U && !T && HasSVE2() && HasSME()) return uaddlb_z_zz(ctx, dec); // -> uaddlb_z_zz_
	if(!op && !S && U && T && HasSVE2() && HasSME()) return uaddlt_z_zz(ctx, dec); // -> uaddlt_z_zz_
	if(!op && S && !U && !T && HasSVE2() && HasSME()) return ssublb_z_zz(ctx, dec); // -> ssublb_z_zz_
	if(!op && S && !U && T && HasSVE2() && HasSME()) return ssublt_z_zz(ctx, dec); // -> ssublt_z_zz_
	if(!op && S && U && !T && HasSVE2() && HasSME()) return usublb_z_zz(ctx, dec); // -> usublb_z_zz_
	if(!op && S && U && T && HasSVE2() && HasSME()) return usublt_z_zz(ctx, dec); // -> usublt_z_zz_
	if(op && S && !U && !T && HasSVE2() && HasSME()) return sabdlb_z_zz(ctx, dec); // -> sabdlb_z_zz_
	if(op && S && !U && T && HasSVE2() && HasSME()) return sabdlt_z_zz(ctx, dec); // -> sabdlt_z_zz_
	if(op && S && U && !T && HasSVE2() && HasSME()) return uabdlb_z_zz(ctx, dec); // -> uabdlb_z_zz_
	if(op && S && U && T && HasSVE2() && HasSME()) return uabdlt_z_zz(ctx, dec); // -> uabdlt_z_zz_
	if(op && !S) UNALLOCATED(ENC_UNALLOCATED_679_SVE_INTX_CONS_ARITH_LONG);
	UNMATCHED;
}

int decode_iclass_sve_intx_cons_arith_wide(context *ctx, Instruction *dec)
{
	uint32_t S=(INSWORD>>12)&1, U=(INSWORD>>11)&1, T=(INSWORD>>10)&1;
	if(!S && !U && !T && HasSVE2() && HasSME()) return saddwb_z_zz(ctx, dec); // -> saddwb_z_zz_
	if(!S && !U && T && HasSVE2() && HasSME()) return saddwt_z_zz(ctx, dec); // -> saddwt_z_zz_
	if(!S && U && !T && HasSVE2() && HasSME()) return uaddwb_z_zz(ctx, dec); // -> uaddwb_z_zz_
	if(!S && U && T && HasSVE2() && HasSME()) return uaddwt_z_zz(ctx, dec); // -> uaddwt_z_zz_
	if(S && !U && !T && HasSVE2() && HasSME()) return ssubwb_z_zz(ctx, dec); // -> ssubwb_z_zz_
	if(S && !U && T && HasSVE2() && HasSME()) return ssubwt_z_zz(ctx, dec); // -> ssubwt_z_zz_
	if(S && U && !T && HasSVE2() && HasSME()) return usubwb_z_zz(ctx, dec); // -> usubwb_z_zz_
	if(S && U && T && HasSVE2() && HasSME()) return usubwt_z_zz(ctx, dec); // -> usubwt_z_zz_
	UNMATCHED;
}

int decode_iclass_sve_intx_cons_mul_long(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, op=(INSWORD>>12)&1, U=(INSWORD>>11)&1, T=(INSWORD>>10)&1;
	if(!size && !op && U && !T && HasSVE_PMULL128()) return pmullb_z_zz(ctx, dec); // -> pmullb_z_zz_q
	if(!size && !op && U && T && HasSVE_PMULL128()) return pmullt_z_zz(ctx, dec); // -> pmullt_z_zz_q
	if(size && !op && U && !T && HasSVE2() && HasSME()) return pmullb_z_zz(ctx, dec); // -> pmullb_z_zz_
	if(size && !op && U && T && HasSVE2() && HasSME()) return pmullt_z_zz(ctx, dec); // -> pmullt_z_zz_
	if(!op && !U && !T && HasSVE2() && HasSME()) return sqdmullb_z_zz(ctx, dec); // -> sqdmullb_z_zz_
	if(!op && !U && T && HasSVE2() && HasSME()) return sqdmullt_z_zz(ctx, dec); // -> sqdmullt_z_zz_
	if(op && !U && !T && HasSVE2() && HasSME()) return smullb_z_zz(ctx, dec); // -> smullb_z_zz_
	if(op && !U && T && HasSVE2() && HasSME()) return smullt_z_zz(ctx, dec); // -> smullt_z_zz_
	if(op && U && !T && HasSVE2() && HasSME()) return umullb_z_zz(ctx, dec); // -> umullb_z_zz_
	if(op && U && T && HasSVE2() && HasSME()) return umullt_z_zz(ctx, dec); // -> umullt_z_zz_
	UNMATCHED;
}

int decode_iclass_sve_abal(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>11)&1;
	if(!U && HasSVE2p3() && HasSME2p3()) return sabal_z_zzz(ctx, dec); // -> sabal_z_zz_
	if(U && HasSVE2p3() && HasSME2p3()) return uabal_z_zzz(ctx, dec); // -> uabal_z_zz_
	UNMATCHED;
}

int decode_iclass_sve_fp_fmmla_nw(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>22)&1;
	if(!op && HasSVE2p2() && HasF16MM()) return fmmla_z_zzz(ctx, dec); // -> fmmla_z_zzz_h
	if(op && HasSVE_B16MM()) return bfmmla_z16_zzz(ctx, dec); // -> bfmmla_z_zzz_h
	UNMATCHED;
}

int decode_iclass_sve_fp_pairwise(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&7;
	if(!opc && HasSVE2() && HasSME()) return faddp_z_p_zz(ctx, dec); // -> faddp_z_p_zz_
	if(opc==1) UNALLOCATED(ENC_UNALLOCATED_681_SVE_FP_PAIRWISE);
	if(opc==4 && HasSVE2() && HasSME()) return fmaxnmp_z_p_zz(ctx, dec); // -> fmaxnmp_z_p_zz_
	if(opc==5 && HasSVE2() && HasSME()) return fminnmp_z_p_zz(ctx, dec); // -> fminnmp_z_p_zz_
	if(opc==6 && HasSVE2() && HasSME()) return fmaxp_z_p_zz(ctx, dec); // -> fmaxp_z_p_zz_
	if(opc==7 && HasSVE2() && HasSME()) return fminp_z_p_zz(ctx, dec); // -> fminp_z_p_zz_
	if((opc&6)==2) UNALLOCATED(ENC_UNALLOCATED_680_SVE_FP_PAIRWISE);
	UNMATCHED;
}

int decode_iclass_sve_fp_z2op_p_zd_a(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>16)&1, opc2=(INSWORD>>13)&3;
	if(!op && !opc2 && HasSVE2p2() && HasSME2p2()) return frinta_z_p_z(ctx, dec); // -> frintn_z_p_z_z
	if(!op && opc2==1 && HasSVE2p2() && HasSME2p2()) return frinta_z_p_z(ctx, dec); // -> frintp_z_p_z_z
	if(!op && opc2==2 && HasSVE2p2() && HasSME2p2()) return frinta_z_p_z(ctx, dec); // -> frintm_z_p_z_z
	if(!op && opc2==3 && HasSVE2p2() && HasSME2p2()) return frinta_z_p_z(ctx, dec); // -> frintz_z_p_z_z
	if(op && !opc2 && HasSVE2p2() && HasSME2p2()) return frinta_z_p_z(ctx, dec); // -> frinta_z_p_z_z
	if(op && opc2==1) UNALLOCATED(ENC_UNALLOCATED_682_SVE_FP_Z2OP_P_ZD_A);
	if(op && opc2==2 && HasSVE2p2() && HasSME2p2()) return frinta_z_p_z(ctx, dec); // -> frintx_z_p_z_z
	if(op && opc2==3 && HasSVE2p2() && HasSME2p2()) return frinta_z_p_z(ctx, dec); // -> frinti_z_p_z_z
	UNMATCHED;
}

int decode_iclass_sve_fp_z2op_p_zd_b_0(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>22)&3, opc2=(INSWORD>>13)&3;
	if(!opc && opc2==2 && HasSVE2p2() && HasSME2p2()) return fcvtx_z_p_z(ctx, dec); // -> fcvtx_z_p_z_d2sz
	if(opc==2 && !opc2 && HasSVE2p2() && HasSME2p2()) return fcvt_z_p_z(ctx, dec); // -> fcvt_z_p_z_s2hz
	if(opc==2 && opc2==1 && HasSVE2p2() && HasSME2p2()) return fcvt_z_p_z(ctx, dec); // -> fcvt_z_p_z_h2sz
	if(opc==2 && opc2==2 && HasSVE2p2() && HasSME2p2()) return bfcvt_z_p_z(ctx, dec); // -> bfcvt_z_p_z_s2bfz
	if(opc==3 && !opc2 && HasSVE2p2() && HasSME2p2()) return fcvt_z_p_z(ctx, dec); // -> fcvt_z_p_z_d2hz
	if(opc==3 && opc2==1 && HasSVE2p2() && HasSME2p2()) return fcvt_z_p_z(ctx, dec); // -> fcvt_z_p_z_h2dz
	if(opc==3 && opc2==2 && HasSVE2p2() && HasSME2p2()) return fcvt_z_p_z(ctx, dec); // -> fcvt_z_p_z_d2sz
	if(opc==3 && opc2==3 && HasSVE2p2() && HasSME2p2()) return fcvt_z_p_z(ctx, dec); // -> fcvt_z_p_z_s2dz
	if(!(opc&1) && opc2==3) UNALLOCATED(ENC_UNALLOCATED_685_SVE_FP_Z2OP_P_ZD_B_0);
	if(!opc && !(opc2&2)) UNALLOCATED(ENC_UNALLOCATED_684_SVE_FP_Z2OP_P_ZD_B_0);
	if(opc==1) UNALLOCATED(ENC_UNALLOCATED_683_SVE_FP_Z2OP_P_ZD_B_0);
	UNMATCHED;
}

int decode_iclass_sve_fp_z2op_p_zd_b_1(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>13)&3;
	if(!opc && HasSVE2p2() && HasSME2p2()) return frecpx_z_p_z(ctx, dec); // -> frecpx_z_p_z_z
	if(opc==1 && HasSVE2p2() && HasSME2p2()) return fsqrt_z_p_z(ctx, dec); // -> fsqrt_z_p_z_z
	if((opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_686_SVE_FP_Z2OP_P_ZD_B_1);
	UNMATCHED;
}

int decode_iclass_sve_fp_z2op_p_zd_c(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>22)&3, o2=(INSWORD>>16)&1, o3=(INSWORD>>14)&1, U=(INSWORD>>13)&1;
	if(opc==1 && !o2 && o3 && !U && HasSVE2p2() && HasSME2p2()) return scvtf_z_p_z(ctx, dec); // -> scvtf_z_p_z_h2fp16z
	if(opc==1 && !o2 && o3 && U && HasSVE2p2() && HasSME2p2()) return ucvtf_z_p_z(ctx, dec); // -> ucvtf_z_p_z_h2fp16z
	if(opc==1 && o2 && !o3 && !U && HasSVE2p2() && HasSME2p2()) return scvtf_z_p_z(ctx, dec); // -> scvtf_z_p_z_w2fp16z
	if(opc==1 && o2 && !o3 && U && HasSVE2p2() && HasSME2p2()) return ucvtf_z_p_z(ctx, dec); // -> ucvtf_z_p_z_w2fp16z
	if(opc==1 && o2 && o3 && !U && HasSVE2p2() && HasSME2p2()) return scvtf_z_p_z(ctx, dec); // -> scvtf_z_p_z_x2fp16z
	if(opc==1 && o2 && o3 && U && HasSVE2p2() && HasSME2p2()) return ucvtf_z_p_z(ctx, dec); // -> ucvtf_z_p_z_x2fp16z
	if(opc==2 && o2 && !o3 && !U && HasSVE2p2() && HasSME2p2()) return scvtf_z_p_z(ctx, dec); // -> scvtf_z_p_z_w2sz
	if(opc==2 && o2 && !o3 && U && HasSVE2p2() && HasSME2p2()) return ucvtf_z_p_z(ctx, dec); // -> ucvtf_z_p_z_w2sz
	if(opc==3 && !o2 && !o3 && !U && HasSVE2p2() && HasSME2p2()) return scvtf_z_p_z(ctx, dec); // -> scvtf_z_p_z_w2dz
	if(opc==3 && !o2 && !o3 && U && HasSVE2p2() && HasSME2p2()) return ucvtf_z_p_z(ctx, dec); // -> ucvtf_z_p_z_w2dz
	if(opc==3 && o2 && !o3 && !U && HasSVE2p2() && HasSME2p2()) return scvtf_z_p_z(ctx, dec); // -> scvtf_z_p_z_x2sz
	if(opc==3 && o2 && !o3 && U && HasSVE2p2() && HasSME2p2()) return ucvtf_z_p_z(ctx, dec); // -> ucvtf_z_p_z_x2sz
	if(opc==3 && o2 && o3 && !U && HasSVE2p2() && HasSME2p2()) return scvtf_z_p_z(ctx, dec); // -> scvtf_z_p_z_x2dz
	if(opc==3 && o2 && o3 && U && HasSVE2p2() && HasSME2p2()) return ucvtf_z_p_z(ctx, dec); // -> ucvtf_z_p_z_x2dz
	if(!opc && !o2 && !U && HasSVE2p2() && HasSME2p2()) return frint32z_z_p_z(ctx, dec); // -> frint32z_z_p_z_z
	if(!opc && !o2 && U && HasSVE2p2() && HasSME2p2()) return frint32x_z_p_z(ctx, dec); // -> frint32x_z_p_z_z
	if(!opc && o2 && !U && HasSVE2p2() && HasSME2p2()) return frint64z_z_p_z(ctx, dec); // -> frint64z_z_p_z_z
	if(!opc && o2 && U && HasSVE2p2() && HasSME2p2()) return frint64x_z_p_z(ctx, dec); // -> frint64x_z_p_z_z
	if(opc==1 && !o2 && !o3) UNALLOCATED(ENC_UNALLOCATED_688_SVE_FP_Z2OP_P_ZD_C);
	if(opc==2 && o2 && o3) UNALLOCATED(ENC_UNALLOCATED_689_SVE_FP_Z2OP_P_ZD_C);
	if(opc==3 && !o2 && o3) UNALLOCATED(ENC_UNALLOCATED_690_SVE_FP_Z2OP_P_ZD_C);
	if(opc==2 && !o2) UNALLOCATED(ENC_UNALLOCATED_687_SVE_FP_Z2OP_P_ZD_C);
	UNMATCHED;
}

int decode_iclass_sve_fp_z2op_p_zd_d(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>22)&3, o2=(INSWORD>>16)&1, o3=(INSWORD>>14)&1, U=(INSWORD>>13)&1;
	if(opc==1 && !o2 && o3 && !U && HasSVE2p2() && HasSME2p2()) return fcvtzs_z_p_z(ctx, dec); // -> fcvtzs_z_p_z_fp162hz
	if(opc==1 && !o2 && o3 && U && HasSVE2p2() && HasSME2p2()) return fcvtzu_z_p_z(ctx, dec); // -> fcvtzu_z_p_z_fp162hz
	if(opc==1 && o2 && !o3 && !U && HasSVE2p2() && HasSME2p2()) return fcvtzs_z_p_z(ctx, dec); // -> fcvtzs_z_p_z_fp162wz
	if(opc==1 && o2 && !o3 && U && HasSVE2p2() && HasSME2p2()) return fcvtzu_z_p_z(ctx, dec); // -> fcvtzu_z_p_z_fp162wz
	if(opc==1 && o2 && o3 && !U && HasSVE2p2() && HasSME2p2()) return fcvtzs_z_p_z(ctx, dec); // -> fcvtzs_z_p_z_fp162xz
	if(opc==1 && o2 && o3 && U && HasSVE2p2() && HasSME2p2()) return fcvtzu_z_p_z(ctx, dec); // -> fcvtzu_z_p_z_fp162xz
	if(opc==2 && o2 && !o3 && !U && HasSVE2p2() && HasSME2p2()) return fcvtzs_z_p_z(ctx, dec); // -> fcvtzs_z_p_z_s2wz
	if(opc==2 && o2 && !o3 && U && HasSVE2p2() && HasSME2p2()) return fcvtzu_z_p_z(ctx, dec); // -> fcvtzu_z_p_z_s2wz
	if(opc==3 && !o2 && !o3 && !U && HasSVE2p2() && HasSME2p2()) return fcvtzs_z_p_z(ctx, dec); // -> fcvtzs_z_p_z_d2wz
	if(opc==3 && !o2 && !o3 && U && HasSVE2p2() && HasSME2p2()) return fcvtzu_z_p_z(ctx, dec); // -> fcvtzu_z_p_z_d2wz
	if(opc==3 && o2 && !o3 && !U && HasSVE2p2() && HasSME2p2()) return fcvtzs_z_p_z(ctx, dec); // -> fcvtzs_z_p_z_s2xz
	if(opc==3 && o2 && !o3 && U && HasSVE2p2() && HasSME2p2()) return fcvtzu_z_p_z(ctx, dec); // -> fcvtzu_z_p_z_s2xz
	if(opc==3 && o2 && o3 && !U && HasSVE2p2() && HasSME2p2()) return fcvtzs_z_p_z(ctx, dec); // -> fcvtzs_z_p_z_d2xz
	if(opc==3 && o2 && o3 && U && HasSVE2p2() && HasSME2p2()) return fcvtzu_z_p_z(ctx, dec); // -> fcvtzu_z_p_z_d2xz
	if(opc==1 && !o2 && !o3) UNALLOCATED(ENC_UNALLOCATED_693_SVE_FP_Z2OP_P_ZD_D);
	if(opc==2 && o2 && o3) UNALLOCATED(ENC_UNALLOCATED_694_SVE_FP_Z2OP_P_ZD_D);
	if(opc==3 && !o2 && o3) UNALLOCATED(ENC_UNALLOCATED_695_SVE_FP_Z2OP_P_ZD_D);
	if(!opc && !o2 && HasSVE2p2() && HasSME2p2()) return flogb_z_p_z(ctx, dec); // -> flogb_z_p_z_z
	if(!opc && o2) UNALLOCATED(ENC_UNALLOCATED_691_SVE_FP_Z2OP_P_ZD_D);
	if(opc==2 && !o2) UNALLOCATED(ENC_UNALLOCATED_692_SVE_FP_Z2OP_P_ZD_D);
	UNMATCHED;
}

int decode_iclass_sve_intx_histcnt(context *ctx, Instruction *dec)
{
	return histcnt_z_p_zz(ctx, dec);
}

int decode_iclass_sve_ptr_muladd_unpred(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>22)&3, o2=(INSWORD>>11)&1;
	if(opc==3 && !o2 && HasSVE() && HasCPA()) return mlapt_z_zzz(ctx, dec); // -> mlapt_z_zzz_
	if(opc==3 && o2 && HasSVE() && HasCPA()) return madpt_z_zzz(ctx, dec); // -> madpt_z_zzz_
	if(opc!=3) UNALLOCATED(ENC_UNALLOCATED_696_SVE_PTR_MULADD_UNPRED);
	UNMATCHED;
}

