/* GENERATED FILE */
#include <stddef.h>
#include <stdbool.h>

#include "decode.h"
#include "decode1.h"
#include "pcode.h"

int decode_spec(context *ctx, Instruction *dec)
{
	uint32_t op0, op1, op2, op3, op4, op5, op6;

	dec->insword = ctx->insword;
	dec->setflags = (ctx->S==1) ? FLAGEFFECT_SETS : FLAGEFFECT_NONE;
	/* GROUP: root */
	op0 = INSWORD>>31;
	op1 = (INSWORD>>25)&15;
	if(!op0 && !op1) {
		/* GROUP: reserved */
		op0 = (INSWORD>>29)&3;
		op1 = (INSWORD>>16)&0x1ff;
		if(!op0 && !op1)
			return decode_iclass_perm_undef(ctx, dec);
		if(!op0 && op1)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_2_reserved
		if(op0)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_1_reserved
		RESERVED(ENC_UNKNOWN); // group: reserved
	}
	if(op0 && !op1) {
		/* GROUP: sme */
		op0 = (INSWORD>>29)&3;
		op1 = (INSWORD>>10)&0x7fff;
		op2 = INSWORD&0x3f;
		if(!op0 && !(op1&0x305f) && !(op2&0x24)) {
			/* GROUP: mortlach2_prod4 */
			op0 = (INSWORD>>24)&1;
			op1 = (INSWORD>>21)&1;
			op2 = (INSWORD>>15)&1;
			op3 = (INSWORD>>3)&3;
			op4 = (INSWORD>>1)&1;
			if(!op0 && !op1 && !op2 && !(op3&1))
				return decode_iclass_mortlach_f32f32_prod4(ctx, dec);
			if(!op0 && !op1 && !op2 && op3&1 && !op4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_38_mortlach2_prod4
			if(!op0 && op1 && !op2 && !op3)
				return decode_iclass_mortlach_f8f32_prod4(ctx, dec);
			if(!op0 && op1 && !op2 && op3==1 && !op4)
				return decode_iclass_mortlach_f8f16_prod4(ctx, dec);
			if(!op0 && op1 && !op2 && op3==2 && op4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_40_mortlach2_prod4
			if(!op0 && op1 && !op2 && (op3&2)==2 && !op4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_39_mortlach2_prod4
			if(op0 && !op1 && !op2 && !(op3&1))
				return decode_iclass_mortlach_b16f32_prod4(ctx, dec);
			if(op0 && !op1 && !op2 && op3&1 && !op4)
				return decode_iclass_mortlach_f16f16_prod4(ctx, dec);
			if(op0 && op1 && !op2 && !(op3&1))
				return decode_iclass_mortlach_f16f32_prod4(ctx, dec);
			if(op0 && op1 && !op2 && op3&1 && !op4)
				return decode_iclass_mortlach_b16b16_prod4(ctx, dec);
			if(!op1 && op2 && op3&1)
				return decode_iclass_mortlach_i16i32_prod4(ctx, dec);
			if(op1 && op2 && op3&1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_36_mortlach2_prod4
			if(!op2 && op3&1 && op4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_37_mortlach2_prod4
			if(op2 && !(op3&1))
				return decode_iclass_mortlach_i8i32_prod4(ctx, dec);
			UNMATCHED;
		}
		if(!op0 && !(op1&0x305f) && (op2&0x24)==0x20)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_31_sme
		if(!op0 && (op1&0x305f)==1 && !(op2&4))
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_25_sme
		if(!op0 && (op1&0x305e)==2 && !(op2&4))
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_22_sme
		if(!op0 && (op1&0x305c)==4 && !(op2&4))
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_17_sme
		if(!op0 && (op1&0x3058)==8 && !(op2&4))
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_13_sme
		if(!op0 && (op1&0x3050)==0x40 && !(op2&4))
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_9_sme
		if(!op0 && (op1&0x3010)==0x1000 && !(op2&4)) {
			/* GROUP: mortlach2_ss_prod */
			op0 = (INSWORD>>24)&1;
			op1 = (INSWORD>>21)&1;
			op2 = (INSWORD>>15)&1;
			op3 = (INSWORD>>13)&1;
			op4 = (INSWORD>>3)&1;
			op5 = (INSWORD>>1)&1;
			if(!op0 && !op1 && !op2 && !op3 && !op4)
				return decode_iclass_mortlach_f32f32_1in2ss_prod(ctx, dec);
			if(!op0 && !op1 && !op2 && !op3 && op4 && !op5)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_44_mortlach2_ss_prod
			if(!op0 && op1 && !op2 && !op3 && !op4)
				return decode_iclass_mortlach_f8f32_2in4ss_prod(ctx, dec);
			if(!op0 && op1 && !op2 && !op3 && op4 && !op5)
				return decode_iclass_mortlach_f8f16_2in4ss_prod(ctx, dec);
			if(op0 && !op1 && !op2 && !op3 && !op4)
				return decode_iclass_mortlach_b16f32_2in4ss_prod(ctx, dec);
			if(op0 && !op1 && !op2 && !op3 && op4 && !op5)
				return decode_iclass_mortlach_f16f16_1in2ss_prod(ctx, dec);
			if(op0 && op1 && !op2 && !op3 && !op4)
				return decode_iclass_mortlach_f16f32_2in4ss_prod(ctx, dec);
			if(op0 && op1 && !op2 && !op3 && op4 && !op5)
				return decode_iclass_mortlach_b16b16_1in2ss_prod(ctx, dec);
			if(!op1 && op2 && !op3 && op4)
				return decode_iclass_mortlach_i16i32_2in4ss_prod(ctx, dec);
			if(op1 && op2 && !op3 && op4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_42_mortlach2_ss_prod
			if(!op2 && !op3 && op4 && op5)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_43_mortlach2_ss_prod
			if(op2 && !op3 && !op4)
				return decode_iclass_mortlach_i8i32_2in4ss_prod(ctx, dec);
			if(op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_41_mortlach2_ss_prod
			UNMATCHED;
		}
		if(!op0 && !(op1&0x2010) && (op2&4)==4)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_6_sme
		if(!op0 && (op1&0x2010)==0x10)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_3_sme
		if(!op0 && (op1&0x3000)==0x2000 && !(op2&12)) {
			/* GROUP: mortlach_32bit_fp_prod */
			op0 = (INSWORD>>24)&1;
			op1 = (INSWORD>>21)&1;
			op2 = (INSWORD>>4)&1;
			if(!op0 && !op1)
				return decode_iclass_mortlach_f32f32_prod(ctx, dec);
			if(!op0 && op1 && !op2)
				return decode_iclass_mortlach_f8f32_prod(ctx, dec);
			if(!op0 && op1 && op2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_45_mortlach_32bit_fp_prod
			if(op0 && !op1)
				return decode_iclass_mortlach_b16f32_prod(ctx, dec);
			if(op0 && op1)
				return decode_iclass_mortlach_f16f32_prod(ctx, dec);
			UNMATCHED;
		}
		if(!op0 && (op1&0x3000)==0x2000 && (op2&12)==8) {
			/* GROUP: mortlach2_misc_prod */
			op0 = (INSWORD>>24)&1;
			op1 = (INSWORD>>21)&1;
			op2 = (INSWORD>>4)&1;
			op3 = (INSWORD>>1)&1;
			if(!op0 && !op1)
				return decode_iclass_mortlach_bini32_prod(ctx, dec);
			if(!op0 && op1 && !op2 && !op3)
				return decode_iclass_mortlach_f8f16_prod(ctx, dec);
			if(!op0 && op1 && op2 && !op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_48_mortlach2_misc_prod
			if(!op0 && op1 && op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_47_mortlach2_misc_prod
			if(op0 && !op1 && !op3)
				return decode_iclass_mortlach_f16f16_prod(ctx, dec);
			if(op0 && op1 && !op3)
				return decode_iclass_mortlach_b16b16_prod(ctx, dec);
			if(op0 && op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_46_mortlach2_misc_prod
			UNMATCHED;
		}
		if(op0==1 && !(op1&0x6000)) {
			/* GROUP: mortlach_multi_mem_ctg */
			op0 = (INSWORD>>20)&7;
			op1 = (INSWORD>>15)&1;
			op2 = (INSWORD>>1)&1;
			if(!(op0&6) && !op1)
				return decode_iclass_mortlach_multi2_cld_cldnt_ss_ctg(ctx, dec);
			if(!(op0&6) && op1 && !op2)
				return decode_iclass_mortlach_multi4_cld_cldnt_ss_ctg(ctx, dec);
			if((op0&6)==2 && !op1)
				return decode_iclass_mortlach_multi2_cst_cstnt_ss_ctg(ctx, dec);
			if((op0&6)==2 && op1 && !op2)
				return decode_iclass_mortlach_multi4_cst_cstnt_ss_ctg(ctx, dec);
			if((op0&5)==1 && op1 && op2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_51_mortlach_multi_mem_ctg
			if(op0==4 && !op1)
				return decode_iclass_mortlach_multi2_cld_cldnt_si_ctg(ctx, dec);
			if(op0==4 && op1 && !op2)
				return decode_iclass_mortlach_multi4_cld_cldnt_si_ctg(ctx, dec);
			if(op0==6 && !op1)
				return decode_iclass_mortlach_multi2_cst_cstnt_si_ctg(ctx, dec);
			if(op0==6 && op1 && !op2)
				return decode_iclass_mortlach_multi4_cst_cstnt_si_ctg(ctx, dec);
			if((op0&5)==5)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_49_mortlach_multi_mem_ctg
			if(!(op0&1) && op1 && op2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_50_mortlach_multi_mem_ctg
			UNMATCHED;
		}
		if(op0==1 && (op1&0x6000)==0x4000) {
			/* GROUP: mortlach_multi_mem_nctg */
			op0 = (INSWORD>>20)&7;
			op1 = (INSWORD>>15)&1;
			op2 = (INSWORD>>2)&1;
			if(!(op0&6) && !op1)
				return decode_iclass_mortlach_multi2_cld_cldnt_ss_nctg(ctx, dec);
			if(!(op0&6) && op1 && !op2)
				return decode_iclass_mortlach_multi4_cld_cldnt_ss_nctg(ctx, dec);
			if((op0&6)==2 && !op1)
				return decode_iclass_mortlach_multi2_cst_cstnt_ss_nctg(ctx, dec);
			if((op0&6)==2 && op1 && !op2)
				return decode_iclass_mortlach_multi4_cst_cstnt_ss_nctg(ctx, dec);
			if((op0&5)==1 && op1 && op2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_54_mortlach_multi_mem_nctg
			if(op0==4 && !op1)
				return decode_iclass_mortlach_multi2_cld_cldnt_si_nctg(ctx, dec);
			if(op0==4 && op1 && !op2)
				return decode_iclass_mortlach_multi4_cld_cldnt_si_nctg(ctx, dec);
			if(op0==6 && !op1)
				return decode_iclass_mortlach_multi2_cst_cstnt_si_nctg(ctx, dec);
			if(op0==6 && op1 && !op2)
				return decode_iclass_mortlach_multi4_cst_cstnt_si_nctg(ctx, dec);
			if((op0&5)==5)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_52_mortlach_multi_mem_nctg
			if(!(op0&1) && op1 && op2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_53_mortlach_multi_mem_nctg
			UNMATCHED;
		}
		if(op0==1 && (op1&0x3000)==0x2000 && !(op2&4)) {
			/* GROUP: mortlach_32bit_int_prod */
			op0 = (INSWORD>>21)&1;
			op1 = (INSWORD>>3)&1;
			if(!op0 && op1)
				return decode_iclass_mortlach_i16i32_prod(ctx, dec);
			if(op0 && op1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_55_mortlach_32bit_int_prod
			if(!op1)
				return decode_iclass_mortlach_i8i32_prod(ctx, dec);
			UNMATCHED;
		}
		if(!(op0&2) && (op1&0x3000)==0x2000 && (op2&4)==4)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_4_sme
		if(!(op0&2) && (op1&0x307f)==0x3000 && (op2&0x28)==8) {
			/* GROUP: mortlach2_64bit_prod4 */
			op0 = (INSWORD>>29)&1;
			op1 = (INSWORD>>24)&1;
			op2 = (INSWORD>>21)&1;
			if(!op0 && !op1 && !op2)
				return decode_iclass_mortlach_f64f64_prod4(ctx, dec);
			if(!op0 && !op1 && op2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_57_mortlach2_64bit_prod4
			if(!op0 && op1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_56_mortlach2_64bit_prod4
			if(op0)
				return decode_iclass_mortlach_i16i64_prod4(ctx, dec);
			UNMATCHED;
		}
		if(!(op0&2) && (op1&0x307f)==0x3000 && (op2&0x28)==0x28)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_32_sme
		if(!(op0&2) && (op1&0x307f)==0x3001 && (op2&8)==8)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_26_sme
		if(!(op0&2) && (op1&0x307e)==0x3002 && (op2&8)==8)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_23_sme
		if(!(op0&2) && (op1&0x307c)==0x3004 && (op2&8)==8)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_18_sme
		if(!(op0&2) && (op1&0x3078)==0x3008 && (op2&8)==8)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_14_sme
		if(!(op0&2) && (op1&0x3070)==0x3010 && (op2&8)==8)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_10_sme
		if(!(op0&2) && (op1&0x3060)==0x3020 && (op2&8)==8)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_8_sme
		if(!(op0&2) && (op1&0x3040)==0x3040 && (op2&8)==8)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_7_sme
		if(!(op0&2) && (op1&0x3000)==0x3000 && !(op2&8)) {
			/* GROUP: mortlach_64bit_prod */
			op0 = (INSWORD>>29)&1;
			op1 = (INSWORD>>24)&1;
			op2 = (INSWORD>>21)&1;
			if(!op0 && !op1 && !op2)
				return decode_iclass_mortlach_f64f64_prod(ctx, dec);
			if(!op0 && !op1 && op2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_59_mortlach_64bit_prod
			if(!op0 && op1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_58_mortlach_64bit_prod
			if(op0)
				return decode_iclass_mortlach_i16i64_prod(ctx, dec);
			UNMATCHED;
		}
		if(op0==2 && (op1&0x7f00)==0x200) {
			/* GROUP: mortlach_zero */
			op0 = (INSWORD>>8)&0x3ff;
			if(!op0)
				return decode_iclass_mortlach_zero(ctx, dec);
			if(op0)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_60_mortlach_zero
			UNMATCHED;
		}
		if(op0==2 && (op1&0x7f00)==0x300) {
			/* GROUP: mortlach_multizero */
			op0 = (INSWORD>>3)&0x3ff;
			if(!op0)
				return decode_iclass_mortlach_multi_zero(ctx, dec);
			if(op0)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_61_mortlach_multizero
			UNMATCHED;
		}
		if(op0==2 && (op1&0x7f00)==0x1200)
			return decode_iclass_mortlach_zero_zt(ctx, dec);
		if(op0==2 && (op1&0x7f00)==0x1300) {
			/* GROUP: mortlach_mov_zt */
			op0 = (INSWORD>>17)&1;
			op1 = (INSWORD>>15)&3;
			op2 = (INSWORD>>14)&1;
			if(!op0 && !op1)
				return decode_iclass_mortlach_extract_zt(ctx, dec);
			if(!op0 && op1==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_63_mortlach_mov_zt
			if(op0 && !op1)
				return decode_iclass_mortlach_insert_zt(ctx, dec);
			if(op0 && op1==2 && !op2)
				return decode_iclass_mortlach_move_to_zt(ctx, dec);
			if(op0 && op1==2 && op2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_64_mortlach_mov_zt
			if(op1&1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_62_mortlach_mov_zt
			UNMATCHED;
		}
		if(op0==2 && (op1&0x6e00)==0x600)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_11_sme
		if(op0==2 && (op1&0x7e00)==0x2600) {
			/* GROUP: mortlach_zt_expand_nctg */
			op0 = (INSWORD>>16)&7;
			op1 = (INSWORD>>14)&3;
			op4 = (INSWORD>>6)&1;
			op2 = (INSWORD>>5)&1;
			op3 = (INSWORD>>2)&3;
			if(!(op0&6) && !op1 && !op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_68_mortlach_zt_expand_nctg
			if(op0==2 && !op1 && !op4 && !op2 && !op3)
				return decode_iclass_mortlach_expand_4dst3src_nctg(ctx, dec);
			if(op0==2 && !op1 && op4 && !op2 && !op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_70_mortlach_zt_expand_nctg
			if(op0==3 && !op1 && !op2 && !op3)
				return decode_iclass_mortlach_expand_4dst2src_nctg(ctx, dec);
			if((op0&6)==2 && !op1 && op2 && !op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_69_mortlach_zt_expand_nctg
			if((op0&4)==4 && !op1 && !op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_67_mortlach_zt_expand_nctg
			if(op1==2 && !op3)
				return decode_iclass_mortlach_expand_4dst_nctg(ctx, dec);
			if(!(op1&1) && op3==1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_66_mortlach_zt_expand_nctg
			if(op1&1 && !(op3&2))
				return decode_iclass_mortlach_expand_2dst_nctg(ctx, dec);
			if((op3&2)==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_65_mortlach_zt_expand_nctg
			UNMATCHED;
		}
		if(op0==2 && (op1&0x7e00)==0x3600)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_15_sme
		if(op0==2 && (op1&0x6e00)==0x2200) {
			/* GROUP: mortlach_zt_expand_ctg */
			op0 = (INSWORD>>22)&1;
			op1 = (INSWORD>>14)&0x1f;
			op4 = (INSWORD>>6)&1;
			op2 = (INSWORD>>5)&1;
			op3 = INSWORD&3;
			if(!op0 && !(op1&0x1b) && !op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_74_mortlach_zt_expand_ctg
			if(!op0 && op1==8 && !op4 && !op2 && !op3)
				return decode_iclass_mortlach_expand_4dst3src_ctg(ctx, dec);
			if(!op0 && op1==8 && op4 && !op2 && !op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_76_mortlach_zt_expand_ctg
			if(!op0 && op1==12 && !op2 && !op3)
				return decode_iclass_mortlach_expand_4dst2src_ctg(ctx, dec);
			if(!op0 && (op1&0x1b)==8 && op2 && !op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_75_mortlach_zt_expand_ctg
			if(!op0 && (op1&0x13)==0x10 && !op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_73_mortlach_zt_expand_ctg
			if(!op0 && (op1&3)==2 && !op3)
				return decode_iclass_mortlach_expand_4dst_ctg(ctx, dec);
			if(!op0 && !(op1&1) && op3==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_72_mortlach_zt_expand_ctg
			if(!op0 && op1&1 && !(op3&1))
				return decode_iclass_mortlach_expand_2dst_ctg(ctx, dec);
			if(!op0 && op3&1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_71_mortlach_zt_expand_ctg
			if(op0)
				return decode_iclass_mortlach_expand_1dst(ctx, dec);
			UNMATCHED;
		}
		if(op0==2 && !(op1&0x4e80) && !(op2&0x10)) {
			/* GROUP: mortlach_ins */
			op0 = (INSWORD>>22)&3;
			op1 = (INSWORD>>18)&1;
			op2 = (INSWORD>>15)&3;
			op3 = (INSWORD>>10)&7;
			op4 = (INSWORD>>5)&3;
			op5 = (INSWORD>>3)&1;
			if(!op0 && op1 && !op2 && op3==2 && !(op4&1) && !op5)
				return decode_iclass_mortlach_multi2_za_insert_ctg(ctx, dec);
			if(!op0 && op1 && !op2 && op3==3 && !op4 && !op5)
				return decode_iclass_mortlach_multi4_za_insert_ctg(ctx, dec);
			if(!op0 && op1 && !op2 && op3==3 && op4==2 && !op5)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_84_mortlach_ins
			if(!op0 && op1 && op2==1 && (op3&6)==2 && !(op4&1) && !op5)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_83_mortlach_ins
			if(!op1)
				return decode_iclass_mortlach_insert_pred(ctx, dec);
			if(op1 && !(op2&2) && !op3 && !(op4&1) && !op5)
				return decode_iclass_mortlach_multi2_insert_ctg(ctx, dec);
			if(op1 && !(op2&2) && op3==1 && !op4 && !op5)
				return decode_iclass_mortlach_multi4_insert_ctg(ctx, dec);
			if(op1 && !(op2&2) && op3==1 && op4==2 && !op5)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_82_mortlach_ins
			if(op1 && !(op2&2) && !(op3&4) && !(op4&1) && op5)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_80_mortlach_ins
			if(op1 && !(op2&2) && !(op3&4) && op4&1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_79_mortlach_ins
			if(op1 && !(op2&2) && (op3&4)==4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_78_mortlach_ins
			if(op1 && (op2&2)==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_77_mortlach_ins
			if(op0 && op1 && !(op2&2) && (op3&6)==2 && !(op4&1) && !op5)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_81_mortlach_ins
			UNMATCHED;
		}
		if(op0==2 && !(op1&0x4e80) && (op2&0x10)==0x10)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_16_sme
		if(op0==2 && (op1&0x4e80)==0x80) {
			/* GROUP: mortlach_ext */
			op0 = (INSWORD>>22)&3;
			op1 = (INSWORD>>18)&1;
			op2 = (INSWORD>>15)&3;
			op3 = (INSWORD>>10)&7;
			op4 = (INSWORD>>8)&3;
			op5 = INSWORD&3;
			if(!op0 && op1 && !op2 && op3==2 && !op4 && !(op5&1))
				return decode_iclass_mortlach_multi2_za_extract_ctg(ctx, dec);
			if(!op0 && op1 && !op2 && op3==2 && op4==2 && !(op5&1))
				return decode_iclass_mortlach_multi2_za_extract_zero(ctx, dec);
			if(!op0 && op1 && !op2 && op3==3 && !op4 && !op5)
				return decode_iclass_mortlach_multi4_za_extract_ctg(ctx, dec);
			if(!op0 && op1 && !op2 && op3==3 && op4==2 && !op5)
				return decode_iclass_mortlach_multi4_za_extract_zero(ctx, dec);
			if(!op0 && op1 && !op2 && op3==3 && !(op4&1) && op5==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_93_mortlach_ext
			if(!op0 && op1 && op2==1 && (op3&6)==2 && !(op4&1) && !(op5&1))
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_92_mortlach_ext
			if(!op1 && !op3 && (op4&2)==2)
				return decode_iclass_mortlach_extract_zero(ctx, dec);
			if(!op1 && !(op4&2))
				return decode_iclass_mortlach_extract_pred(ctx, dec);
			if(!op1 && op3 && (op4&2)==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_86_mortlach_ext
			if(op1 && !(op2&2) && !op3 && !op4 && !(op5&1))
				return decode_iclass_mortlach_multi2_extract_ctg(ctx, dec);
			if(op1 && !(op2&2) && !op3 && op4==2 && !(op5&1))
				return decode_iclass_mortlach_multi2_extract_zero(ctx, dec);
			if(op1 && !(op2&2) && op3==1 && !op4 && !op5)
				return decode_iclass_mortlach_multi4_extract_ctg(ctx, dec);
			if(op1 && !(op2&2) && op3==1 && op4==2 && !op5)
				return decode_iclass_mortlach_multi4_extract_zero(ctx, dec);
			if(op1 && !(op2&2) && op3==1 && !(op4&1) && op5==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_91_mortlach_ext
			if(op1 && !(op2&2) && !(op3&4) && !(op4&1) && op5&1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_89_mortlach_ext
			if(op1 && !(op2&2) && !(op3&4) && op4&1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_88_mortlach_ext
			if(op1 && !(op2&2) && (op3&4)==4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_87_mortlach_ext
			if(op1 && (op2&2)==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_85_mortlach_ext
			if(op0 && op1 && !(op2&2) && (op3&6)==2 && !(op4&1) && !(op5&1))
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_90_mortlach_ext
			UNMATCHED;
		}
		if(op0==2 && (op1&0x4e00)==0x400 && !(op2&8)) {
			/* GROUP: mortlach_hvadd */
			op0 = (INSWORD>>23)&1;
			op1 = (INSWORD>>17)&3;
			op2 = (INSWORD>>4)&1;
			if(!op0)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_94_mortlach_hvadd
			if(op0 && !op1 && !op2)
				return decode_iclass_mortlach_addhv(ctx, dec);
			if(op0 && !op1 && op2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_96_mortlach_hvadd
			if(op0 && op1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_95_mortlach_hvadd
			UNMATCHED;
		}
		if(op0==2 && (op1&0x4e00)==0x400 && (op2&8)==8)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_12_sme
		if(op0==2 && (op1&0x4800)==0x800)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_5_sme
		if(op0==2 && (op1&0x6c20)==0x4800) {
			/* GROUP: mortlach_multi_array_1a */
			op0 = (INSWORD>>22)&1;
			op1 = (INSWORD>>10)&7;
			op2 = (INSWORD>>2)&7;
			op3 = (INSWORD>>1)&1;
			if(!op0 && !op1 && !op2 && op3)
				return decode_iclass_mortlach_multi2_zz_za_fp8_fma_long_long_sm(ctx, dec);
			if(!op0 && !op1 && op2 && op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_100_mortlach_multi_array_1a
			if(!op0 && op1==2)
				return decode_iclass_mortlach_multi2_zz_za_fma_long_sm(ctx, dec);
			if(!op0 && op1==3)
				return decode_iclass_mortlach_multi1_zz_za_fma_long_sm(ctx, dec);
			if(!op0 && op1==4)
				return decode_iclass_mortlach_multi2_z_za_fpdot_sm(ctx, dec);
			if(!op0 && op1==5 && (op2&2)==2)
				return decode_iclass_mortlach_multi2_z_za_mixed_dot_sm(ctx, dec);
			if(op0 && !op1 && op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_99_mortlach_multi_array_1a
			if(op0 && op1==2)
				return decode_iclass_mortlach_multi2_zz_za_mla_long_sm(ctx, dec);
			if(op0 && op1==3)
				return decode_iclass_mortlach_multi1_zz_za_mla_long_sm(ctx, dec);
			if(op0 && op1==4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_97_mortlach_multi_array_1a
			if(op0 && op1==5 && (op2&2)==2)
				return decode_iclass_mortlach_multi2_z_za_2way_dot_sm(ctx, dec);
			if(!op1 && !op3)
				return decode_iclass_mortlach_multi2_zz_za_mla_long_long_sm(ctx, dec);
			if(op1==1)
				return decode_iclass_mortlach_multi1_zz_za_mla_long_long_sm(ctx, dec);
			if(op1==5 && !(op2&2))
				return decode_iclass_mortlach_multi2_z_za_4way_dot_sm(ctx, dec);
			if(op1==6 && !(op2&4))
				return decode_iclass_mortlach_multi2_zz_za_float_sm(ctx, dec);
			if(op1==6 && (op2&4)==4)
				return decode_iclass_mortlach_multi2_zz_za_int_sm(ctx, dec);
			if(op1==7 && !(op2&4))
				return decode_iclass_mortlach_multi2_zz_za_f16_sm(ctx, dec);
			if(op1==7 && (op2&4)==4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_98_mortlach_multi_array_1a
			UNMATCHED;
		}
		if(op0==2 && (op1&0x6c20)==0x4c00) {
			/* GROUP: mortlach_multi_array_1b */
			op0 = (INSWORD>>22)&1;
			op1 = (INSWORD>>10)&7;
			op2 = (INSWORD>>2)&7;
			op3 = (INSWORD>>1)&1;
			if(!op0 && !op1 && !op2 && op3)
				return decode_iclass_mortlach_multi4_zz_za_fp8_fma_long_long_sm(ctx, dec);
			if(!op0 && !op1 && op2 && op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_107_mortlach_multi_array_1b
			if(!op0 && op1==1 && !op2)
				return decode_iclass_mortlach_multi1_zz_za_fp8_fma_long_long_sm(ctx, dec);
			if(!op0 && op1==1 && op2==1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_108_mortlach_multi_array_1b
			if(!op0 && op1==2)
				return decode_iclass_mortlach_multi4_zz_za_fma_long_sm(ctx, dec);
			if(!op0 && op1==3 && !(op2&6))
				return decode_iclass_mortlach_multi1_zz_za_fp8_fma_long_sm(ctx, dec);
			if(!op0 && (op1&5)==1 && (op2&6)==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_105_mortlach_multi_array_1b
			if(!op0 && (op1&5)==1 && (op2&4)==4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_102_mortlach_multi_array_1b
			if(!op0 && op1==4)
				return decode_iclass_mortlach_multi4_z_za_fpdot_sm(ctx, dec);
			if(!op0 && op1==5 && (op2&2)==2)
				return decode_iclass_mortlach_multi4_z_za_mixed_dot_sm(ctx, dec);
			if(op0 && !op1 && op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_106_mortlach_multi_array_1b
			if(op0 && op1==2)
				return decode_iclass_mortlach_multi4_zz_za_mla_long_sm(ctx, dec);
			if(op0 && (op1&5)==1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_101_mortlach_multi_array_1b
			if(op0 && op1==4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_103_mortlach_multi_array_1b
			if(op0 && op1==5 && (op2&2)==2)
				return decode_iclass_mortlach_multi4_z_za_2way_dot_sm(ctx, dec);
			if(!op1 && !op3)
				return decode_iclass_mortlach_multi4_zz_za_mla_long_long_sm(ctx, dec);
			if(op1==5 && !(op2&2))
				return decode_iclass_mortlach_multi4_z_za_4way_dot_sm(ctx, dec);
			if(op1==6 && !(op2&4))
				return decode_iclass_mortlach_multi4_zz_za_float_sm(ctx, dec);
			if(op1==6 && (op2&4)==4)
				return decode_iclass_mortlach_multi4_zz_za_int_sm(ctx, dec);
			if(op1==7 && !(op2&4))
				return decode_iclass_mortlach_multi4_zz_za_f16_sm(ctx, dec);
			if(op1==7 && (op2&4)==4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_104_mortlach_multi_array_1b
			UNMATCHED;
		}
		if(op0==2 && (op1&0x683c)==0x483c) {
			/* GROUP: mortlach_multi_sve_6 */
			op0 = (INSWORD>>10)&3;
			op1 = INSWORD&15;
			if(op0==1 && !(op1&3))
				return decode_iclass_mortlach_multi4_lut6_16_ctg(ctx, dec);
			if(op0==1 && (op1&3)==1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_112_mortlach_multi_sve_6
			if(op0==1 && (op1&2)==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_110_mortlach_multi_sve_6
			if(op0==3 && !(op1&12))
				return decode_iclass_mortlach_multi4_lut6_16_nctg(ctx, dec);
			if(op0==3 && (op1&12)==4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_113_mortlach_multi_sve_6
			if(op0==3 && (op1&8)==8)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_111_mortlach_multi_sve_6
			if(!(op0&1))
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_109_mortlach_multi_sve_6
			UNMATCHED;
		}
		if(op0==2 && (op1&0x6860)==0x6800) {
			/* GROUP: mortlach_multi_array_2a */
			op0 = (INSWORD>>22)&1;
			op1 = (INSWORD>>19)&3;
			op2 = (INSWORD>>17)&3;
			op3 = (INSWORD>>10)&7;
			op4 = (INSWORD>>5)&1;
			op5 = (INSWORD>>2)&7;
			op6 = (INSWORD>>1)&1;
			if(!op0 && !op3 && op4 && !op5 && !op6)
				return decode_iclass_mortlach_multi2_zz_za_fp8_fma_long_long_mm(ctx, dec);
			if(!op0 && !op3 && op4 && op5==1 && !op6)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_130_mortlach_multi_array_2a
			if(!op0 && !op3 && op4 && (op5&6)==4 && !op6)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_128_mortlach_multi_array_2a
			if(!op0 && !op3 && op4 && !(op5&2) && op6)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_124_mortlach_multi_array_2a
			if(!op0 && op3==2 && !op4 && !(op5&1))
				return decode_iclass_mortlach_multi2_zz_za_fma_long_mm(ctx, dec);
			if(!op0 && op3==2 && op4 && !op5)
				return decode_iclass_mortlach_multi2_zz_za_fp8_fma_long_mm(ctx, dec);
			if(!op0 && op3==2 && op4 && op5==4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_129_mortlach_multi_array_2a
			if(!op0 && op3==2 && op4 && (op5&3)==1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_125_mortlach_multi_array_2a
			if(!op0 && (op3&5)==1 && op4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_116_mortlach_multi_array_2a
			if(!op0 && op3==4 && !(op5&2))
				return decode_iclass_mortlach_multi2_z_za_fpdot_mm(ctx, dec);
			if(!op0 && op3==5 && !op4 && (op5&6)==2)
				return decode_iclass_mortlach_multi2_z_za_mixed_dot_mm(ctx, dec);
			if(!op0 && op3==5 && !op4 && (op5&6)==6)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_126_mortlach_multi_array_2a
			if(!op0 && op3==6 && op4 && !(op5&2))
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_122_mortlach_multi_array_2a
			if(!op0 && (op3&5)==5 && op4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_117_mortlach_multi_array_2a
			if(!op0 && !(op3&1) && op4 && (op5&2)==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_118_mortlach_multi_array_2a
			if(op0 && op3==2 && !op4 && !(op5&1))
				return decode_iclass_mortlach_multi2_zz_za_mla_long_mm(ctx, dec);
			if(op0 && op3==4 && !op4 && !(op5&2))
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_123_mortlach_multi_array_2a
			if(op0 && op3==5 && !op4 && (op5&2)==2)
				return decode_iclass_mortlach_multi2_z_za_2way_dot_mm(ctx, dec);
			if(op0 && op4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_114_mortlach_multi_array_2a
			if(!op1 && !op2 && op3==7 && !op4 && !(op5&4))
				return decode_iclass_mortlach_multi2_z_za_float_mm(ctx, dec);
			if(!op1 && !op2 && op3==7 && !op4 && (op5&4)==4)
				return decode_iclass_mortlach_multi2_z_za_int_mm(ctx, dec);
			if(!op1 && op2==2 && op3==7 && !op4 && !(op5&4))
				return decode_iclass_mortlach_multi2_z_za_f16_mm(ctx, dec);
			if(!op1 && op2==2 && op3==7 && !op4 && (op5&4)==4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_131_mortlach_multi_array_2a
			if(!op1 && op2&1 && op3==7 && !op4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_127_mortlach_multi_array_2a
			if(!op3 && !op4 && !op6)
				return decode_iclass_mortlach_multi2_zz_za_mla_long_long_mm(ctx, dec);
			if(!op3 && !op4 && op6)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_120_mortlach_multi_array_2a
			if(op3==2 && !op4 && op5&1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_121_mortlach_multi_array_2a
			if((op3&5)==1 && !op4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_115_mortlach_multi_array_2a
			if(op3==4 && !op4 && (op5&2)==2)
				return decode_iclass_mortlach_multi2_zz_za_f16_mm(ctx, dec);
			if(op3==5 && !op4 && !(op5&2))
				return decode_iclass_mortlach_multi2_z_za_4way_dot_mm(ctx, dec);
			if(op3==6 && !op4 && !(op5&4))
				return decode_iclass_mortlach_multi2_zz_za_float_mm(ctx, dec);
			if(op3==6 && !op4 && (op5&4)==4)
				return decode_iclass_mortlach_multi2_zz_za_int_mm(ctx, dec);
			if(op1 && op3==7 && !op4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_119_mortlach_multi_array_2a
			UNMATCHED;
		}
		if(op0==2 && (op1&0x6860)==0x6840) {
			/* GROUP: mortlach_multi_array_2b */
			op0 = (INSWORD>>22)&1;
			op1 = (INSWORD>>19)&3;
			op2 = (INSWORD>>17)&3;
			op3 = (INSWORD>>10)&7;
			op4 = (INSWORD>>5)&3;
			op5 = (INSWORD>>2)&7;
			op6 = (INSWORD>>1)&1;
			if(!op0 && !(op2&1) && !op3 && op4==1 && !op5 && !op6)
				return decode_iclass_mortlach_multi4_zz_za_fp8_fma_long_long_mm(ctx, dec);
			if(!op0 && !(op2&1) && !op3 && op4==1 && op5==1 && !op6)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_150_mortlach_multi_array_2b
			if(!op0 && !(op2&1) && !op3 && op4==1 && (op5&6)==4 && !op6)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_147_mortlach_multi_array_2b
			if(!op0 && !(op2&1) && !op3 && op4==1 && !(op5&2) && op6)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_144_mortlach_multi_array_2b
			if(!op0 && !(op2&1) && op3==2 && !op4 && !(op5&1))
				return decode_iclass_mortlach_multi4_zz_za_fma_long_mm(ctx, dec);
			if(!op0 && !(op2&1) && op3==2 && op4==1 && !op5)
				return decode_iclass_mortlach_multi4_zz_za_fp8_fma_long_mm(ctx, dec);
			if(!op0 && !(op2&1) && op3==2 && op4==1 && op5==4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_148_mortlach_multi_array_2b
			if(!op0 && !(op2&1) && op3==2 && op4==1 && (op5&3)==1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_145_mortlach_multi_array_2b
			if(!op0 && !(op2&1) && (op3&5)==1 && op4==1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_136_mortlach_multi_array_2b
			if(!op0 && !(op2&1) && op3==4 && !(op4&2) && !(op5&2))
				return decode_iclass_mortlach_multi4_z_za_fpdot_mm(ctx, dec);
			if(!op0 && !(op2&1) && op3==5 && !op4 && (op5&6)==2)
				return decode_iclass_mortlach_multi4_z_za_mixed_dot_mm(ctx, dec);
			if(!op0 && !(op2&1) && op3==5 && !op4 && (op5&6)==6)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_146_mortlach_multi_array_2b
			if(!op0 && !(op2&1) && op3==6 && op4==1 && !(op5&2))
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_142_mortlach_multi_array_2b
			if(!op0 && !(op2&1) && (op3&5)==5 && op4==1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_137_mortlach_multi_array_2b
			if(!op0 && !(op2&1) && !(op3&1) && op4==1 && (op5&2)==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_138_mortlach_multi_array_2b
			if(op0 && !(op2&1) && op3==2 && !op4 && !(op5&1))
				return decode_iclass_mortlach_multi4_zz_za_mla_long_mm(ctx, dec);
			if(op0 && !(op2&1) && op3==4 && !op4 && !(op5&2))
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_143_mortlach_multi_array_2b
			if(op0 && !(op2&1) && op3==5 && !op4 && (op5&2)==2)
				return decode_iclass_mortlach_multi4_z_za_2way_dot_mm(ctx, dec);
			if(op0 && !(op2&1) && op4==1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_134_mortlach_multi_array_2b
			if(!op1 && !op2 && op3==7 && !op4 && !(op5&4))
				return decode_iclass_mortlach_multi4_z_za_float_mm(ctx, dec);
			if(!op1 && !op2 && op3==7 && !op4 && (op5&4)==4)
				return decode_iclass_mortlach_multi4_z_za_int_mm(ctx, dec);
			if(!op1 && op2==2 && op3==7 && !op4 && !(op5&4))
				return decode_iclass_mortlach_multi4_z_za_f16_mm(ctx, dec);
			if(!op1 && op2==2 && op3==7 && !op4 && (op5&4)==4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_149_mortlach_multi_array_2b
			if(!(op2&1) && !op3 && !op4 && !op6)
				return decode_iclass_mortlach_multi4_zz_za_mla_long_long_mm(ctx, dec);
			if(!(op2&1) && !op3 && !op4 && op6)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_140_mortlach_multi_array_2b
			if(!(op2&1) && op3==2 && !op4 && op5&1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_141_mortlach_multi_array_2b
			if(!(op2&1) && (op3&5)==1 && !op4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_135_mortlach_multi_array_2b
			if(!(op2&1) && op3==4 && !op4 && (op5&2)==2)
				return decode_iclass_mortlach_multi4_zz_za_f16_mm(ctx, dec);
			if(!(op2&1) && op3==5 && !op4 && !(op5&2))
				return decode_iclass_mortlach_multi4_z_za_4way_dot_mm(ctx, dec);
			if(!(op2&1) && op3==6 && !op4 && !(op5&4))
				return decode_iclass_mortlach_multi4_zz_za_float_mm(ctx, dec);
			if(!(op2&1) && op3==6 && !op4 && (op5&4)==4)
				return decode_iclass_mortlach_multi4_zz_za_int_mm(ctx, dec);
			if(!(op2&1) && (op4&2)==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_133_mortlach_multi_array_2b
			if(op2&1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_132_mortlach_multi_array_2b
			if(op1 && !(op2&1) && op3==7 && !op4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_139_mortlach_multi_array_2b
			UNMATCHED;
		}
		if(op0==2 && (op1&0x683c)==0x683c)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_19_sme
		if(op0==2 && (op1&0x4c00)==0x4000) {
			/* GROUP: mortlach_multi_indexed_1 */
			op0 = (INSWORD>>22)&3;
			op1 = (INSWORD>>12)&1;
			op2 = (INSWORD>>2)&7;
			if(!op0)
				return decode_iclass_mortlach_multi1_mla_long_long_idx_s(ctx, dec);
			if(op0==1 && !op2)
				return decode_iclass_mortlach_multi1_fp8_fma_long_long_idx(ctx, dec);
			if(op0==1 && op2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_151_mortlach_multi_indexed_1
			if(op0==2 && !op1 && !(op2&1))
				return decode_iclass_mortlach_multi1_mla_long_long_idx_d(ctx, dec);
			if(op0==2 && !op1 && op2&1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_152_mortlach_multi_indexed_1
			if(op0==2 && op1)
				return decode_iclass_mortlach_multi1_fma_long_idx(ctx, dec);
			if(op0==3 && !op1 && !(op2&4))
				return decode_iclass_mortlach_multi1_fp8_fma_long_idx(ctx, dec);
			if(op0==3 && !op1 && (op2&4)==4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_153_mortlach_multi_indexed_1
			if(op0==3 && op1)
				return decode_iclass_mortlach_multi1_mla_long_idx(ctx, dec);
			UNMATCHED;
		}
		if(op0==2 && (op1&0x4c20)==0x4400) {
			/* GROUP: mortlach_multi_indexed_2 */
			op0 = (INSWORD>>22)&3;
			op1 = (INSWORD>>11)&3;
			op2 = (INSWORD>>5)&1;
			op3 = (INSWORD>>3)&3;
			if(!op0 && !(op1&2))
				return decode_iclass_mortlach_multi2_mla_long_long_idx_s(ctx, dec);
			if(!op0 && (op1&2)==2)
				return decode_iclass_mortlach_multi2_zza_idx_h(ctx, dec);
			if(op0==1)
				return decode_iclass_mortlach_multi2_zza_idx_s(ctx, dec);
			if(op0==2 && !op1 && !op2)
				return decode_iclass_mortlach_multi2_mla_long_long_idx_d(ctx, dec);
			if(op0==2 && op1==1 && !op2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_155_mortlach_multi_indexed_2
			if(op0==2 && !(op1&2) && op2 && !op3)
				return decode_iclass_mortlach_multi2_fp8_fma_long_long_idx(ctx, dec);
			if(op0==2 && !(op1&2) && op2 && op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_156_mortlach_multi_indexed_2
			if(op0==2 && (op1&2)==2 && !op2)
				return decode_iclass_mortlach_multi2_fma_long_idx(ctx, dec);
			if(op0==2 && (op1&2)==2 && op2 && !(op3&2))
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_157_mortlach_multi_indexed_2
			if(op0==2 && (op1&2)==2 && op2 && (op3&2)==2)
				return decode_iclass_mortlach_multi2_fp8_fma_long_idx(ctx, dec);
			if(op0==3 && !op1 && !op2)
				return decode_iclass_mortlach_multi2_zza_idx_d(ctx, dec);
			if(op0==3 && op1==1 && !op2)
				return decode_iclass_mortlach_multi2_fp8_fvdot_idx_s(ctx, dec);
			if(op0==3 && (op1&2)==2 && !op2)
				return decode_iclass_mortlach_multi2_mla_long_idx(ctx, dec);
			if(op0==3 && op2 && !(op3&2))
				return decode_iclass_mortlach_multi2_fp8_fdot_idx(ctx, dec);
			if(op0==3 && op2 && (op3&2)==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_154_mortlach_multi_indexed_2
			UNMATCHED;
		}
		if(op0==2 && (op1&0x4c20)==0x4420) {
			/* GROUP: mortlach_multi_indexed_3 */
			op0 = (INSWORD>>22)&3;
			op1 = (INSWORD>>11)&3;
			op2 = (INSWORD>>4)&7;
			op3 = (INSWORD>>3)&1;
			if(!op0 && !(op1&2) && !(op2&4))
				return decode_iclass_mortlach_multi4_mla_long_long_idx_s(ctx, dec);
			if(!op0 && !(op1&2) && op2==4 && !op3)
				return decode_iclass_mortlach_multi4_fp8_fma_long_long_idx(ctx, dec);
			if(!op0 && !(op1&2) && op2==4 && op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_165_mortlach_multi_indexed_3
			if(!op0 && (op1&2)==2 && !(op2&4))
				return decode_iclass_mortlach_multi4_zza_idx_h(ctx, dec);
			if(!op0 && (op1&2)==2 && op2==4)
				return decode_iclass_mortlach_multi4_fp8_fdot_idx_h(ctx, dec);
			if(!op0 && op2==5)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_161_mortlach_multi_indexed_3
			if(!op0 && (op2&6)==6)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_159_mortlach_multi_indexed_3
			if(op0==1 && !(op2&4))
				return decode_iclass_mortlach_multi4_zza_idx_s(ctx, dec);
			if(op0==2 && !op1 && !(op2&6))
				return decode_iclass_mortlach_multi4_mla_long_long_idx_d(ctx, dec);
			if(op0==2 && op1==1 && !(op2&6))
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_163_mortlach_multi_indexed_3
			if(op0==2 && !(op1&2) && (op2&6)==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_162_mortlach_multi_indexed_3
			if(op0==2 && (op1&2)==2 && !(op2&6))
				return decode_iclass_mortlach_multi4_fma_long_idx(ctx, dec);
			if(op0==2 && (op1&2)==2 && op2==2)
				return decode_iclass_mortlach_multi4_fp8_fma_long_idx(ctx, dec);
			if(op0==2 && (op1&2)==2 && op2==3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_164_mortlach_multi_indexed_3
			if(op0==3 && !(op1&2) && !(op2&6))
				return decode_iclass_mortlach_multi4_zza_idx_d(ctx, dec);
			if(op0==3 && (op1&2)==2 && !(op2&6))
				return decode_iclass_mortlach_multi4_mla_long_idx(ctx, dec);
			if(op0==3 && (op2&6)==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_160_mortlach_multi_indexed_3
			if(op0 && (op2&4)==4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_158_mortlach_multi_indexed_3
			UNMATCHED;
		}
		if(op0==2 && (op1&0x4c3e)==0x4828) {
			/* GROUP: mortlach_multi_sve_2a */
			op0 = (INSWORD>>10)&1;
			op1 = (INSWORD>>8)&3;
			op2 = (INSWORD>>5)&7;
			if(!op0 && !op1 && !(op2&6))
				return decode_iclass_mortlach_multi2_z_z_minmax_sm(ctx, dec);
			if(!op0 && !op1 && op2==5)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_172_mortlach_multi_sve_2a
			if(!op0 && op1==1 && !(op2&6))
				return decode_iclass_mortlach_multi2_z_z_fminmax_sm(ctx, dec);
			if(!op0 && op1==1 && op2==4)
				return decode_iclass_mortlach_multi2_z_z_fscale_sm(ctx, dec);
			if(!op0 && op1==1 && op2==5)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_173_mortlach_multi_sve_2a
			if(!op0 && !(op1&2) && (op2&2)==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_167_mortlach_multi_sve_2a
			if(!op0 && op1==2)
				return decode_iclass_mortlach_multi2_z_z_shift_sm(ctx, dec);
			if(!op0 && op1==3 && !op2)
				return decode_iclass_mortlach_multi2_z_z_add_sm(ctx, dec);
			if(!op0 && op1==3 && op2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_168_mortlach_multi_sve_2a
			if(op0 && !op1 && !op2)
				return decode_iclass_mortlach_multi2_z_z_sqdmulh_sm(ctx, dec);
			if(op0 && !op1 && (op2&3)==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_170_mortlach_multi_sve_2a
			if(op0 && !op1 && op2&1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_169_mortlach_multi_sve_2a
			if(op0 && op1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_166_mortlach_multi_sve_2a
			if(!op1 && op2==4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_171_mortlach_multi_sve_2a
			UNMATCHED;
		}
		if(op0==2 && (op1&0x4c3e)==0x482a && !(op2&2)) {
			/* GROUP: mortlach_multi_sve_2b */
			op0 = (INSWORD>>10)&1;
			op1 = (INSWORD>>8)&3;
			op2 = (INSWORD>>5)&7;
			if(!op0 && !op1 && !(op2&6))
				return decode_iclass_mortlach_multi4_z_z_minmax_sm(ctx, dec);
			if(!op0 && !op1 && op2==5)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_180_mortlach_multi_sve_2b
			if(!op0 && op1==1 && !(op2&6))
				return decode_iclass_mortlach_multi4_z_z_fminmax_sm(ctx, dec);
			if(!op0 && op1==1 && op2==4)
				return decode_iclass_mortlach_multi4_z_z_fscale_sm(ctx, dec);
			if(!op0 && op1==1 && op2==5)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_181_mortlach_multi_sve_2b
			if(!op0 && !(op1&2) && (op2&2)==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_175_mortlach_multi_sve_2b
			if(!op0 && op1==2)
				return decode_iclass_mortlach_multi4_z_z_shift_sm(ctx, dec);
			if(!op0 && op1==3 && !op2)
				return decode_iclass_mortlach_multi4_z_z_add_sm(ctx, dec);
			if(!op0 && op1==3 && op2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_176_mortlach_multi_sve_2b
			if(op0 && !op1 && !op2)
				return decode_iclass_mortlach_multi4_z_z_sqdmulh_sm(ctx, dec);
			if(op0 && !op1 && (op2&3)==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_178_mortlach_multi_sve_2b
			if(op0 && !op1 && op2&1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_177_mortlach_multi_sve_2b
			if(op0 && op1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_174_mortlach_multi_sve_2b
			if(!op1 && op2==4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_179_mortlach_multi_sve_2b
			UNMATCHED;
		}
		if(op0==2 && (op1&0x4c3e)==0x482a && (op2&2)==2)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_27_sme
		if(op0==2 && (op1&0x4c3c)==0x4c28)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_20_sme
		if(op0==2 && (op1&0x48ff)==0x482e && !(op2&2)) {
			/* GROUP: mortlach_multi_sve_2d0 */
			op0 = (INSWORD>>7)&7;
			if(!op0)
				return decode_iclass_mortlach_multi4_z_z_minmax_mm(ctx, dec);
			if(op0==1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_183_mortlach_multi_sve_2d0
			if(op0==2)
				return decode_iclass_mortlach_multi4_z_z_fminmax_mm(ctx, dec);
			if(op0==3)
				return decode_iclass_mortlach_multi4_z_z_fscale_mm(ctx, dec);
			if((op0&6)==4)
				return decode_iclass_mortlach_multi4_z_z_shift_mm(ctx, dec);
			if((op0&6)==6)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_182_mortlach_multi_sve_2d0
			UNMATCHED;
		}
		if(op0==2 && (op1&0x48ff)==0x482f && !(op2&2)) {
			/* GROUP: mortlach_multi_sve_2d1 */
			op0 = (INSWORD>>5)&0x1f;
			if(!op0)
				return decode_iclass_mortlach_multi4_z_z_sqdmulh_mm(ctx, dec);
			if(op0)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_184_mortlach_multi_sve_2d1
			UNMATCHED;
		}
		if(op0==2 && (op1&0x48fe)==0x48ae && !(op2&2))
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_33_sme
		if(op0==2 && (op1&0x487f)==0x482c) {
			/* GROUP: mortlach_multi_sve_2c0 */
			op0 = (INSWORD>>7)&7;
			if(!op0)
				return decode_iclass_mortlach_multi2_z_z_minmax_mm(ctx, dec);
			if(op0==1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_186_mortlach_multi_sve_2c0
			if(op0==2)
				return decode_iclass_mortlach_multi2_z_z_fminmax_mm(ctx, dec);
			if(op0==3)
				return decode_iclass_mortlach_multi2_z_z_fscale_mm(ctx, dec);
			if((op0&6)==4)
				return decode_iclass_mortlach_multi2_z_z_shift_mm(ctx, dec);
			if((op0&6)==6)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_185_mortlach_multi_sve_2c0
			UNMATCHED;
		}
		if(op0==2 && (op1&0x487f)==0x482d) {
			/* GROUP: mortlach_multi_sve_2c1 */
			op0 = (INSWORD>>5)&0x1f;
			if(!op0)
				return decode_iclass_mortlach_multi2_z_z_sqdmulh_mm(ctx, dec);
			if(op0)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_187_mortlach_multi_sve_2c1
			UNMATCHED;
		}
		if(op0==2 && (op1&0x487e)==0x482e && (op2&2)==2)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_28_sme
		if(op0==2 && (op1&0x487c)==0x486c)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_21_sme
		if(op0==2 && (op1&0x4838)==0x4820) {
			/* GROUP: mortlach_multi_sve_1 */
			op0 = (INSWORD>>16)&3;
			op1 = (INSWORD>>5)&3;
			op2 = INSWORD&3;
			if(op0==1 && !op1 && !op2)
				return decode_iclass_mortlach_multi4_select_int(ctx, dec);
			if(op0==1 && !op1 && op2==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_192_mortlach_multi_sve_1
			if(op0==1 && op1==2 && !(op2&1))
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_191_mortlach_multi_sve_1
			if(op0==3 && !(op1&1) && !(op2&1))
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_190_mortlach_multi_sve_1
			if(!(op0&1) && !(op1&1) && !(op2&1))
				return decode_iclass_mortlach_multi2_select_int(ctx, dec);
			if(!(op1&1) && op2&1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_189_mortlach_multi_sve_1
			if(op1&1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_188_mortlach_multi_sve_1
			UNMATCHED;
		}
		if(op0==2 && (op1&0x4838)==0x4830) {
			/* GROUP: mortlach_multi_sve_3 */
			op0 = (INSWORD>>22)&3;
			op1 = (INSWORD>>10)&7;
			op2 = (INSWORD>>1)&1;
			if(!op0 && op1==5)
				return decode_iclass_mortlach_multi2_z_z_long_zip(ctx, dec);
			if(op0==1 && op1==5)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_194_mortlach_multi_sve_3
			if(op0==2 && op1==5)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_195_mortlach_multi_sve_3
			if(op0==3 && op1==5)
				return decode_iclass_mortlach_multi2_qrshr(ctx, dec);
			if(!op1)
				return decode_iclass_mortlach_multi2_fclamp(ctx, dec);
			if(op1==1)
				return decode_iclass_mortlach_multi2_clamp_int(ctx, dec);
			if(op1==2 && !op2)
				return decode_iclass_mortlach_multi4_fclamp(ctx, dec);
			if(op1==3 && !op2)
				return decode_iclass_mortlach_multi4_clamp_int(ctx, dec);
			if((op1&6)==2 && op2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_193_mortlach_multi_sve_3
			if(op1==4)
				return decode_iclass_mortlach_multi2_z_z_zip(ctx, dec);
			if((op1&6)==6)
				return decode_iclass_mortlach_multi4_qrshr(ctx, dec);
			UNMATCHED;
		}
		if(op0==2 && (op1&0x483f)==0x4838) {
			/* GROUP: mortlach_multi_sve_4 */
			op0 = (INSWORD>>22)&3;
			op1 = (INSWORD>>18)&7;
			op2 = (INSWORD>>16)&3;
			op3 = (INSWORD>>5)&3;
			op4 = INSWORD&3;
			if(!op0 && !op1 && op2==1 && !(op4&1))
				return decode_iclass_mortlach_multi2_fpint_cvrt(ctx, dec);
			if(!op0 && !op1 && op2==2 && !(op4&1))
				return decode_iclass_mortlach_multi2_intfp_cvrt(ctx, dec);
			if(!op0 && op1==4 && op2==1 && !(op3&2) && !op4)
				return decode_iclass_mortlach_multi4_fpint_cvrt(ctx, dec);
			if(!op0 && op1==4 && op2==2 && !(op3&2) && !op4)
				return decode_iclass_mortlach_multi4_intfp_cvrt(ctx, dec);
			if(!op0 && op1==5 && !op2 && !(op3&2))
				return decode_iclass_mortlach_multi4_narrow_fp8_cvrt(ctx, dec);
			if(!op0 && op1==5 && op2==3 && !op3 && !(op4&1))
				return decode_iclass_mortlach_multi4_z_z_long_zip(ctx, dec);
			if(op0==1 && !op1 && op2==1 && !(op4&1))
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_218_mortlach_multi_sve_4
			if(op0==1 && op1==1 && op2==3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_211_mortlach_multi_sve_4
			if(op0==1 && op1==5 && !op2 && !(op3&2) && (op4&2)==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_225_mortlach_multi_sve_4
			if(op0==1 && (op1&6)==4 && !op2 && !(op3&2) && !(op4&2))
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_219_mortlach_multi_sve_4
			if(!(op0&2) && !op1 && !op2)
				return decode_iclass_mortlach_multi2_narrow_fp_cvrt(ctx, dec);
			if(!(op0&2) && !op1 && op2==3)
				return decode_iclass_mortlach_multi2_narrow_int_cvrt(ctx, dec);
			if(!(op0&2) && op1==1 && !op2 && !(op3&1))
				return decode_iclass_mortlach_multi2_narrow_fp8_cvrt(ctx, dec);
			if(!(op0&2) && op1==1 && !op2 && op3&1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_212_mortlach_multi_sve_4
			if(op0==2 && !op1 && !op2)
				return decode_iclass_mortlach_multi2_wide_fp_cvrt(ctx, dec);
			if(op0==2 && op1==1 && !op2 && (op3&2)==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_220_mortlach_multi_sve_4
			if(op0==2 && (op1&3)==1 && !op2 && !(op3&2))
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_213_mortlach_multi_sve_4
			if(op0==3 && !(op1&6) && !op2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_200_mortlach_multi_sve_4
			if(op0==3 && op1==5 && !op2 && !(op3&2) && (op4&2)==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_226_mortlach_multi_sve_4
			if(op0==3 && (op1&6)==4 && !op2 && !(op3&2) && !(op4&2))
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_221_mortlach_multi_sve_4
			if((op0&2)==2 && !op1 && op2==3 && op4&1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_215_mortlach_multi_sve_4
			if((op0&2)==2 && !op1 && op2&1 && !(op4&1))
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_201_mortlach_multi_sve_4
			if(!(op0&1) && op1==4 && !op2 && !(op3&2) && !(op4&2))
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_222_mortlach_multi_sve_4
			if(!op1 && op2==1 && op4&1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_203_mortlach_multi_sve_4
			if(!op1 && op2==2 && op4&1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_204_mortlach_multi_sve_4
			if(op1==1 && op2==1)
				return decode_iclass_mortlach_multi2_wide_int(ctx, dec);
			if(op1==1 && op2==2)
				return decode_iclass_mortlach_multi2_wide_fp8_cvrt(ctx, dec);
			if((op1&6)==2 && !(op3&1) && !(op4&1))
				return decode_iclass_mortlach_multi2_frint(ctx, dec);
			if(op1==4 && op2==1 && !(op3&2) && op4==1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_223_mortlach_multi_sve_4
			if(op1==4 && op2==1 && (op3&2)==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_205_mortlach_multi_sve_4
			if(op1==4 && op2==2 && !(op3&2) && op4==1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_224_mortlach_multi_sve_4
			if(op1==4 && op2==3)
				return decode_iclass_mortlach_multi4_narrow_int_cvrt(ctx, dec);
			if(op1==4 && op2!=3 && !(op3&2) && (op4&2)==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_206_mortlach_multi_sve_4
			if(op1==5 && op2==1 && !(op3&1) && !(op4&2))
				return decode_iclass_mortlach_multi4_wide_int(ctx, dec);
			if(op1==5 && op2==1 && !(op3&1) && (op4&2)==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_216_mortlach_multi_sve_4
			if(op1==5 && op2==1 && op3&1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_207_mortlach_multi_sve_4
			if(op1==5 && op2==2 && !op3 && !(op4&1))
				return decode_iclass_mortlach_multi4_z_z_zip(ctx, dec);
			if(op1==5 && op2==3 && (op3&2)==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_208_mortlach_multi_sve_4
			if(op1==5 && (op2&2)==2 && !op3 && op4&1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_217_mortlach_multi_sve_4
			if(op1==5 && (op2&2)==2 && op3==1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_209_mortlach_multi_sve_4
			if((op1&6)==4 && !(op2&1) && (op3&2)==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_198_mortlach_multi_sve_4
			if((op1&6)==6 && !op3 && !op4)
				return decode_iclass_mortlach_multi4_frint(ctx, dec);
			if((op1&6)==6 && !op3 && op4==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_210_mortlach_multi_sve_4
			if((op1&6)==6 && op3==2 && !(op4&1))
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_199_mortlach_multi_sve_4
			if((op1&2)==2 && !(op3&1) && op4&1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_197_mortlach_multi_sve_4
			if((op1&2)==2 && op3&1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_196_mortlach_multi_sve_4
			if(op0 && !op1 && op2==2 && !(op4&1))
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_214_mortlach_multi_sve_4
			if(op0 && op1==4 && op2==1 && !(op3&2) && !op4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_227_mortlach_multi_sve_4
			if(op0 && op1==4 && op2==2 && !(op3&2) && !op4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_228_mortlach_multi_sve_4
			if(op0 && op1==5 && op2==3 && !op3 && !(op4&1))
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_229_mortlach_multi_sve_4
			if(op0!=1 && op1==1 && op2==3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_202_mortlach_multi_sve_4
			UNMATCHED;
		}
		if(op0==2 && (op1&0x483f)==0x4839 && !(op2&0x21)) {
			/* GROUP: mortlach_multi_sve_5a */
			op0 = (INSWORD>>16)&3;
			op1 = (INSWORD>>6)&1;
			op2 = (INSWORD>>1)&1;
			if(op0==1 && !op1 && !op2)
				return decode_iclass_mortlach_multi4_fmul_mm(ctx, dec);
			if(op0==1 && !op1 && op2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_232_mortlach_multi_sve_5a
			if(op0==1 && op1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_231_mortlach_multi_sve_5a
			if(op0==3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_230_mortlach_multi_sve_5a
			if(!(op0&1))
				return decode_iclass_mortlach_multi2_fmul_mm(ctx, dec);
			UNMATCHED;
		}
		if(op0==2 && (op1&0x483f)==0x4839 && (op2&0x21)==1)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_34_sme
		if(op0==2 && (op1&0x483f)==0x4839 && (op2&0x20)==0x20)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_29_sme
		if(op0==2 && (op1&0x483f)==0x483a && !(op2&0x21)) {
			/* GROUP: mortlach_multi_sve_5b */
			op0 = (INSWORD>>16)&1;
			op1 = (INSWORD>>6)&1;
			op2 = (INSWORD>>1)&1;
			if(!op0)
				return decode_iclass_mortlach_multi2_fmul_sm(ctx, dec);
			if(op0 && !op1 && !op2)
				return decode_iclass_mortlach_multi4_fmul_sm(ctx, dec);
			if(op0 && !op1 && op2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_234_mortlach_multi_sve_5b
			if(op0 && op1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_233_mortlach_multi_sve_5b
			UNMATCHED;
		}
		if(op0==2 && (op1&0x483f)==0x483a && (op2&0x21)==1)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_35_sme
		if(op0==2 && (op1&0x483f)==0x483a && (op2&0x20)==0x20)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_30_sme
		if(op0==2 && (op1&0x483f)==0x483b)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_24_sme
		if(op0==3) {
			/* GROUP: mortlach_mem */
			op0 = (INSWORD>>21)&15;
			op1 = (INSWORD>>16)&0x1f;
			op2 = (INSWORD>>15)&1;
			op3 = (INSWORD>>10)&0x1f;
			op4 = (INSWORD>>2)&7;
			if(!(op0&9) && !(op4&4))
				return decode_iclass_mortlach_contig_load(ctx, dec);
			if((op0&9)==1 && !(op4&4))
				return decode_iclass_mortlach_contig_store(ctx, dec);
			if((op0&14)==8 && !op1 && !op2 && !(op3&7) && !(op4&4))
				return decode_iclass_mortlach_ctxt_ldst(ctx, dec);
			if((op0&14)==8 && op2 && !op3 && !op4)
				return decode_iclass_mortlach_zt_ldst(ctx, dec);
			if((op0&14)==8 && op2 && !op3 && op4==1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_245_mortlach_mem
			if((op0&14)==8 && op2 && !op3 && (op4&6)==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_244_mortlach_mem
			if((op0&14)==8 && op2 && op3==8 && !(op4&4))
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_243_mortlach_mem
			if((op0&14)==8 && op2 && (op3&0x17)==0x10 && !(op4&4))
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_242_mortlach_mem
			if((op0&14)==8 && (op3&7)==1 && !(op4&4))
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_240_mortlach_mem
			if((op0&14)==8 && (op3&6)==2 && !(op4&4))
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_239_mortlach_mem
			if((op0&14)==8 && (op3&4)==4 && !(op4&4))
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_238_mortlach_mem
			if((op0&14)==8 && op1 && !op2 && !(op3&7) && !(op4&4))
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_241_mortlach_mem
			if((op0&14)==10 && !(op4&4))
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_236_mortlach_mem
			if((op0&14)==12 && !(op4&4))
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_237_mortlach_mem
			if(op0==14 && !(op4&4))
				return decode_iclass_mortlach_contig_qload(ctx, dec);
			if(op0==15 && !(op4&4))
				return decode_iclass_mortlach_contig_qstore(ctx, dec);
			if((op4&4)==4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_235_mortlach_mem
			UNMATCHED;
		}
		UNMATCHED;
	}
	if(op1==2) {
		/* GROUP: sve */
		op0 = INSWORD>>29;
		op1 = (INSWORD>>17)&0xff;
		op2 = (INSWORD>>10)&0x3f;
		op3 = (INSWORD>>4)&1;
		if(!op0 && !(op1&0x90) && !(op2&0x38)) {
			/* GROUP: sve_int_pred_bin */
			op0 = (INSWORD>>18)&7;
			if(!(op0&6))
				return decode_iclass_sve_int_bin_pred_arit_0(ctx, dec);
			if((op0&6)==2)
				return decode_iclass_sve_int_bin_pred_arit_1(ctx, dec);
			if(op0==4)
				return decode_iclass_sve_int_bin_pred_arit_2(ctx, dec);
			if(op0==5)
				return decode_iclass_sve_int_bin_pred_div(ctx, dec);
			if((op0&6)==6)
				return decode_iclass_sve_int_bin_pred_log(ctx, dec);
			UNMATCHED;
		}
		if(!op0 && !(op1&0x90) && (op2&0x38)==8) {
			/* GROUP: sve_int_pred_red */
			op0 = (INSWORD>>18)&7;
			if(!op0)
				return decode_iclass_sve_int_reduce_0(ctx, dec);
			if(op0==1)
				return decode_iclass_sve_int_reduce_0q(ctx, dec);
			if(op0==2)
				return decode_iclass_sve_int_reduce_1(ctx, dec);
			if(op0==3)
				return decode_iclass_sve_int_reduce_1q(ctx, dec);
			if((op0&6)==4)
				return decode_iclass_sve_int_movprfx_pred(ctx, dec);
			if(op0==6)
				return decode_iclass_sve_int_reduce_2(ctx, dec);
			if(op0==7)
				return decode_iclass_sve_int_reduce_2q(ctx, dec);
			UNMATCHED;
		}
		if(!op0 && !(op1&0x90) && (op2&0x38)==0x20) {
			/* GROUP: sve_int_pred_shift */
			op0 = (INSWORD>>19)&3;
			if(!(op0&2))
				return decode_iclass_sve_int_bin_pred_shift_0(ctx, dec);
			if(op0==2)
				return decode_iclass_sve_int_bin_pred_shift_1(ctx, dec);
			if(op0==3)
				return decode_iclass_sve_int_bin_pred_shift_2(ctx, dec);
			UNMATCHED;
		}
		if(!op0 && !(op1&0x90) && (op2&0x38)==0x28) {
			/* GROUP: sve_int_pred_un */
			op0 = (INSWORD>>19)&3;
			if(!(op0&1))
				return decode_iclass_sve_int_un_pred_arit_0(ctx, dec);
			if(op0&1)
				return decode_iclass_sve_int_un_pred_arit_1(ctx, dec);
			UNMATCHED;
		}
		if(!op0 && !(op1&0x90) && (op2&0x10)==0x10) {
			/* GROUP: sve_int_muladd_pred */
			op0 = (INSWORD>>15)&1;
			if(!op0)
				return decode_iclass_sve_int_mlas_vvv_pred(ctx, dec);
			if(op0)
				return decode_iclass_sve_int_mladdsub_vvv_pred(ctx, dec);
			UNMATCHED;
		}
		if(!op0 && (op1&0x90)==0x10 && (op2&0x38)==8) {
			/* GROUP: sve_int_unpred_logical */
			op0 = (INSWORD>>10)&7;
			if(!(op0&4))
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_265_sve_int_unpred_logical
			if(op0==4)
				return decode_iclass_sve_int_bin_cons_log(ctx, dec);
			if(op0==5)
				return decode_iclass_sve_int_rotate_imm(ctx, dec);
			if((op0&6)==6)
				return decode_iclass_sve_int_tern_log(ctx, dec);
			UNMATCHED;
		}
		if(!op0 && (op1&0x90)==0x10 && (op2&0x3c)==0x10) {
			/* GROUP: sve_index */
			op0 = (INSWORD>>10)&3;
			if(!op0)
				return decode_iclass_sve_int_index_ii(ctx, dec);
			if(op0==1)
				return decode_iclass_sve_int_index_ri(ctx, dec);
			if(op0==2)
				return decode_iclass_sve_int_index_ir(ctx, dec);
			if(op0==3)
				return decode_iclass_sve_int_index_rr(ctx, dec);
			UNMATCHED;
		}
		if(!op0 && (op1&0x90)==0x10 && (op2&0x3c)==0x14) {
			/* GROUP: sve_alloca */
			op0 = (INSWORD>>23)&1;
			op1 = (INSWORD>>11)&1;
			if(!op0 && !op1)
				return decode_iclass_sve_int_arith_vl(ctx, dec);
			if(!op0 && op1)
				return decode_iclass_sve_int_arith_svl(ctx, dec);
			if(op0 && !op1)
				return decode_iclass_sve_int_read_vl_a(ctx, dec);
			if(op0 && op1)
				return decode_iclass_sve_int_read_svl_a(ctx, dec);
			UNMATCHED;
		}
		if(!op0 && (op1&0x90)==0x10 && (op2&0x38)==0x18) {
			/* GROUP: sve_int_unpred_arit_b */
			op0 = (INSWORD>>10)&7;
			if(!(op0&4))
				return decode_iclass_sve_int_mul_b(ctx, dec);
			if((op0&6)==4)
				return decode_iclass_sve_int_sqdmulh(ctx, dec);
			if(op0==6)
				return decode_iclass_sve_int_addqp(ctx, dec);
			if(op0==7)
				return decode_iclass_sve_int_addsubp(ctx, dec);
			UNMATCHED;
		}
		if(!op0 && (op1&0x90)==0x10 && (op2&0x38)==0x20) {
			/* GROUP: sve_int_unpred_shift */
			op0 = (INSWORD>>12)&1;
			if(!op0)
				return decode_iclass_sve_int_bin_cons_shift_a(ctx, dec);
			if(op0)
				return decode_iclass_sve_int_bin_cons_shift_b(ctx, dec);
			UNMATCHED;
		}
		if(!op0 && (op1&0x90)==0x10 && (op2&0x3c)==0x2c) {
			/* GROUP: sve_int_unpred_misc */
			op0 = (INSWORD>>10)&3;
			if(!(op0&2))
				return decode_iclass_sve_int_bin_cons_misc_0_b(ctx, dec);
			if(op0==2)
				return decode_iclass_sve_int_bin_cons_misc_0_c(ctx, dec);
			if(op0==3)
				return decode_iclass_sve_int_bin_cons_misc_0_d(ctx, dec);
			UNMATCHED;
		}
		if(!op0 && (op1&0x90)==0x10 && (op2&0x30)==0x30) {
			/* GROUP: sve_countelt */
			op0 = (INSWORD>>20)&1;
			op1 = (INSWORD>>11)&7;
			if(!op0 && !(op1&6))
				return decode_iclass_sve_int_countvlv0(ctx, dec);
			if(!op0 && op1==4)
				return decode_iclass_sve_int_count(ctx, dec);
			if(!op0 && op1==5)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_268_sve_countelt
			if(op0 && !op1)
				return decode_iclass_sve_int_countvlv1(ctx, dec);
			if(op0 && op1==4)
				return decode_iclass_sve_int_pred_pattern_a(ctx, dec);
			if(op0 && (op1&3)==1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_267_sve_countelt
			if((op1&6)==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_266_sve_countelt
			if((op1&6)==6)
				return decode_iclass_sve_int_pred_pattern_b(ctx, dec);
			UNMATCHED;
		}
		if(!op0 && (op1&0xd0)==0x90 && !(op2&0x38)) {
			/* GROUP: sve_perm_extract */
			op0 = (INSWORD>>22)&1;
			if(!op0)
				return decode_iclass_sve_int_perm_extract_i(ctx, dec);
			if(op0)
				return decode_iclass_sve_intx_perm_extract_i(ctx, dec);
			UNMATCHED;
		}
		if(!op0 && (op1&0xd0)==0xd0 && !(op2&0x38)) {
			/* GROUP: sve_perm_inter_long */
			op0 = (INSWORD>>22)&1;
			if(!op0)
				return decode_iclass_sve_int_perm_bin_long_perm_zz(ctx, dec);
			if(op0)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_269_sve_perm_inter_long
			UNMATCHED;
		}
		if(!op0 && (op1&0x98)==0x80) {
			/* GROUP: sve_maskimm */
			op0 = (INSWORD>>22)&3;
			op1 = (INSWORD>>18)&3;
			if(op0==3 && !op1)
				return decode_iclass_sve_int_dup_mask_imm(ctx, dec);
			if(op1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_270_sve_maskimm
			if(op0!=3 && !op1)
				return decode_iclass_sve_int_log_imm(ctx, dec);
			UNMATCHED;
		}
		if(!op0 && (op1&0x98)==0x88) {
			/* GROUP: sve_wideimm_pred */
			op0 = (INSWORD>>13)&7;
			if(!(op0&4))
				return decode_iclass_sve_int_dup_imm_pred(ctx, dec);
			if((op0&6)==4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_271_sve_wideimm_pred
			if(op0==6)
				return decode_iclass_sve_int_dup_fpimm_pred(ctx, dec);
			if(op0==7)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_272_sve_wideimm_pred
			UNMATCHED;
		}
		if(!op0 && (op1&0x90)==0x90 && op2==9) {
			/* GROUP: sve_perm_quads_a */
			op0 = (INSWORD>>22)&3;
			op1 = (INSWORD>>20)&1;
			if(!op0)
				return decode_iclass_sve_int_perm_dupq_i(ctx, dec);
			if(op0==1 && !op1)
				return decode_iclass_sve_int_perm_extq(ctx, dec);
			if(op0==1 && op1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_274_sve_perm_quads_a
			if((op0&2)==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_273_sve_perm_quads_a
			UNMATCHED;
		}
		if(!op0 && (op1&0x90)==0x90 && op2==14) {
			/* GROUP: sve_perm_unpred_d */
			op0 = (INSWORD>>19)&3;
			op1 = (INSWORD>>16)&7;
			op2 = (INSWORD>>9)&1;
			op3 = (INSWORD>>4)&1;
			if(!op0 && !op1)
				return decode_iclass_sve_int_perm_dup_r(ctx, dec);
			if(!op0 && op1==4)
				return decode_iclass_sve_int_perm_insrs(ctx, dec);
			if(!op0 && (op1&3)==1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_277_sve_perm_unpred_d
			if(!op0 && (op1&2)==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_275_sve_perm_unpred_d
			if(op0==1 && !(op1&1) && !op3)
				return decode_iclass_sve_int_mov_v2p(ctx, dec);
			if(op0==1 && !(op1&1) && op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_278_sve_perm_unpred_d
			if(op0==1 && op1&1 && !op2)
				return decode_iclass_sve_int_mov_p2v(ctx, dec);
			if(op0==1 && op1&1 && op2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_279_sve_perm_unpred_d
			if(op0==2 && !(op1&4))
				return decode_iclass_sve_int_perm_unpk(ctx, dec);
			if(op0==2 && op1==4)
				return decode_iclass_sve_int_perm_insrv(ctx, dec);
			if(op0==2 && op1==5)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_281_sve_perm_unpred_d
			if(op0==2 && (op1&6)==6)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_280_sve_perm_unpred_d
			if(op0==3 && !op1)
				return decode_iclass_sve_int_perm_reverse_z(ctx, dec);
			if(op0==3 && op1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_276_sve_perm_unpred_d
			UNMATCHED;
		}
		if(!op0 && (op1&0x90)==0x90 && op2==15)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_259_sve
		if(!op0 && (op1&0x90)==0x90 && (op2&0x38)==0x10) {
			/* GROUP: sve_perm_predicates */
			op0 = (INSWORD>>22)&3;
			op1 = (INSWORD>>16)&0x1f;
			op2 = (INSWORD>>9)&15;
			op3 = (INSWORD>>4)&1;
			if(!op0 && (op1&0x1e)==0x10 && !op2 && !op3)
				return decode_iclass_sve_int_perm_punpk(ctx, dec);
			if(!(op1&0x10) && !(op2&1) && !op3)
				return decode_iclass_sve_int_perm_bin_perm_pp(ctx, dec);
			if(op1==0x14 && !op2 && !op3)
				return decode_iclass_sve_int_perm_reverse_p(ctx, dec);
			if(op1==0x15 && !op2 && !op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_290_sve_perm_predicates
			if((op1&0x1a)==0x10 && op2==2 && !op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_288_sve_perm_predicates
			if((op1&0x1a)==0x10 && (op2&13)==4 && !op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_287_sve_perm_predicates
			if((op1&0x1a)==0x10 && (op2&9)==8 && !op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_286_sve_perm_predicates
			if((op1&0x1a)==0x12 && !(op2&1) && !op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_285_sve_perm_predicates
			if((op1&0x18)==0x18 && !(op2&1) && !op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_284_sve_perm_predicates
			if(!(op2&1) && op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_283_sve_perm_predicates
			if(op2&1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_282_sve_perm_predicates
			if(op0 && (op1&0x1e)==0x10 && !op2 && !op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_289_sve_perm_predicates
			UNMATCHED;
		}
		if(!op0 && (op1&0x90)==0x90 && (op2&0x30)==0x20) {
			/* GROUP: sve_perm_pred */
			op0 = (INSWORD>>20)&1;
			op1 = (INSWORD>>17)&7;
			op2 = (INSWORD>>16)&1;
			op3 = (INSWORD>>13)&1;
			if(!op0 && !op1 && !op2 && !op3)
				return decode_iclass_sve_int_perm_cpy_v(ctx, dec);
			if(!op0 && !op1 && op2 && !op3)
				return decode_iclass_sve_int_perm_compact(ctx, dec);
			if(!op0 && !op1 && op3)
				return decode_iclass_sve_int_perm_last_r(ctx, dec);
			if(!op0 && op1==1 && op2 && op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_294_sve_perm_pred
			if(!op0 && op1==1 && !op3)
				return decode_iclass_sve_int_perm_last_v(ctx, dec);
			if(!op0 && (op1&6)==2)
				return decode_iclass_sve_int_perm_rev(ctx, dec);
			if(!op0 && op1==4 && !op2 && op3)
				return decode_iclass_sve_int_perm_cpy_r(ctx, dec);
			if(!op0 && op1==4 && !op3)
				return decode_iclass_sve_int_perm_clast_zz(ctx, dec);
			if(!op0 && op1==5 && !op3)
				return decode_iclass_sve_int_perm_clast_vz(ctx, dec);
			if(!op0 && op1==6 && !op2 && !op3)
				return decode_iclass_sve_int_perm_splice(ctx, dec);
			if(!op0 && op1==6 && !op2 && op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_295_sve_perm_pred
			if(!op0 && op1==6 && op2 && !op3)
				return decode_iclass_sve_intx_perm_splice(ctx, dec);
			if(!op0 && op1==7 && !op2)
				return decode_iclass_sve_int_perm_revd(ctx, dec);
			if(!op0 && op1==7 && op2 && !op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_296_sve_perm_pred
			if(!op0 && (op1&4)==4 && op2 && op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_292_sve_perm_pred
			if(!op0 && (op1&3)==1 && !op2 && op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_293_sve_perm_pred
			if(op0 && !op1 && !op2 && !op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_297_sve_perm_pred
			if(op0 && !op1 && op2 && !op3)
				return decode_iclass_sve_int_perm_expand(ctx, dec);
			if(op0 && !op1 && op3)
				return decode_iclass_sve_int_perm_clast_rz(ctx, dec);
			if(op0 && op1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_291_sve_perm_pred
			UNMATCHED;
		}
		if(op0==1 && !(op1&0x90)) {
			/* GROUP: sve_cmpvec */
			op0 = (INSWORD>>14)&1;
			if(!op0)
				return decode_iclass_sve_int_cmp_0(ctx, dec);
			if(op0)
				return decode_iclass_sve_int_cmp_1(ctx, dec);
			UNMATCHED;
		}
		if(op0==1 && (op1&0x98)==0x80 && (op2&0x30)==0x30) {
			/* GROUP: sve_pred_gen_b */
			op0 = (INSWORD>>9)&1;
			if(!op0)
				return decode_iclass_sve_int_brkp(ctx, dec);
			if(op0)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_298_sve_pred_gen_b
			UNMATCHED;
		}
		if(op0==1 && (op1&0x98)==0x88 && (op2&0x30)==0x10) {
			/* GROUP: sve_pred_gen_c */
			op0 = (INSWORD>>23)&1;
			op1 = (INSWORD>>16)&15;
			op2 = (INSWORD>>9)&1;
			op3 = (INSWORD>>4)&1;
			if(!op0 && op1==8 && !op2 && !op3)
				return decode_iclass_sve_int_brkn(ctx, dec);
			if(!op0 && op1==8 && !op2 && op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_304_sve_pred_gen_c
			if(op0 && op1==8 && !op2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_303_sve_pred_gen_c
			if(!op1 && !op2)
				return decode_iclass_sve_int_break(ctx, dec);
			if(!(op1&7) && op2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_302_sve_pred_gen_c
			if((op1&7)==1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_301_sve_pred_gen_c
			if((op1&6)==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_300_sve_pred_gen_c
			if((op1&4)==4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_299_sve_pred_gen_c
			UNMATCHED;
		}
		if(op0==1 && (op1&0x98)==0x88 && (op2&0x30)==0x30) {
			/* GROUP: sve_pred_gen_d */
			op0 = (INSWORD>>16)&15;
			op1 = (INSWORD>>11)&7;
			op2 = (INSWORD>>9)&3;
			op3 = (INSWORD>>5)&15;
			op4 = (INSWORD>>4)&1;
			if(!op0 && !(op2&1) && !op4)
				return decode_iclass_sve_int_ptest(ctx, dec);
			if(!op0 && op2&1 && !op4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_310_sve_pred_gen_d
			if(op0==1 && !op4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_308_sve_pred_gen_d
			if(op0==8 && !op1 && !op2 && !op4)
				return decode_iclass_sve_int_pfirst(ctx, dec);
			if(op0==8 && !op1 && op2==2 && !op4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_315_sve_pred_gen_d
			if(op0==8 && op1==4 && op2==2 && !op3 && !op4)
				return decode_iclass_sve_int_pfalse(ctx, dec);
			if(op0==8 && op1==4 && op2==2 && op3 && !op4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_318_sve_pred_gen_d
			if(op0==8 && op1==6 && !op2 && !op4)
				return decode_iclass_sve_int_rdffr(ctx, dec);
			if(op0==9 && !op1 && !op2 && !op4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_316_sve_pred_gen_d
			if(op0==9 && !op1 && op2==2 && !op4)
				return decode_iclass_sve_int_pnext(ctx, dec);
			if(op0==9 && op1==4 && op2==2 && !op4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_317_sve_pred_gen_d
			if(op0==9 && op1==6 && !op2 && !op3 && !op4)
				return decode_iclass_sve_int_rdffr_2(ctx, dec);
			if(op0==9 && op1==6 && !op2 && op3 && !op4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_319_sve_pred_gen_d
			if((op0&14)==8 && op1==2 && !(op2&1) && !op4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_312_sve_pred_gen_d
			if((op0&14)==8 && !(op1&5) && op2&1 && !op4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_311_sve_pred_gen_d
			if((op0&14)==8 && op1==4 && !(op2&2) && !op4)
				return decode_iclass_sve_int_ptrue(ctx, dec);
			if((op0&14)==8 && op1==4 && op2==3 && !op4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_314_sve_pred_gen_d
			if((op0&14)==8 && op1==6 && op2 && !op4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_313_sve_pred_gen_d
			if((op0&14)==8 && op1&1 && !op4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_309_sve_pred_gen_d
			if(!(op0&6) && op4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_307_sve_pred_gen_d
			if((op0&6)==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_306_sve_pred_gen_d
			if((op0&4)==4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_305_sve_pred_gen_d
			UNMATCHED;
		}
		if(op0==1 && (op1&0x9c)==0x90 && (op2&0x30)==0x20) {
			/* GROUP: sve_pred_count_a */
			op0 = (INSWORD>>11)&7;
			op1 = (INSWORD>>9)&1;
			if(!op0 && op1)
				return decode_iclass_sve_int_pcount_pn(ctx, dec);
			if(!op1)
				return decode_iclass_sve_int_pcount_pred(ctx, dec);
			if(op0 && op1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_320_sve_pred_count_a
			UNMATCHED;
		}
		if(op0==1 && (op1&0x9c)==0x94 && (op2&0x3c)==0x20) {
			/* GROUP: sve_pred_count_b */
			op0 = (INSWORD>>18)&1;
			op1 = (INSWORD>>11)&1;
			if(!op0 && !op1)
				return decode_iclass_sve_int_count_v_sat(ctx, dec);
			if(!op0 && op1)
				return decode_iclass_sve_int_count_r_sat(ctx, dec);
			if(op0 && !op1)
				return decode_iclass_sve_int_count_v(ctx, dec);
			if(op0 && op1)
				return decode_iclass_sve_int_count_r(ctx, dec);
			UNMATCHED;
		}
		if(op0==1 && (op1&0x9c)==0x94 && (op2&0x3c)==0x24) {
			/* GROUP: sve_pred_wrffr */
			op0 = (INSWORD>>18)&1;
			op1 = (INSWORD>>16)&3;
			op2 = (INSWORD>>9)&7;
			op3 = (INSWORD>>5)&15;
			op4 = INSWORD&0x1f;
			if(!op0 && !op1 && !op2 && !op4)
				return decode_iclass_sve_int_wrffr(ctx, dec);
			if(op0 && !op1 && !op2 && !op3 && !op4)
				return decode_iclass_sve_int_setffr(ctx, dec);
			if(op0 && !op1 && !op2 && op3 && !op4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_324_sve_pred_wrffr
			if(!op1 && !op2 && op4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_323_sve_pred_wrffr
			if(!op1 && op2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_322_sve_pred_wrffr
			if(op1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_321_sve_pred_wrffr
			UNMATCHED;
		}
		if(op0==1 && (op1&0x9c)==0x94 && (op2&0x38)==0x28)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_255_sve
		if(op0==1 && (op1&0x98)==0x98 && (op2&0x30)==0x20)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_246_sve
		if(op0==1 && (op1&0x90)==0x90 && !(op2&0x30)) {
			/* GROUP: sve_cmpgpr */
			op0 = (INSWORD>>12)&3;
			op1 = (INSWORD>>10)&3;
			op2 = INSWORD&15;
			if(!(op0&2))
				return decode_iclass_sve_int_while_rr(ctx, dec);
			if(op0==2 && !op1 && !op2)
				return decode_iclass_sve_int_cterm(ctx, dec);
			if(op0==2 && !op1 && op2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_326_sve_cmpgpr
			if(op0==3 && !op1)
				return decode_iclass_sve_int_whilenc(ctx, dec);
			if((op0&2)==2 && op1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_325_sve_cmpgpr
			UNMATCHED;
		}
		if(op0==1 && (op1&0x90)==0x90 && (op2&0x30)==0x10 && op3) {
			/* GROUP: sve_while_pn */
			op0 = (INSWORD>>16)&0x1f;
			op1 = (INSWORD>>11)&7;
			op2 = (INSWORD>>5)&0x3f;
			op3 = (INSWORD>>3)&1;
			if(!op0 && op1==6)
				return decode_iclass_sve_int_ctr_to_mask(ctx, dec);
			if(!op0 && op1==7 && !op2 && !op3)
				return decode_iclass_sve_int_pn_ptrue(ctx, dec);
			if(!op0 && op1==7 && !op2 && op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_329_sve_while_pn
			if(!op0 && op1==7 && op2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_328_sve_while_pn
			if((op1&6)==2)
				return decode_iclass_sve_int_while_rr_pair(ctx, dec);
			if(!(op1&2))
				return decode_iclass_sve_int_while_rr_pn(ctx, dec);
			if(op0 && (op1&6)==6)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_327_sve_while_pn
			UNMATCHED;
		}
		if(op0==1 && (op1&0x90)==0x90 && (op2&0x30)==0x30) {
			/* GROUP: sve_wideimm_unpred */
			op0 = (INSWORD>>19)&3;
			op1 = (INSWORD>>16)&1;
			if(!op0)
				return decode_iclass_sve_int_arith_imm0(ctx, dec);
			if(op0==1)
				return decode_iclass_sve_int_arith_imm1(ctx, dec);
			if(op0==2)
				return decode_iclass_sve_int_arith_imm2(ctx, dec);
			if(op0==3 && !op1)
				return decode_iclass_sve_int_dup_imm(ctx, dec);
			if(op0==3 && op1)
				return decode_iclass_sve_int_dup_fpimm(ctx, dec);
			UNMATCHED;
		}
		if(op0==2 && (op1&0xb0)==0x20 && (op2&0x3e)==0x32)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_260_sve
		if(op0==2 && !(op1&0x90) && !(op2&0x20)) {
			/* GROUP: sve_intx_muladd_unpred */
			op0 = (INSWORD>>10)&0x1f;
			if(!(op0&0x1e))
				return decode_iclass_sve_intx_dot(ctx, dec);
			if((op0&0x1e)==2)
				return decode_iclass_sve_intx_qdmlalbt(ctx, dec);
			if((op0&0x1c)==4)
				return decode_iclass_sve_intx_cdot(ctx, dec);
			if((op0&0x18)==8)
				return decode_iclass_sve_intx_cmla(ctx, dec);
			if((op0&0x18)==0x10)
				return decode_iclass_sve_intx_mlal_long(ctx, dec);
			if((op0&0x1c)==0x18)
				return decode_iclass_sve_intx_qdmlal_long(ctx, dec);
			if((op0&0x1e)==0x1c)
				return decode_iclass_sve_intx_qrdmlah(ctx, dec);
			if(op0==0x1e)
				return decode_iclass_sve_intx_mixed_dot(ctx, dec);
			if(op0==0x1f)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_330_sve_intx_muladd_unpred
			UNMATCHED;
		}
		if(op0==2 && !(op1&0x90) && (op2&0x30)==0x20) {
			/* GROUP: sve_intx_predicated */
			op0 = (INSWORD>>17)&15;
			op1 = (INSWORD>>13)&1;
			if(op0==2 && op1)
				return decode_iclass_sve_intx_accumulate_long_pairs(ctx, dec);
			if(op0==3 && op1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_333_sve_intx_predicated
			if((op0&14)==6 && op1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_332_sve_intx_predicated
			if(!(op0&10) && op1)
				return decode_iclass_sve_intx_pred_arith_unary(ctx, dec);
			if(!(op0&8) && !op1)
				return decode_iclass_sve_intx_bin_pred_shift_sat_round(ctx, dec);
			if((op0&12)==8 && !op1)
				return decode_iclass_sve_intx_pred_arith_binary(ctx, dec);
			if((op0&12)==8 && op1)
				return decode_iclass_sve_intx_arith_binary_pairs(ctx, dec);
			if((op0&12)==12 && !op1)
				return decode_iclass_sve_intx_pred_arith_binary_sat(ctx, dec);
			if((op0&12)==12 && op1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_331_sve_intx_predicated
			UNMATCHED;
		}
		if(op0==2 && (op1&0x90)==0x10) {
			/* GROUP: sve_intx_by_indexed_elem */
			op0 = (INSWORD>>10)&0x3f;
			if(!(op0&0x3e))
				return decode_iclass_sve_intx_dot_by_indexed_elem(ctx, dec);
			if((op0&0x3e)==2)
				return decode_iclass_sve_intx_mla_by_indexed_elem(ctx, dec);
			if((op0&0x3e)==4)
				return decode_iclass_sve_intx_qrdmlah_by_indexed_elem(ctx, dec);
			if((op0&0x3e)==6)
				return decode_iclass_sve_intx_mixed_dot_by_indexed_elem(ctx, dec);
			if((op0&0x38)==8)
				return decode_iclass_sve_intx_qdmla_long_by_indexed_elem(ctx, dec);
			if((op0&0x3c)==0x10)
				return decode_iclass_sve_intx_cdot_by_indexed_elem(ctx, dec);
			if((op0&0x3c)==0x14)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_334_sve_intx_by_indexed_elem
			if((op0&0x3c)==0x18)
				return decode_iclass_sve_intx_cmla_by_indexed_elem(ctx, dec);
			if((op0&0x3c)==0x1c)
				return decode_iclass_sve_intx_qrdcmla_by_indexed_elem(ctx, dec);
			if((op0&0x30)==0x20)
				return decode_iclass_sve_intx_mla_long_by_indexed_elem(ctx, dec);
			if((op0&0x38)==0x30)
				return decode_iclass_sve_intx_mul_long_by_indexed_elem(ctx, dec);
			if((op0&0x3c)==0x38)
				return decode_iclass_sve_intx_qdmul_long_by_indexed_elem(ctx, dec);
			if((op0&0x3e)==0x3c)
				return decode_iclass_sve_intx_qdmulh_by_indexed_elem(ctx, dec);
			if(op0==0x3e)
				return decode_iclass_sve_intx_mul_by_indexed_elem(ctx, dec);
			if(op0==0x3f)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_335_sve_intx_by_indexed_elem
			UNMATCHED;
		}
		if(op0==2 && (op1&0x90)==0x80 && !(op2&0x20)) {
			/* GROUP: sve_intx_cons_widening */
			op0 = (INSWORD>>13)&3;
			if(!(op0&2))
				return decode_iclass_sve_intx_cons_arith_long(ctx, dec);
			if(op0==2)
				return decode_iclass_sve_intx_cons_arith_wide(ctx, dec);
			if(op0==3)
				return decode_iclass_sve_intx_cons_mul_long(ctx, dec);
			UNMATCHED;
		}
		if(op0==2 && (op1&0x90)==0x80 && (op2&0x30)==0x20) {
			/* GROUP: sve_intx_constructive */
			op0 = (INSWORD>>23)&1;
			op1 = (INSWORD>>10)&15;
			if(!op0 && (op1&12)==8)
				return decode_iclass_sve_intx_shift_long(ctx, dec);
			if(op0 && (op1&12)==8)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_336_sve_intx_constructive
			if(!(op1&12))
				return decode_iclass_sve_intx_clong(ctx, dec);
			if((op1&14)==4)
				return decode_iclass_sve_intx_eorx(ctx, dec);
			if(op1==6)
				return decode_iclass_sve_intx_mmla(ctx, dec);
			if(op1==7)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_337_sve_intx_constructive
			if((op1&12)==12)
				return decode_iclass_sve_intx_perm_bit(ctx, dec);
			UNMATCHED;
		}
		if(op0==2 && (op1&0x90)==0x80 && (op2&0x30)==0x30) {
			/* GROUP: sve_intx_acc */
			op0 = (INSWORD>>17)&15;
			op1 = (INSWORD>>11)&7;
			if(!op0 && op1==3)
				return decode_iclass_sve_intx_cadd(ctx, dec);
			if(!(op1&6))
				return decode_iclass_sve_intx_aba_long(ctx, dec);
			if(op1==2)
				return decode_iclass_sve_intx_adc_long(ctx, dec);
			if((op1&6)==4)
				return decode_iclass_sve_intx_sra(ctx, dec);
			if(op1==6)
				return decode_iclass_sve_intx_shift_insert(ctx, dec);
			if(op1==7)
				return decode_iclass_sve_intx_aba(ctx, dec);
			if(op0 && op1==3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_338_sve_intx_acc
			UNMATCHED;
		}
		if(op0==2 && (op1&0x90)==0x90 && !(op2&0x20)) {
			/* GROUP: sve_intx_narrowing */
			op0 = (INSWORD>>23)&1;
			op1 = (INSWORD>>17)&3;
			op2 = (INSWORD>>16)&1;
			op3 = (INSWORD>>13)&3;
			op4 = (INSWORD>>10)&1;
			op5 = (INSWORD>>5)&1;
			if(!op0 && !op1 && !op2 && op3==2)
				return decode_iclass_sve_intx_extract_narrow(ctx, dec);
			if(!op0 && !op1 && op2 && op3==2 && !op4 && !op5)
				return decode_iclass_sve_intx_multi_extract_narrow(ctx, dec);
			if(!op0 && !op1 && op2 && op3==2 && !op4 && op5)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_344_sve_intx_narrowing
			if(!op0 && !op1 && op2 && op3==2 && op4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_343_sve_intx_narrowing
			if(!op0 && !(op3&2))
				return decode_iclass_sve_intx_shift_narrow(ctx, dec);
			if(!op0 && op1 && op3==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_341_sve_intx_narrowing
			if(op0 && !(op3&2) && !op4 && !op5)
				return decode_iclass_sve_intx_multi_shift_narrow(ctx, dec);
			if(op0 && !(op3&2) && !op4 && op5)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_342_sve_intx_narrowing
			if(op0 && !(op3&2) && op4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_339_sve_intx_narrowing
			if(op0 && op3==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_340_sve_intx_narrowing
			if(op3==3)
				return decode_iclass_sve_intx_arith_narrow(ctx, dec);
			UNMATCHED;
		}
		if(op0==2 && (op1&0x90)==0x90 && (op2&0x38)==0x28) {
			/* GROUP: sve_intx_histseg_lut */
			op2 = (INSWORD>>23)&1;
			op0 = (INSWORD>>22)&1;
			op1 = (INSWORD>>10)&7;
			if(!op2 && !op0 && op1==1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_346_sve_intx_histseg_lut
			if(!op2 && !op0 && op1==3)
				return decode_iclass_sve_intx_lut6_8(ctx, dec);
			if(op2 && !op0 && (op1&5)==1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_345_sve_intx_histseg_lut
			if(op0 && op1==1)
				return decode_iclass_sve_intx_lut4_8(ctx, dec);
			if(op0 && op1==3)
				return decode_iclass_sve_intx_lut6_16(ctx, dec);
			if(!op1)
				return decode_iclass_sve_intx_histseg(ctx, dec);
			if(op1==4)
				return decode_iclass_sve_intx_lut2_8(ctx, dec);
			if((op1&5)==5)
				return decode_iclass_sve_intx_lut4_16(ctx, dec);
			if((op1&3)==2)
				return decode_iclass_sve_intx_lut2_16(ctx, dec);
			UNMATCHED;
		}
		if(op0==2 && (op1&0x90)==0x90 && (op2&0x38)==0x38) {
			/* GROUP: sve_intx_crypto */
			op0 = (INSWORD>>18)&7;
			op1 = (INSWORD>>16)&3;
			op2 = (INSWORD>>10)&7;
			op3 = (INSWORD>>5)&0x1f;
			op4 = INSWORD&1;
			if(!op0 && !op1 && !(op2&6) && !op3)
				return decode_iclass_sve_crypto_unary(ctx, dec);
			if(!op0 && !op1 && !(op2&6) && op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_352_sve_intx_crypto
			if(!op0 && op1==1 && !(op2&6))
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_351_sve_intx_crypto
			if(!op0 && (op1&2)==2 && !(op2&6))
				return decode_iclass_sve_crypto_binary_dest(ctx, dec);
			if(!(op0&1) && (op1&2)==2 && (op2&6)==2)
				return decode_iclass_sve_crypto_binary_multi2(ctx, dec);
			if(op0&1 && (op1&2)==2 && (op2&6)==2)
				return decode_iclass_sve_crypto_binary_multi4(ctx, dec);
			if(!op1 && (op2&6)==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_349_sve_intx_crypto
			if(op1==1 && (op2&6)==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_350_sve_intx_crypto
			if((op2&6)==4)
				return decode_iclass_sve_crypto_binary_const(ctx, dec);
			if(op2==6 && !op4)
				return decode_iclass_sve_crypto_pmull_multi(ctx, dec);
			if(op2==7 && !op4)
				return decode_iclass_sve_crypto_pmlal_multi(ctx, dec);
			if((op2&6)==6 && op4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_348_sve_intx_crypto
			if(op0 && !(op2&6))
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_347_sve_intx_crypto
			UNMATCHED;
		}
		if(op0==3 && (op1&0xb0)==0x10 && (op2&0x3c)==0x1c)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_256_sve
		if(op0==3 && (op1&0xb0)==0x10 && (op2&0x33)==0x22) {
			/* GROUP: sve_fp8_fma_w */
			op0 = (INSWORD>>23)&1;
			op1 = (INSWORD>>13)&1;
			if(!op0)
				return decode_iclass_sve_fp8_fma_long_long(ctx, dec);
			if(op0 && !op1)
				return decode_iclass_sve_fp8_fma_long(ctx, dec);
			if(op0 && op1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_353_sve_fp8_fma_w
			UNMATCHED;
		}
		if(op0==3 && (op1&0xb0)==0x10 && (op2&0x33)==0x23)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_257_sve
		if(op0==3 && (op1&0xb0)==0x10 && (op2&0x34)==0x34)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_249_sve
		if(op0==3 && (op1&0xb0)==0x30 && (op2&0x32)==0x22)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_250_sve
		if(op0==3 && (op1&0xb0)==0x30 && (op2&0x14)==0x14)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_247_sve
		if(op0==3 && (op1&0x9f)==1 && (op2&0x38)==0x20)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_264_sve
		if(op0==3 && (op1&0x9e)==4 && (op2&0x38)==0x20)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_261_sve
		if(op0==3 && !(op1&0x9a) && (op2&0x30)==0x30)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_251_sve
		if(op0==3 && (op1&0x9a)==2 && (op2&0x20)==0x20)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_248_sve
		if(op0==3 && (op1&0x9c)==8 && (op2&0x30)==0x30)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_252_sve
		if(op0==3 && (op1&0x9c)==12 && (op2&0x20)==0x20) {
			/* GROUP: sve_fp_zeroing_unary */
			op0 = (INSWORD>>16)&7;
			if(!(op0&6))
				return decode_iclass_sve_fp_z2op_p_zd_a(ctx, dec);
			if(op0==2)
				return decode_iclass_sve_fp_z2op_p_zd_b_0(ctx, dec);
			if(op0==3)
				return decode_iclass_sve_fp_z2op_p_zd_b_1(ctx, dec);
			if((op0&6)==4)
				return decode_iclass_sve_fp_z2op_p_zd_c(ctx, dec);
			if((op0&6)==6)
				return decode_iclass_sve_fp_z2op_p_zd_d(ctx, dec);
			UNMATCHED;
		}
		if(op0==3 && (op1&0x90)==0x10 && op2==11)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_262_sve
		if(op0==3 && (op1&0x90)==0x10 && (op2&0x3c)==12)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_253_sve
		if(op0==3 && (op1&0x90)==0x10 && (op2&0x34)==0x10) {
			/* GROUP: sve_fp_fma_w_by_indexed_elem */
			op0 = (INSWORD>>23)&1;
			op1 = (INSWORD>>13)&1;
			if(!op0 && !op1)
				return decode_iclass_sve_fp_fdot_by_indexed_elem(ctx, dec);
			if(!op0 && op1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_354_sve_fp_fma_w_by_indexed_elem
			if(op0)
				return decode_iclass_sve_fp_fma_long_by_indexed_elem(ctx, dec);
			UNMATCHED;
		}
		if(op0==3 && (op1&0x90)==0x10 && (op2&0x36)==0x20) {
			/* GROUP: sve_fp_fma_w */
			op0 = (INSWORD>>23)&1;
			op1 = (INSWORD>>13)&1;
			if(!op0 && !op1)
				return decode_iclass_sve_fp_fdot(ctx, dec);
			if(!op0 && op1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_355_sve_fp_fma_w
			if(op0)
				return decode_iclass_sve_fp_fma_long(ctx, dec);
			UNMATCHED;
		}
		if(op0==3 && (op1&0x90)==0x10 && (op2&0x36)==0x24)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_254_sve
		if(op0==3 && (op1&0x90)==0x10 && (op2&0x3e)==0x3a)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_258_sve
		if(op0==3 && (op1&0x9c)==0x84 && (op2&0x3c)==8)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_263_sve
		if(op0==3 && (op1&0x9c)==0x84 && (op2&0x3c)==12) {
			/* GROUP: sve_fp_unary_unpred */
			op0 = (INSWORD>>22)&3;
			op1 = (INSWORD>>16)&7;
			op2 = (INSWORD>>10)&3;
			op3 = (INSWORD>>5)&1;
			if(!op0 && !(op1&6))
				return decode_iclass_sve_fp8_fcvt_wide(ctx, dec);
			if(!op0 && op1==2 && !op3)
				return decode_iclass_sve_fp8_fcvt_narrow(ctx, dec);
			if(!op0 && op1==2 && op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_361_sve_fp_unary_unpred
			if(!op0 && op1==3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_359_sve_fp_unary_unpred
			if(op1==4)
				return decode_iclass_sve_fp_ucvtf_wide(ctx, dec);
			if(op1==5 && !(op2&2) && !op3)
				return decode_iclass_sve_fp_fcvtzu_narrow(ctx, dec);
			if(op1==5 && !(op2&2) && op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_360_sve_fp_unary_unpred
			if(op1==5 && (op2&2)==2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_358_sve_fp_unary_unpred
			if((op1&6)==6 && !op2)
				return decode_iclass_sve_fp_2op_u_zd(ctx, dec);
			if((op1&6)==6 && op2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_357_sve_fp_unary_unpred
			if(op0 && !(op1&4))
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_356_sve_fp_unary_unpred
			UNMATCHED;
		}
		if(op0==3 && (op1&0x9c)==0x88 && (op2&0x38)==8) {
			/* GROUP: sve_fp_cmpzero */
			op0 = (INSWORD>>18)&1;
			if(!op0)
				return decode_iclass_sve_fp_2op_p_pd(ctx, dec);
			if(op0)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_362_sve_fp_cmpzero
			UNMATCHED;
		}
		if(op0==3 && (op1&0x9c)==0x8c && (op2&0x38)==8) {
			/* GROUP: sve_fp_slowreduce */
			op0 = (INSWORD>>18)&1;
			if(!op0)
				return decode_iclass_sve_fp_2op_p_vd(ctx, dec);
			if(op0)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_363_sve_fp_slowreduce
			UNMATCHED;
		}
		if(op0==3 && (op1&0x90)==0x80 && (op2&0x38)==0x20) {
			/* GROUP: sve_fp_pred */
			op0 = (INSWORD>>19)&3;
			op1 = (INSWORD>>10)&7;
			op2 = (INSWORD>>6)&15;
			if(!(op0&2))
				return decode_iclass_sve_fp_2op_p_zds(ctx, dec);
			if(op0==2 && !op1)
				return decode_iclass_sve_fp_ftmad(ctx, dec);
			if(op0==2 && op1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_364_sve_fp_pred
			if(op0==3 && !op2)
				return decode_iclass_sve_fp_2op_i_p_zds(ctx, dec);
			if(op0==3 && op2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_365_sve_fp_pred
			UNMATCHED;
		}
		if(op0==3 && (op1&0x90)==0x80 && (op2&0x38)==0x28) {
			/* GROUP: sve_fp_unary */
			op0 = (INSWORD>>18)&7;
			if(!(op0&6))
				return decode_iclass_sve_fp_2op_p_zd_a(ctx, dec);
			if(op0==2)
				return decode_iclass_sve_fp_2op_p_zd_b_0(ctx, dec);
			if(op0==3)
				return decode_iclass_sve_fp_2op_p_zd_b_1(ctx, dec);
			if((op0&6)==4)
				return decode_iclass_sve_fp_2op_p_zd_c(ctx, dec);
			if((op0&6)==6)
				return decode_iclass_sve_fp_2op_p_zd_d(ctx, dec);
			UNMATCHED;
		}
		if(op0==3 && (op1&0x90)==0x90) {
			/* GROUP: sve_fp_fma */
			op0 = (INSWORD>>15)&1;
			if(!op0)
				return decode_iclass_sve_fp_3op_p_zds_a(ctx, dec);
			if(op0)
				return decode_iclass_sve_fp_3op_p_zds_b(ctx, dec);
			UNMATCHED;
		}
		if(op0==4) {
			/* GROUP: sve_mem32 */
			op0 = (INSWORD>>23)&3;
			op1 = (INSWORD>>21)&3;
			op2 = (INSWORD>>13)&7;
			op3 = (INSWORD>>4)&1;
			if(!op0 && op1&1 && !(op2&4) && !op3)
				return decode_iclass_sve_mem_32b_prfm_sv(ctx, dec);
			if(!op0 && op1&1 && !(op2&4) && op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_366_sve_mem32
			if(op0==1 && op1&1 && !(op2&4))
				return decode_iclass_sve_mem_32b_gld_sv_a(ctx, dec);
			if(op0==2 && op1&1 && !(op2&4))
				return decode_iclass_sve_mem_32b_gld_sv_b(ctx, dec);
			if(op0==3 && !(op1&2) && !op2 && !op3)
				return decode_iclass_sve_mem_32b_pfill(ctx, dec);
			if(op0==3 && !(op1&2) && !op2 && op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_370_sve_mem32
			if(op0==3 && !(op1&2) && op2==2)
				return decode_iclass_sve_mem_32b_fill(ctx, dec);
			if(op0==3 && !(op1&2) && (op2&5)==1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_367_sve_mem32
			if(op0==3 && (op1&2)==2 && !(op2&4) && !op3)
				return decode_iclass_sve_mem_prfm_si(ctx, dec);
			if(op0==3 && (op1&2)==2 && !(op2&4) && op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_368_sve_mem32
			if(!op1 && (op2&6)==4)
				return decode_iclass_sve_mem_32b_gldnt_vs(ctx, dec);
			if(!op1 && op2==6 && !op3)
				return decode_iclass_sve_mem_prfm_ss(ctx, dec);
			if(!op1 && op2==7 && !op3)
				return decode_iclass_sve_mem_32b_prfm_vi(ctx, dec);
			if(!op1 && (op2&6)==6 && op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_369_sve_mem32
			if(op1==1 && (op2&4)==4)
				return decode_iclass_sve_mem_32b_gld_vi(ctx, dec);
			if((op1&2)==2 && (op2&4)==4)
				return decode_iclass_sve_mem_ld_dup(ctx, dec);
			if(op0!=3 && !(op1&1) && !(op2&4))
				return decode_iclass_sve_mem_32b_gld_vs(ctx, dec);
			UNMATCHED;
		}
		if(op0==5) {
			/* GROUP: sve_memcld */
			op0 = (INSWORD>>21)&3;
			op1 = (INSWORD>>20)&1;
			op2 = (INSWORD>>13)&7;
			if(!op0 && !op1 && op2==7)
				return decode_iclass_sve_mem_cldnt_si(ctx, dec);
			if(!op0 && op1 && op2==1)
				return decode_iclass_sve_mem_cld_si_q(ctx, dec);
			if(!op0 && op1 && op2==7)
				return decode_iclass_sve_mem_eldq_si(ctx, dec);
			if(!op0 && op2==4)
				return decode_iclass_sve_mem_cld_ss_q(ctx, dec);
			if(!op0 && op2==6)
				return decode_iclass_sve_mem_cldnt_ss(ctx, dec);
			if(op0==1 && op2==4)
				return decode_iclass_sve_mem_eldq_ss(ctx, dec);
			if((op0&2)==2 && op2==4)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_371_sve_memcld
			if(!op1 && op2==1)
				return decode_iclass_sve_mem_ldqr_si(ctx, dec);
			if(!op1 && op2==5)
				return decode_iclass_sve_mem_cld_si(ctx, dec);
			if(op1 && op2==5)
				return decode_iclass_sve_mem_cldnf_si(ctx, dec);
			if(!op2)
				return decode_iclass_sve_mem_ldqr_ss(ctx, dec);
			if(op2==2)
				return decode_iclass_sve_mem_cld_ss(ctx, dec);
			if(op2==3)
				return decode_iclass_sve_mem_cldff_ss(ctx, dec);
			if(op0 && !op1 && op2==7)
				return decode_iclass_sve_mem_eld_si(ctx, dec);
			if(op0 && op1 && op2==1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_372_sve_memcld
			if(op0 && op1 && op2==7)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_373_sve_memcld
			if(op0 && op2==6)
				return decode_iclass_sve_mem_eld_ss(ctx, dec);
			UNMATCHED;
		}
		if(op0==6) {
			/* GROUP: sve_mem64 */
			op0 = (INSWORD>>23)&3;
			op1 = (INSWORD>>21)&3;
			op2 = (INSWORD>>13)&7;
			op3 = (INSWORD>>4)&1;
			if(!op0 && !op1 && op2==5)
				return decode_iclass_sve_mem_64b_gldq_vs(ctx, dec);
			if(!op0 && op1==1 && !(op2&4) && op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_375_sve_mem64
			if(!op0 && op1==3 && (op2&4)==4 && !op3)
				return decode_iclass_sve_mem_64b_prfm_sv2(ctx, dec);
			if(!op0 && op1==3 && op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_374_sve_mem64
			if(!op0 && op1&1 && !(op2&4) && !op3)
				return decode_iclass_sve_mem_64b_prfm_sv(ctx, dec);
			if(!op1 && op2==7 && !op3)
				return decode_iclass_sve_mem_64b_prfm_vi(ctx, dec);
			if(!op1 && op2==7 && op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_377_sve_mem64
			if(!op1 && (op2&5)==4)
				return decode_iclass_sve_mem_64b_gldnt_vs(ctx, dec);
			if(op1==1 && (op2&4)==4)
				return decode_iclass_sve_mem_64b_gld_vi(ctx, dec);
			if(op1==2 && (op2&4)==4)
				return decode_iclass_sve_mem_64b_gld_vs2(ctx, dec);
			if(!(op1&1) && !(op2&4))
				return decode_iclass_sve_mem_64b_gld_vs(ctx, dec);
			if(op0 && !op1 && op2==5)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_376_sve_mem64
			if(op0 && op1==3 && (op2&4)==4)
				return decode_iclass_sve_mem_64b_gld_sv2(ctx, dec);
			if(op0 && op1&1 && !(op2&4))
				return decode_iclass_sve_mem_64b_gld_sv(ctx, dec);
			UNMATCHED;
		}
		if(op0==7 && (op2&0x38)==8) {
			/* GROUP: sve_memsst_nt */
			op0 = (INSWORD>>22)&7;
			op1 = (INSWORD>>21)&1;
			if(!op0 && op1)
				return decode_iclass_sve_mem_sstq_64b_vs(ctx, dec);
			if(!(op0&1) && !op1)
				return decode_iclass_sve_mem_sstnt_64b_vs(ctx, dec);
			if(op0&1 && !op1)
				return decode_iclass_sve_mem_sstnt_32b_vs(ctx, dec);
			if(op0 && op1)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_378_sve_memsst_nt
			UNMATCHED;
		}
		if(op0==7 && (op2&0x38)==0x18) {
			/* GROUP: sve_memcst_nt */
			op0 = (INSWORD>>21)&3;
			if(!op0)
				return decode_iclass_sve_mem_cstnt_ss(ctx, dec);
			if(op0)
				return decode_iclass_sve_mem_est_ss(ctx, dec);
			UNMATCHED;
		}
		if(op0==7 && !(op2&0x28)) {
			/* GROUP: sve_memst_cs */
			op0 = (INSWORD>>22)&7;
			op1 = (INSWORD>>20)&3;
			op2 = (INSWORD>>14)&1;
			op3 = (INSWORD>>4)&1;
			if(!(op0&4) && !op1 && !op2)
				return decode_iclass_sve_mem_estq_si(ctx, dec);
			if(!(op0&4) && op1==1 && !op2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_380_sve_memst_cs
			if(!(op0&4) && (op1&2)==2 && !op2)
				return decode_iclass_sve_mem_estq_ss(ctx, dec);
			if((op0&6)==4 && !op2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_379_sve_memst_cs
			if(op0==6 && !op2 && !op3)
				return decode_iclass_sve_mem_pspill(ctx, dec);
			if(op0==6 && !op2 && op3)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_382_sve_memst_cs
			if(op0==6 && op2)
				return decode_iclass_sve_mem_spill(ctx, dec);
			if(op0==7 && !op2)
				UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_381_sve_memst_cs
			if(op0!=6 && op2)
				return decode_iclass_sve_mem_cst_ss(ctx, dec);
			UNMATCHED;
		}
		if(op0==7 && (op2&0x38)==0x28) {
			/* GROUP: sve_memst_ss2 */
			op0 = (INSWORD>>21)&3;
			if(!op0)
				return decode_iclass_sve_mem_sst_vs2(ctx, dec);
			if(op0==1)
				return decode_iclass_sve_mem_sst_sv2(ctx, dec);
			if(op0==2)
				return decode_iclass_sve_mem_sst_vi_a(ctx, dec);
			if(op0==3)
				return decode_iclass_sve_mem_sst_vi_b(ctx, dec);
			UNMATCHED;
		}
		if(op0==7 && (op2&0x38)==0x38) {
			/* GROUP: sve_memst_si */
			op0 = (INSWORD>>21)&3;
			op1 = (INSWORD>>20)&1;
			if(!op0 && op1)
				return decode_iclass_sve_mem_cstnt_si(ctx, dec);
			if(!op1)
				return decode_iclass_sve_mem_cst_si(ctx, dec);
			if(op0 && op1)
				return decode_iclass_sve_mem_est_si(ctx, dec);
			UNMATCHED;
		}
		if(op0==7 && (op2&0x28)==0x20) {
			/* GROUP: sve_memst_ss */
			op0 = (INSWORD>>21)&3;
			if(!op0)
				return decode_iclass_sve_mem_sst_vs_a(ctx, dec);
			if(op0==1)
				return decode_iclass_sve_mem_sst_sv_a(ctx, dec);
			if(op0==2)
				return decode_iclass_sve_mem_sst_vs_b(ctx, dec);
			if(op0==3)
				return decode_iclass_sve_mem_sst_sv_b(ctx, dec);
			UNMATCHED;
		}
		if(!op0 && (op1&0x90)==0x10 && !(op2&0x38))
			return decode_iclass_sve_int_bin_cons_arit_0(ctx, dec);
		if(!op0 && (op1&0x90)==0x10 && (op2&0x3c)==0x28)
			return decode_iclass_sve_int_bin_cons_misc_0_a(ctx, dec);
		if(!op0 && (op1&0x90)==0x90 && op2==8)
			return decode_iclass_sve_int_perm_dup_i(ctx, dec);
		if(!op0 && (op1&0x90)==0x90 && (op2&0x3e)==10)
			return decode_iclass_sve_int_perm_tbl_3src(ctx, dec);
		if(!op0 && (op1&0x90)==0x90 && op2==12)
			return decode_iclass_sve_int_perm_tbl(ctx, dec);
		if(!op0 && (op1&0x90)==0x90 && op2==13)
			return decode_iclass_sve_int_perm_tbxquads(ctx, dec);
		if(!op0 && (op1&0x90)==0x90 && (op2&0x38)==0x18)
			return decode_iclass_sve_int_perm_bin_perm_zz(ctx, dec);
		if(!op0 && (op1&0x90)==0x90 && (op2&0x30)==0x30)
			return decode_iclass_sve_int_sel_vvv(ctx, dec);
		if(op0==1 && (op1&0x90)==0x10)
			return decode_iclass_sve_int_ucmp_vi(ctx, dec);
		if(op0==1 && (op1&0x98)==0x80 && (op2&0x30)==0x10)
			return decode_iclass_sve_int_pred_log(ctx, dec);
		if(op0==1 && (op1&0x90)==0x80 && !(op2&0x10))
			return decode_iclass_sve_int_scmp_vi(ctx, dec);
		if(op0==1 && (op1&0x90)==0x90 && (op2&0x30)==0x10 && !op3)
			return decode_iclass_sve_int_pred_dup(ctx, dec);
		if(op0==2 && !(op1&0xf0) && (op2&0x3e)==0x32)
			return decode_iclass_sve_intx_dot2(ctx, dec);
		if(op0==2 && (op1&0xf0)==0x40 && (op2&0x3e)==0x32)
			return decode_iclass_sve_intx_dot2_by_indexed_elem(ctx, dec);
		if(op0==2 && !(op1&0x90) && (op2&0x3e)==0x30)
			return decode_iclass_sve_intx_clamp(ctx, dec);
		if(op0==2 && !(op1&0x90) && (op2&0x3d)==0x34)
			return decode_iclass_sve_ptr_muladd_unpred(ctx, dec);
		if(op0==2 && !(op1&0x90) && (op2&0x3d)==0x35)
			return decode_iclass_sve_abal(ctx, dec);
		if(op0==2 && !(op1&0x90) && (op2&0x38)==0x38)
			return decode_iclass_sve_int_perm_binquads(ctx, dec);
		if(op0==2 && (op1&0x90)==0x90 && (op2&0x38)==0x20)
			return decode_iclass_sve_intx_match(ctx, dec);
		if(op0==2 && (op1&0x90)==0x90 && (op2&0x38)==0x30)
			return decode_iclass_sve_intx_histcnt(ctx, dec);
		if(op0==3 && (op1&0xd0)==0x10 && op2==0x38)
			return decode_iclass_sve_fp8_fmmla(ctx, dec);
		if(op0==3 && (op1&0xd0)==0x50 && op2==0x38)
			return decode_iclass_sve_fp_fmmla_nw(ctx, dec);
		if(op0==3 && (op1&0xb0)==0x10 && (op2&0x3c)==0x14)
			return decode_iclass_sve_fp8_fma_long_by_indexed_elem(ctx, dec);
		if(op0==3 && !(op1&0x9f) && (op2&0x38)==0x20)
			return decode_iclass_sve_fp_fcadd(ctx, dec);
		if(op0==3 && !(op1&0x9e) && (op2&0x38)==0x28)
			return decode_iclass_sve_fp_fcvt2z(ctx, dec);
		if(op0==3 && (op1&0x9e)==4 && (op2&0x38)==0x28)
			return decode_iclass_sve_fp_fcvt2(ctx, dec);
		if(op0==3 && (op1&0x9c)==8 && (op2&0x38)==0x20)
			return decode_iclass_sve_fp_pairwise(ctx, dec);
		if(op0==3 && (op1&0x9c)==8 && (op2&0x38)==0x28)
			return decode_iclass_sve_fp_fast_redq(ctx, dec);
		if(op0==3 && !(op1&0x90) && !(op2&0x20))
			return decode_iclass_sve_fp_fcmla(ctx, dec);
		if(op0==3 && (op1&0x90)==0x10 && !(op2&0x3c))
			return decode_iclass_sve_fp_fma_by_indexed_elem(ctx, dec);
		if(op0==3 && (op1&0x90)==0x10 && (op2&0x3c)==4)
			return decode_iclass_sve_fp_fcmla_by_indexed_elem(ctx, dec);
		if(op0==3 && (op1&0x90)==0x10 && op2==9)
			return decode_iclass_sve_fp_clamp(ctx, dec);
		if(op0==3 && (op1&0x90)==0x10 && (op2&0x3d)==8)
			return decode_iclass_sve_fp_fmul_by_indexed_elem(ctx, dec);
		if(op0==3 && (op1&0x90)==0x10 && (op2&0x3c)==0x30)
			return decode_iclass_sve_fp8_fma_long_long_by_indexed_elem(ctx, dec);
		if(op0==3 && (op1&0x90)==0x10 && op2==0x39)
			return decode_iclass_sve_fp_fmmla(ctx, dec);
		if(op0==3 && (op1&0x9c)==0x80 && (op2&0x38)==8)
			return decode_iclass_sve_fp_fast_red(ctx, dec);
		if(op0==3 && (op1&0x90)==0x80 && !(op2&0x38))
			return decode_iclass_sve_fp_3op_u_zd(ctx, dec);
		if(op0==3 && (op1&0x90)==0x80 && (op2&0x10)==0x10)
			return decode_iclass_sve_fp_3op_p_pd(ctx, dec);
		UNMATCHED;
	}
	if((op1&13)==1)
		UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_0_A64
	if((op1&14)==8) {
		/* GROUP: dpimm */
		op0 = (INSWORD>>29)&3;
		op1 = (INSWORD>>22)&15;
		if(op0==3 && (op1&14)==14)
			return decode_iclass_dp_1src_imm(ctx, dec);
		if(!(op1&12))
			return decode_iclass_pcreladdr(ctx, dec);
		if((op1&14)==4)
			return decode_iclass_addsub_imm(ctx, dec);
		if(op1==6)
			return decode_iclass_addsub_immtags(ctx, dec);
		if(op1==7)
			return decode_iclass_minmax_imm(ctx, dec);
		if((op1&14)==8)
			return decode_iclass_log_imm(ctx, dec);
		if((op1&14)==10)
			return decode_iclass_movewide(ctx, dec);
		if((op1&14)==12)
			return decode_iclass_bitfield(ctx, dec);
		if(op0!=3 && (op1&14)==14)
			return decode_iclass_extract(ctx, dec);
		UNMATCHED;
	}
	if((op1&14)==10) {
		/* GROUP: control */
		op0 = INSWORD>>29;
		op1 = (INSWORD>>12)&0x3fff;
		op2 = INSWORD&0x1f;
		if(op0==2 && !(op1&0x3000))
			return decode_iclass_condbranch(ctx, dec);
		if(op0==2 && (op1&0x3000)==0x1000)
			return decode_iclass_miscbranch(ctx, dec);
		if(op0==3 && (op1&0x3008)==8)
			return decode_iclass_compbranch_regs2(ctx, dec);
		if((op0&6)==2 && (op1&0x2000)==0x2000)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_383_control
		if(op0==6 && !(op1&0x3000))
			return decode_iclass_exception(ctx, dec);
		if(op0==6 && (op1&0x3fec)==0x1000)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_394_control
		if(op0==6 && (op1&0x3ffc)==0x1020)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_396_control
		if(op0==6 && op1==0x1030)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_397_control
		if(op0==6 && op1==0x1031)
			return decode_iclass_systeminstrswithreg(ctx, dec);
		if(op0==6 && op1==0x1032 && op2==0x1f)
			return decode_iclass_hints(ctx, dec);
		if(op0==6 && op1==0x1032 && op2!=0x1f)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_398_control
		if(op0==6 && op1==0x1033)
			return decode_iclass_barriers(ctx, dec);
		if(op0==6 && (op1&0x3fcc)==0x1040)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_392_control
		if(op0==6 && (op1&0x3f8f)==0x1004)
			return decode_iclass_pstate(ctx, dec);
		if(op0==6 && (op1&0x3f8f)==0x1005)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_395_control
		if(op0==6 && (op1&0x3f8e)==0x1006)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_393_control
		if(op0==6 && (op1&0x3f88)==0x1008)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_391_control
		if(op0==6 && (op1&0x3f80)==0x1200)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_390_control
		if(op0==6 && (op1&0x3d80)==0x1080)
			return decode_iclass_systeminstrs(ctx, dec);
		if(op0==6 && (op1&0x3d00)==0x1100)
			return decode_iclass_systemmove(ctx, dec);
		if(op0==6 && (op1&0x3d80)==0x1400)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_389_control
		if(op0==6 && (op1&0x3d80)==0x1480)
			return decode_iclass_syspairinstrs(ctx, dec);
		if(op0==6 && (op1&0x3d00)==0x1500)
			return decode_iclass_systemmovepr(ctx, dec);
		if(op0==6 && (op1&0x3800)==0x1800)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_386_control
		if(op0==6 && (op1&0x2000)==0x2000)
			return decode_iclass_branch_reg(ctx, dec);
		if(op0==7 && (op1&0x3008)==8)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_387_control
		if(op0==7 && (op1&0x2000)==0x2000)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_384_control
		if(!(op0&3))
			return decode_iclass_branch_imm(ctx, dec);
		if((op0&3)==1 && !(op1&0x2000))
			return decode_iclass_compbranch(ctx, dec);
		if((op0&3)==1 && (op1&0x2000)==0x2000)
			return decode_iclass_testbranch(ctx, dec);
		if((op0&3)==3 && !(op1&0x300c))
			return decode_iclass_compbranch_regs(ctx, dec);
		if((op0&3)==3 && (op1&0x300c)==4)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_388_control
		if((op0&3)==3 && (op1&0x3004)==0x1000)
			return decode_iclass_compbranch_imm(ctx, dec);
		if((op0&3)==3 && (op1&0x3004)==0x1004)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_385_control
		UNMATCHED;
	}
	if((op1&7)==5) {
		/* GROUP: dpreg */
		op0 = (INSWORD>>30)&1;
		op1 = (INSWORD>>28)&1;
		op2 = (INSWORD>>21)&15;
		op3 = (INSWORD>>10)&0x3f;
		if(!op0 && op1 && op2==6)
			return decode_iclass_dp_2src(ctx, dec);
		if(op0 && op1 && op2==6)
			return decode_iclass_dp_1src(ctx, dec);
		if(!op1 && !(op2&8))
			return decode_iclass_log_shift(ctx, dec);
		if(!op1 && (op2&9)==8)
			return decode_iclass_addsub_shift(ctx, dec);
		if(!op1 && (op2&9)==9)
			return decode_iclass_addsub_ext(ctx, dec);
		if(op1 && !op2 && !op3)
			return decode_iclass_addsub_carry(ctx, dec);
		if(op1 && !op2 && (op3&0x38)==8)
			return decode_iclass_addsub_pt(ctx, dec);
		if(op1 && !op2 && (op3&0x38)==0x18)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_401_dpreg
		if(op1 && !op2 && op3==0x20)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_406_dpreg
		if(op1 && !op2 && (op3&0x28)==0x28)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_400_dpreg
		if(op1 && !op2 && (op3&0x1f)==1)
			return decode_iclass_rmif(ctx, dec);
		if(op1 && !op2 && (op3&0x1e)==4)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_404_dpreg
		if(op1 && !op2 && (op3&0x1a)==0x10)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_402_dpreg
		if(op1 && !op2 && (op3&15)==2)
			return decode_iclass_setf(ctx, dec);
		if(op1 && !op2 && (op3&15)==3)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_405_dpreg
		if(op1 && !op2 && (op3&14)==6)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_403_dpreg
		if(op1 && op2==2 && !(op3&2))
			return decode_iclass_condcmp_reg(ctx, dec);
		if(op1 && op2==2 && (op3&2)==2)
			return decode_iclass_condcmp_imm(ctx, dec);
		if(op1 && op2==4)
			return decode_iclass_condsel(ctx, dec);
		if(op1 && (op2&9)==1)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_399_dpreg
		if(op1 && (op2&8)==8)
			return decode_iclass_dp_3src(ctx, dec);
		UNMATCHED;
	}
	if((op1&7)==7) {
		/* GROUP: simd_dp */
		op0 = INSWORD>>28;
		op1 = (INSWORD>>23)&3;
		op2 = (INSWORD>>19)&15;
		op3 = (INSWORD>>10)&0x1ff;
		if(!(op0&13) && !(op1&2) && (op2&7)==5 && (op3&0x183)==2)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_432_simd_dp
		if(!(op0&13) && op1==3 && op3&1)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_412_simd_dp
		if(op0==4 && !(op1&2) && (op2&7)==5 && (op3&0x183)==2)
			return decode_iclass_cryptoaes(ctx, dec);
		if(op0==5 && !(op1&2) && !(op2&4) && !(op3&0x23))
			return decode_iclass_cryptosha3(ctx, dec);
		if(op0==5 && !(op1&2) && !(op2&4) && (op3&0x23)==2)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_423_simd_dp
		if(op0==5 && !(op1&2) && !(op2&4) && (op3&0x21)==0x20)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_417_simd_dp
		if(op0==5 && !(op1&2) && (op2&7)==5 && (op3&0x183)==2)
			return decode_iclass_cryptosha2(ctx, dec);
		if(op0==7 && !(op1&2) && !(op2&4) && !(op3&1))
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_414_simd_dp
		if((op0&14)==6 && !(op1&2) && (op2&7)==5 && (op3&0x183)==2)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_433_simd_dp
		if((op0&13)==5 && !op1 && !(op2&12) && (op3&0x21)==1)
			return decode_iclass_asisdone(ctx, dec);
		if((op0&13)==5 && op1==1 && !(op2&12) && (op3&0x21)==1)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_424_simd_dp
		if((op0&13)==5 && !(op1&2) && op2==7 && (op3&0x183)==2)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_437_simd_dp
		if((op0&13)==5 && !(op1&2) && (op2&12)==8 && (op3&0x31)==1)
			return decode_iclass_asisdsamefp16(ctx, dec);
		if((op0&13)==5 && !(op1&2) && (op2&12)==8 && (op3&0x31)==0x11)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_425_simd_dp
		if((op0&13)==5 && !(op1&2) && op2==15 && (op3&0x183)==2)
			return decode_iclass_asisdmiscfp16(ctx, dec);
		if((op0&13)==5 && !(op1&2) && !(op2&4) && (op3&0x21)==0x21)
			return decode_iclass_asisdsame2(ctx, dec);
		if((op0&13)==5 && !(op1&2) && (op2&7)==4 && (op3&0x183)==2)
			return decode_iclass_asisdmisc(ctx, dec);
		if((op0&13)==5 && !(op1&2) && (op2&7)==6 && (op3&0x183)==2)
			return decode_iclass_asisdpair(ctx, dec);
		if((op0&13)==5 && !(op1&2) && (op2&4)==4 && (op3&0x183)==0x82)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_426_simd_dp
		if((op0&13)==5 && !(op1&2) && (op2&4)==4 && (op3&0x103)==0x102)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_418_simd_dp
		if((op0&13)==5 && !(op1&2) && (op2&4)==4 && !(op3&3))
			return decode_iclass_asisddiff(ctx, dec);
		if((op0&13)==5 && !(op1&2) && (op2&4)==4 && op3&1)
			return decode_iclass_asisdsame(ctx, dec);
		if((op0&13)==5 && op1==2 && op3&1)
			return decode_iclass_asisdshf(ctx, dec);
		if((op0&13)==5 && (op1&2)==2 && !(op3&1))
			return decode_iclass_asisdelem(ctx, dec);
		if((op0&12)==4 && op1==3 && op3&1)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_410_simd_dp
		if(!(op0&11) && !(op1&2) && !(op2&4) && !(op3&0x23))
			return decode_iclass_asimdtbl(ctx, dec);
		if(!(op0&11) && !(op1&2) && !(op2&4) && (op3&0x23)==2)
			return decode_iclass_asimdperm(ctx, dec);
		if((op0&11)==2 && !(op1&2) && !(op2&4) && !(op3&0x21))
			return decode_iclass_asimdext(ctx, dec);
		if(!(op0&9) && !op1 && !(op2&12) && (op3&0x21)==1)
			return decode_iclass_asimdins(ctx, dec);
		if(!(op0&9) && op1==1 && !(op2&12) && (op3&0x21)==1)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_419_simd_dp
		if(!(op0&9) && !(op1&2) && op2==7 && (op3&0x183)==2)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_434_simd_dp
		if(!(op0&9) && !(op1&2) && (op2&12)==8 && (op3&0x31)==1)
			return decode_iclass_asimdsamefp16(ctx, dec);
		if(!(op0&9) && !(op1&2) && (op2&12)==8 && (op3&0x31)==0x11)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_420_simd_dp
		if(!(op0&9) && !(op1&2) && op2==15 && (op3&0x183)==2)
			return decode_iclass_asimdmiscfp16(ctx, dec);
		if(!(op0&9) && !(op1&2) && !(op2&4) && (op3&0x21)==0x20)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_413_simd_dp
		if(!(op0&9) && !(op1&2) && !(op2&4) && (op3&0x21)==0x21)
			return decode_iclass_asimdsame2(ctx, dec);
		if(!(op0&9) && !(op1&2) && (op2&7)==4 && (op3&0x183)==2)
			return decode_iclass_asimdmisc(ctx, dec);
		if(!(op0&9) && !(op1&2) && (op2&7)==6 && (op3&0x183)==2)
			return decode_iclass_asimdall(ctx, dec);
		if(!(op0&9) && !(op1&2) && (op2&4)==4 && (op3&0x183)==0x82)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_421_simd_dp
		if(!(op0&9) && !(op1&2) && (op2&4)==4 && (op3&0x103)==0x102)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_415_simd_dp
		if(!(op0&9) && !(op1&2) && (op2&4)==4 && !(op3&3))
			return decode_iclass_asimddiff(ctx, dec);
		if(!(op0&9) && !(op1&2) && (op2&4)==4 && op3&1)
			return decode_iclass_asimdsame(ctx, dec);
		if(!(op0&9) && op1==2 && !op2 && op3&1)
			return decode_iclass_asimdimm(ctx, dec);
		if(!(op0&9) && op1==2 && op2 && op3&1)
			return decode_iclass_asimdshf(ctx, dec);
		if(!(op0&9) && (op1&2)==2 && !(op3&1))
			return decode_iclass_asimdelem(ctx, dec);
		if((op0&13)==8)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_407_simd_dp
		if(op0==12 && !op1 && !(op2&8) && (op3&0x20)==0x20)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_422_simd_dp
		if(op0==12 && !op1 && (op2&12)==8 && (op3&0x30)==0x20)
			return decode_iclass_crypto3_imm2(ctx, dec);
		if(op0==12 && !op1 && (op2&12)==8 && (op3&0x30)==0x30)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_428_simd_dp
		if(op0==12 && !op1 && (op2&12)==12 && (op3&0x2c)==0x20)
			return decode_iclass_cryptosha512_3(ctx, dec);
		if(op0==12 && !op1 && (op2&12)==12 && (op3&0x2c)==0x24)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_435_simd_dp
		if(op0==12 && !op1 && (op2&12)==12 && (op3&0x28)==0x28)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_429_simd_dp
		if(op0==12 && !op1 && !(op3&0x20))
			return decode_iclass_crypto4(ctx, dec);
		if(op0==12 && op1==1 && !(op2&12))
			return decode_iclass_crypto3_imm6(ctx, dec);
		if(op0==12 && op1==1 && op2==8 && !(op3&0x1e0))
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_440_simd_dp
		if(op0==12 && op1==1 && op2==8 && (op3&0x1fc)==0x20)
			return decode_iclass_cryptosha512_2(ctx, dec);
		if(op0==12 && op1==1 && op2==8 && (op3&0x1fc)==0x30)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_443_simd_dp
		if(op0==12 && op1==1 && op2==8 && (op3&0x1ec)==0x24)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_442_simd_dp
		if(op0==12 && op1==1 && op2==8 && (op3&0x1e8)==0x28)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_441_simd_dp
		if(op0==12 && op1==1 && op2==8 && (op3&0x1c0)==0x40)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_439_simd_dp
		if(op0==12 && op1==1 && op2==8 && (op3&0x180)==0x80)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_438_simd_dp
		if(op0==12 && op1==1 && op2==8 && (op3&0x100)==0x100)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_436_simd_dp
		if(op0==12 && op1==1 && op2==9)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_430_simd_dp
		if(op0==12 && op1==1 && (op2&14)==10)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_427_simd_dp
		if(op0==12 && op1==1 && (op2&4)==4)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_416_simd_dp
		if(op0==12 && (op1&2)==2)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_411_simd_dp
		if(op0==14)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_409_simd_dp
		if((op0&13)==13)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_408_simd_dp
		if((op0&5)==1 && !(op1&2) && !(op2&4))
			return decode_iclass_float2fix(ctx, dec);
		if((op0&5)==1 && !(op1&2) && (op2&4)==4 && !(op3&0x3f))
			return decode_iclass_float2int(ctx, dec);
		if((op0&5)==1 && !(op1&2) && (op2&4)==4 && (op3&0x3f)==0x20)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_431_simd_dp
		if((op0&5)==1 && !(op1&2) && (op2&4)==4 && (op3&0x1f)==0x10)
			return decode_iclass_floatdp1(ctx, dec);
		if((op0&5)==1 && !(op1&2) && (op2&4)==4 && (op3&15)==8)
			return decode_iclass_floatcmp(ctx, dec);
		if((op0&5)==1 && !(op1&2) && (op2&4)==4 && (op3&7)==4)
			return decode_iclass_floatimm(ctx, dec);
		if((op0&5)==1 && !(op1&2) && (op2&4)==4 && (op3&3)==1)
			return decode_iclass_floatccmp(ctx, dec);
		if((op0&5)==1 && !(op1&2) && (op2&4)==4 && (op3&3)==2)
			return decode_iclass_floatdp2(ctx, dec);
		if((op0&5)==1 && !(op1&2) && (op2&4)==4 && (op3&3)==3)
			return decode_iclass_floatsel(ctx, dec);
		if((op0&5)==1 && (op1&2)==2)
			return decode_iclass_floatdp3(ctx, dec);
		UNMATCHED;
	}
	if((op1&5)==4) {
		/* GROUP: ldst */
		op0 = INSWORD>>28;
		op1 = (INSWORD>>26)&1;
		op2 = (INSWORD>>10)&0x7fff;
		if(!op0 && !op1 && (op2&0x4800)==0x4800)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_449_ldst
		if(op0==1 && op1 && (op2&0x4800)==0x4800)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_450_ldst
		if(!(op0&11) && !op1 && (op2&0x6800)==0x800)
			return decode_iclass_comswappr(ctx, dec);
		if(!(op0&11) && !op1 && (op2&0x6800)==0x4000)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_451_ldst
		if(!(op0&11) && !op1 && (op2&0x6800)==0x6000)
			return decode_iclass_comswappr_unpriv(ctx, dec);
		if(!(op0&11) && op1 && !(op2&0x6fc0))
			return decode_iclass_asisdlse(ctx, dec);
		if(!(op0&11) && op1 && (op2&0x6fc0)==0x40)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_474_ldst
		if(!(op0&11) && op1 && (op2&0x6800)==0x2000)
			return decode_iclass_asisdlsep(ctx, dec);
		if(!(op0&11) && op1 && (op2&0x4800)==0x800)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_445_ldst
		if(!(op0&11) && op1 && (op2&0x6f80)==0x4880)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_470_ldst
		if(!(op0&11) && op1 && (op2&0x6f00)==0x4900)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_465_ldst
		if(!(op0&11) && op1 && (op2&0x6e00)==0x4a00)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_460_ldst
		if(!(op0&11) && op1 && (op2&0x6c00)==0x4c00)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_456_ldst
		if(!(op0&11) && op1 && (op2&0x6780)==0x4000)
			return decode_iclass_asisdlso(ctx, dec);
		if(!(op0&11) && op1 && (op2&0x6000)==0x6000)
			return decode_iclass_asisdlsop(ctx, dec);
		if(!(op0&11) && op1 && (op2&0x2f80)==0x80)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_466_ldst
		if(!(op0&11) && op1 && (op2&0x2f00)==0x100)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_461_ldst
		if(!(op0&11) && op1 && (op2&0x2e00)==0x200)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_457_ldst
		if(!(op0&11) && op1 && (op2&0x2c00)==0x400)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_452_ldst
		if((op0&11)==1 && !op1 && (op2&0x4803)==0x4003)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_458_ldst
		if((op0&11)==1 && !op1 && (op2&0x483f)==0x4802)
			return decode_iclass_rcwcomswap(ctx, dec);
		if((op0&11)==1 && !op1 && (op2&0x483f)==0x4803)
			return decode_iclass_rcwcomswappr(ctx, dec);
		if((op0&11)==1 && !op1 && (op2&0x483e)==0x4806)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_471_ldst
		if((op0&11)==1 && !op1 && (op2&0x483a)==0x480a)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_467_ldst
		if((op0&11)==1 && !op1 && (op2&0x4832)==0x4812)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_462_ldst
		if((op0&11)==1 && !op1 && (op2&0x4822)==0x4822)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_459_ldst
		if((op0&11)==1 && !op1 && (op2&0x4803)==0x4800)
			return decode_iclass_memop_128(ctx, dec);
		if((op0&11)==1 && !op1 && (op2&0x4803)==0x4801)
			return decode_iclass_memop_unpriv(ctx, dec);
		if(op0==9 && !op1 && (op2&0x4803)==0x4003)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_463_ldst
		if(op0==9 && op1 && (op2&0x4800)==0x4800)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_453_ldst
		if((op0&14)==8 && !op1 && (op2&0x4800)==0x4800)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_446_ldst
		if(op0==13 && !op1 && (op2&0x7fe3)==0x47c3)
			return decode_iclass_ldst_gcs(ctx, dec);
		if(op0==13 && !op1 && (op2&0x7fe3)==0x67c3)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_485_ldst
		if(op0==13 && !op1 && (op2&0x5c03)==0x4003)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_472_ldst
		if(op0==13 && !op1 && (op2&0x5e03)==0x4403)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_475_ldst
		if(op0==13 && !op1 && (op2&0x5f03)==0x4603)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_477_ldst
		if(op0==13 && !op1 && (op2&0x5f83)==0x4703)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_479_ldst
		if(op0==13 && !op1 && (op2&0x5fc3)==0x4783)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_481_ldst
		if(op0==13 && !op1 && (op2&0x5fe3)==0x47e3)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_483_ldst
		if(op0==13 && !op1 && (op2&0x5803)==0x5003)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_468_ldst
		if(op0==13 && !op1 && (op2&0x4800)==0x4800)
			return decode_iclass_ldsttags(ctx, dec);
		if((op0&11)==8 && !op1 && (op2&0x6800)==0x800)
			return decode_iclass_ldstexclp(ctx, dec);
		if((op0&11)==8 && !op1 && (op2&0x6800)==0x4000)
			return decode_iclass_ldstexclr_unpriv(ctx, dec);
		if((op0&11)==8 && !op1 && (op2&0x6800)==0x6000)
			return decode_iclass_comswap_unpriv(ctx, dec);
		if((op0&11)==8 && op1)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_444_ldst
		if((op0&7)==4 && !op1 && (op2&0x4800)==0x4800)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_447_ldst
		if((op0&7)==5 && op1 && (op2&0x4800)==0x4800)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_448_ldst
		if(!(op0&3) && !op1 && !(op2&0x6800))
			return decode_iclass_ldstexclr(ctx, dec);
		if(!(op0&3) && !op1 && (op2&0x6800)==0x2000)
			return decode_iclass_ldstord(ctx, dec);
		if(!(op0&3) && !op1 && (op2&0x6800)==0x2800)
			return decode_iclass_comswap(ctx, dec);
		if((op0&3)==1 && !op1 && (op2&0x6803)==0x4002)
			return decode_iclass_ldiappstilp(ctx, dec);
		if((op0&3)==1 && !op1 && (op2&0x6fff)==0x6002)
			return decode_iclass_ldapstl_writeback(ctx, dec);
		if((op0&3)==1 && !op1 && (op2&0x6fff)==0x6006)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_486_ldst
		if((op0&3)==1 && !op1 && (op2&0x6ffb)==0x600a)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_484_ldst
		if((op0&3)==1 && !op1 && (op2&0x6ff3)==0x6012)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_482_ldst
		if((op0&3)==1 && !op1 && (op2&0x6fe3)==0x6022)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_480_ldst
		if((op0&3)==1 && !op1 && (op2&0x6fc3)==0x6042)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_478_ldst
		if((op0&3)==1 && !op1 && (op2&0x6f83)==0x6082)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_476_ldst
		if((op0&3)==1 && !op1 && (op2&0x6f03)==0x6102)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_473_ldst
		if((op0&3)==1 && !op1 && (op2&0x6e03)==0x6202)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_469_ldst
		if((op0&3)==1 && !op1 && (op2&0x6c03)==0x6402)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_464_ldst
		if((op0&3)==1 && !op1 && (op2&0x4803)==0x4000)
			return decode_iclass_ldapstl_unscaled(ctx, dec);
		if((op0&3)==1 && op1 && (op2&0x4803)==0x4000)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_454_ldst
		if((op0&3)==1 && op1 && (op2&0x4803)==0x4002)
			return decode_iclass_ldapstl_simd(ctx, dec);
		if((op0&3)==1 && op1 && (op2&0x4803)==0x4003)
			UNALLOCATED(ENC_UNKNOWN); // iclass: UNALLOCATED_455_ldst
		if((op0&3)==1 && !(op2&0x4000))
			return decode_iclass_loadlit(ctx, dec);
		if((op0&3)==1 && (op2&0x4803)==0x4001)
			return decode_iclass_memcms(ctx, dec);
		if((op0&3)==2 && !(op2&0x6000))
			return decode_iclass_ldstnapair_offs(ctx, dec);
		if((op0&3)==2 && (op2&0x6000)==0x2000)
			return decode_iclass_ldstpair_post(ctx, dec);
		if((op0&3)==2 && (op2&0x6000)==0x4000)
			return decode_iclass_ldstpair_off(ctx, dec);
		if((op0&3)==2 && (op2&0x6000)==0x6000)
			return decode_iclass_ldstpair_pre(ctx, dec);
		if((op0&3)==3 && !(op2&0x4803))
			return decode_iclass_ldst_unscaled(ctx, dec);
		if((op0&3)==3 && (op2&0x4803)==1)
			return decode_iclass_ldst_immpost(ctx, dec);
		if((op0&3)==3 && (op2&0x4803)==2)
			return decode_iclass_ldst_unpriv(ctx, dec);
		if((op0&3)==3 && (op2&0x4803)==3)
			return decode_iclass_ldst_immpre(ctx, dec);
		if((op0&3)==3 && (op2&0x4803)==0x800)
			return decode_iclass_memop(ctx, dec);
		if((op0&3)==3 && (op2&0x4803)==0x802)
			return decode_iclass_ldst_regoff(ctx, dec);
		if((op0&3)==3 && (op2&0x4801)==0x801)
			return decode_iclass_ldst_pac(ctx, dec);
		if((op0&3)==3 && (op2&0x4000)==0x4000)
			return decode_iclass_ldst_pos(ctx, dec);
		UNMATCHED;
	}
	UNMATCHED;
}
