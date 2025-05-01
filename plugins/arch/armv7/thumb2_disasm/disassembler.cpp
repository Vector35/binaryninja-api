#include <map>
#include <string>
#include <vector>
#include <iostream>

#include "spec.h"
#include "disassembler.h"

/* from ../armv7/armv7.h */
#include "armv7.h"
using namespace armv7;

using namespace std;

/* helper prototypes */
int get_reg_name(int reg_idx, char *reg_name);

/* decompose an instruction stream into a decomposition result */
int thumb_decompose(struct decomp_request *info, struct decomp_result *result)
{
	int rc;

	/* initialize result */
	result->flags = STATUS_OK;
	result->status = FLAG_NONE;
	result->addrMode = ADDRMODE_UNSPECIFIED;
	memset(result->fields_mask, 0, sizeof(result->fields_mask));
	result->format = nullptr;
	result->formats = nullptr;
	result->formatCount = 0;
	result->pc = info->addr + 4;

	/* jump into generated code */
	rc = thumb_root(info, result);

	/* easy case #1: only one format string */
	if(result->formatCount == 1) {
		result->format = &result->formats[0];
	}
	/* easy case #2: pcode specified which format to use */
	else if(IS_FIELD_PRESENT(result, FIELD_fmt_idx)) {
		result->format = &result->formats[result->fields[FIELD_fmt_idx]];
	}
	/* determine address mode for neon instructions (reference: A7.7.1 Advanced SIMD addressing mode) */
	else if(result->group == INSN_GROUP_NEON) {
		uint32_t Rm = result->fields[FIELD_Rm];

		if(Rm == 0xF) {
			/* [<Rn>{@<align>}] */
			result->addrMode = ADDRMODE_ADVSIMD_0;
		}
		else if(Rm == 0xD) {
			/* [<Rn>{@<align>}]! */
			result->addrMode = ADDRMODE_ADVSIMD_1;
		}
		else {
			/* [<Rn>{@<align>}], <Rm> */
			result->addrMode = ADDRMODE_ADVSIMD_2;
		}
	}
	/* determine address mode for 3-format instructions */
	else if(result->formatCount == 3 &&
	  IS_FIELD_PRESENT(result, FIELD_index) &&
	  IS_FIELD_PRESENT(result, FIELD_wback))
	{
		uint32_t index = result->fields[FIELD_index];
		uint32_t wback = result->fields[FIELD_wback];

		if(index && !wback)
			result->addrMode = ADDRMODE_OFFSET;
		else if(index && wback)
			result->addrMode = ADDRMODE_PREINDEX;
		else if(!index && wback)
			result->addrMode = ADDRMODE_POSTINDEX;
		else
			result->flags |= FLAG_ADDRMODE_AMBIGUITY;
	}

	/* determine the address mode for 2 and 4-format instructions */
	else if((result->formatCount==2 || result->formatCount==4) &&
	  IS_FIELD_PRESENT(result, FIELD_P) &&
	  IS_FIELD_PRESENT(result, FIELD_W) &&
	  IS_FIELD_PRESENT(result, FIELD_U))
	{
		uint32_t P = result->fields[FIELD_P];
		uint32_t W = result->fields[FIELD_W];
		uint32_t U = result->fields[FIELD_U];

		if(result->formatCount == 4) {
			if(P && !W) result->addrMode = ADDRMODE_OFFSET;
			else if(P && W) result->addrMode = ADDRMODE_PREINDEX;
			else if(!P && W) result->addrMode = ADDRMODE_POSTINDEX;
			else if(!P && !W && U) result->addrMode = ADDRMODE_UNINDEXED;
			else result->flags |= FLAG_ADDRMODE_AMBIGUITY;
		}
		else if(result->formatCount == 2) {
			if(P && !W) result->addrMode = ADDRMODE_OFFSET;
			else if(!P && !W && U) result->addrMode = ADDRMODE_UNINDEXED;
			else result->flags |= FLAG_ADDRMODE_AMBIGUITY;
		}
	}

	/* choose from the n decompose formats
		result->formats[ addressing mode ] */
	if((rc == STATUS_OK) && !(result->status & STATUS_UNDEFINED) && !(result->format)) {

		/* if we resolved an address mode, select the format */
		if(result->addrMode != ADDRMODE_UNSPECIFIED) {
			result->format = &result->formats[result->addrMode];
		}

		/* otherwise, just choose the first one in the list */
		else if(result->formatCount >= 1) {
			result->flags |= FLAG_ADDRMODE_AMBIGUITY;
			result->format = &result->formats[0];
		}
		else {
			printf("major error! no format in decomposition result\n");
			rc = STATUS_UNDEFINED;
		}
	}

	#ifdef DEBUG_DISASM
	if(getenv("DEBUG_DISASM")) {
		printf("decomp_result status:\n");
		if(result->status & STATUS_OK) printf("  OK\n");
		if(result->status & STATUS_NO_BIT_MATCH) printf("  NO_BIT_MATCH\n");
		if(result->status & STATUS_ARCH_UNSUPPORTED) printf("  ARCH_UNSUPPORTED\n");
		if(result->status & STATUS_UNDEFINED) printf("  UNDEFINED\n");

		printf("decomp_result flags:\n");
		if(result->flags & FLAG_UNPREDICTABLE) printf("  UNPREDICTABLE\n");
		if(result->flags & FLAG_NOTPERMITTED) printf("  NOTPERMITTED\n");

		printf("address mode: %d\n", result->addrMode);
		if(result->addrMode == ADDRMODE_OFFSET) printf("  OFFSET\n");
		if(result->addrMode == ADDRMODE_PREINDEX) printf("  PREINDEX\n");
		if(result->addrMode == ADDRMODE_POSTINDEX) printf("  POSTINDEX\n");
		if(result->addrMode == ADDRMODE_UNSPECIFIED) printf("  UNSPECIFIED\n");
	}
	#endif

	return rc;
}

const char* get_thumb_condition_name(uint32_t cond)
{
	static const char *COND_lookup_str[] = {
			"eq", /* equal, Z==1 */
			"ne", /* not equal, Z==0 */
			"cs", /* greater than, equal, or unordered C==1, AKA HS */
			"cc", /* AKA "LO" */
			"mi",
			"pl",
			"vs",
			"vc",
			"hi",
			"ls",
			"ge",
			"lt",
			"gt",
			"le",
			"al",
			""
	};

	if (cond >= 0x10) {
			#ifdef DEBUG_DISASM
			if(getenv("DEBUG_DISASM")) {
					cout << "ERROR: invalid condition code " << cond << endl;
			}
			#endif
			return "";
	}
	return COND_lookup_str[cond];
}

bool thumb_has_writeback(struct decomp_result* result)
{
    /* for 16-bit LDM, {!} is removed if the base register is in the register list */
    if(result->mnem == armv7::ARMV7_LDM && result->instrSize==16) {
        int list = result->fields[FIELD_register_list];
        int Rn = result->fields[FIELD_Rn];
        //printf("Rn: 0x%x\n", Rn);
        /* if the base register is in the register list, we discard the bang */
        if(list & (1 << Rn))
        	return false;
        else
        	return true;
    }
    else
       	/* for others, {!} field determined by "W" element */
       	if(IS_FIELD_PRESENT(result, FIELD_W)) {
            if(result->fields[FIELD_W])
                return true;
       	}
       	else {
#ifdef DEBUG_DISASM
            if(getenv("DEBUG_DISASM")) {
                printf("ERROR: don't know how to deal with {!} field\n");
            }
#endif
            return false;
       	}
    return false;
}

/* inspect the decomposition result to return the operation name

	NOTE: this is more complicated than OP_ID -> string mapping
	because of standard assembler syntax fields, eg "VABS<c><q>.<dt>"

	main functioning is by:
	1) seeking struct instruction_format from the decomposition result
	2) inspecting .operation
	3) inspect .operationFlags
*/
std::string get_thumb_operation_name(struct decomp_result* result)
{
	if ((result->status & STATUS_UNDEFINED) || (!result->format)) {
		return "undefined";
	}

	const instruction_format* format = result->format;
	std::string contents = format->operation;

	/* the standard "{S}" setflag field */
	if (format->operationFlags & INSTR_FORMAT_FLAG_OPTIONAL_STATUS) {
		if(IS_FIELD_PRESENT(result, FIELD_S)) {
			if(result->fields[FIELD_S]) {
				contents += "s";
			}
		}
	}

	if(format->operationFlags & INSTR_FORMAT_FLAG_MASK) {
		const char *lookup_fc0[16] = {
			"undef", "ttt", "tt", "tte", "t", "tet", "te", "tee",
			"", "ett", "et", "ete", "e", "eet", "ee", "eee"
		};

		const char *lookup_fc1[16] = {
			"undef", "eee", "ee", "eet", "e", "ete", "et", "ett",
			"", "tee", "te", "tet", "t", "tte", "tt", "ttt"
		};

		const char **lookup = lookup_fc0;

		if(result->fields[FIELD_firstcond] & 1) {
			lookup = lookup_fc1;
		}

		contents += lookup[result->fields[FIELD_mask]];
	}

	if (format->operationFlags & INSTR_FORMAT_FLAG_EFFECT) {
		/* see B6.1.1 CPS */
		/* Encoding T1 (16 bit) */
		if(IS_FIELD_PRESENT(result, FIELD_im)) {
			const char *lookup[2] = {"ie", "id"};
			contents += lookup[result->fields[FIELD_im]];
		}
		/* Encoding T2 (32-bit) */
		else if(IS_FIELD_PRESENT(result, FIELD_imod)) {
			const char *lookup[4] = {"", "", "ie", "id"};
			contents += lookup[result->fields[FIELD_imod]];
		}
		else {
#ifdef DEBUG_DISASM
			if(getenv("DEBUG_DISASM")) {
				cout << "ERROR: can't populate <effect> field" << endl;
			}
#endif
			while(0);
		}
	}

	/* is conditional execution code? "<c>" */
	if (format->operationFlags & INSTR_FORMAT_FLAG_CONDITIONAL) {
		uint32_t value = COND_AL;
		if (IS_FIELD_PRESENT(result, FIELD_cond))
			value = result->fields[FIELD_cond];

		if(value < 15) {
			if(value != COND_AL)
				contents += get_thumb_condition_name(value);
		}
#ifdef DEBUG_DISASM
		else
			cout << "ERROR: invalid condition code index" << value << endl;
#endif
	}

	if(format->operationFlags & INSTR_FORMAT_FLAG_NEON_SIZE) {
		const char *lookup[4] = {".8", ".16", ".32", ".64"};
		int index = 0;
		if(IS_FIELD_PRESENT(result, FIELD_size))
			index = result->fields[FIELD_size];
		contents += lookup[index];
	}
	if(format->operationFlags & INSTR_FORMAT_FLAG_NEON_SINGLE_SIZE) {
		const char *lookup[4] = {"8", "16", "32", "64"};
		int index = 0;
		if(IS_FIELD_PRESENT(result, FIELD_size))
			index = result->fields[FIELD_size];
		contents += lookup[index];
	}
	if(format->operationFlags & INSTR_FORMAT_FLAG_NEON_TYPE_SIZE) {
		const char *tlookup[4] = {".error", ".S", ".S", ".U"};
		const char *slookup[4] = {"16", "32", "64", "8"};
		int tindex = 0;
		int sindex = 0;
		if(IS_FIELD_PRESENT(result, FIELD_size) && IS_FIELD_PRESENT(result, FIELD_type)) {
			tindex = result->fields[FIELD_type];
			sindex = result->fields[FIELD_size];
		}
		contents += tlookup[tindex];
		contents += slookup[sindex];
	}
	if (format->operationFlags & INSTR_FORMAT_FLAG_F16) {
		contents += ".F16";
	}
	if (format->operationFlags & INSTR_FORMAT_FLAG_F32) {
		contents += ".F32";
	}
	if (format->operationFlags & INSTR_FORMAT_FLAG_F64) {
		contents += ".F64";
	}

	if (format->operationFlags & INSTR_FORMAT_FLAG_WIDE) {
		contents += ".w";
	}

	if (format->operationFlags & INSTR_FORMAT_FLAG_INCREMENT_AFTER) {
		contents += "ia";
	}

	if (format->operationFlags & INSTR_FORMAT_FLAG_VFP_DATA_SIZE) {
		if(IS_FIELD_PRESENT(result, FIELD_dt)) {
			if(IS_FIELD_PRESENT(result, FIELD_td)) {
				switch(result->fields[FIELD_dt]) {
					case VFP_DATA_SIZE_S32F32: contents += ".S32.F32"; break;
					case VFP_DATA_SIZE_U32F32: contents += ".U32.F32"; break;
					case VFP_DATA_SIZE_F32S32: contents += ".F32.S32"; break;
					case VFP_DATA_SIZE_F32U32: contents += ".F32.U32"; break;
					default: contents += ".error"; break;
				}
			}
			else if(IS_FIELD_PRESENT(result, FIELD_unsigned)) {
				switch(result->fields[FIELD_dt]) {
					case VFP_DATA_SIZE_S8: contents += ".S8"; break;
					case VFP_DATA_SIZE_S16: contents += ".S16"; break;
					case VFP_DATA_SIZE_S32: contents += ".S32"; break;
					case VFP_DATA_SIZE_S64: contents += ".S64"; break;
					case VFP_DATA_SIZE_U8: contents += ".U8"; break;
					case VFP_DATA_SIZE_U16: contents += ".U16"; break;
					case VFP_DATA_SIZE_U32: contents += ".U32"; break;
					case VFP_DATA_SIZE_U64: contents += ".U64"; break;
					case VFP_DATA_SIZE_32: contents += ".32"; break;
					default: contents += ".error"; break;
				}
			}
			else if (IS_FIELD_PRESENT(result, FIELD_cmode)) {
				uint8_t cmode = result->fields[FIELD_cmode];
				uint8_t op = result->fields[FIELD_op];
				if (cmode >> 1 <= 3) contents += ".I32";
				else if (cmode >> 1 <= 5) contents += ".I16";
				else if (cmode == 12 || cmode == 13) contents += ".I32";
				else if (cmode == 12 || cmode == 13) contents += ".I32";
				else if (op == 0 && cmode == 14) contents += ".I8";
				else if (op == 0 && cmode == 15) contents += ".F32";
				else if (op == 1 && cmode == 14) contents += ".I64";
				else if (op == 1 && cmode == 15) contents += ".undefined";
				else contents += ".error";
			}
			else if(IS_FIELD_PRESENT(result, FIELD_iword)) {
				switch(result->fields[FIELD_dt]) {
					case VFP_DATA_SIZE_I8: contents += ".I8"; break;
					case VFP_DATA_SIZE_I16: contents += ".I16"; break;
					case VFP_DATA_SIZE_I32: contents += ".I32"; break;
					case VFP_DATA_SIZE_I64: contents += ".I64"; break;
					case VFP_DATA_SIZE_I_F32: contents += ".F32"; break;
					default: contents += ".error"; break;
				}
			}
			else {
				switch(result->fields[FIELD_dt]) {
					case VFP_DATA_SIZE_S8: contents += ".S8"; break;
					case VFP_DATA_SIZE_S16: contents += ".S16"; break;
					case VFP_DATA_SIZE_S32: contents += ".S32"; break;
					case VFP_DATA_SIZE_F32: contents += ".F32"; break;
					case VFP_DATA_SIZE_F64: contents += ".F64"; break;
					default: contents += ".error"; break;
				}
			}
		}
		if(IS_FIELD_PRESENT(result, FIELD_dt_suffix)) {
			switch(result->fields[FIELD_dt_suffix]) {
				case 0: contents += ".F32"; break;
				case 1: contents += ".F64"; break;
				default: contents += ".error"; break;
			}
		}
	}

	return contents;
}

int
get_reg_name(int reg_idx, char *reg_name)
{
	int rc = -1;

	reg_name[0] = '\0';

	switch(reg_idx) {
		case REG_R0: strcpy(reg_name, "r0"); break;
		case REG_R1: strcpy(reg_name, "r1"); break;
		case REG_R2: strcpy(reg_name, "r2"); break;
		case REG_R3: strcpy(reg_name, "r3"); break;
		case REG_R4: strcpy(reg_name, "r4"); break;
		case REG_R5: strcpy(reg_name, "r5"); break;
		case REG_R6: strcpy(reg_name, "r6"); break;
		case REG_R7: strcpy(reg_name, "r7"); break;
		case REG_R8: strcpy(reg_name, "r8"); break;
		case REG_R9: strcpy(reg_name, "r9"); break;
		case REG_R10: strcpy(reg_name, "r10"); break;
		case REG_R11: strcpy(reg_name, "r11"); break;
		case REG_R12: strcpy(reg_name, "r12"); break;
		case REG_SP: strcpy(reg_name, "sp"); break; // 13
		case REG_LR: strcpy(reg_name, "lr"); break; // 14
		case REG_PC: strcpy(reg_name, "pc"); break; // 15
		case REG_S0: strcpy(reg_name, "s0"); break;
		case REG_S1: strcpy(reg_name, "s1"); break;
		case REG_S2: strcpy(reg_name, "s2"); break;
		case REG_S3: strcpy(reg_name, "s3"); break;
		case REG_S4: strcpy(reg_name, "s4"); break;
		case REG_S5: strcpy(reg_name, "s5"); break;
		case REG_S6: strcpy(reg_name, "s6"); break;
		case REG_S7: strcpy(reg_name, "s7"); break;
		case REG_S8: strcpy(reg_name, "s8"); break;
		case REG_S9: strcpy(reg_name, "s9"); break;
		case REG_S10: strcpy(reg_name, "s10"); break;
		case REG_S11: strcpy(reg_name, "s11"); break;
		case REG_S12: strcpy(reg_name, "s12"); break;
		case REG_S13: strcpy(reg_name, "s13"); break;
		case REG_S14: strcpy(reg_name, "s14"); break;
		case REG_S15: strcpy(reg_name, "s15"); break;
		case REG_S16: strcpy(reg_name, "s16"); break;
		case REG_S17: strcpy(reg_name, "s17"); break;
		case REG_S18: strcpy(reg_name, "s18"); break;
		case REG_S19: strcpy(reg_name, "s19"); break;
		case REG_S20: strcpy(reg_name, "s20"); break;
		case REG_S21: strcpy(reg_name, "s21"); break;
		case REG_S22: strcpy(reg_name, "s22"); break;
		case REG_S23: strcpy(reg_name, "s23"); break;
		case REG_S24: strcpy(reg_name, "s24"); break;
		case REG_S25: strcpy(reg_name, "s25"); break;
		case REG_S26: strcpy(reg_name, "s26"); break;
		case REG_S27: strcpy(reg_name, "s27"); break;
		case REG_S28: strcpy(reg_name, "s28"); break;
		case REG_S29: strcpy(reg_name, "s29"); break;
		case REG_S30: strcpy(reg_name, "s30"); break;
		case REG_S31: strcpy(reg_name, "s31"); break;
		case REG_D0: strcpy(reg_name, "d0"); break;
		case REG_D1: strcpy(reg_name, "d1"); break;
		case REG_D2: strcpy(reg_name, "d2"); break;
		case REG_D3: strcpy(reg_name, "d3"); break;
		case REG_D4: strcpy(reg_name, "d4"); break;
		case REG_D5: strcpy(reg_name, "d5"); break;
		case REG_D6: strcpy(reg_name, "d6"); break;
		case REG_D7: strcpy(reg_name, "d7"); break;
		case REG_D8: strcpy(reg_name, "d8"); break;
		case REG_D9: strcpy(reg_name, "d9"); break;
		case REG_D10: strcpy(reg_name, "d10"); break;
		case REG_D11: strcpy(reg_name, "d11"); break;
		case REG_D12: strcpy(reg_name, "d12"); break;
		case REG_D13: strcpy(reg_name, "d13"); break;
		case REG_D14: strcpy(reg_name, "d14"); break;
		case REG_D15: strcpy(reg_name, "d15"); break;
		case REG_D16: strcpy(reg_name, "d16"); break;
		case REG_D17: strcpy(reg_name, "d17"); break;
		case REG_D18: strcpy(reg_name, "d18"); break;
		case REG_D19: strcpy(reg_name, "d19"); break;
		case REG_D20: strcpy(reg_name, "d20"); break;
		case REG_D21: strcpy(reg_name, "d21"); break;
		case REG_D22: strcpy(reg_name, "d22"); break;
		case REG_D23: strcpy(reg_name, "d23"); break;
		case REG_D24: strcpy(reg_name, "d24"); break;
		case REG_D25: strcpy(reg_name, "d25"); break;
		case REG_D26: strcpy(reg_name, "d26"); break;
		case REG_D27: strcpy(reg_name, "d27"); break;
		case REG_D28: strcpy(reg_name, "d28"); break;
		case REG_D29: strcpy(reg_name, "d29"); break;
		case REG_D30: strcpy(reg_name, "d30"); break;
		case REG_D31: strcpy(reg_name, "d31"); break;
		case REG_Q0: strcpy(reg_name, "q0"); break;
		case REG_Q1: strcpy(reg_name, "q1"); break;
		case REG_Q2: strcpy(reg_name, "q2"); break;
		case REG_Q3: strcpy(reg_name, "q3"); break;
		case REG_Q4: strcpy(reg_name, "q4"); break;
		case REG_Q5: strcpy(reg_name, "q5"); break;
		case REG_Q6: strcpy(reg_name, "q6"); break;
		case REG_Q7: strcpy(reg_name, "q7"); break;
		case REG_Q8: strcpy(reg_name, "q8"); break;
		case REG_Q9: strcpy(reg_name, "q9"); break;
		case REG_Q10: strcpy(reg_name, "q10"); break;
		case REG_Q11: strcpy(reg_name, "q11"); break;
		case REG_Q12: strcpy(reg_name, "q12"); break;
		case REG_Q13: strcpy(reg_name, "q13"); break;
		case REG_Q14: strcpy(reg_name, "q14"); break;
		case REG_Q15: strcpy(reg_name, "q15"); break;
		default:
					  strcpy(reg_name, "ERROR");
					  goto cleanup;
	}

	rc = 0;
cleanup:
	//printf("in response to %d, returned %s and rc=%d\n", reg_idx, reg_name, rc);
	return rc;
}

