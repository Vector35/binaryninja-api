/******************************************************************************

See disassembler.h for more information about how this fits into the PPC
architecture plugin picture.

******************************************************************************/

#include <string.h> // strcpy, etc.

#define MYLOG(...) while(0);
//#include <binaryninjaapi.h>
//#define MYLOG BinaryNinja::LogDebug

#include "disassembler.h"

/* have to do this... while options can be toggled after initialization (thru
	cs_option(), the modes cannot, and endianness is considered a mode) */
thread_local csh handle_lil = 0;
thread_local csh handle_big = 0;

extern "C" int
powerpc_init(int cs_mode_arg)
{
	int rc = -1;

	MYLOG("powerpc_init()\n");

	if(handle_lil || handle_big) {
		MYLOG("ERROR: already initialized!\n");
		goto cleanup;
	}

	/* initialize capstone handle */
	if(cs_open(CS_ARCH_PPC, (cs_mode)((int)CS_MODE_BIG_ENDIAN | cs_mode_arg), &handle_big) != CS_ERR_OK) {
		MYLOG("ERROR: cs_open()\n");
		goto cleanup;
	}

	if(cs_open(CS_ARCH_PPC, (cs_mode)((int)CS_MODE_LITTLE_ENDIAN | cs_mode_arg), &handle_lil) != CS_ERR_OK) {
		MYLOG("ERROR: cs_open()\n");
		goto cleanup;
	}

	cs_option(handle_big, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(handle_lil, CS_OPT_DETAIL, CS_OPT_ON);

	rc = 0;
	cleanup:
	if(rc) {
		powerpc_release();
	}

	return rc;
}

extern "C" void
powerpc_release(void)
{
	if(handle_lil) {
		cs_close(&handle_lil);
		handle_lil = 0;
	}

	if(handle_big) {
		cs_close(&handle_big);
		handle_big = 0;
	}
}

extern "C" int
powerpc_decompose(const uint8_t *data, int size, uint32_t addr, bool lil_end,
	struct decomp_result *res, int cs_mode_arg)
{
	int rc = -1;
	res->status = STATUS_ERROR_UNSPEC;

	if(!handle_lil) {
		powerpc_init(cs_mode_arg);
	}

	//typedef struct cs_insn {
	//	unsigned int id; /* see capstone/ppc.h for PPC_INS_ADD, etc. */
	//	uint64_t address;
	//	uint16_t size;
	//	uint8_t bytes[16];
	//	char mnemonic[32]; /* string */
	//	char op_str[160]; /* string */
	//	cs_detail *detail; /* need CS_OP_DETAIL ON and CS_OP_SKIPDATA is OFF */
	//} cs_insn;

	// where cs_detail is some details + architecture specific part
	// typedef struct cs_detail {
	//   uint8_t regs_read[12];
	//   uint8_t regs_read_count;
	//   uint8_t regs_write;
	//   uint8_t regs_write_count;
	//   uint8_t groups[8];
	//   uint8_t groups_count;
	//   cs_ppc *ppc;
	// }

	// and finally ppc is:
	// typedef struct cs_ppc {
	//   ppc_bc bc; /* branch code, see capstone/ppc.h for PPC_BC_LT, etc. */
	//   ppc_bh bh; /* branch hint, see capstone/ppc.h for PPC_BH_PLUS, etc. */
	//   bool update_cr0;
	//   uint8_t op_count;
	//   cs_ppc_op operands[8];
    // } cs_ppc;

	// and each operand is:
	// typedef struct cs_ppc_op {
	//   ppc_op_type type; /* see capstone/ppc.h for PPC_OP_REG, etc. */
	//   union {
	//	   unsigned int reg;	// register value for REG operand
	//	   int32_t imm;		// immediate value for IMM operand
	//	   ppc_op_mem mem;		// struct ppc_op_mem { uint base; int disp }
	//	   ppc_op_crx crx;		// struct ppc_op_crx { uint scale, uint reg }
	//   };
	// } cs_ppc_op;

	csh handle;
	struct cs_struct *hand_tmp = 0;
	cs_insn *insn = 0; /* instruction information
					cs_disasm() will allocate array of cs_insn here */

	/* which handle to use?
		BIG end or LITTLE end? */
	handle = handle_big;
	if(lil_end) handle = handle_lil;
	res->handle = handle;

	hand_tmp = (struct cs_struct *)handle;
	hand_tmp->mode = (cs_mode)((int)hand_tmp->mode | cs_mode_arg);

	/* call */
	size_t n = cs_disasm(handle, data, size, addr, 1, &insn);
	if(n != 1) {
		MYLOG("ERROR: cs_disasm() returned %" PRIdPTR " (cs_errno:%d)\n", n, cs_errno(handle));
		goto cleanup;
	}

	/* set the status */
	res->status = STATUS_SUCCESS;

	/* copy the instruction struct, and detail sub struct to result */
	memcpy(&(res->insn), insn, sizeof(cs_insn));
	memcpy(&(res->detail), insn->detail, sizeof(cs_detail));

	rc = 0;
	cleanup:
	if(insn) {
		cs_free(insn, 1);
		insn = 0;
	}
	return rc;
}

extern "C" int
powerpc_disassemble(struct decomp_result *res, char *buf, size_t len)
{
	/* ideally the "heavy" string disassemble result is derived from light data
		in the decomposition result, but capstone doesn't make this distinction */
	int rc = -1;

	if(len < strlen(res->insn.mnemonic)+strlen(res->insn.op_str) + 2) {
		MYLOG("ERROR: insufficient room\n");
		goto cleanup;
	}

	strcpy(buf, res->insn.mnemonic);
	strcat(buf, " ");
	strcat(buf, res->insn.op_str);

	rc = 0;
	cleanup:
	return rc;
}

extern "C" const char *
powerpc_reg_to_str(uint32_t rid, int cs_mode_arg)
{
	if(!handle_lil) {
		powerpc_init(cs_mode_arg);
	}

	return cs_reg_name(handle_lil, rid);
}

