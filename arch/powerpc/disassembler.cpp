/******************************************************************************

See disassembler.h for more information about how this fits into the PPC
architecture plugin picture.

******************************************************************************/

#include <string.h> // strcpy, etc.

#define MYLOG(...) while(0);
//#include <binaryninjaapi.h>
//#define MYLOG BinaryNinja::LogDebug

#include "disassembler.h"
#include "util.h"

/* have to do this... while options can be toggled after initialization (thru
	cs_option(), the modes cannot, and endianness is considered a mode) */
thread_local csh handle_lil = 0;
thread_local csh handle_big = 0;

int DoesQualifyForLocalDisassembly(const uint8_t *data, bool bigendian)
{
	uint32_t insword = *(uint32_t *)data;
	int result = PPC_INS_INVALID;
	uint32_t tmp = 0;

	if(bigendian == true)
	{
		insword = bswap32(insword);
	}

	// 111111xxx00xxxxxxxxxx00001000000 <- fcmpo
	tmp = insword & 0xFC6007FF;
	if (tmp==0xFC000040)
		result =  PPC_INS_BN_FCMPO;
	// 111100xxxxxxxxxxxxxxx00111010xxx <- xxpermr
	if((insword & 0xFC0007F8) == 0xF00001D0)
		result = PPC_INS_BN_XXPERMR;

	return result;
}

void ppc_fcmpo(uint32_t insword, decomp_result *res)
{
	unsigned regtmp = 0;

	// 111111AAA00BBBBBCCCCC00001000000 "fcmpo crA,fB,fC"
	regtmp = PPC_REG_CR0 + ((insword >> 23) & 7);
	res->detail.ppc.operands[0].reg = (ppc_reg)(regtmp);
	res->detail.ppc.operands[0].type = PPC_OP_REG;

	regtmp = PPC_REG_F0 + ((insword >> 16) & 31);
	res->detail.ppc.operands[1].reg = (ppc_reg)(regtmp);
	res->detail.ppc.operands[1].type = PPC_OP_REG;

	regtmp = PPC_REG_F0 + ((insword >> 11) & 31);
	res->detail.ppc.operands[2].reg = (ppc_reg)(regtmp);
	res->detail.ppc.operands[2].type = PPC_OP_REG;


#ifdef FORCE_TEST
	SStream ss;
	struct cs_struct* handle = 0;
	struct MCInst tempmc = {0};
	char* first_space = 0;

	// SStream_Init(&ss);
	ss.index = 0;
	ss.buffer[0] = '\0';
	regtmp = PPC_REG_CR0 + ((insword >> 23) & 7);
	tempmc.Operands[0].MachineOperandType = MCOperand::kRegister;
	tempmc.Operands[0].Kind = 1;
	tempmc.Operands[0].RegVal = regtmp;
	regtmp = PPC_REG_F0 + ((insword >> 16) & 31);
	tempmc.Operands[1].MachineOperandType = MCOperand::kRegister;
	tempmc.Operands[1].Kind = 1;
	tempmc.Operands[1].RegVal = regtmp;
	regtmp = PPC_REG_F0 + ((insword >> 11) & 31);
	tempmc.Operands[2].Kind = 1;
	tempmc.Operands[2].MachineOperandType = MCOperand::kRegister;
	tempmc.Operands[2].RegVal = regtmp;

	// temporarily set this so that print processing succeeds
	res->insn.id = PPC_INS_FCMPU;

	if (handle_big != 0)
	{
		handle = (struct cs_struct*)handle_big;
	}
	else if (handle_lil != 0)
	{
		handle = (struct cs_struct*)handle_lil;
	}

#define PPC_FCMPUS 804

	tempmc.csh = handle;
	tempmc.Opcode = PPC_FCMPUS;
	tempmc.flat_insn = &res->insn;
	tempmc.flat_insn->detail = &res->detail;

	if (handle != 0)
	{
		handle->printer(&tempmc, &ss, handle->printer_info);
	}

	// replace the 'fcmpu' with 'fcmpo'
	first_space = strchr(ss.buffer, ' ');
	strncpy(res->insn.op_str, first_space + 1, sizeof(res->insn.op_str));
#endif

	strncpy(res->insn.mnemonic, "fcmpo", sizeof(res->insn.mnemonic));

	// reset this to the target value
	res->insn.id = PPC_INS_BN_FCMPO;
	res->detail.ppc.op_count = 3;
}

void ppc_xxpermr(uint32_t insword, decomp_result *res)
{
	// 111100AAAAABBBBBCCCCC00011010BCA "xxpermr vsA,vsB,vsC"
	int a = ((insword & 0x3E00000)>>21)|((insword & 0x1)<<5);
	int b = ((insword & 0x1F0000)>>16)|((insword & 0x4)<<3);
	int c = ((insword & 0xF800)>>11)|((insword & 0x2)<<4);

	res->detail.ppc.operands[0].reg = (ppc_reg)(PPC_REG_VS0 + a);
	res->detail.ppc.operands[0].type = PPC_OP_REG;
	res->detail.ppc.operands[1].reg = (ppc_reg)(PPC_REG_VS0 + b);
	res->detail.ppc.operands[1].type = PPC_OP_REG;
	res->detail.ppc.operands[2].reg = (ppc_reg)(PPC_REG_VS0 + c);
	res->detail.ppc.operands[2].type = PPC_OP_REG;

	res->insn.id = PPC_INS_BN_XXPERMR;
	res->detail.ppc.op_count = 3;
	strncpy(res->insn.mnemonic, "xxpermr", sizeof(res->insn.mnemonic));
}

bool PerformLocalDisassembly(const uint8_t *data, uint64_t addr, size_t &len, decomp_result* res, bool bigendian)
{
	uint32_t local_op = 0;
	uint32_t insword = *(uint32_t *)data;

	if(bigendian == true)
	{
		insword = bswap32(insword);
	}

	local_op = DoesQualifyForLocalDisassembly(data, bigendian);

	switch(local_op)
	{
	case PPC_INS_BN_FCMPO:
		ppc_fcmpo(insword, res);
		break;
	case PPC_INS_BN_XXPERMR:
		ppc_xxpermr(insword, res);
		break;
	default:
		return false;
	}
	return true;
}

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
powerpc_decompose(const uint8_t *data, int size, uint64_t addr, bool lil_end,
	struct decomp_result *res, bool is_64bit, int cs_mode_arg)
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

static const char* const gqr_array[] = {"gqr0", "gqr1", "gqr2", "gqr3", "gqr4", "gqr5", "gqr6", "gqr7"};

extern "C" const char *
powerpc_reg_to_str(uint32_t rid, int cs_mode_arg)
{
	if ((cs_mode_arg & CS_MODE_PS) != 0)
	{
		if ((rid >= PPC_REG_BN_GQR0) && (rid < PPC_REG_BN_ENDING))
		{
			return gqr_array[rid - PPC_REG_BN_GQR0];
		}
	}
	
	if(!handle_lil) {
		powerpc_init(cs_mode_arg);
	}

	return cs_reg_name(handle_lil, rid);
}

extern "C" const uint32_t
powerpc_crx_to_reg(uint32_t rid)
{
	if (rid >= PPC_REG_CR0EQ && rid <= PPC_REG_CR7EQ)
		return (rid - PPC_REG_CR0EQ) * 4 + 2;
	else if (rid >= PPC_REG_CR0GT && rid <= PPC_REG_CR7GT)
		return (rid - PPC_REG_CR0GT) * 4 + 1;
	else if (rid >= PPC_REG_CR0LT && rid <= PPC_REG_CR7LT)
		return (rid - PPC_REG_CR0LT) * 4 + 0;
	else if (rid >= PPC_REG_CR0UN && rid <= PPC_REG_CR7UN)
		return (rid - PPC_REG_CR0UN) * 4 + 3;
	else
		return rid;
}

