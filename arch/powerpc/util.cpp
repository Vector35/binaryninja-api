#include "disassembler.h"

#include <binaryninjaapi.h>
#define MYLOG(...) while(0);
//#define MYLOG BinaryNinja::LogDebug

void printOperandVerbose(decomp_result *res, cs_ppc_op *op)
{
	(void)res;
	if(op == NULL) {
		MYLOG("NULL\n");
		return;
	}

 	switch(op->type) {
		case PPC_OP_INVALID:
			MYLOG("invalid\n");
			break;
		case PPC_OP_REG:
			MYLOG("reg: %s\n", cs_reg_name(res->handle, op->reg));
			break;
		case PPC_OP_IMM:
			MYLOG("imm: 0x%X\n", op->imm);
			break;
		case PPC_OP_MEM:
			MYLOG("mem (%s + %d)\n", cs_reg_name(res->handle, op->mem.base),
				op->mem.disp);
			break;
		case PPC_OP_CRX:
			MYLOG("crx (scale:%d, reg:%s)\n", op->crx.scale,
				cs_reg_name(res->handle, op->crx.reg));
			break;
		default:
			MYLOG("unknown (%d)\n", op->type);
			break;
	}
}

void printInstructionVerbose(decomp_result *res)
{
	struct cs_insn *insn = &(res->insn);
	struct cs_detail *detail = &(res->detail);
	struct cs_ppc *ppc = &(detail->ppc);
	(void)insn;

	/* LEVEL1: id, address, size, bytes, mnemonic, op_str */
	MYLOG("instruction id: %d \"%s %s\"\n", insn->id, insn->mnemonic,
	  insn->op_str);

	MYLOG("  bytes: %02X %02X %02X %02X\n", insn->bytes[0], insn->bytes[1],
	  insn->bytes[2], insn->bytes[3]);

	/* LEVEL2: regs_read, regs_write, groups */
	MYLOG("  regs read:");
	for(int j=0; j<detail->regs_read_count; ++j) {
		MYLOG(" %s", cs_reg_name(res->handle, detail->regs_read[j]));
	}
	MYLOG("\n");
	MYLOG("  regs write:");
	for(int j=0; j<detail->regs_write_count; ++j) {
		MYLOG(" %s", cs_reg_name(res->handle, detail->regs_write[j]));
	}
	MYLOG("\n");
	MYLOG("  groups:");
	for(int j=0; j<detail->groups_count; ++j) {
		int group = detail->groups[j];
		(void)group;
		MYLOG(" %d(%s)", group, cs_group_name(res->handle, group));
	}
	MYLOG("\n");

	/* LEVEL3: branch code, branch hint, update_cr0, operands */
	if(1 /* branch instruction */) {
		MYLOG("  branch code: %d\n", ppc->bc); // PPC_BC_LT, PPC_BC_LE, etc.
		MYLOG("  branch hint: %d\n", ppc->bh); // PPC_BH_PLUS, PPC_BH_MINUS
	}

	MYLOG("  update_cr0: %d\n", ppc->update_cr0);

	// .op_count is number of operands
	// .operands[] is array of cs_ppc_op
	for(int j=0; j<ppc->op_count; ++j) {
		MYLOG("  operand%d: ", j);
		printOperandVerbose(res, &(ppc->operands[j]));
	}
}


