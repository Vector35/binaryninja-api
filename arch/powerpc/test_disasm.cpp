/******************************************************************************

Tests just the disassembler part (NOT the architecture plugin).

Provide command line arguments for different cool tests.
Like `./test repl` to get an interactive disassembler
Like `./test speed` to get a timed test of instruction decomposition

g++ -std=c++11 -O0 -g -I capstone/include -L./build/capstone test_disasm.cpp disassembler.cpp -o test_disasm -lcapstone

******************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#if defined(_WIN32)
#include <winpos.h>
#else
#include <unistd.h>
#endif

#include "disassembler.h"

int print_errors = 1;
int cs_mode_local = 0;

int disas_instr_word(uint32_t instr_word, char *buf)
{
	int rc = -1;

	struct decomp_result res;
	struct cs_insn *insn = &(res.insn);
	struct cs_detail *detail = &(res.detail);
	struct cs_ppc *ppc = &(detail->ppc);

	if(powerpc_decompose((const uint8_t *)&instr_word, 4, 0, true, &res, cs_mode_local)) {
		if(print_errors) printf("ERROR: powerpc_decompose()\n");
		goto cleanup;
	}

	/* MEGA DETAILS, IF YOU WANT 'EM */
	if(0) {
		/* LEVEL1: id, address, size, bytes, mnemonic, op_str */
		printf("instruction id: %d\n", res.insn.id);

		/* LEVEL2: regs_read, regs_write, groups */
		printf("  regs read:");
		for(int j=0; j<detail->regs_read_count; ++j) {
			printf(" %s", cs_reg_name(res.handle, detail->regs_read[j]));
		}
		printf("\n");
		printf("  regs write:");
		for(int j=0; j<detail->regs_write_count; ++j) {
			printf(" %s", cs_reg_name(res.handle, detail->regs_write[j]));
		}
		printf("\n");
		printf("  groups:");
		for(int j=0; j<detail->groups_count; ++j) {
			int group = detail->groups[j];
			printf(" %d(%s)", group, cs_group_name(res.handle, group));
		}
		printf("\n");

		/* LEVEL3: branch code, branch hint, update_cr0, operands */
		if(1 /* branch instruction */) {
			printf("  branch code: %d\n", ppc->bc); // PPC_BC_LT, PPC_BC_LE, etc.
			printf("  branch hint: %d\n", ppc->bh); // PPC_BH_PLUS, PPC_BH_MINUS
		}

		printf("  update_cr0: %d\n", ppc->update_cr0);

		for(int j=0; j<ppc->op_count; ++j) {
			printf("  operand%d: ", j);

			// .op_count is number of operands
			// .operands[] is array of cs_ppc_op
			cs_ppc_op op = ppc->operands[j];

		 	switch(op.type) {
				case PPC_OP_INVALID:
					printf("invalid\n");
					break;
				case PPC_OP_REG:
					printf("reg: %s\n", cs_reg_name(res.handle, op.reg));
					break;
				case PPC_OP_IMM:
					printf("imm: 0x%X\n", op.imm);
					break;
				case PPC_OP_MEM:
					printf("mem (%s + %d)\n", cs_reg_name(res.handle, op.mem.base),
						op.mem.disp);
					break;
				case PPC_OP_CRX:
					printf("crx (scale:%d, reg:%s)\n", op.crx.scale,
						cs_reg_name(res.handle, op.crx.reg));
					break;
				default:
					printf("unknown (%d)\n", op.type);
					break;
			}
		}
	}

	if(powerpc_disassemble(&res, buf, 128)) {
	   if(print_errors) printf("ERROR: powerpc_disassemble()\n");
	   goto cleanup;
	}

	rc = 0;
	cleanup:
	return rc;
}

void usage()
{
	printf("send argument \"repl\" or \"speed\"\n");
}

int main(int ac, char **av)
{
	int rc = -1;
	char buf[256];
	int index;
	char* disasm_cmd = 0;
	int c;

#define BATCH 10000000
	opterr = 0;

	while ((c = getopt(ac, av, "qsp")) != -1)
	{
		switch (c)
		{
		case 'q':
			cs_mode_local = CS_MODE_QPX;
			break;
		case 's':
			cs_mode_local = CS_MODE_SPE;
			break;
		case 'p':
			cs_mode_local = CS_MODE_PS;
			break;
		default:
			usage();
			goto cleanup;
		}
	}

	if (optind >= ac)
	{
		usage();
		goto cleanup;
	}

	disasm_cmd = av[optind];

	powerpc_init(cs_mode_local);

	if(!strcasecmp(disasm_cmd, "repl")) {
		printf("REPL mode!\n");
		printf("example inputs (write the words as if after endian fetch):\n");
		printf("93e1fffc\n");
		printf("9421ffe0\n");
		printf("7c3fb380\n");
		printf("38a00000\n");
		while(1) {
			printf("disassemble> ");

			/* get line */
			if(NULL == fgets(buf, sizeof(buf), stdin)) {
				printf("ERROR: fgets()\n");
				continue;
			}

			uint32_t instr_word = strtoul(buf, NULL, 16);
			//printf("instruction word: %08X\n", instr_word);

			/* convert to string */
			if(disas_instr_word(instr_word, buf)) {
				printf("ERROR: disas_instr_word()\n");
				continue;
			}

			printf("%s\n", buf);
		}
	}
	else if(!strcasecmp(disasm_cmd, "speed")) {
		printf("SPEED TEST THAT COUNTS QUICK RETURNS FROM BAD INSTRUCTIONS AS DISASSEMBLED\n");
		print_errors = 0;
		uint32_t instr_word = 0x780b3f7c;

		while(1) {
			clock_t t0 = clock();

			for(int i=0; i<BATCH; ++i) {
				disas_instr_word(instr_word, buf);
				//printf("%08X: %s\n", instr_word, buf);
				instr_word++;
			}

			clock_t t1 = clock();
			double ellapsed = ((double)t1 - t0) / CLOCKS_PER_SEC;
			printf("current rate: %f instructions per second\n", (float)BATCH/ellapsed);
		}
	}
	else if(!strcasecmp(disasm_cmd, "speed2")) {
		printf("SPEED TEST THAT IS GIVEN NO CREDIT FOR QUICK RETURNS FROM BAD INSTRUCTIONS\n");
		print_errors = 0;
		uint32_t instr_word = 0x780b3f7c;

		while(1) {
			clock_t t0 = clock();
			int ndisasms = 0;

			for(int i=0; i<BATCH; ++i) {
				if(disas_instr_word(instr_word, buf) == 0) {
					ndisasms++;
				}
				//printf("%08X: %s\n", instr_word, buf);
				instr_word += 27;
			}

			clock_t t1 = clock();
			double ellapsed = ((double)t1 - t0) / CLOCKS_PER_SEC;
			printf("current rate: %f instructions per second\n", (float)ndisasms/ellapsed);
		}
	}
	else {
		printf("ERROR: dunno what to do with \"%s\"\n", av[1]);
		goto cleanup;
	}

	rc = 0;
	cleanup:
	return rc;
}

