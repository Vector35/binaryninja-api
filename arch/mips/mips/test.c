/* build me, debug me:
gcc -g test.c mips.c -o test
lldb ./test -- e28f007b
b mips_decompose
b mips_disassemble
*/

#include <stdio.h>
#include <stdint.h>

#include "mips.h"

int disassemble(uint32_t insword, uint64_t address, enum MipsVersion version, char *result)
{
	int rc;
	Instruction instr;
	uint32_t bigendian = 0;

	memset(&instr, 0, sizeof(instr));
	rc = mips_decompose(&insword, 4, &instr, version, address, bigendian, 1);
	if(rc) {
		printf("ERROR: mips_decompose() returned %d\n", rc);
		return rc;
	}

	result[0] = '\0';
	rc = mips_disassemble(&instr, result, 4096);
	if(rc) {
		printf("ERROR: mips_disassemble() returned %d\n", rc);
		return rc;
	}

	return 0;
}

#define ASSERT(X) \
	if(!(X)) { \
		printf("failed assert() at %s:%d\n", __FILE__, __LINE__); \
		exit(-1); \
	}

int main(int ac, char **av)
{
	char instxt[4096];

	if(ac == 1) {
		printf("usage:\n");
		printf("\t%s [<address>] <instruction_word>\n", av[0]);
		printf("\t%s <instruction_word>\n", av[0]);
		printf("\t%s test\n", av[0]);
		printf("examples:\n");
		printf("\t%s 0 14E00003\n", av[0]);
		printf("\t%s 00405A58 14E00003\n", av[0]);
		printf("\t%s test\n", av[0]);
		exit(-1);
	}

	if(ac == 2 && !strcmp(av[1], "test")) {
		disassemble(0x14E00003, 0, MIPS_32, instxt);
		ASSERT(!strcmp(instxt, "bne\t$a3, $zero, 0x10"));
		disassemble(0x14E00003, 0x405a58, MIPS_32, instxt);
		ASSERT(!strcmp(instxt, "bne\t$a3, $zero, 0x405a68"));
		exit(0);
	}

	uint64_t address = 0;
	uint32_t insword = 0;
	if(ac == 2) {
		address = 0;
		insword = strtoul(av[1], NULL, 16);
	}
	else if(ac == 3) {
		address = strtoul(av[1], NULL, 16);
		insword = strtoul(av[2], NULL, 16);
	}

	if(0 == disassemble(insword, address, MIPS_32, instxt)) {
		printf("%08llX: %08X %s\n", address, insword, instxt);
	}
}
