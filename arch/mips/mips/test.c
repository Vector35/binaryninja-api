/* build me, debug me:
gcc -g test.c mips.c -o test
lldb ./test -- e28f007b
b mips_decompose
b mips_disassemble
*/

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

#include "mips.h"

int disassemble(uint32_t insword, uint64_t address, MipsVersion version, char *result)
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

void usage(char** av)
{
	printf("usage:\n");
	printf("\t%s [instruction_words]\n", av[0]);
	printf("\t%s test\n", av[0]);
	printf("example:\n");
	printf("\t%s 3c028081 68435a50 24445a50 6c830007\n", av[0]);
	printf("\t%s test\n", av[0]);
	exit(-1);
}

int main(int ac, char **av)
{
	char instxt[4096];
	uint32_t insword = 0;
	uint64_t baseaddr = 0;
	int instindex = 0;
	int c = 0;
	int version = MIPS_32;

	while ((c = getopt(ac, av, "klmnoa:")) != -1)
	{
		switch (c)
		{
		case 'k':
			version = MIPS_64;
			break;
		case 'l':
			version = MIPS_1;
			break;
		case 'm':
			version = MIPS_2;
			break;
		case 'n':
			version = MIPS_3;
			break;
		case 'o':
			version = MIPS_4;
			break;
		case 'a':
			baseaddr = strtoull(optarg, NULL, 0x10);
			break;
		default:
			usage(av);
			goto cleanup;
		}
	}

	if (optind >= ac)
	{
		usage(av);
		goto cleanup;
	}

	instindex = optind;

	if (ac == 2 && !strcmp(av[1], "test"))
	{
		disassemble(0x14E00003, 0, version, instxt);
		ASSERT(!strcmp(instxt, "bne\t$a3, $zero, 0x10"));
		disassemble(0x14E00003, 4, version, instxt);
		ASSERT(!strcmp(instxt, "bne\t$a3, $zero, 0x405a68"));
		exit(0);
	}

	while (instindex < ac)
	{
		insword = strtoul(av[instindex], NULL, 16);

		if (0 == disassemble(insword, baseaddr, version, instxt))
		{
			printf("%08llX: %08X %s\n", baseaddr, insword, instxt);
		}
		else
		{
			printf("%08llX: %08X ??\n", baseaddr, insword);
		}

		baseaddr += 4;
		instindex++;
	}

cleanup:
	return 0;
}
