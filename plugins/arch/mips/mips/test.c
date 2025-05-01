/* build me, debug me:
gcc -g test.c mips.c -o test
lldb ./test -- e28f007b
b mips_decompose
b mips_disassemble
*/

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

#include "mips.h"

int disassemble(uint32_t insword, uint64_t address, MipsVersion version, int flags, char *result)
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
	do { if(!(X)) { \
		printf("failed assert() at %s:%d\n", __FILE__, __LINE__); \
		exit(-1); \
	} } while(0)


void usage(char** av)
{
	printf("usage:\n");
	printf("\t%s [-mips32|-mips64|-mips1|-mips2|-mips3|-mips4|-cavium] [-a BASEADDR] [instruction_words]+\n", av[0]);
	printf("\t\tdisassemble for the given MIPS version (MIPS32 by default)\n");
	printf("\t\tBASEADDR must be an unsigned 32-bit integer in hexadecimal\n");
	printf("\t%s test\n", av[0]);
	printf("example:\n");
	printf("\t%s 0c1001dc 8ca40000 2c410020 10200013\n", av[0]);
	printf("\t%s test\n", av[0]);
	exit(-1);
}

int main(int ac, char **av)
{
	char instxt[4096];
	uint32_t insword = 0;
	uint64_t baseaddr = 0;
	int instindex = 1;
	int c = 0;
	int version = -1;
	int flags = 0;
	int result = 0;

	if (ac > 1) {
		if (!strcmp("-mips64", av[1]))
			version = MIPS_64;
		else if (!strcmp("-mips32", av[1]))
			version = MIPS_32;
		else if (!strcmp("-mips1", av[1]))
			version = MIPS_1;
		else if (!strcmp("-mips2", av[1]))
			version = MIPS_2;
		else if (!strcmp("-mips3", av[1]))
			version = MIPS_3;
		else if (!strcmp("-mips4", av[1]))
			version = MIPS_4;
		else if (!strcmp("-cavium", av[1]))
		{
			version = MIPS_64;
			flags = DECOMPOSE_FLAGS_CAVIUM;
		}
		else if (!strcmp("-a", av[1]))
			;
		else if (av[1][0] == '-')
		{
			usage(av);
			goto cleanup;
		}
		if (version != -1)
		{
			instindex++;
		}
	}
	if (version == -1)
		version = MIPS_32;

	if (instindex < ac && !strcmp(av[instindex], "test"))
	{
		insword = 0x14E00003;
		baseaddr = 0;
		if (0 == disassemble(insword, baseaddr, version, flags, instxt))
		{
			printf("%08llX: %08X %s\n", baseaddr, insword, instxt);
		}
		else
		{
			printf("%08llX: %08X ??\n", baseaddr, insword);
		}
		// disassemble(0x14E00003, 0, version, flags, instxt);
		if (version < MIPS_32)
			ASSERT(!strcmp(instxt, "bne\t$a3, $zero, 0x10"));
		else
			ASSERT(!strcmp(instxt, "bnez\t$a3, 0x10"));
		baseaddr = 0x405a58;
		if (0 == disassemble(insword, baseaddr, version, flags, instxt))
		{
			printf("%08llX: %08X %s\n", baseaddr, insword, instxt);
		}
		else
		{
			printf("%08llX: %08X ??\n", baseaddr, insword);
		}
		// disassemble(0x14E00003, 4, version, flags, instxt);
		if (version < MIPS_32)
			ASSERT(!strcmp(instxt, "bne\t$a3, $zero, 0x405a68"));
		else
			ASSERT(!strcmp(instxt, "bnez\t$a3, 0x405a68"));
		exit(0);
	}

	if (instindex < ac && !strcmp(av[instindex], "-a")) {
		if (ac <= ++instindex) {
			printf("ERROR: Missing argument for -a\n");
            usage(av);
			result = -1;
            goto cleanup;
		}
        errno = 0;
		char *endptr;
		char *addr = av[instindex];
		if (addr[0] == '0' && addr[1] == 'x')
			addr += 2;
		baseaddr = strtoul(addr, &endptr, 16);
		if (errno == EINVAL || errno == ERANGE || (addr[0] != '\0' && (*(void **) endptr) == addr)) {
			printf("ERROR: Invalid argument for -a: \"%s\"\n", av[instindex]);
            usage(av);
			result = -1;
            goto cleanup;
		}
		if (ac <= ++instindex) {
			usage(av);
			result = -1;
			goto cleanup;
		}
	}

	while (instindex < ac)
	{
		insword = strtoul(av[instindex], NULL, 16);

		if (0 == disassemble(insword, baseaddr, version, flags, instxt))
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
	return result;
}
