// gcc -g test.c armv7.c -o test
// lldb ./test -- e28f007b
// b armv7_decompose
// b armv7_disassemble
//

#include <stdio.h>
#include <stdio.h>
#include <stdint.h>
#include "armv7.h"

int main(int ac, char **av)
{
	uint32_t insword = strtoul(av[1], NULL, 16);
	uint32_t address = 0;
	uint32_t endian = 0;
	uint32_t rc;

	Instruction instr;
	memset(&instr, 0, sizeof(instr));

	rc = armv7_decompose(insword, &instr, address, endian);
	if(rc) {
		printf("ERROR: armv7_decompose() returned %d\n", rc);
		return rc;
	}

	char instxt[4096];
	memset(instxt, 0, sizeof(instxt));
	rc = armv7_disassemble(&instr, instxt, sizeof(instxt));
	if(rc) {
		printf("ERROR: armv7_disassemble() returned %d\n", rc);
		return rc;
	}

	printf("%08X: %s\n", address, instxt);
}

