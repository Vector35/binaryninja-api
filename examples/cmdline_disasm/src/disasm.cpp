#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "binaryninjacore.h"
#include "binaryninjaapi.h"

using namespace BinaryNinja;

/* forward declarations */
int parse_nib(const char *str, uint8_t *val);
int parse_uint8_hex(const char *str, uint8_t *result);

/******************************************************************************
 MAIN
******************************************************************************/

void usage(int ac, char **av)
{
	(void)ac;
	printf("  syntax: %s <arch+mode> <byte0> <byte1> ...\n", av[0]);
	printf("examples:\n");
	printf("  %s x86 83   83 ec 0c\n", av[0]);
	printf("  %s x86_64   48 89 e5\n", av[0]);
	printf("  %s armv7    14 d0 4d e2\n", av[0]);
	printf("  %s armv7eb  d0 14 e2 4d\n", av[0]);
	printf("  %s thumb2   4f f0 00 0c\n", av[0]);
	printf("  %s thumb2eb f0 4f 0c 00\n", av[0]);
	printf("  %s ppc      93 e1 ff fc\n", av[0]);
	printf("  %s aarch64  ff 43 00 d1\n", av[0]);
	printf("  %s mips32   27 bd ff f0\n", av[0]);
	printf("  %s mipsel32 f0 ff bd 27\n", av[0]);
}

int main(int ac, char **av)
{
	int rc = -1;
	unsigned int i;

	char					*archmode;
	BNArchitecture			*arch;

	size_t					nBytesDisasm;

	uint8_t					input[64];
	unsigned int			input_n;

	BNInstructionTextToken	*ttResult = NULL;
	size_t					ttCount;

	char					*path_bundled_plugins;

	/* plugin path */
	path_bundled_plugins = BNGetBundledPluginDirectory();
	printf("using bundled plugin path: %s\n", path_bundled_plugins);
	BNSetBundledPluginDirectory(path_bundled_plugins);
	BNInitPlugins(true);

	/* parse architecture argument */
	if(ac < 2)
		{ usage(ac, av); goto cleanup; }
	archmode = av[1];

	printf("looking up architecture \"%s\"\n", archmode);
	arch = BNGetArchitectureByName(archmode);
	if(!arch) {
		printf("ERROR: BNGetArchitectureByName() (is \"%s\" valid?)\n", archmode);
		usage(ac, av);
		goto cleanup;
	}

	/* parse bytes argument */
	input_n = ac - 2;
	for(i=0; i<input_n && i<sizeof(input); ++i) {
		if(parse_uint8_hex(av[i+2], input+i)) {
			printf("ERROR: can't parse byte: %s\n", av[i+2]);
			goto cleanup;
		}
	}

	printf("parsed bytes: ");
	for(i=0; i<input_n; ++i)
		printf("%02X ", input[i]);
	printf("\n");

	/* actually disassemble now */
	nBytesDisasm = input_n;
	BNGetInstructionText(arch, (const uint8_t *)input, 0, &nBytesDisasm,
	  &ttResult, &ttCount);

	//printf("%zu text tokens\n", ttCount);

	for(i=0; i<ttCount; ++i)
		printf("%s", ttResult[i].text);
	printf("\n");

	/* done! */
	cleanup:
	if(ttResult)
		BNFreeInstructionText(ttResult, ttCount);

	// Shutting down is required to allow for clean exit of the core
	BNShutdown();

	return rc;
}

/******************************************************************************
 PARSING
******************************************************************************/

int parse_nib(const char *str, uint8_t *val)
{
	int rc = -1;
	char c = *str;

	if(c>='0' && c<='9') {
		*val = c-'0';
		rc = 0;
	}
	else if(c>='a' && c<='f') {
		*val = 10 + (c-'a');
		rc = 0;
	}
	else if(c>='A' && c<='F') {
		*val = 10 + (c-'A');
		rc = 0;
	}
	else {
		printf("ERROR: %s('%c', ...)\n", __func__, c);
	}

	return rc;
}

int parse_uint8_hex(const char *str, uint8_t *result)
{
	int rc=-1;
	uint8_t v1, v2;

	if(parse_nib(str, &v1))
		goto cleanup;
	if(parse_nib(str+1, &v2))
		goto cleanup;

	*result = (v1 << 4) | v2;
	rc = 0;

	cleanup:
	return rc;
}

