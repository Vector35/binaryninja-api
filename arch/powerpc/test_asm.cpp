/* this is meant to be linked up against assembler.cpp for stress test and
	benchmarking

g++ -std=c++11 -O0 -g -I capstone/include -L./build/capstone test_asm.cpp assembler.cpp -o test_asm -lcapstone

*/

/* */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

/* c++ stuff */
#include <map>
#include <string>
#include <vector>
using namespace std;

/* capstone stuff */
#include <capstone/capstone.h>

#include <sys/types.h>
#include <sys/stat.h>
#if defined(_WIN32)
#include <winpos.h>
#else
#include <unistd.h>
#endif

#include "assembler.h"

/*****************************************************************************/
/* main */
/*****************************************************************************/

#define TEST_ADDR 0xCAFEBAB0

int main(int ac, char **av)
{
	int rc = -1;
	uint32_t insWord = 0x800000A;
	uint8_t encoding[4];

	/* statistics crap */
	string srcWorstTime, srcWorstFails;
	clock_t t0, t1;
	double tdelta, tavg=0, tsum=0, tworst=0;
	int tcount = 0;
	uint32_t insWordWorstTime, insWordWorstFails;
	int failsWorst = 0;

	srand(time(NULL));

	/* decide mode */
	#define MODE_FILE 0
	#define MODE_RANDOM 1
	#define MODE_SINGLE 2
	int mode;
	if(ac > 1) {
		struct stat st;
		stat(av[1], &st);
		if(S_ISREG(st.st_mode)) {
			printf("FILE MODE!\n");
			mode = MODE_FILE;
		}
		else if(!strcmp(av[1], "random")) {
			printf("RANDOM MODE!\n");
			mode = MODE_RANDOM;
		}
		else {
			printf("SINGLE MODE!\n");
			mode = MODE_SINGLE;
		}
	}
	else {
		printf("need args!\n");
		return -1;
	}

	if(mode == MODE_FILE) {
		char *line;
		string src, err;
		size_t len;

		/* read file */
		FILE *fp = fopen(av[1], "r");
		if(!fp) {
			printf("ERROR: fopen(%s)\n", av[1]);
			return -1;
		}
		while(getline(&line, &len, fp) != -1)
			src += line;
		fclose(fp);

		/* assemble */
		vector<uint8_t> result;
		if(assemble_multiline(src, result, err)) {
			printf("error: %s", err.c_str());
			return -1;
		}

		/* result */
		printf("result: ");
		for(int i=0; i<result.size(); ++i)
			printf("%02X ", result[i]);
		printf("\n");

		return 0;
	}

	if(mode == MODE_SINGLE) {
		t0 = clock();

		int failures;
		string err;
		if(assemble_single(av[1], TEST_ADDR, encoding, err, failures)) {
			printf("ERROR: %s", err.c_str());
			return -1;
		}
		tdelta = (double)(clock()-t0)/CLOCKS_PER_SEC;

		printf("assemble_single() duration: %fs (%f assembles/sec)\n", tdelta, 1/tdelta);
		printf("converged after %d failures\n", failures);

		printf("result: ");
		for(int i=0; i<4; ++i)
			printf("%02X ", encoding[i]);
		printf("\n");

		return 0;
	}

	if(mode == MODE_RANDOM) {
		int failures;
		string src, err;

		while(1) {
			/* generate random word, disassemble with capstone */
			insWord = (rand()<<16) | rand();
			if(0 != disasm_capstone((uint8_t *)&insWord, TEST_ADDR, src, err)) {
				printf("ERROR: %s\n", err.c_str());
				return -1;
			}
			if(src == "undefined")
				continue;
			printf("%08X: %s\n", insWord, src.c_str());

			/* try to assemble it back to the instruction word */
			t0 = clock();
			if(assemble_single(src, TEST_ADDR, encoding, err, failures)) {
				printf("ERROR: %s", err.c_str());
				return -1;
			}

			/* benchmarking */
			tdelta = (double)(clock()-t0)/CLOCKS_PER_SEC;
			tsum += tdelta;
			tcount += 1;
			tavg = tsum/tcount;
			printf("assemble_single() duration: %fs, average: %fs (%f assembles/second)\n",
				tdelta, tavg, 1/tavg);

			if(tdelta > tworst) {
				insWordWorstTime = insWord;
				srcWorstTime = src;
				tworst = tdelta;
			}

			if(failures > failsWorst) {
				insWordWorstFails = insWord;
				failsWorst = failures;
				srcWorstFails = src;
			}

			printf("worst time: %f held by %08X: %s\n", tworst, insWordWorstTime, srcWorstTime.c_str());
			printf("worst fails: %d held by %08X: %s\n", failsWorst, insWordWorstFails, srcWorstFails.c_str());
		}

		return 0;
	}

	rc = 0;
	cleanup:
	return rc;
}

