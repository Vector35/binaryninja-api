#!/bin/sh
gcc -I decode decode/decode.c decode/mnemonic.c decode/names.c decode/operands.c decode/priv.c capstone_compare_test.c -l capstone -g -Wall -O3 -o capstone_compare.bin
