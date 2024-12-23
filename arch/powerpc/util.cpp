#include "disassembler.h"

#include <binaryninjaapi.h>
#define MYLOG(...) while(0);
//#define MYLOG BinaryNinja::LogDebug

uint64_t sign_extend(size_t addressSize_local, uint64_t target, int signBit)
{
	if ((target >> signBit) & 1)
	{
		target = target | (~((1 << signBit) - 1));
	}

	if (addressSize_local == 4)
	{
		target = target & 0xffffffff;
	}
	return target;
}

