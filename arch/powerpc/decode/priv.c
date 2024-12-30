#include "priv.h"

uint32_t GetA(uint32_t word32)
{
	return (word32 >> 16) & 0x1f;
}

uint32_t GetB(uint32_t word32)
{
	return (word32 >> 11) & 0x1f;
}

uint32_t GetC(uint32_t word32)
{
	return (word32 >> 6) & 0x1f;
}

uint32_t GetD(uint32_t word32)
{
	return (word32 >> 21) & 0x1f;
}

uint32_t GetS(uint32_t word32)
{
	return (word32 >> 21) & 0x1f;
}

uint32_t GetBI(uint32_t word32)
{
	return (word32 >> 16) & 0x1f;
}

uint32_t GetBO(uint32_t word32)
{
	return (word32 >> 21) & 0x1f;
}

uint32_t GetVsxA(uint32_t word32)
{
	uint32_t ax = (word32 >> 2) & 0x1;
	uint32_t a = (word32 >> 16) & 0x1f;

	return (ax << 5) | a;
}

uint32_t GetVsxB(uint32_t word32)
{
	uint32_t bx = (word32 >> 1) & 0x1;
	uint32_t b = (word32 >> 11) & 0x1f;
	
	return (bx << 5) | b;
}

uint32_t GetVsxC(uint32_t word32)
{
	uint32_t cx = (word32 >> 3) & 0x1;
	uint32_t c = (word32 >> 6) & 0x1f;

	return (cx << 5) | c;
}

uint32_t GetVsxD(uint32_t word32)
{
	uint32_t dx = word32 & 0x1;
	uint32_t d = (word32 >> 21) & 0x1f;

	return (dx << 5) | d;
}

uint32_t GetSpecialRegisterCommon(uint32_t word32)
{
	uint32_t xr5_9 = (word32 >> 16) & 0x1f;
	uint32_t xr0_4 = (word32 >> 11) & 0x1f;
	uint32_t xr = (xr0_4 << 5) | xr5_9;

	return xr;
}

uint32_t GetME(uint32_t word32)
{
	return (word32 >> 1) & 0x1f;
}

uint32_t GetMB(uint32_t word32)
{
	return (word32 >> 6) & 0x1f;
}

uint32_t GetSH(uint32_t word32)
{
	return (word32 >> 11) & 0x1f;
}

uint32_t GetSH64(uint32_t word32)
{
	uint32_t sh5 = (word32 >> 1) & 0x1;
	uint32_t sh4_0 = (word32 >> 11) & 0x1f;

	return (sh5 << 5) | sh4_0;
}

uint32_t GetMX64(uint32_t word32)
{
	uint32_t mx = (word32 >> 5) & 0x3f;

	// x <- mx5 || mx[0:5] in powerpc's stupid bit order
	return ((mx & 0x1) << 5) | (mx >> 1);
}

