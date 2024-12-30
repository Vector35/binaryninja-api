#include <inttypes.h>

#include "decode.h"

uint32_t GetA(uint32_t word32);
uint32_t GetB(uint32_t word32);
uint32_t GetC(uint32_t word32);
uint32_t GetD(uint32_t word32);
uint32_t GetS(uint32_t word32);

uint32_t GetBI(uint32_t word32);
uint32_t GetBO(uint32_t word32);

uint32_t GetVsxA(uint32_t word32);
uint32_t GetVsxB(uint32_t word32);
uint32_t GetVsxC(uint32_t word32);
uint32_t GetVsxD(uint32_t word32);

uint32_t GetSpecialRegisterCommon(uint32_t word32);

uint32_t GetME(uint32_t word32);
uint32_t GetMB(uint32_t word32);
uint32_t GetSH(uint32_t word32);
uint32_t GetSH64(uint32_t word32);
uint32_t GetMX64(uint32_t word32);

void FillOperands(Instruction* instruction, uint32_t word32, uint64_t address);
