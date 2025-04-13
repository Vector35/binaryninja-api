#include <inttypes.h>

#include "decode.h"

int32_t sign_extend(uint32_t x, unsigned numBits);

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

void FillOperands32(Instruction* instruction, uint32_t word32, uint64_t address);

Register Gpr(uint32_t value);
Register Crf(uint32_t value);
void PushUIMMValue(Instruction* instruction, uint64_t uimm);
void PushSIMMValue(Instruction* instruction, int32_t simm);
void PushRegister(Instruction* instruction, OperandClass cls, Register reg);
void PushRA(Instruction* instruction, uint32_t word32);
void PushRB(Instruction* instruction, uint32_t word32);
void PushRD(Instruction* instruction, uint32_t word32);
void PushRS(Instruction* instruction, uint32_t word32);
void PushCRBitA(Instruction* instruction, uint32_t word32);
void PushCRBitB(Instruction* instruction, uint32_t word32);
void PushCRBitD(Instruction* instruction, uint32_t word32);
void PushCRFD(Instruction* instruction, uint32_t word32);
void PushCRFDImplyCR0(Instruction* instruction, uint32_t word32);
void PushCRFS(Instruction* instruction, uint32_t word32);
void PushMem(Instruction* instruction, OperandClass cls, Register reg, int32_t offset);
void PushMemRA(Instruction* instruction, uint32_t word32);
void PushLabel(Instruction* instruction, uint64_t address);

void CopyOperand(Operand* dst, const Operand* src);

InstructionId Decode0x04(uint32_t word32, uint32_t decodeFlags);
InstructionId Decode0x1F(uint32_t word32, uint32_t decodeFlags);
InstructionId VleTranslateMnemonic(InstructionId id);
