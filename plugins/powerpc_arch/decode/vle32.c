#include <string.h>

#include "decode.h"
#include "priv.h"

void PushMemRA8(Instruction* instruction, uint32_t word32)
{
	int32_t offset = (int32_t)((int8_t)(word32 & 0xff));
	PushMem(instruction, PPC_OP_MEM_RA, Gpr(GetA(word32)), offset);
}

static InstructionId Decode32Vle0x06(uint32_t word32, uint32_t decodeFlags)
{
	uint32_t subop = (word32 >> 12) & 0xf;
	switch (subop)
	{
		case 0x8:
			return PPC_ID_VLE_E_ADDIx;

		case 0x9:
			return PPC_ID_VLE_E_ADDIx;

		case 0xb:
			return PPC_ID_VLE_E_SUBFICx;

		case 0xc:
			return PPC_ID_VLE_E_ANDIx;

		case 0xd:
			return PPC_ID_VLE_E_ORIx;

		case 0xe:
			return PPC_ID_VLE_E_XORIx;

		default:
			;
	}

	subop = (word32 >> 11) & 0x1f;
	switch (subop)
	{
		case 0x14:
			return PPC_ID_VLE_E_MULLI;

		case 0x15:
		{
			uint32_t subsubop = ((word32 >> 23) & 0x7);
			switch (subsubop)
			{
				case 0:
					return PPC_ID_VLE_E_CMPI;

				case 1:
					return PPC_ID_VLE_E_CMPLI;

				default:
					;
			}
		}

		default:
			;
	}

	subop = (word32 >> 8) & 0xff;
	switch (subop)
	{
		case 0x00: 
			return PPC_ID_VLE_E_LBZU;
		
		case 0x01:
			return PPC_ID_VLE_E_LHZU;

		case 0x02:
			return PPC_ID_VLE_E_LWZU;

		case 0x03:
			return PPC_ID_VLE_E_LHAU;

		case 0x04:
			return PPC_ID_VLE_E_STBU;

		case 0x05:
			return PPC_ID_VLE_E_STHU;

		case 0x06:
			return PPC_ID_VLE_E_STWU;

		case 0x08:
			return PPC_ID_VLE_E_LMW;

		case 0x09:
			return PPC_ID_VLE_E_STMW;

		case 0x10:
		{
			uint32_t subsubop = (word32 >> 21) & 0x1f;
			switch (subsubop)
			{
				case 0: return PPC_ID_VLE_E_LDVGPRW;
				case 1: return PPC_ID_VLE_E_LDVSPRW;
				case 4: return PPC_ID_VLE_E_LDVSRRW;
				case 5: return PPC_ID_VLE_E_LDVCSRRW;
				case 6: return PPC_ID_VLE_E_LDVDSRRW;
				default: return PPC_ID_INVALID;
			}
		}

		case 0x11:
		{
			uint32_t subsubop = (word32 >> 21) & 0x1f;
			switch (subsubop)
			{
				case 0: return PPC_ID_VLE_E_STMVGPRW;
				case 1: return PPC_ID_VLE_E_STMVSPRW;
				case 4: return PPC_ID_VLE_E_STMVSRRW;
				case 5: return PPC_ID_VLE_E_STMVCSRRW;
				case 6: return PPC_ID_VLE_E_STMVDSRRW;
				default: return PPC_ID_INVALID;
			}
		}

		default:
			return PPC_ID_INVALID;
	}
}

static InstructionId Decode32Vle0x1C(uint32_t word32, uint32_t decodeFlags)
{
	uint32_t subop = (word32 >> 15) & 0x1;
	if (subop == 0)
		return PPC_ID_VLE_E_LI;

	subop = (word32 >> 11) & 0x1f;
	switch (subop)
	{
		case 0x11:
			return PPC_ID_VLE_E_ADD2I;

		case 0x12:
			return PPC_ID_VLE_E_ADD2IS;

		case 0x13:
			return PPC_ID_VLE_E_CMP16I;

		case 0x14:
			return PPC_ID_VLE_E_MULL2I;

		case 0x15:
			return PPC_ID_VLE_E_CMPL16I;

		case 0x16:
			return PPC_ID_VLE_E_CMPH16I;

		case 0x17:
			return PPC_ID_VLE_E_CMPHL16I;

		case 0x18:
			return PPC_ID_VLE_E_OR2I;

		case 0x19:
			return PPC_ID_VLE_E_AND2I;

		case 0x1a:
			return PPC_ID_VLE_E_OR2IS;

		case 0x1c:
			return PPC_ID_VLE_E_LIS;

		case 0x1d:
			return PPC_ID_VLE_E_AND2IS;

		default:
			return PPC_ID_INVALID;
	}
}

static InstructionId Decode32Vle0x1F(uint32_t word32, uint32_t decodeFlags)
{
	uint32_t subop = word32 & 0x7ff;
	switch (subop)
	{
		// There are a handful of VLE-specific instructions for this
		// primary opcode, but the rest are standard
		case 0x020:
			return PPC_ID_VLE_E_MCRF;

		case 0x042:
			return PPC_ID_VLE_E_CRNOR;

		case 0x05c:
			if ((word32 & 0x00600000) == 0)
				return PPC_ID_INVALID;
			else
				return PPC_ID_VLE_E_CMPHL;

		case 0x070:
		case 0x071:
			return PPC_ID_VLE_E_SLWIx;

		case 0x102:
			return PPC_ID_VLE_E_CRANDC;

		case 0x182:
			return PPC_ID_VLE_E_CRXOR;

		case 0x1c2:
			return PPC_ID_VLE_E_CRNAND;

		case 0x202:
			return PPC_ID_VLE_E_CRAND;

		case 0x230:
		case 0x231:
			return PPC_ID_VLE_E_RLWx;

		case 0x242:
			return PPC_ID_VLE_E_CREQV;

		case 0x270:
		case 0x271:
			return PPC_ID_VLE_E_RLWIx;

		case 0x342:
			return PPC_ID_VLE_E_CRORC;

		case 0x382:
			return PPC_ID_VLE_E_CROR;

		case 0x470:
		case 0x471:
			return PPC_ID_VLE_E_SRWIx;

		default:
			return Decode0x1F(word32, decodeFlags);
	}
}

static InstructionId Decode32Vle(uint32_t word32, uint32_t decodeFlags)
{
	uint32_t primary = (word32 >> 26) & 0x3f;
	switch (primary)
	{
		// 0x1000_0000
		case 0x04:
			// This is the same as non-VLE decoding
			return Decode0x04(word32, decodeFlags);

		// 0x1800_0000
		case 0x06:
			return Decode32Vle0x06(word32, decodeFlags);

		// 0x1c00_0000
		case 0x07:
			return PPC_ID_VLE_E_ADD16I;

		// 0x3000_0000
		case 0x0c:
			return PPC_ID_VLE_E_LBZ;

		// 0x3400_0000
		case 0x0d:
			return PPC_ID_VLE_E_STB;

		// 0x3800_0000
		case 0x0e:
			return PPC_ID_VLE_E_LHA;

		// 0x5000_0000
		case 0x14:
			return PPC_ID_VLE_E_LWZ;

		// 0x5400_0000
		case 0x15:
			return PPC_ID_VLE_E_STW;

		// 0x5800_0000
		case 0x16:
			return PPC_ID_VLE_E_LHZ;

		// 0x5c00_0000
		case 0x17:
			return PPC_ID_VLE_E_STH;

		// 0x7000_0000
		case 0x1c:
			return Decode32Vle0x1C(word32, decodeFlags);

		// 0x7400_0000
		case 0x1d:
			if ((word32 & 0x1) == 0)
				return PPC_ID_VLE_E_RLWIMI;
			else
				return PPC_ID_VLE_E_RLWINM;

		// 0x7800_0000
		case 0x1e:
			if ((word32 & 0x02000000) == 0)
				return PPC_ID_VLE_E_Bx;
			else if ((word32 & 0xffc00000) == 0x7a000000)
				return PPC_ID_VLE_E_BCx;
			else
				return PPC_ID_INVALID;

		// 0x7c00_0000
		case 0x1f:
			return Decode32Vle0x1F(word32, decodeFlags);

		default:
			return PPC_ID_INVALID;
	}
}

static uint32_t ComputeSCI8(uint32_t word32) {
	unsigned int scl = (word32 >> 8) & 0x3;
	unsigned int shift = 8*scl;
	uint32_t ui8 = word32 & 0xff;
	bool f = (word32 >> 10) & 0x1;

	uint32_t imm_value = f ? 0xffffffff : 0;
	imm_value &= ~(0xfful << shift);
	imm_value |= (ui8 << shift);

	return imm_value;
}

static void FillOperands32Vle(Instruction* instruction, uint32_t word32, uint64_t address, bool translate)
{
	uint16_t ui0_4 = (word32 >> 21) & 0x1f;
	uint16_t ui5_15 = word32 & 0x7ff;
	uint32_t ui_split16 = (ui0_4 << 11) | ui5_15;
	int32_t si_split16 = (int32_t)(int16_t)(uint16_t)(ui_split16);

	// Surprisingly (or maybe not surprisingly), PowerPC throws us a bone
	// and puts registers in the same bit locations that they are in normal
	// PowerPC

	switch (instruction->id) {
		// <op>[.] rD, rA, SCI8 
		case PPC_ID_VLE_E_ADDIx:
		case PPC_ID_VLE_E_ADDICx:
		case PPC_ID_VLE_E_SUBFICx:
			PushRD(instruction, word32);
			PushRA(instruction, word32);
			PushSIMMValue(instruction, (int32_t)ComputeSCI8(word32));

			instruction->flags.rc = (word32 >> 11) & 0x1;
			break;

		// <op> rD, rA, SCI8 (unconditional no-dot)
		case PPC_ID_VLE_E_MULLI:
			PushRD(instruction, word32);
			PushRA(instruction, word32);
			PushSIMMValue(instruction, (int32_t)ComputeSCI8(word32));

			break;

		// <op>[.] rA, rS, SCI8
		case PPC_ID_VLE_E_ANDIx:
		case PPC_ID_VLE_E_ORIx:
		case PPC_ID_VLE_E_XORIx:
			PushRA(instruction, word32);
			PushRS(instruction, word32);
			PushUIMMValue(instruction, ComputeSCI8(word32));

			instruction->flags.rc = (word32 >> 11) & 0x1;
			break;

		case PPC_ID_VLE_E_ADD2I:
		case PPC_ID_VLE_E_ADD2IS:
		case PPC_ID_VLE_E_MULL2I:
			PushRD(instruction, word32);
			if (translate)
				PushRA(instruction, word32);

			PushSIMMValue(instruction, si_split16);
			if (instruction->id == PPC_ID_VLE_E_ADD2I)
				instruction->flags.rc = true;
			break;

		// <op>_2i rD, UI
		case PPC_ID_VLE_E_AND2I:
		case PPC_ID_VLE_E_AND2IS:
		case PPC_ID_VLE_E_OR2I:
		case PPC_ID_VLE_E_OR2IS:
		{
			uint32_t ui5_15 = word32 & 0x7ff;
			uint32_t ui0_4 = (word32 >> 16) & 0x1f;
			uint32_t ui = (ui0_4 << 11) | ui5_15;

			PushRD(instruction, word32);
			if (translate)
				PushRS(instruction, word32);

			PushUIMMValue(instruction, ui);
			if ((instruction->id == PPC_ID_VLE_E_AND2I) || (instruction->id == PPC_ID_VLE_E_AND2IS))
				instruction->flags.rc = true;
			break;
		}

		case PPC_ID_VLE_E_LIS:
		{
			uint32_t ui5_15 = word32 & 0x7ff;
			uint32_t ui0_4 = (word32 >> 16) & 0x1f;
			uint32_t ui = (ui0_4 << 11) | ui5_15;
			PushRD(instruction, word32);
			PushUIMMValue(instruction, ui);
			break;
		}

		// <op>[.] rA, rS, SH
		case PPC_ID_VLE_E_RLWIx:
		case PPC_ID_VLE_E_SLWIx:
		case PPC_ID_VLE_E_SRWIx:
		{
			uint32_t sh = (word32 >> 11) & 0x1f;
			PushRA(instruction, word32);
			PushRS(instruction, word32);
			PushUIMMValue(instruction, sh);
			instruction->flags.rc = word32 & 0x1;
			break;
		}

		// <op> crbD, crbA, crbB
		case PPC_ID_VLE_E_CRAND:
		case PPC_ID_VLE_E_CRANDC:
		case PPC_ID_VLE_E_CREQV:
		case PPC_ID_VLE_E_CRNAND:
		case PPC_ID_VLE_E_CRNOR:
		case PPC_ID_VLE_E_CROR:
		case PPC_ID_VLE_E_CRORC:
		case PPC_ID_VLE_E_CRXOR:
			PushCRBitD(instruction, word32);
			PushCRBitA(instruction, word32);
			PushCRBitB(instruction, word32);
			break;

		// loads
		case PPC_ID_VLE_E_LBZ:
		case PPC_ID_VLE_E_LHA:
		case PPC_ID_VLE_E_LHZ:
		case PPC_ID_VLE_E_LWZ:
			PushRD(instruction, word32);
			PushMemRA(instruction, word32);
			break;

		// loads with update/load multiple
		case PPC_ID_VLE_E_LBZU:
		case PPC_ID_VLE_E_LHAU:
		case PPC_ID_VLE_E_LHZU:
		case PPC_ID_VLE_E_LWZU:
		case PPC_ID_VLE_E_LMW:
			PushRD(instruction, word32);
			PushMemRA8(instruction, word32);
			break;

		// stores
		case PPC_ID_VLE_E_STB:
		case PPC_ID_VLE_E_STH:
		case PPC_ID_VLE_E_STW:
			PushRS(instruction, word32);
			PushMemRA(instruction, word32);
			break;

		// stores with update/store multiple
		case PPC_ID_VLE_E_STBU:
		case PPC_ID_VLE_E_STHU:
		case PPC_ID_VLE_E_STMW:
		case PPC_ID_VLE_E_STWU:
			PushRS(instruction, word32);
			PushMemRA8(instruction, word32);
			break;

		// vector loads/stores
		case PPC_ID_VLE_E_LDVGPRW:
		case PPC_ID_VLE_E_LDVSPRW:
		case PPC_ID_VLE_E_LDVSRRW:
		case PPC_ID_VLE_E_LDVCSRRW:
		case PPC_ID_VLE_E_LDVDSRRW:
		case PPC_ID_VLE_E_STMVGPRW:
		case PPC_ID_VLE_E_STMVSPRW:
		case PPC_ID_VLE_E_STMVSRRW:
		case PPC_ID_VLE_E_STMVCSRRW:
		case PPC_ID_VLE_E_STMVDSRRW:
			PushMemRA8(instruction, word32);
			break;

		// <op> rA, rS, SH, MB, ME
		case PPC_ID_VLE_E_RLWIMI:
		case PPC_ID_VLE_E_RLWINM:
		{
			uint32_t sh = (word32 >> 11) & 0x1f;
			uint32_t mb = (word32 >> 6) & 0x1f;
			uint32_t me = (word32 >> 1) & 0x1f;
			PushRA(instruction, word32);
			PushRS(instruction, word32);
			PushUIMMValue(instruction, sh);
			PushUIMMValue(instruction, mb);
			PushUIMMValue(instruction, me);
			break;
		}

		// <op>_16i rA, SI
		case PPC_ID_VLE_E_CMP16I:
		case PPC_ID_VLE_E_CMPH16I:
			if (translate)
				PushRegister(instruction, PPC_OP_REG_CRFD_IMPLY0, Crf(0));

			PushRA(instruction, word32);
			PushSIMMValue(instruction, si_split16);
			break;

		// <op>_16i rA, UI
		case PPC_ID_VLE_E_CMPL16I:
		case PPC_ID_VLE_E_CMPHL16I:
			if (translate)
				PushRegister(instruction, PPC_OP_REG_CRFD_IMPLY0, Crf(0));

			PushRA(instruction, word32);
			PushUIMMValue(instruction, ui_split16);
			break;

		// one-off
		case PPC_ID_VLE_E_ADD16I:
		{
			int16_t si = (int16_t)(uint16_t)(word32 & 0xffff);
			PushRD(instruction, word32);
			PushRA(instruction, word32);
			PushSIMMValue(instruction, si);
			break;
		}

		case PPC_ID_VLE_E_Bx:
		{
			uint32_t bd24 = word32 & 0x01fffffe;
			uint64_t target = address + (int64_t)sign_extend(bd24, 24);
			PushLabel(instruction, target);
			instruction->flags.lk = word32 & 0x1;
			break;
		}

		case PPC_ID_VLE_E_BCx:
		{
			uint32_t bo32 = (word32 >> 20) & 0x3;
			uint32_t bi32 = (word32 >> 16) & 0xf;
			uint32_t bd15 = word32 & 0xfffe;

			if (translate)
			{
				// VLEPEM Table 2-5: BO32 Field Encodings
				// 	00 --> branch if condition false
				// 	01 --> branch if condition true
				// 	10 --> decrement CTR, branch if CTR!=0
				// 	11 --> decrement CTR, branch if CTR==0
				//
				// PowerPC programming environments 8-7: BO Operand Encodings
				// (relevant excerpt)
				//   001zy --> branch if condition false
				//   011zy --> branch if condition true
				//   1z00y --> decrement CTR, branch if CTR!=0
				//   1z01y --> decrement CTR, branch if CTR==0
				//
				// VLE doesn't encode hints, so we just map to encodings
				// with z and y equal to 0

				uint32_t mapped_bo = 0;
				switch (bo32) {
					case 0: mapped_bo = 0x04; break;
					case 1: mapped_bo = 0x0c; break;
					case 2: mapped_bo = 0x10; break;
					case 3: mapped_bo = 0x12; break;
					default:
						// unreachable
						;
				}

				PushUIMMValue(instruction, mapped_bo);
			}
			else
			{
				PushUIMMValue(instruction, bo32);
			}

			// BI32 maps to the same as the non-VLE variant, it's
			// just a more restricted value
			PushUIMMValue(instruction, bi32);
			uint64_t target = address + (int64_t)sign_extend(bd15, 15);
			PushLabel(instruction, target);

			instruction->flags.lk = word32 & 0x1;
			break;
		}

		case PPC_ID_VLE_E_CMPI:
		{
			// We can't use PushCRFDImplyCR0, since the CRD32 field
			// is 2 bits instead of 3
			uint32_t crd32 = ((word32) >> 21) & 0x3;
			PushRegister(instruction, PPC_OP_REG_CRFD_IMPLY0, Crf(crd32));
			PushRA(instruction, word32);
			PushUIMMValue(instruction, (int32_t)ComputeSCI8(word32));
			break;
		}

		case PPC_ID_VLE_E_CMPLI:
		{
			// We can't use PushCRFDImplyCR0, since the CRD32 field
			// is 2 bits instead of 3
			uint32_t crd32 = ((word32) >> 21) & 0x3;
			PushRegister(instruction, PPC_OP_REG_CRFD_IMPLY0, Crf(crd32));
			PushRA(instruction, word32);
			PushUIMMValue(instruction, ComputeSCI8(word32));
			break;
		}

		case PPC_ID_VLE_E_CMPHL:
			PushCRFDImplyCR0(instruction, word32);
			PushRA(instruction, word32);
			PushRB(instruction, word32);
			break;

		case PPC_ID_VLE_E_LI:
		{
			uint32_t li20_4_8 = (word32 >> 16) & 0x1f;
			uint32_t li20_0_3 = (word32 >> 11) & 0xf;
			uint32_t li20_9_19 = word32 & 0x7ff;
			uint32_t li20 = (li20_0_3 << 16) | (li20_4_8 << 11) | li20_9_19;
			int32_t signed_li20 = sign_extend(li20, 20);

			PushRD(instruction, word32);
			PushSIMMValue(instruction, signed_li20);
			break;
		}

		case PPC_ID_VLE_E_MCRF:
			PushCRFD(instruction, word32);
			PushCRFS(instruction, word32);
			break;

		case PPC_ID_VLE_E_RLWx:
			PushRA(instruction, word32);
			PushRS(instruction, word32);
			PushRB(instruction, word32);
			instruction->flags.rc = word32 & 0x1;
			break;

		default:
			;
	}
}

bool IsVleInstructionId(InstructionId id)
{
	return PPC_ID_VLE_E_ADDIx <= id && id <= PPC_ID_VLE_SE_SUBIx;
}

bool Decompose32Vle(Instruction* instruction, uint32_t word32, uint64_t address, uint32_t flags)
{
	size_t numBytes = instruction->numBytes;
	memset(instruction, 0, sizeof *instruction);
	instruction->numBytes = numBytes;
	instruction->id = Decode32Vle(word32, flags);
	if (instruction->id == PPC_ID_INVALID)
		return false;

	if (!IsVleInstructionId(instruction->id))
	{
		// Fill operands for instructions that are shared between VLE
		// and non-VLE
		FillOperands32(instruction, word32, address);
		return true;
	}

	if ((flags & DECODE_FLAGS_VLE_TRANSLATE) != 0)
	{
		FillOperands32Vle(instruction, word32, address, true);
		instruction->id = VleTranslateMnemonic(instruction->id);
	}
	else
	{
		FillOperands32Vle(instruction, word32, address, false);
	}

	return true;
}

void FillVle32BcxOperands(OperandsList *e_bcx, const Instruction *instruction)
{
	memset(e_bcx, 0, sizeof *e_bcx);

	if (instruction->id != PPC_ID_VLE_E_BCx)
		return;

	uint32_t bo = instruction->operands[0].uimm;
	uint32_t bi = instruction->operands[1].uimm;

	switch (bo)
	{
		// Condition is true/false: use crn, copy target
		case 0:
		case 1:

			e_bcx->operands[0].cls = PPC_OP_REG_CRFS_IMPLY0;
			e_bcx->operands[0].reg = Crf(bi >> 2);
			CopyOperand(&e_bcx->operands[1], &instruction->operands[2]);
			e_bcx->numOperands = 2;
			break;

		// Decrement CTR, branch if equal/not to 0: no operands
		case 2:
		case 3:
			CopyOperand(&e_bcx->operands[0], &instruction->operands[2]);
			e_bcx->numOperands = 1;
			break;

		default:
			// unreachable
			;
	}
}
