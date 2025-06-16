#include <string.h>

#include "decode.h"
#include "priv.h"

static InstructionId Decode16Vle0x00(uint16_t word16, uint32_t decodeFlags)
{
	switch (word16) {
	case 0x0000:
		return PPC_ID_VLE_SE_ILLEGAL;

	case 0x0001:
		return PPC_ID_VLE_SE_ISYNC;

	case 0x0002:
		return PPC_ID_VLE_SE_SC;

	case 0x0004:
	case 0x0005:
		return PPC_ID_VLE_SE_BLRx;

	case 0x0006:
	case 0x0007:
		return PPC_ID_VLE_SE_BCTRx;

	case 0x0008:
		return PPC_ID_VLE_SE_RFI;

	case 0x0009:
		return PPC_ID_VLE_SE_RFCI;

	case 0x000a:
		return PPC_ID_VLE_SE_RFDI;

	case 0x000b:
		return PPC_ID_VLE_SE_RFMCI;

	default:
		;
	}

	uint32_t subop = (word16 >> 4) & 0xfff;
	switch (subop) {
		case 0x002:
			return PPC_ID_VLE_SE_NOT;

		case 0x003:
			return PPC_ID_VLE_SE_NEG;

		case 0x008:
			return PPC_ID_VLE_SE_MFLR;

		case 0x009:
			return PPC_ID_VLE_SE_MTLR;

		case 0x00a:
			return PPC_ID_VLE_SE_MFCTR;

		case 0x00b:
			return PPC_ID_VLE_SE_MTCTR;

		case 0x00c:
			return PPC_ID_VLE_SE_EXTZB;

		case 0x00d:
			return PPC_ID_VLE_SE_EXTSB;

		case 0x00e:
			return PPC_ID_VLE_SE_EXTZH;

		case 0x00f:
			return PPC_ID_VLE_SE_EXTSH;

		default:
			return PPC_ID_INVALID;;
	}
}
static InstructionId Decode16Vle(uint16_t word16, uint32_t decodeFlags)
{
	uint8_t hi = (word16 >> 8) & 0xff;
	switch (hi) {
		case 0x00:
			return Decode16Vle0x00(word16, decodeFlags);

		case 0x01:
			return PPC_ID_VLE_SE_MR;

		case 0x02:
			return PPC_ID_VLE_SE_MTAR;

		case 0x03:
			return PPC_ID_VLE_SE_MFAR;

		case 0x04:
			return PPC_ID_VLE_SE_ADD;

		case 0x05:
			return PPC_ID_VLE_SE_MULLW;

		case 0x06:
			return PPC_ID_VLE_SE_SUB;

		case 0x07:
			return PPC_ID_VLE_SE_SUBF;

		case 0x0c:
			return PPC_ID_VLE_SE_CMP;

		case 0x0d:
			return PPC_ID_VLE_SE_CMPL;

		case 0x0e:
			return PPC_ID_VLE_SE_CMPH;

		case 0x0f:
			return PPC_ID_VLE_SE_CMPHL;

		case 0x20:
		case 0x21:
			return PPC_ID_VLE_SE_ADDI;

		case 0x22:
		case 0x23:
			return PPC_ID_VLE_SE_CMPLI;

		case 0x24:
		case 0x25:
		case 0x26:
		case 0x27:
			return PPC_ID_VLE_SE_SUBIx;

		case 0x2a:
		case 0x2b:
			return PPC_ID_VLE_SE_CMPI;

		case 0x2c:
		case 0x2d:
			return PPC_ID_VLE_SE_BMASKI;

		case 0x2e:
		case 0x2f:
			return PPC_ID_VLE_SE_ANDI;

		case 0x40:
			return PPC_ID_VLE_SE_SRW;

		case 0x41:
			return PPC_ID_VLE_SE_SRAW;

		case 0x42:
			return PPC_ID_VLE_SE_SLW;

		case 0x44:
		{
			// rY = 0, rX = 0
			// Not technically documented, but compiler
			// occasionally emits `or, r0, r0`, which are NOPs in
			// 32-bit land
			if ((word16 & 0xff) == 0x00)
				return PPC_ID_VLE_SE_NOP;
			else
				return PPC_ID_VLE_SE_OR;
		}

		case 0x45:
			return PPC_ID_VLE_SE_ANDC;

		case 0x46:
		case 0x47:
			return PPC_ID_VLE_SE_ANDx;

		case 0x48:
		case 0x49:
		case 0x4a:
		case 0x4b:
		case 0x4c:
		case 0x4d:
		case 0x4e:
		case 0x4f:
			return PPC_ID_VLE_SE_LI;

		case 0x60:
		case 0x61:
			return PPC_ID_VLE_SE_BCLRI;

		case 0x62:
		case 0x63:
			return PPC_ID_VLE_SE_BGENI;

		case 0x64:
		case 0x65:
			return PPC_ID_VLE_SE_BSETI;

		case 0x66:
		case 0x67:
			return PPC_ID_VLE_SE_BTSTI;

		case 0x68:
		case 0x69:
			return PPC_ID_VLE_SE_SRWI;

		case 0x6a:
		case 0x6b:
			return PPC_ID_VLE_SE_SRAWI;

		case 0x6c:
		case 0x6d:
			return PPC_ID_VLE_SE_SLWI;

		case 0x80:
		case 0x81:
		case 0x82:
		case 0x83:
		case 0x84:
		case 0x85:
		case 0x86:
		case 0x87:
		case 0x88:
		case 0x89:
		case 0x8a:
		case 0x8b:
		case 0x8c:
		case 0x8d:
		case 0x8e:
		case 0x8f:
			return PPC_ID_VLE_SE_LBZ;

		case 0x90:
		case 0x91:
		case 0x92:
		case 0x93:
		case 0x94:
		case 0x95:
		case 0x96:
		case 0x97:
		case 0x98:
		case 0x99:
		case 0x9a:
		case 0x9b:
		case 0x9c:
		case 0x9d:
		case 0x9e:
		case 0x9f:
			return PPC_ID_VLE_SE_STB;

		case 0xa0:
		case 0xa1:
		case 0xa2:
		case 0xa3:
		case 0xa4:
		case 0xa5:
		case 0xa6:
		case 0xa7:
		case 0xa8:
		case 0xa9:
		case 0xaa:
		case 0xab:
		case 0xac:
		case 0xad:
		case 0xae:
		case 0xaf:
			return PPC_ID_VLE_SE_LHZ;

		case 0xb0:
		case 0xb1:
		case 0xb2:
		case 0xb3:
		case 0xb4:
		case 0xb5:
		case 0xb6:
		case 0xb7:
		case 0xb8:
		case 0xb9:
		case 0xba:
		case 0xbb:
		case 0xbc:
		case 0xbd:
		case 0xbe:
		case 0xbf:
			return PPC_ID_VLE_SE_STH;

		case 0xc0:
		case 0xc1:
		case 0xc2:
		case 0xc3:
		case 0xc4:
		case 0xc5:
		case 0xc6:
		case 0xc7:
		case 0xc8:
		case 0xc9:
		case 0xca:
		case 0xcb:
		case 0xcc:
		case 0xcd:
		case 0xce:
		case 0xcf:
			return PPC_ID_VLE_SE_LWZ;

		case 0xd0:
		case 0xd1:
		case 0xd2:
		case 0xd3:
		case 0xd4:
		case 0xd5:
		case 0xd6:
		case 0xd7:
		case 0xd8:
		case 0xd9:
		case 0xda:
		case 0xdb:
		case 0xdc:
		case 0xdd:
		case 0xde:
		case 0xdf:
			return PPC_ID_VLE_SE_STW;

		case 0xe0:
		case 0xe1:
		case 0xe2:
		case 0xe3:
		case 0xe4:
		case 0xe5:
		case 0xe6:
		case 0xe7:
			return PPC_ID_VLE_SE_BC;

		case 0xe8:
		case 0xe9:
			return PPC_ID_VLE_SE_Bx;

		default:
			return PPC_ID_INVALID;
	}
}
static uint16_t Get16Rx(uint16_t word16)
{
	return word16 & 0xf;
}

static uint16_t Get16Ry(uint16_t word16)
{
	return (word16 >> 4) & 0xf;
}

static uint16_t Get16Rz(uint16_t word16)
{
	return (word16 >> 4) & 0xf;
}

static void FillOperands16Vle(Instruction* instruction, uint16_t word16, uint64_t address, bool translate)
{
	uint16_t rx = Get16Rx(word16);
	uint16_t ry = Get16Ry(word16);
	uint16_t rz = Get16Rz(word16);

	switch (instruction->id)
	{
		// <op>
		case PPC_ID_VLE_SE_ILLEGAL:
		case PPC_ID_VLE_SE_ISYNC:
		case PPC_ID_VLE_SE_NOP:
		case PPC_ID_VLE_SE_RFCI:
		case PPC_ID_VLE_SE_RFDI:
		case PPC_ID_VLE_SE_RFI:
		case PPC_ID_VLE_SE_RFMCI:
		case PPC_ID_VLE_SE_SC:
			return;

		// <op> rX, rY (4-bit) no rc
		case PPC_ID_VLE_SE_ADD:
		case PPC_ID_VLE_SE_ANDC:
		case PPC_ID_VLE_SE_MR:
		case PPC_ID_VLE_SE_MULLW:
		case PPC_ID_VLE_SE_OR:
		case PPC_ID_VLE_SE_SLW:
		case PPC_ID_VLE_SE_SRAW:
		case PPC_ID_VLE_SE_SRW:
		case PPC_ID_VLE_SE_SUB:
			PushRegister(instruction, PPC_OP_REG_RD, Gpr(rx));
			PushRegister(instruction, PPC_OP_REG_RA, Gpr(ry));
			if (translate)
				PushRegister(instruction, PPC_OP_REG_RB, Gpr(rx));

			break;

		case PPC_ID_VLE_SE_SUBF:
			// Subtle difference between this and SE_SUB:
			//	SUB  rX, rY --> SUBF rX, rY, rX (rX := rX - rY)
			//	SUBF rX, rY --> SUBF rX, rX, rY (rX := rY - rX)
			if (translate)
			{
				PushRegister(instruction, PPC_OP_REG_RD, Gpr(rx));
				PushRegister(instruction, PPC_OP_REG_RA, Gpr(rx));
				PushRegister(instruction, PPC_OP_REG_RB, Gpr(ry));
			}
			else
			{
				PushRegister(instruction, PPC_OP_REG_RD, Gpr(rx));
				PushRegister(instruction, PPC_OP_REG_RA, Gpr(ry));
			}

			break;

		// <op> rX, rY, comparisons
		case PPC_ID_VLE_SE_CMP:
		case PPC_ID_VLE_SE_CMPH:
		case PPC_ID_VLE_SE_CMPHL:
		case PPC_ID_VLE_SE_CMPL:
			if (translate)
				PushRegister(instruction, PPC_OP_REG_CRFD_IMPLY0, Crf(0));

			PushRegister(instruction, PPC_OP_REG_RA, Gpr(rx));
			PushRegister(instruction, PPC_OP_REG_RB, Gpr(ry));
			break;

		// <op> rX, rY (4-bit) with rc
		case PPC_ID_VLE_SE_ANDx:
			PushRegister(instruction, PPC_OP_REG_RD, Gpr(rx));
			PushRegister(instruction, PPC_OP_REG_RA, Gpr(ry));
			if (translate)
				PushRegister(instruction, PPC_OP_REG_RB, Gpr(rx));

			instruction->flags.rc = (word16 & 0x100) != 0;
			break;

		// <op> rX (4-bit)
		case PPC_ID_VLE_SE_EXTSB:
		case PPC_ID_VLE_SE_EXTSH:
			PushRegister(instruction, PPC_OP_REG_RS, Gpr(rx));
			if (translate)
				PushRegister(instruction, PPC_OP_REG_RA, Gpr(rx));

			break;

		// There aren't any non-VLE instructions that correspond
		// directly to these, but they can be mimicked by
		// ANDI'ing with 0xff and 0xffff directly
		// <op> rX (4-bit)
		case PPC_ID_VLE_SE_EXTZB:
		case PPC_ID_VLE_SE_EXTZH:
			if (translate)
			{
				// ANDI rX, rX, 0xff
				PushRegister(instruction, PPC_OP_REG_RS, Gpr(rx));
				PushRegister(instruction, PPC_OP_REG_RA, Gpr(rx));
				if (instruction->id == PPC_ID_VLE_SE_EXTZB)
					PushUIMMValue(instruction, 0xff);
				else
					PushUIMMValue(instruction, 0xffff);
			}
			else
			{
				PushRegister(instruction, PPC_OP_REG_RS, Gpr(rx));
			}

			break;

		case PPC_ID_VLE_SE_NEG:
		case PPC_ID_VLE_SE_NOT:
			PushRegister(instruction, PPC_OP_REG_RD, Gpr(rx));
			if (translate)
				PushRegister(instruction, PPC_OP_REG_RA, Gpr(rx));

			break;

		case PPC_ID_VLE_SE_MFCTR:
		case PPC_ID_VLE_SE_MFLR:
			PushRegister(instruction, PPC_OP_REG_RD, Gpr(rx));
			break;

		case PPC_ID_VLE_SE_MTCTR:
		case PPC_ID_VLE_SE_MTLR:
			PushRegister(instruction, PPC_OP_REG_RS, Gpr(rx));
			break;

		// <op> rX,UI5
		case PPC_ID_VLE_SE_ANDI:
		case PPC_ID_VLE_SE_SLWI:
		case PPC_ID_VLE_SE_SRAWI:
		case PPC_ID_VLE_SE_SRWI:
		{
			uint16_t ui5 = (word16 >> 4) & 0x1f;
			PushRegister(instruction, PPC_OP_REG_RA, Gpr(rx));
			if (translate)
				PushRegister(instruction, PPC_OP_REG_RS, Gpr(rx));

			PushUIMMValue(instruction, ui5);

			break;
		}

		case PPC_ID_VLE_SE_CMPI:
		{
			uint16_t ui5 = (word16 >> 4) & 0x1f;
			if (translate)
				PushRegister(instruction, PPC_OP_REG_CRFD_IMPLY0, Crf(0));

			PushRegister(instruction, PPC_OP_REG_RA, Gpr(rx));
			PushUIMMValue(instruction, ui5);
			break;
		}

		// <op> rX, OIMM (no rc)
		case PPC_ID_VLE_SE_ADDI:
		{
			uint32_t oim5 = (word16 >> 4) & 0x1f;
			PushRegister(instruction, PPC_OP_REG_RD, Gpr(rx));

			if (translate)
				PushRegister(instruction, PPC_OP_REG_RA, Gpr(rx));

			PushSIMMValue(instruction, oim5 + 1);
			break;
		}

		// <op> rX, OIMM (no rc)
		case PPC_ID_VLE_SE_CMPLI:
		{
			uint32_t oim5 = (word16 >> 4) & 0x1f;
			if (translate)
				PushRegister(instruction, PPC_OP_REG_CRFD_IMPLY0, Crf(0));

			PushRegister(instruction, PPC_OP_REG_RA, Gpr(rx));
			PushUIMMValue(instruction, oim5 + 1);
			break;
		}

		// <op> rX, OIMM (rc)
		case PPC_ID_VLE_SE_SUBIx:
		{
			uint32_t oim5 = (word16 >> 4) & 0x1f;
			uint32_t imm5 = oim5 + 1;
			bool rc = (word16 >> 9) & 0x1;
			PushRegister(instruction, PPC_OP_REG_RD, Gpr(rx));
			if (translate)
			{
				// In non-VLE, SUBI is a pseudo-op for ADDI with
				// a negative value
				PushRegister(instruction, PPC_OP_REG_RA, Gpr(rx));
				PushSIMMValue(instruction, -((int32_t)imm5));
			}
			else
			{
				PushSIMMValue(instruction, imm5);
			}
			instruction->flags.rc = rc;
				break;
		}

		// <op>[l]
		case PPC_ID_VLE_SE_BCTRx:
		case PPC_ID_VLE_SE_BLRx:
			instruction->flags.lk = word16 & 0x1;
			break;

		// one-off
		case PPC_ID_VLE_SE_Bx:
		{
			bool lk = (word16 >> 8) & 0x1;
			uint16_t bd8 = word16 & 0xff;

			instruction->flags.lk = lk;
			uint64_t target = address + (int32_t)sign_extend(bd8 << 1, 9);
			PushLabel(instruction, target);
			break;
		}

		case PPC_ID_VLE_SE_BC:
		{
			uint16_t bo16 = (word16 >> 10) & 0x1;
			uint16_t bi16 = (word16 >> 8) & 0x3;
			uint16_t bd8 = word16 & 0xff;

			if (translate)
			{
				// VLEPEM Table 2-6: BO16 Field Encodings
				// 	0 --> branch if condition false
				// 	1 --> branch if condition true
				//
				// PowerPC programming environments 8-7: BO Operand Encodings
				// (relevant excerpt)
				//   001zy --> branch if condition false
				//   011zy --> branch if condition true
				//
				// VLE doesn't encode hints, so we just map to encodings
				// with z and y equal to 0
				uint32_t mapped_bo;

				switch (bo16) {
					case 0: mapped_bo = 0x04; break;
					case 1: mapped_bo = 0x0c; break;
					default:
						// should be unreachable
						mapped_bo = 0;  // only to silence compiler warning
				}

				PushUIMMValue(instruction, mapped_bo);
			}
			else
			{
				PushUIMMValue(instruction, bo16);
			}
			PushUIMMValue(instruction, bi16);

			uint64_t target = address + (int32_t)sign_extend(bd8 << 1, 9);
			PushLabel(instruction, target);
			break;
		}

		case PPC_ID_VLE_SE_BCLRI:
		{
			// --> PPC_ID_ANDI
			uint16_t ui5 = (word16 >> 4) & 0x1f;
			PushRegister(instruction, PPC_OP_REG_RA, Gpr(rx));
			if (translate)
			{
				PushRegister(instruction, PPC_OP_REG_RS, Gpr(rx));
				PushUIMMValue(instruction, ~(1 << ui5));
			}
			else
			{
				PushUIMMValue(instruction, ui5);
			}
			break;
		}

		case PPC_ID_VLE_SE_BGENI:
		{
			// --> PPC_ID_LI
			uint16_t ui5 = (word16 >> 4) & 0x1f;
			PushRegister(instruction, PPC_OP_REG_RD, Gpr(rx));
			if (translate)
			{
				uint32_t value = (1ul << ui5);
				PushUIMMValue(instruction, value);
			}
			else
			{
				PushUIMMValue(instruction, ui5);
			}

			break;
		}

		case PPC_ID_VLE_SE_BMASKI:
		{
			// --> PPC_ID_LI
			uint16_t ui5 = (word16 >> 4) & 0x1f;
			PushRegister(instruction, PPC_OP_REG_RD, Gpr(rx));
			if (translate)
			{
				uint32_t value = ~(1ul << ui5);
				PushUIMMValue(instruction, value);
			}
			else
			{
				PushUIMMValue(instruction, ui5);
			}
			break;
		}

		case PPC_ID_VLE_SE_BSETI:
		{
			// --> PPC_ID_ORI
			uint16_t ui5 = (word16 >> 4) & 0x1f;
			PushRegister(instruction, PPC_OP_REG_RA, Gpr(rx));
			if (translate)
			{
				uint32_t value = 1ul << ui5;
				PushRegister(instruction, PPC_OP_REG_RS, Gpr(rx));
				PushUIMMValue(instruction, value);
			}
			else
			{
				PushUIMMValue(instruction, ui5);
			}
			break;
		}

		case PPC_ID_VLE_SE_BTSTI:
		{
			// This instruction isn't expressible in standard powerpc,
			// so we don't bother trying to convert it to anything
			uint16_t ui5 = (word16 >> 4) & 0x1f;
			PushRegister(instruction, PPC_OP_REG_RA, Gpr(rx));
			PushUIMMValue(instruction, ui5);
			break;
		}

		// NOTE: LBZ, LHZ, and LWZ in VLE don't turn rX=0 into 0
		case PPC_ID_VLE_SE_LBZ:
		{
			uint32_t sd4 = (word16 >> 8) & 0xf;
			PushRegister(instruction, PPC_OP_REG_RD, Gpr(rz));
			PushMem(instruction, PPC_OP_MEM_RA, Gpr(rx), (int32_t)sd4);
			break;
		}

		case PPC_ID_VLE_SE_LHZ:
		{
			uint32_t sd4 = ((word16 >> 8) & 0xf) * 2;
			PushRegister(instruction, PPC_OP_REG_RD, Gpr(rz));
			PushMem(instruction, PPC_OP_MEM_RA, Gpr(rx), (int32_t)sd4);
			break;
		}

		case PPC_ID_VLE_SE_LI:
		{
			uint32_t ui7 = (word16 >> 4) & 0x7f;
			PushRegister(instruction, PPC_OP_REG_RD, Gpr(rx));
			PushUIMMValue(instruction, ui7);
			break;
		}

		case PPC_ID_VLE_SE_LWZ:
		{
			uint32_t sd4 = ((word16 >> 8) & 0xf) * 4;
			PushRegister(instruction, PPC_OP_REG_RD, Gpr(rz));
			PushMem(instruction, PPC_OP_MEM_RA, Gpr(rx), (int32_t)sd4);
			break;
		}

		case PPC_ID_VLE_SE_MFAR:
			PushRegister(instruction, PPC_OP_REG_RA, Gpr(rx));
			PushRegister(instruction, PPC_OP_REG_RS, Gpr(8 + ry));
			break;

		case PPC_ID_VLE_SE_MTAR:
			PushRegister(instruction, PPC_OP_REG_RA, Gpr(8 + rx));
			PushRegister(instruction, PPC_OP_REG_RS, Gpr(ry));
			break;

		// NOTE: STB, STH, and STW in VLE don't turn rX=0 into 0
		case PPC_ID_VLE_SE_STB:
		{
			uint32_t sd4 = (word16 >> 8) & 0xf;
			PushRegister(instruction, PPC_OP_REG_RS, Gpr(rz));
			PushMem(instruction, PPC_OP_MEM_RA, Gpr(rx), (int32_t)sd4);
			break;
		}

		case PPC_ID_VLE_SE_STH:
		{
			uint32_t sd4 = ((word16 >> 8) & 0xf) * 2;
			PushRegister(instruction, PPC_OP_REG_RS, Gpr(rz));
			PushMem(instruction, PPC_OP_MEM_RA, Gpr(rx), (int32_t)sd4);
			break;
		}

		case PPC_ID_VLE_SE_STW:
		{
			uint32_t sd4 = ((word16 >> 8) & 0xf) * 4;
			PushRegister(instruction, PPC_OP_REG_RS, Gpr(rz));
			PushMem(instruction, PPC_OP_MEM_RA, Gpr(rx), (int32_t)sd4);
			break;
		}

		default:
			;
	}
}

bool Decompose16Vle(Instruction* instruction, uint16_t word16, uint64_t address, uint32_t flags)
{
	memset(instruction, 0, sizeof *instruction);
	instruction->id = Decode16Vle(word16, flags);
	if (instruction->id == PPC_ID_INVALID)
		return false;

	bool translate = (flags & DECODE_FLAGS_VLE_TRANSLATE) != 0;
	FillOperands16Vle(instruction, word16, address, translate);
	if (translate)
		instruction->id = VleTranslateMnemonic(instruction->id);

	return true;
}

void FillVle16BcOperands(OperandsList *se_bc, const Instruction *instruction)
{
	memset(se_bc, 0, sizeof *se_bc);

	if (instruction->id != PPC_ID_VLE_SE_BC)
		return;

	// se_bc only looks at CR0
	se_bc->operands[0].cls = PPC_OP_REG_CRFS_IMPLY0;
	se_bc->operands[0].reg = Crf(0);
	se_bc->numOperands = 1;
}
