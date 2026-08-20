#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "capstone/capstone.h"

#include "decode/decode.h"

bool crbit_equal(ppc_reg cs_reg, uint32_t crbit)
{
	if (crbit >= 32)
	{
		printf("invalid new crbit %d\n", crbit);
		return false;
	}

	if (cs_reg < PPC_REG_CR0EQ || cs_reg > PPC_REG_CR7UN)
	{
		printf("invalid cs crbit cs reg %d\n", cs_reg);
		return false;
	}

	uint32_t crn = 0;
	uint32_t bit = 0;
	if (PPC_REG_CR0EQ <= cs_reg && cs_reg <= PPC_REG_CR7EQ) 
	{
		crn = cs_reg - PPC_REG_CR0EQ;
		bit = 2;
	}
	else if (PPC_REG_CR0GT <= cs_reg && cs_reg <= PPC_REG_CR7GT)
	{
		crn = cs_reg - PPC_REG_CR0GT;
		bit = 1;
	}
	else if (PPC_REG_CR0LT <= cs_reg && cs_reg <= PPC_REG_CR7LT)
	{
		crn = cs_reg - PPC_REG_CR0LT;
		bit = 0;
	} else {
		// PPC_REG_CR0UN <= cs_reg && cs_reg <= PPC_REG_CR7UN
		crn = cs_reg - PPC_REG_CR0UN;
		bit = 3;
	}

	uint32_t cs_equivalent = 4*crn + bit;
	return crbit == cs_equivalent;
}

bool ops_equal(csh handle, const cs_ppc_op* capstone_op, const Operand* new_op)
{
	switch (new_op->cls)
	{
		case PPC_OP_NONE: return capstone_op->type == PPC_OP_INVALID;

		case PPC_OP_UIMM:
		{
			// handle RA|0
			if (capstone_op->type == PPC_OP_REG)
			{
				if (capstone_op->reg == PPC_REG_INVALID)
				{
					if (new_op->uimm != 0)
					{
						printf("new operand is UIMM %ld != 0, when capstone is PPC_REG_INVALID\n",
								new_op->uimm);

						return false;
					}

					return true;
				}

				printf("new operand is UIMM %ld, capstone is REG %d != PPC_REG_INVALID\n",
					new_op->uimm, capstone_op->reg);
				return false;
			}

			if (capstone_op->type != PPC_OP_IMM)
			{
				printf("new operand is UIMM, but capstone is %d\n", capstone_op->type);
				return false;
			}

			int64_t capstone_imm = capstone_op->imm;
			int64_t new_imm = new_op->uimm;

			if (capstone_imm != new_imm)
			{
				printf("new operand UIMM is %#lx, capstone imm is %#lx\n",
					new_imm, capstone_imm);
				return false;
			}

			return true;
		}

		case PPC_OP_SIMM:
		{
			if (capstone_op->type != PPC_OP_IMM)
			{
				printf("new operand is SIMM, but capstone is %d\n", capstone_op->type);
				return false;
			}

			int64_t capstone_imm = capstone_op->imm;
			int64_t new_imm = new_op->simm;

			if (capstone_imm != new_imm)
			{
				printf("new operand SIMM is %#lx, capstone imm is %#lx\n",
					new_imm, capstone_imm);
				return false;
			}

			return true;
		}

		case PPC_OP_REG_RA:
		case PPC_OP_REG_RB:
		case PPC_OP_REG_RC:
		case PPC_OP_REG_RD:
		case PPC_OP_REG_RS:
		{
			if (capstone_op->type != PPC_OP_REG)
			{
				printf("new operand is register, but capstone is %d\n", capstone_op->type);
				return false;
			}

			int capstone_reg = capstone_op->reg - PPC_REG_R0;
			int new_reg = new_op->reg - NUPPC_REG_GPR0;

			if (capstone_reg != new_reg)
			{
				printf("new operand register %d, capstone register %d\n",
					new_reg, capstone_reg);

				return false;
			}

			return true;
		}

		case PPC_OP_REG_FRA:
		case PPC_OP_REG_FRB:
		case PPC_OP_REG_FRC:
		case PPC_OP_REG_FRD:
		case PPC_OP_REG_FRS:
		{
			if (capstone_op->type != PPC_OP_REG)
			{
				printf("new operand is register, but capstone is %d\n", capstone_op->type);
				return false;
			}

			int capstone_reg = capstone_op->reg - PPC_REG_F0;
			int new_reg = new_op->reg - NUPPC_REG_FR0;

			if (capstone_reg != new_reg)
			{
				printf("new operand register %d, capstone register %d\n",
					new_reg, capstone_reg);

				return false;
			}

			return true;
		}

		case PPC_OP_REG_CRFD:
		case PPC_OP_REG_CRFD_IMPLY0:
		case PPC_OP_REG_CRFS:
		{
			if (capstone_op->type != PPC_OP_REG)
			{
				printf("new operand is CR, but capstone is %d\n", capstone_op->type);
				return false;
			}

			int capstone_reg = capstone_op->reg - PPC_REG_CR0;
			int new_reg = new_op->reg - NUPPC_REG_CRF0;
			
			if (capstone_reg != new_reg)
			{
				printf("new operand CR %d, capstone CR register %d\n",
					new_reg, capstone_reg);

				return false;
			}

			return true;
		}

		case PPC_OP_CRBIT_A:
		case PPC_OP_CRBIT_B:
		case PPC_OP_CRBIT_D:
		{
			if (capstone_op->type != PPC_OP_REG)
			{
				printf("new operand is CRbit, but capstone is %d\n", capstone_op->type);
				return false;
			}

			const char* capstone_name = cs_reg_name(handle, capstone_op->reg);
			
			if (!crbit_equal(capstone_op->reg, new_op->crbit))
			{
				printf("new operand CR %d, capstone CR register %d (%s)\n",
					new_op->crbit, capstone_op->reg, capstone_name);

				return false;
			}

			return true;
		}

		case PPC_OP_REG_AV_VA:
		case PPC_OP_REG_AV_VB:
		case PPC_OP_REG_AV_VC:
		case PPC_OP_REG_AV_VD:
		case PPC_OP_REG_AV_VS:
		{
			if (capstone_op->type != PPC_OP_REG)
			{
				printf("new operand is altivec register, but capstone is %d\n", capstone_op->type);
				return false;
			}

			int capstone_reg = capstone_op->reg - PPC_REG_V0;
			int new_reg = new_op->reg - NUPPC_REG_AV_VR0;

			if (capstone_reg != new_reg)
			{
				printf("new operand altivec register %d, capstone altivec register %d\n",
					new_reg, capstone_reg);

				return false;
			}

			return true;
		}

		case PPC_OP_REG_VSX_RA:
		case PPC_OP_REG_VSX_RB:
		case PPC_OP_REG_VSX_RC:
		case PPC_OP_REG_VSX_RD:
		case PPC_OP_REG_VSX_RS:
		{
			if (capstone_op->type != PPC_OP_REG)
			{
				printf("new operand is vsx (full) register, but capstone is %d\n", capstone_op->type);
				return false;
			}

			const char* capstone_name = cs_reg_name(handle, capstone_op->reg);
			int new_reg = new_op->reg - NUPPC_REG_VSX_VR0;
			int capstone_reg;
			if (PPC_REG_VS0 <= capstone_op->reg && capstone_op->reg <= PPC_REG_VS63)
				capstone_reg = capstone_op->reg - PPC_REG_VS0;
			else if (PPC_REG_V0 <= capstone_op->reg && capstone_op->reg <= PPC_REG_V31)
				capstone_reg = capstone_op->reg - PPC_REG_V0 + 32;
			else
			{
				printf("new operand vsx (full) register %d, capstone register %d (%s) isn't any kind of vector\n", new_reg, capstone_op->reg, capstone_name);

				return false;
			}

			if (capstone_reg != new_reg)
			{
				printf("new operand vsx (full) register %d, capstone vsx register %d (%s)\n",
					new_reg, capstone_reg, capstone_name);

				return false;
			}

			return true;
		}

		case PPC_OP_REG_VSX_RA_DWORD0:
		case PPC_OP_REG_VSX_RB_DWORD0:
		case PPC_OP_REG_VSX_RC_DWORD0:
		case PPC_OP_REG_VSX_RD_DWORD0:
		case PPC_OP_REG_VSX_RS_DWORD0:
		{
			if (capstone_op->type != PPC_OP_REG)
			{
				printf("new operand is vsx (dword0) register, but capstone is %d\n", capstone_op->type);
				return false;
			}

			const char* capstone_name = cs_reg_name(handle, capstone_op->reg);
			int new_reg = new_op->reg - NUPPC_REG_VSX_VR0;
			int capstone_reg;
			if (PPC_REG_VS0 <= capstone_op->reg && capstone_op->reg <= PPC_REG_VS63)
				capstone_reg = capstone_op->reg - PPC_REG_VS0;
			else if (PPC_REG_V0 <= capstone_op->reg && capstone_op->reg <= PPC_REG_V31)
				capstone_reg = capstone_op->reg - PPC_REG_V0 + 32;
			else if (PPC_REG_F0 <= capstone_op->reg && capstone_op->reg <= PPC_REG_F31)
				capstone_reg = capstone_op->reg - PPC_REG_F0;
			else
			{
				printf("new operand vsx (dword0) register %d, capstone register %d (%s) isn't any kind of vector\n", new_reg, capstone_op->reg, capstone_name);

				return false;
			}


			if (capstone_reg != new_reg)
			{
				printf("new operand vsx (dword0) register %d, capstone vsx register %d (%s)\n",
					new_reg, capstone_reg, capstone_name);

				return false;
			}

			return true;
		}

		case PPC_OP_MEM_RA:
		{
			if (capstone_op->type != PPC_OP_MEM)
			{
				printf("new operand is memory, but capstone is %d\n", capstone_op->type);
				return false;
			}

			// memory are of the form RA|0
			int new_reg = new_op->mem.reg - NUPPC_REG_GPR0;
			if (new_reg == 0)
			{
				if (capstone_op->mem.base != PPC_REG_INVALID)
				{
					printf("new operand mem reg is r0, capstone mem reg is %d != invalid\n",
						capstone_op->mem.base);
					return false;
				}
			}
			else
			{
				int capstone_reg = capstone_op->mem.base - PPC_REG_R0;
				if (capstone_reg != new_reg)
				{
					printf("new operand mem reg is %d, capstone mem reg is %d\n",
						new_reg, capstone_reg);
					return false;
				}
			}

			int capstone_offset = capstone_op->mem.disp;
			int new_offset = new_op->mem.offset;

			if (capstone_offset != new_offset)
			{
				printf("new operand mem offset is %d, capstone mem offset is %d\n",
					new_offset, capstone_offset);

				return false;
			}

			return true;
		}

		default:
			printf("unhandled class %d\n", new_op->cls);
			return false;
	}

}

uint32_t bc_to_bi(ppc_bc bc)
{
	switch (bc)
	{
		case PPC_BC_LT: return 0;
		case PPC_BC_GT: return 1;
		case PPC_BC_EQ: return 2;
		case PPC_BC_SO: return 3;
		default:        return 0xffffffff;
	}
}

uint32_t crx_to_bi(const ppc_op_crx* crx)
{
	uint32_t crn = (crx->reg - PPC_REG_CR0);
	uint32_t extra = 0;
	switch (crx->cond)
	{
		case PPC_BC_LT: extra = 0; break;
		case PPC_BC_GT: extra = 1; break;
		case PPC_BC_EQ: extra = 2; break;
		case PPC_BC_SO: extra = 3; break;

		default:
			printf("bcx capstone op 0 cond is weird %d\n",
				crx->cond);
			return 0xffffffff;
	}

	return crx->scale*crn + extra;
}

// compare bcx <bit> <label> (for decrementing CTR and checking if bit is true)
bool bcx_equal(csh handle, const cs_ppc* capstone_instruction, const Instruction* new_instruction, const OperandsList* bcx, uint64_t address)
{
	if (bcx->operands[0].cls != PPC_OP_UIMM || bcx->operands[1].cls != PPC_OP_LABEL)
	{
		printf("bcx new ops 0/1 are %d/%d not UIMM/LABEL\n",
			bcx->operands[0].cls,
			bcx->operands[1].cls);
		return false;
	}

	if (capstone_instruction->op_count == 0)
	{
		// I don't know if it's idiomatic to be able to exclude the
		// address for branch instructions, but when BD is 0 (whether
		// the 'aa' bit is set or not), capstone omits the address
		// token?
		if (new_instruction->flags.aa && bcx->operands[1].label == 0)
			return true;

		if (!new_instruction->flags.aa && bcx->operands[1].label == address)
			return true;

		printf("bcx capstone 0 operands but new target %" PRIx64 " isn't address %" PRIx64" \n",
			bcx->operands[1].label, address);

		return false;
	}

	switch (capstone_instruction->operands[0].type)
	{
		case PPC_OP_IMM:
		{
			if (bcx->operands[1].label != capstone_instruction->operands[0].imm)
			{
				printf("bcx new op1 %08lx != capstone bc %08lx\n",
					bcx->operands[1].uimm, capstone_instruction->operands[0].imm);

				return false;
			}

			return true;
		}
		case PPC_OP_CRX:
		{
			printf("capstone op 0 is crx");
			return false;
		}

		case PPC_OP_REG:
		{
			if (capstone_instruction->op_count >= 3) {
				printf("bcx (crbit) capstone has too many (%d) args\n",
					capstone_instruction->op_count);
				
				return false;
			}

			if (!crbit_equal(capstone_instruction->operands[0].reg, bcx->operands[0].uimm))
			{
				printf("bcx (crbit) crbit not equivalent: new uimm %ld, cs reg %d\n",
					bcx->operands[0].uimm, capstone_instruction->operands[0].reg);
				return false;
			}

			if (capstone_instruction->op_count == 2 && (capstone_instruction->operands[1].imm != bcx->operands[1].label))
			{
				printf("bcx (crbit) labels not equivalent: new label %lx, cs imm %lx\n",
					bcx->operands[1].label, capstone_instruction->operands[1].imm);

				return false;
			}

			return true;
		}

		default:
			printf("bcx capstone op 0 is %d not PPC_OP_IMM\n",
				capstone_instruction->operands[0].type);
			return false;
	}

	return true;
}

bool bcx_2op_equal(csh handle, const cs_ppc* capstone_instruction, const Instruction* new_instruction, const OperandsList* bcx, uint64_t address)
{
	if (bcx->numOperands != 2)
	{
		printf("bcx 2op equal unknown number of arguments for new %ld\n",
			bcx->numOperands);

		return false;
	}

	if (bcx->operands[0].cls != PPC_OP_REG_CRFS && bcx->operands[1].cls != PPC_OP_LABEL)
	{
		printf("bcx 2op equal unexpected op classes %d/%d (new)\n",
			bcx->operands[0].cls, bcx->operands[1].cls);

		return false;
	}

	if (capstone_instruction->op_count == 0)
	{
		if (bcx->operands[0].reg != NUPPC_REG_CRF0)
		{
			printf("bcx 2op equal capstone 0 operands but new reg %d isn't CRF0 %d\n",
				bcx->operands[0].reg, NUPPC_REG_CRF0);

			return false;
		}

		// I don't know if it's idiomatic to be able to exclude the
		// address for branch instructions, but when BD is 0 (whether
		// the 'aa' bit is set or not), capstone omits the address
		// token?
		if (new_instruction->flags.aa && bcx->operands[1].label == 0)
			return true;

		if (!new_instruction->flags.aa && bcx->operands[1].label == address)
			return true;

		printf("bcx 2op equal capstone 0 operand but new target %lx isn't address %lx\n",
			bcx->operands[1].label, address);

		return false;
	}

	if (capstone_instruction->op_count == 1)
	{
		if (capstone_instruction->operands[0].type == PPC_OP_REG)
		{
			// I don't know if it's idiomatic to be able to exclude the
			// address for branch instructions, but when BD is 0 (whether
			// the 'aa' bit is set or not), capstone omits the address
			// token?
			if (new_instruction->flags.aa && bcx->operands[1].label == 0)
				return true;

			if (!new_instruction->flags.aa && bcx->operands[1].label == address)
				return true;

			printf("bcx 2op equal capstone 1 operand but new target %lx isn't address %lx\n",
				bcx->operands[1].label, address);

			return false;
		}
		else if (capstone_instruction->operands[0].type == PPC_OP_IMM)
		{
			if (bcx->operands[0].reg != NUPPC_REG_CRF0)
			{
				printf("bcx 2op equal capstone 1 operand but new reg %d isn't CRF0 %d\n",
					bcx->operands[0].reg, NUPPC_REG_CRF0);

				return false;
			}

			if (bcx->operands[1].label != capstone_instruction->operands[0].imm)
			{
				printf("bcx 2op equal capstone 1 operand but new target %lx isn't capstone target %lx\n",
					bcx->operands[1].label, capstone_instruction->operands[0].imm);

				return false;
			}

			return true;
		}

		printf("bcx 2op equal unexpected op type %d (capstone)\n",
			capstone_instruction->operands[0].type);

		return false;	
	}

	if (capstone_instruction->operands[0].type != PPC_OP_REG || capstone_instruction->operands[1].type != PPC_OP_IMM)
	{
		printf("bcx 2op equal unexpected op type %d/%d (capstone)\n",
			capstone_instruction->operands[0].type, capstone_instruction->operands[1].type);

		return false;	
	}

	uint32_t new_crn = bcx->operands[0].reg - NUPPC_REG_CRF0;
	uint32_t cs_crn = capstone_instruction->operands[0].reg - PPC_REG_CR0;

	if (new_crn != cs_crn)
	{
		printf("bcx 2op equal regs are different cs %d != new %d\n",
			cs_crn, new_crn);

		return false;
	}

	if (capstone_instruction->operands[1].imm != bcx->operands[1].label)
	{
		printf("bcx 2op equal targets are different cs %#lx != new %#lx\n",
			capstone_instruction->operands[1].imm, new_instruction->operands[1].label);

		return false;
	}

	return true;
}

bool bcx_1op_equal(csh handle, const cs_ppc* capstone_instruction, const Instruction* new_instruction, const OperandsList* bcx, uint64_t address)
{
	if (bcx->numOperands != 1)
	{
		printf("bcx 1op equal unknown number of arguments for new %ld\n",
			bcx->numOperands);

		return false;
	}

	if (bcx->operands[0].cls != PPC_OP_LABEL)
	{
		printf("bcx 1op equal unexpected op class %d (new)\n",
			bcx->operands[0].cls);

		return false;
	}

	if (capstone_instruction->op_count == 0)
	{
		if (new_instruction->flags.aa && bcx->operands[0].label == 0)
			return true;

		if (!new_instruction->flags.aa && bcx->operands[0].label == address)
			return true;

		printf("bcx 1op equal address mismatch; capstone no operands, aa %d new label %lx address %lx\n",
			new_instruction->flags.aa, bcx->operands[0].label, address);

		return false;
	}

	if (capstone_instruction->op_count != 1)
	{
		printf("bcx 1op equal unexpected count %d (capstone)\n",
			capstone_instruction->op_count);

		return false;
	}

	if (capstone_instruction->operands[0].imm != bcx->operands[0].label)
	{
		printf("bcx 1op equal labels not equal cs %lx != new %lx\n",
			capstone_instruction->operands[0].imm,
			bcx->operands[0].label);

		return false;
	}

	return true;
}

bool bcregx_noargs_equal(csh handle, const cs_ppc* capstone_instruction, const Instruction* new_instruction)
{
	if (new_instruction->numOperands != 0)
	{
		printf("bcregx_noargs unknown number of arguments for new %ld\n",
			new_instruction->numOperands);

		return false;
	}

	if (capstone_instruction->op_count == 0)
		return true;

	// <op> <unnecessary target>
	if (capstone_instruction->op_count == 1 && capstone_instruction->operands[0].type == PPC_OP_IMM)
		return true;

	printf("bcregx_noargs unexpected capstone structure: op count %d/op0 type %d\n",
		capstone_instruction->op_count, capstone_instruction->operands[0].type);
	return false;
}

// for BCCTRx and BCLRx variants when just "<op> BI"
bool bcregx_bi_equal(csh handle, const cs_ppc* capstone_instruction, const Instruction* new_instruction)
{
	if (new_instruction->numOperands != 1)
	{
		printf("bcregx_bi unknown number of arguments for new %ld\n",
			new_instruction->numOperands);

		return false;
	}

	if (new_instruction->operands[0].cls != PPC_OP_UIMM)
	{
		printf("bcregx_bi unknown new op0 class %d\n",
			new_instruction->operands[0].cls);

		return false;
	}

	// capstone uses just condition codes when CRn = 0; condition codes
	// aren't treated as operands, so this happens when op_count == 0 and
	// when capstone (unnecessarily?) adds a branch target
	if (capstone_instruction->op_count == 0 || (capstone_instruction->op_count == 1 && capstone_instruction->operands[0].type == PPC_OP_IMM))
	{
		uint32_t cs_bi = bc_to_bi(capstone_instruction->bc);
		if (new_instruction->operands[0].uimm != cs_bi)
		{
			printf("bcregx_bi cs_bi %d != new bi %ld\n",
				cs_bi, new_instruction->operands[0].uimm);

			return false;
		}

		return true;
	}

	if (capstone_instruction->operands[0].type != PPC_OP_CRX)
	{
		printf("bcregx_bi unknown capstone op0 type %d\n",
			capstone_instruction->operands[0].type);

		return false;
	}

	uint32_t cs_bi = crx_to_bi(&capstone_instruction->operands[0].crx);
	if (cs_bi != new_instruction->operands[0].uimm)
	{
		printf("bcregx_bi capstone BI %d != new BI %ld\n",
			cs_bi, new_instruction->operands[0].uimm);

		return false;
	}

	return true;
}

// bclrx/bcctrx 
bool bcregx1_equal(csh handle, const cs_ppc* capstone_instruction, const Instruction* new_instruction, const OperandsList* bcregx)
{
	if (bcregx->numOperands != 1)
	{
		printf("bcregx1_equal unexpected num operands %ld (new)\n",
			bcregx->numOperands);

		return false;
	}

	if (bcregx->operands[0].cls != PPC_OP_CRBIT)
	{
		printf("bcregx1_equal unexpected op0 type %d isn't %d (new)\n",
			bcregx->operands[0].cls, PPC_OP_CRBIT);

		return false;
	}

	if (capstone_instruction->op_count == 0)
	{
		uint32_t cs_bi = bc_to_bi(capstone_instruction->bc);
		if (bcregx->operands[0].crbit != cs_bi)
		{
			printf("bcregx1_equal capstone 1op op0 imm unexpected value %#x (new) != %#x (cs)\n",
				bcregx->operands[0].crbit, cs_bi);

			return false;
		}

		return true;
	}

	else if (capstone_instruction->op_count == 1)
	{
		if (capstone_instruction->operands[0].type == PPC_OP_REG)
		{
			if (!crbit_equal(capstone_instruction->operands[0].reg, bcregx->operands[0].crbit))
			{
				printf("bcregx1_equal capstone 1op op0 reg %d != crbit %d\n",
					capstone_instruction->operands[0].reg, bcregx->operands[0].crbit);
				return false;
			}

			return true;
		}

		printf("bcregx1_equal capstone 1op op0 unexpected type %d",
			capstone_instruction->operands[0].type);

		return false;
	}
	else if (capstone_instruction->op_count == 2)
	{
		// <op> <BI> [unnecessary target]
		if (capstone_instruction->operands[0].type == PPC_OP_CRX)
		{
			printf("bcregx1_equal 2op crx\n");
			return false;
		}
		else if (capstone_instruction->operands[0].type == PPC_OP_REG)
		{
			if (!crbit_equal(capstone_instruction->operands[0].reg, bcregx->operands[0].crbit))
			{
				printf("bcregx1_equal capstone 2op op0 reg %d != crbit %d\n",
					capstone_instruction->operands[0].reg, bcregx->operands[0].crbit);
				return false;
			}
			return true;
		}
		else
		{
			printf("bcregx1_equal capstone 2op op0 unexpected type %d != PPC_OP_CRX %d\n",
				capstone_instruction->operands[0].type, PPC_OP_CRX);

			return false;
		}
	}

	printf("bcregx1_equal unknown number of capstone operands %d\n",
		capstone_instruction->op_count);

	return false;
}

bool bcregx2_equal(csh handle, const cs_ppc* capstone_instruction, const Instruction* new_instruction, const OperandsList* bcregx)
{
	if (bcregx->numOperands != 1)
	{
		printf("bcregx2_equal unexpected num operands %ld (new)\n",
			bcregx->numOperands);

		return false;
	}

	if (bcregx->operands[0].cls != PPC_OP_REG_CRFS_IMPLY0)
	{
		printf("bcregx2_equal unexpected op0 type %d isn't %d (new)\n",
			bcregx->operands[0].cls, PPC_OP_REG_CRFS);

		return false;
	}

	if (capstone_instruction->op_count == 0)
	{
		if (bcregx->operands[0].reg != NUPPC_REG_CRF0)
		{
			printf("bcregx2_equal capstone no ops but crn is %d != %d\n",
				bcregx->operands[0].reg, NUPPC_REG_CRF0);

			return false;
		}

		return true;
	}

	if (capstone_instruction->op_count == 1)
	{
		if (capstone_instruction->operands[0].type == PPC_OP_REG)
		{
			uint32_t new_reg = bcregx->operands[0].reg - NUPPC_REG_CRF0;
			uint32_t cs_reg = capstone_instruction->operands[0].reg - PPC_REG_CR0;

			if (new_reg != cs_reg)
			{
				printf("bcregx2_equal capstone 1 op REG, new reg is %d != cs reg %d\n",
					new_reg, cs_reg);

				return false;
			}

			return true;
		}
		else if (capstone_instruction->operands[0].type == PPC_OP_IMM)
		{
			if (bcregx->operands[0].reg != NUPPC_REG_CRF0)
			{
				printf("bcregx2_equal capstone 1 op UIMM, new reg is %d != %d\n",
					bcregx->operands[0].reg, NUPPC_REG_CRF0);

				return false;
			}

			return true;
		}

		printf("bcregx2_equal unexpected op0 %d (capstone)\n",
			capstone_instruction->operands[0].type);

		return false;
	}

	if (capstone_instruction->op_count == 2)
	{
		if (capstone_instruction->operands[0].type != PPC_OP_REG)
		{
			printf("bcregx2_equal capstone op0 type %d != %d\n",
				capstone_instruction->operands[0].type, PPC_OP_REG);

			return false;
		}

		uint32_t new_reg = bcregx->operands[0].reg - NUPPC_REG_CRF0;
		uint32_t cs_reg = capstone_instruction->operands[0].reg - PPC_REG_CR0;

		if (new_reg != cs_reg)
		{
			printf("bcregx2_equal capstone 2 op REG/UIMM, new reg is %d != cs reg %d\n",
				new_reg, cs_reg);

			return false;
		}

		return true;
	}

	printf("bcregx2_equal unexpected num ops %d (capstone)\n",
		capstone_instruction->op_count);

	return false;
}

bool bcregx3_equal(csh handle, const cs_ppc* capstone_instruction, const Instruction* new_instruction, const OperandsList* bcregx)
{
	if (bcregx->numOperands != 0)
	{
		printf("bcregx3_equal unexpected num operands %ld != 0 (new)\n",
			bcregx->numOperands);

		return false;
	}

	if (capstone_instruction->op_count == 0)
	{
		return true;
	}
	else if (capstone_instruction->op_count == 1)
	{
		if (capstone_instruction->operands[0].type != PPC_OP_IMM)
		{
			printf("bcregx3_equal cs 1-op unexpected op0 type %d != %d\n",
				capstone_instruction->operands[0].type, PPC_OP_IMM);

			return false;
		}

		return true;
	}

	printf("bcregx3_equal unexpected num operands %d (cs)\n",
		capstone_instruction->op_count);

	return false;
}

bool bcregx_crn_equal(csh handle, const cs_ppc* capstone_instruction, const Instruction* new_instruction)
{
	if (new_instruction->numOperands == 0)
	{
		if (capstone_instruction->op_count == 0)
		{
			return true;
		}

		if (capstone_instruction->op_count == 1 && capstone_instruction->operands[0].type == PPC_OP_IMM)
		{
			return true;
		}

		printf("bcregx_crn new has no ops but capstone has %d ops and op0 is type %d != %d\n",
			capstone_instruction->op_count, capstone_instruction->operands[0].type, PPC_OP_IMM);
		return false;
	}

	if (new_instruction->numOperands != 1)
	{
		printf("bcregx_crn unknown number of arguments for new %ld\n",
			new_instruction->numOperands);

		return false;
	}

	if (new_instruction->operands[0].cls != PPC_OP_REG_CRFS)
	{
		printf("bcregx_crn unknown new op0 class %d\n",
			new_instruction->operands[0].cls);

		return false;
	}

	uint32_t new_reg = new_instruction->operands[0].reg - NUPPC_REG_CRF0;

	if (capstone_instruction->op_count == 0)
	{
		if (new_reg != 0)
		{
			printf("bcregx_crn capstone no ops, new reg %d != 0\n",
				new_reg);

			return false;
		}

		return true;
	}

	// capstone: <op> [cr0] <unnecessary target address> or <op> <crX>
	if (capstone_instruction->op_count == 1)
	{
		if (capstone_instruction->operands[0].type == PPC_OP_REG)
		{
			// capstone: <op> <crX>
			uint32_t cs_reg = capstone_instruction->operands[0].reg - PPC_REG_CR0;
			if (cs_reg != new_reg)
			{
				printf("bcregx_crn capstone 1 reg %d != new reg %d\n",
					cs_reg, new_reg);

				return false;

			}

			return true;
		}
		else if (capstone_instruction->operands[0].type == PPC_OP_IMM)
		{
			// capstone: <op> <target>
			if (new_reg != 0)
			{
				printf("bcregx_crn capstone just target, new reg %d != 0\n",
					new_reg);

				return false;
			}

			return true;
		}
		else
		{
			printf("bcregx_crn capstone 1-op unknown type %d\n",
				capstone_instruction->operands[0].type);

			return false;
		}
	}

	if (capstone_instruction->op_count == 2)
	{
		if (capstone_instruction->operands[0].type != PPC_OP_REG || capstone_instruction->operands[1].type != PPC_OP_IMM)
		{
			printf("bcregx_crn capstone 2-op types %d/%d != %d/%d\n",
				capstone_instruction->operands[0].type,
				capstone_instruction->operands[1].type,
				PPC_OP_REG, PPC_OP_IMM);

			return false;
		}

		uint32_t cs_reg = capstone_instruction->operands[0].reg - PPC_REG_CR0;
		if (cs_reg != new_reg)
		{
			printf("bcregx_crn capstone 2-op new reg %d != cs reg %d\n",
				new_reg, cs_reg);

			return false;
		}

		return true;
	}

	printf("bcregx_crn unknown number of operands in capstone %d\n",
		capstone_instruction->op_count);

	return false;
}

#define ADDRESS 0x1000

int main(int argc, char* argv[])
{
	csh handle;
	cs_insn *cs_instruction;
	Instruction new_instruction;

	int err = cs_open(CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN, &handle);
	if (err != CS_ERR_OK)
	{
		printf("failed to open capstone: err %d\n", err);
		return -1;
	}

	err = cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	if (err != CS_ERR_OK)
	{
		printf("failed to set detail on: err %d\n", err);
		return -1;
	}

	uint32_t i;

	for (i = 0x7c000000; i < 0x80000000; ++i)
	{
		uint32_t op = ((i << 24) & 0xff000000) | ((i << 8) & 0x00ff0000) | ((i >> 8) & 0x0000ff00) | ((i >> 24) & 0x000000ff);

		bool cs_error = cs_disasm(handle, (uint8_t*)&op, sizeof op, ADDRESS, 1, &cs_instruction) != 1;
		bool new_error = !Decompose32(&new_instruction, i, ADDRESS, DECODE_FLAGS_ALTIVEC | DECODE_FLAGS_PPC64 | DECODE_FLAGS_VSX);

		if (cs_error != new_error)
		{
			if (new_error)
			{
				// capstone disassembled something that we don't
				bool complain = true;

				switch (cs_instruction->id)
				{
					// capstone is too eager to decode some instructions
					case PPC_INS_MFSR:
					case PPC_INS_MTSR:
						if ((i & 0x0010f801) != 0)
							complain = false;
						break;
					case PPC_INS_MFSRIN:
					case PPC_INS_MTSRIN:
						if ((i & 0x001f0001) != 0)
							complain = false;
						break;
					case PPC_INS_WRTEE:
						if ((i & 0x001ff801) != 0)
							complain = false;
						break;
					case PPC_INS_WRTEEI:
						if ((i & 0x03ff7801) != 0)
							complain = false;
						break;
					case PPC_INS_MBAR:
					case PPC_INS_MTMSR:
					case PPC_INS_MTMSRD:
						if ((i & 0x001ff801) != 0)
							complain = false;
						break;
					case PPC_INS_DCCCI:
					case PPC_INS_ICCCI:
						if ((i & 0x021ff801) != 0)
							complain = false;
						break;

					case PPC_INS_TLBSX:
						// capstone thinks this has an "RC" bits
						if ((i & 0x1) != 0)
							complain = false;

						// capstone is too eager to decode
						if ((i & 0x03e00000) != 0)
							complain = false;

						break;

					case PPC_INS_SC:
						// capstone is too eager for sc
						if ((i & 0x03fff01d) != 0)
							complain = false;

						break;

					// capstone treats UIM as 5 bits when it's 4,
					// with a reserved bit that should be clear
					case PPC_INS_VEXTRACTD:
					case PPC_INS_VEXTRACTUB:
					case PPC_INS_VEXTRACTUH:
					case PPC_INS_VEXTRACTUW:
					case PPC_INS_VINSERTB:
					case PPC_INS_VINSERTD:
					case PPC_INS_VINSERTH:
					case PPC_INS_VINSERTW:
					case PPC_INS_XXEXTRACTUW:
					case PPC_INS_XXINSERTW:
						if ((i & 0x00100000) != 0)
							complain = false;

						break;

					// capstone has the wrong opcode for this (it's 0x18c, not 0x18d)
					case PPC_INS_ICBLQ:
						if ((i & 0x1) == 0)
							complain = false;

						break;

					case PPC_INS_COPY:
						// capstone doesn't check that bit 10 == 1
						if (((i >> 21) & 0x1f) != 1)
							complain = false;

						break;

					case PPC_INS_PASTE:
						// capstone doesn't check that bit 10 == 1 or that bit 31 == 1
						if ((((i >> 21) & 0x1f) != 1) || ((i & 0x1) != 1))
							complain = false;

						break;

					case PPC_INS_LDMX:
						// this instruction never made it into POWER9:
						// https://inbox.sourceware.org/binutils/c3a53df0-cdf4-de7b-0e50-75150f2fa456@linux.ibm.com/T/
						// I guess we could add support, but it's something that would
						// only apply to like pre-release binaries
						complain = false;
						break;

					case PPC_INS_DCBZLEP:
						// I can't find any official docs about this
						complain = false;
						break;

					case PPC_INS_DCBF:
						// L is only 2 bits, capstone recognizes more
						if (((i >> 21) & 0x1f) > 3)
							complain = false;

						break;

					default:
						;
				}

				if (complain)
					printf("capstone succeeded but new failed for %08x: %s %s [id %d]\n",
						i, cs_instruction->mnemonic, cs_instruction->op_str, cs_instruction->id);

				cs_free(cs_instruction, 1);
			}
			else
			{
				// we disassembled something that capstone doesn't
				bool complain = true;

				switch (new_instruction.id)
				{
					// capstone doesn't seem to handle these
					case PPC_ID_ECIWX:
					case PPC_ID_ECOWX:
					case PPC_ID_FCMPO:
					case PPC_ID_LSWX:
					case PPC_ID_STSWX:
					case PPC_ID_TLBIA:
					case PPC_ID_STDEPX:
						complain = false;
						break;

					// capstone doesn't seem to handle "o" suffix
					case PPC_ID_ADDx:
					case PPC_ID_ADDCx:
					case PPC_ID_ADDEx:
					case PPC_ID_ADDMEx:
					case PPC_ID_ADDZEx:
					case PPC_ID_DIVDx:
					case PPC_ID_DIVDEx:
					case PPC_ID_DIVDEUx:
					case PPC_ID_DIVDUx:
					case PPC_ID_DIVWx:
					case PPC_ID_DIVWEx:
					case PPC_ID_DIVWEUx:
					case PPC_ID_DIVWUx:
					case PPC_ID_MULLDx:
					case PPC_ID_MULLWx:
					case PPC_ID_NEGx:
					case PPC_ID_SUBFx:
					case PPC_ID_SUBFCx:
					case PPC_ID_SUBFEx:
					case PPC_ID_SUBFMEx:
					case PPC_ID_SUBFZEx:
						if (new_instruction.flags.oe)
							complain = false;
						break;

					// capstone doesn't realize these have rc
					case PPC_ID_MTFSB0x:
					case PPC_ID_MTFSB1x:
						if (new_instruction.flags.rc)
							complain = false;
						break;

					// capstone doesn't recognize op in DCI, ICI
					case PPC_ID_DCI:
					case PPC_ID_ICI:
						if ((i & 0x01e00000) != 0)
							complain = false;
						break;

					// capstone doesn't recognize these
					case PPC_ID_AV_BCDADD:
					case PPC_ID_AV_BCDSUB:
						complain = false;
						break;

					// capstone has the wrong opcode: 0x18c instead of 0x18d
					case PPC_ID_ICBLQ:
						if ((i & 0x1) != 0)
							complain = false;
						break;

					case PPC_ID_SLBMFEV:
						// v3.0B includes L bit, capstone still using V2.07 form
						// which doesn't have it
						if (((i >> 16) & 0x1) == 1)
							complain = false;
						break;

					case PPC_ID_DCBFEP:
						// capstone doesn't recognize L!=0
						if (((i >> 21) & 0x3) != 0)
							complain = false;

						break;

					default:
						;
				}

				if (complain)
					printf("new succeeded but capstone failed for %08x (%s)\n", i, GetMnemonic(&new_instruction));


			}

			continue;
		}

		if (cs_error)
		{
			continue;
		}

		const char* new_mnem = GetMnemonic(&new_instruction);
		if (!new_mnem)
		{
			printf("no mnem for %08x (capstone %s)\n", i, cs_instruction->mnemonic);
			cs_free(cs_instruction, 1);
			continue;
		}

		if (strcmp(cs_instruction->mnemonic, new_mnem))
		{
			bool complain = true;

			switch (new_instruction.id)
			{
				case PPC_ID_BCCTRx:
				{
					uint32_t bo = new_instruction.operands[0].uimm;
					if ((bo & 0x4) == 0)
						complain = false;

					// "always branch" is 1z1zz, but
					// capstone disassembles it as "bdnzctr"?
					if ((bo & 0x14) == 0x14)
						complain = false;

					break;
				}

				case PPC_ID_BCLRx:
				{
					uint32_t bo = new_instruction.operands[0].uimm;

					// "always branch" is 1z1zz, but
					// capstone disassembles it as "bdnzlr"?
					if ((bo & 0x14) == 0x14)
						complain = false;

					break;
				}

				// capstone disassembles this as just "cntlz"
				case PPC_ID_CNTLZWx:
					complain = false;
					break;

				// capstone disassembles pseudo-ops for RLWINM
				// differently from RLWINM. for some reason
				case PPC_ID_SLWIx:
					if (new_instruction.flags.rc && !strcmp(cs_instruction->mnemonic, "rotlwi."))
						complain = false;

					// intentional fallthrough
				case PPC_ID_SRWIx:
					if (new_instruction.flags.rc && !strcmp(cs_instruction->mnemonic, "rlwinm."))
						complain = false;

					break;

				// likewise for RLDICR vs RLDICR.
				case PPC_ID_SLDIx:
					if (new_instruction.flags.rc && !strcmp(cs_instruction->mnemonic, "rldicr."))
						complain = false;

					break;

				// capstone doesn't seem to recognize CLRRWI
				case PPC_ID_CLRRWIx:
					complain = false;
					break;

				case PPC_ID_MFSPR:
					complain = !strncmp(cs_instruction->mnemonic, "mf", 3);
					break;

				case PPC_ID_MTSPR:
					complain = !strncmp(cs_instruction->mnemonic, "mt", 3);
					break;

				default:
					;
			}

			if (complain)
			{
				printf("different mnemonics for %08x!  CS: %s NEW: %s\n",
					i, cs_instruction->mnemonic, new_mnem);

				cs_free(cs_instruction, 1);
				continue;
			}
		}

		cs_ppc* capstone_ppc = &cs_instruction->detail->ppc;
		switch (new_instruction.id)
		{
			case PPC_ID_BCx:
			{
				OperandsList bcx;
				FillBcxOperands(&bcx, &new_instruction);

				uint32_t bo = new_instruction.operands[0].uimm;

				switch (bo & 0x1e)
				{
					case 0:
					case 2:
					case 8:
					case 10:
						if (!(bcx_equal(handle, capstone_ppc, &new_instruction, &bcx, ADDRESS)))
						{
							printf("bcx different for %08x (new %s/cs %s %s)!\n",
								i, new_mnem, cs_instruction->mnemonic, cs_instruction->op_str);
						}
						break;

					case 4:
					case 6:
					case 12:
					case 14:
						if (!(bcx_2op_equal(handle, capstone_ppc, &new_instruction, &bcx, ADDRESS)))
						{
							printf("bcx 2op different for %08x (new %s/cs %s %s)!\n",
								i, new_mnem, cs_instruction->mnemonic, cs_instruction->op_str);
						}
						break;

					case 16:
					case 18:
					case 20:
					case 22:
					case 24:
					case 26:
					case 28:
					case 30:
						if (!(bcx_1op_equal(handle, capstone_ppc, &new_instruction, &bcx, ADDRESS)))
						{
							printf("bcx simple different for %08x (new %s/cs %s %s)!\n",
								i, new_mnem, cs_instruction->mnemonic, cs_instruction->op_str);
						}
						break;

					default:
					{
						if (capstone_ppc->op_count != new_instruction.numOperands)
						{
							printf("bcx raw num ops different for %08x (new/cs %ld/%d)\n",
								i, new_instruction.numOperands, capstone_ppc->op_count);
						}

						unsigned int j;
						for (j = 0; j < new_instruction.numOperands; ++j)
						{
							cs_ppc_op* capstone_op = &(capstone_ppc->operands[j]);
							Operand* new_op = &(new_instruction.operands[j]);

							if (!ops_equal(handle, capstone_op, new_op))
							{
								printf("bcx raw op%d for %08x (new %s/cs %s %s)!\n",
									j, i, new_mnem, cs_instruction->mnemonic, cs_instruction->op_str);
							}

						}

						break;
					}
				}

				cs_free(cs_instruction, 1);
				continue;
			}

			case PPC_ID_BCCTRx:
			{
				OperandsList bcctrx;
				FillBcctrxOperands(&bcctrx, &new_instruction);

				uint32_t bo = new_instruction.operands[0].uimm;

				switch (bo & 0x1e)
				{
					case 4:
					case 6:
					case 12:
					case 14:
						if (!(bcregx2_equal(handle, capstone_ppc, &new_instruction, &bcctrx)))
						{
							printf("bcctrx not equal for %08x (new/cs %s/%s %s)\n",
								i, new_mnem, cs_instruction->mnemonic, cs_instruction->op_str);
						}

						break;


					default:
					{
						// invalid for BCCTRx
						if ((bo & 0x4) == 0)
							break;

						// capstone's "branch always" (BO: 1z1zz) is just
						// flat out wrong?
						if ((bo & 0x14) == 0x14)
							break;

						if (capstone_ppc->op_count != new_instruction.numOperands)
						{
							printf("bcctrx raw num ops different for %08x (new/cs %ld/%d)\n",
								i, new_instruction.numOperands, capstone_ppc->op_count);
						}

						unsigned int j;
						for (j = 0; j < new_instruction.numOperands; ++j)
						{
							cs_ppc_op* capstone_op = &(capstone_ppc->operands[j]);
							Operand* new_op = &(new_instruction.operands[j]);

							if (!ops_equal(handle, capstone_op, new_op))
							{
								printf("bcctrx raw op%d for %08x (new %s/cs %s %s)!\n",
									j, i, new_mnem, cs_instruction->mnemonic, cs_instruction->op_str);
							}

						}
					}
				}

				cs_free(cs_instruction, 1);
				continue;
			}

			case PPC_ID_BCLRx:
			{
				OperandsList bclrx;
				FillBclrxOperands(&bclrx, &new_instruction);

				uint32_t bo = new_instruction.operands[0].uimm;

				switch (bo & 0x1e)
				{
					case 0:
					case 2:
					case 8:
					case 10:
						if (!(bcregx1_equal(handle, capstone_ppc, &new_instruction, &bclrx)))
						{
							printf("bcx different for %08x (new %s/cs %s %s)!\n",
								i, new_mnem, cs_instruction->mnemonic, cs_instruction->op_str);
						}
						break;

					case 4:
					case 6:
					case 12:
					case 14:
						if (!(bcregx2_equal(handle, capstone_ppc, &new_instruction, &bclrx)))
						{
							printf("bclrx not equal for %08x (new/cs %s/%s %s)\n",
								i, new_mnem, cs_instruction->mnemonic, cs_instruction->op_str);
						}

						break;

					case 16:
					case 18:
					case 24:
					case 26:
						if (!(bcregx3_equal(handle, capstone_ppc, &new_instruction, &bclrx)))
						{
							printf("bclrx not equal for %08x (new/cs %s/%s %s)\n",
								i, new_mnem, cs_instruction->mnemonic, cs_instruction->op_str);
						}

						break;

					default:
						// capstone's "branch always" is just flat out wrong?
						if ((bo & 0x14) == 0x14)
							break;

						if (capstone_ppc->op_count != new_instruction.numOperands)
						{
							printf("bclrx raw num ops different for %08x (new/cs %ld/%d)\n",
								i, new_instruction.numOperands, capstone_ppc->op_count);
						}

						unsigned int j;
						for (j = 0; j < new_instruction.numOperands; ++j)
						{
							cs_ppc_op* capstone_op = &(capstone_ppc->operands[j]);
							Operand* new_op = &(new_instruction.operands[j]);

							if (!ops_equal(handle, capstone_op, new_op))
							{
								printf("bclrx raw op%d for %08x (new %s/cs %s %s)!\n",
									j, i, new_mnem, cs_instruction->mnemonic, cs_instruction->op_str);
							}

						}
				}

				cs_free(cs_instruction, 1);
				continue;
			}

			default:
				;
		}

		if (capstone_ppc->op_count != new_instruction.numOperands)
		{
			bool complain = true;

			switch (new_instruction.id)
			{
				// capstone seems to think it only has one
				// operand (despite printing 2?)
				case PPC_ID_MFOCRF:
				case PPC_ID_MTOCRF:
					complain = false;
					break;

				// capstone doesn't recognize the 0/1 operand it seems
				case PPC_ID_VSX_XXSPLTD:
					complain = false;
					break;

				case PPC_ID_SLWIx:
				case PPC_ID_SRWIx:
					if (new_instruction.id == PPC_ID_SLWIx && new_instruction.flags.rc && !strcmp(cs_instruction->mnemonic, "rotlwi."))
						complain = false;

					if (new_instruction.flags.rc && !strcmp(cs_instruction->mnemonic, "rlwinm."))
						complain = false;

					break;

				case PPC_ID_CLRRWIx:
					complain = false;
					break;

				// despite printing 3 operands, capstone only thinks there
				// are 2?
				case PPC_ID_SLDIx:
					complain = false;
					break;

				// capstone doesn't recognize rS?
				case PPC_ID_TLBIE:
					complain = false;
					break;

				// we treat "MFSPR" and "MF<some register>" the same,
				// which have different number of arguments
				// (MFSPR rD, UIMM vs. MFxxx rD)
				case PPC_ID_MFSPR:
					complain = false;
					break;

				// we treat "MTSPR" and "MT<some register>" the same,
				// which have different number of arguments
				// (MTSPR UIMM, rS vs. MTxxx rS)
				case PPC_ID_MTSPR:
					complain = false;
					break;

				// capstone treats DCCCI/ICCCI as <op> r0, r0?
				case PPC_ID_DCCCI:
				case PPC_ID_ICCCI:
					complain = false;
					break;

				// we unconditionally use cr0 and only omit it
				// in disassembly
				case PPC_ID_CMPD:
				case PPC_ID_CMPDI:
				case PPC_ID_CMPLD:
				case PPC_ID_CMPLDI:
				case PPC_ID_CMPLW:
				case PPC_ID_CMPLWI:
				case PPC_ID_CMPW:
				case PPC_ID_CMPWI:
					complain = false;
					break;

				// these seem to treat bit 10 as an operand, when
				// v3.0B requires it as a constant 1 in decoding
				case PPC_ID_COPY:
				case PPC_ID_PASTE:
					complain = false;
					break;

				default:
					complain = true;
			}

			if (complain)
			{
				printf("different number of operands for %08x (%s)! CS %d NEW %ld [%s] \n",
					i, new_mnem, capstone_ppc->op_count, new_instruction.numOperands,
					cs_instruction->op_str);
			}

			// we unconditionally finish here since it's not super
			// clear which operands we should compare to which
			cs_free(cs_instruction, 1);
			continue;
		}

		unsigned int j;
		for (j = 0; j < new_instruction.numOperands; ++j)
		{
			cs_ppc_op* capstone_op = &(capstone_ppc->operands[j]);
			Operand* new_op = &(new_instruction.operands[j]);

			switch (new_instruction.id)
			{
				// things we sign extend to 64-bit but capstone
				// doesn't
				case PPC_ID_TDEQI:
				case PPC_ID_TDGTI:
				case PPC_ID_TDLGTI:
				case PPC_ID_TDLLTI:
				case PPC_ID_TDLTI:
				case PPC_ID_TDNEI:
				case PPC_ID_TDUI:
				case PPC_ID_TWEQI:
				case PPC_ID_TWGTI:
				case PPC_ID_TWGEI:
				case PPC_ID_TWLEI:
				case PPC_ID_TWLLEI:
				case PPC_ID_TWLGTI:
				case PPC_ID_TWLLTI:
				case PPC_ID_TWLTI:
				case PPC_ID_TWNEI:
				case PPC_ID_TWUI:
				case PPC_ID_LI:
				case PPC_ID_LIS:
					if (j == 1) continue;
					break;

				// things we sign extend to 64-bit but capstone
				// doesn't
				case PPC_ID_TDI:
				case PPC_ID_TWI:
				case PPC_ID_MULLI:
				case PPC_ID_SUBFIC:
				case PPC_ID_ADDI:
				case PPC_ID_ADDICx:
				case PPC_ID_ADDIS:
				case PPC_ID_TABORTDCI:
				case PPC_ID_TABORTWCI:
					if (j == 2) continue;
					break;

				// capstone sign extends the immediate for some
				// reason
				case PPC_ID_Bx:
					continue;

				// capstone doesn't sign-extend these imms when
				// it should; we also unconditionally decode cr0
				case PPC_ID_CMPDI:
				case PPC_ID_CMPWI:
					if (new_op->cls == PPC_OP_SIMM) continue;
					if (new_op->cls == PPC_OP_REG_CRFD_IMPLY0 && new_op->reg == NUPPC_REG_CRF0) continue;
					break;

				// we unconditionally decode cr0
				case PPC_ID_CMPLDI:
				case PPC_ID_CMPLWI:
					if (new_op->cls == PPC_OP_REG_CRFD_IMPLY0 && new_op->reg == NUPPC_REG_CRF0) continue;
					break;

				// capstone makes operand 3 a register for some
				// reason
				case PPC_ID_ISEL:
					if (j == 3) continue;
					break;

				// capstone doesn't add 0/1 operand
				case PPC_ID_VSX_XXSPLTD:
					if (j == 2) continue;
					break;

				// capstone sometimes uses RA instead of RA|0
				case PPC_ID_LBZCIX:
				case PPC_ID_LDCIX:
				case PPC_ID_LHZCIX:
				case PPC_ID_LWZCIX:
				case PPC_ID_STBCIX:
				case PPC_ID_STDCIX:
				case PPC_ID_STHCIX:
				case PPC_ID_STWCIX:
					if (j == 1)
					{
						if (new_op->cls == PPC_OP_UIMM && new_op->uimm == 0 && capstone_op->type == PPC_OP_REG && capstone_op->reg == PPC_REG_R0)
							continue;
					}
					break;

				// capstone treats these as setting a CR bit (ie cr4+eq), but
				// these instructions clear the rest of the CR field, so it
				// should really be a CR register (ie cr4)
				case PPC_ID_CMPEQB:
				case PPC_ID_CMPRB:
					if (j == 0)
						continue;

					break;

				// capstone seems to swap the "dc" and "dm" bits
				case PPC_ID_VSX_XVTSTDCDP:
				case PPC_ID_VSX_XVTSTDCSP:
					if (j == 2)
						continue;

					break;

				// capstone thinks this is a floating point register
				// (but it could be the weird "altivec/floating point
				// registers and vsx registers are 2 sides of the same
				// coin" thing)
				case PPC_ID_VSX_XSIEXPQP:
					if (j == 2)
						continue;
					break;

				default: ;
			}

			if (!ops_equal(handle, capstone_op, new_op))
			{
				printf("operand %d differs for %08x (%s)!\n",
					j, i, new_mnem);

				break;
			}
		}

		cs_free(cs_instruction, 1);
	}

	return 0;
}
