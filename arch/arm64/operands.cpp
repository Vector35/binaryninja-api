#include "operands.h"

Register OperandRegister(const exarmo_aarch64_operand& operand)
{
	return OperandRegisterAt(operand, 0);
}


Register OperandRegisterAt(const exarmo_aarch64_operand& operand, size_t index)
{
	switch (operand.kind)
	{
	case EXARMO_AARCH64_OPERAND_REG:
		if (index != 0)
			return REG_NONE;
		return ToRegister(operand.reg.reg);
	case EXARMO_AARCH64_OPERAND_MEM:
		if (index == 0)
			return ToRegister(operand.mem.base);
		if (index == 1 && (operand.mem.offset.kind == EXARMO_AARCH64_OFFSET_REG
		                      || operand.mem.offset.kind == EXARMO_AARCH64_OFFSET_VECTOR))
			return ToRegister(operand.mem.offset.reg);
		return REG_NONE;
	case EXARMO_AARCH64_OPERAND_LIST:
		if (index >= operand.list.len)
			return REG_NONE;
		return ToRegister(operand.list.regs[index]);
	default:
		return REG_NONE;
	}
}


int64_t OperandImmediate(const exarmo_aarch64_operand& operand)
{
	return operand.kind == EXARMO_AARCH64_OPERAND_IMM ? (int64_t)operand.imm.value : 0;
}


uint64_t LabelTarget(const exarmo_aarch64_operand& operand, uint64_t addr)
{
	if (operand.kind != EXARMO_AARCH64_OPERAND_LABEL)
		return 0;

	// A64 reads the PC as the instruction's own address, and ADRP names the page the target is
	// in rather than the target.
	const exarmo_aarch64_label& label = operand.label;
	return ((addr + label.pc_ahead) & ~(uint64_t)(label.pc_align - 1)) + label.offset;
}


exarmo_aarch64_modifier OperandModifier(const exarmo_aarch64_operand& operand)
{
	switch (operand.kind)
	{
	case EXARMO_AARCH64_OPERAND_REG:
		return operand.reg.modifier;
	case EXARMO_AARCH64_OPERAND_IMM:
		return operand.imm.modifier;
	case EXARMO_AARCH64_OPERAND_MEM:
		return operand.mem.offset.modifier;
	case EXARMO_AARCH64_OPERAND_MODIFIER:
		return operand.modifier;
	default:
		return exarmo_aarch64_modifier {};
	}
}


exarmo_aarch64_arrangement OperandArrangement(const exarmo_aarch64_operand& operand)
{
	switch (operand.kind)
	{
	case EXARMO_AARCH64_OPERAND_REG:
		return operand.reg.arrangement;
	case EXARMO_AARCH64_OPERAND_LIST:
		return operand.list.arrangement;
	case EXARMO_AARCH64_OPERAND_ZA_SLICE:
		return operand.za_slice.arrangement;
	case EXARMO_AARCH64_OPERAND_MEM:
		return operand.mem.base_arrangement;
	default:
		return exarmo_aarch64_arrangement {};
	}
}


int32_t OperandLaneIndex(const exarmo_aarch64_operand& operand)
{
	switch (operand.kind)
	{
	case EXARMO_AARCH64_OPERAND_REG:
		return operand.reg.index;
	case EXARMO_AARCH64_OPERAND_LIST:
		return operand.list.index;
	default:
		return -1;
	}
}
