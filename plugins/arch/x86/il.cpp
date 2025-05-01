#include <inttypes.h>
#include "il.h"
#include "lowlevelilinstruction.h"
#include "arch_x86_common_architecture.h"

using namespace BinaryNinja;
using namespace std;


static xed_reg_enum_t GetStackPointer(const size_t addrSize)
{
	switch (addrSize)
	{
	case 2:
		return XED_REG_SP;
	case 4:
		return XED_REG_ESP;
	default:
		return XED_REG_RSP;
	}
}


static xed_reg_enum_t GetFramePointer(const size_t addrSize)
{
	switch (addrSize)
	{
	case 2:
		return XED_REG_BP;
	case 4:
		return XED_REG_EBP;
	default:
		return XED_REG_RBP;
	}
}


static xed_reg_enum_t GetCountRegister(const size_t addrSize)
{
	switch (addrSize)
	{
	case 2:
		return XED_REG_CX;
	case 4:
		return XED_REG_ECX;
	default:
		return XED_REG_RCX;
	}
}

//TODO handle imms for MPX args
// For most instructions, instruction_index == operand_index, but some instructions (floating point, some others) have an implicit first operand (st0), so we have to remap things a bit
// Instruction index represents the 'nth' argument/opcode in the instruction, whereas the operand index is index that XED holds that operand in the instruction
static size_t GetILOperandMemoryAddress(LowLevelILFunction& il, const xed_decoded_inst_t* xedd, const uint64_t addr, const size_t instruction_index, const size_t operand_index)
{
	const xed_inst_t*             xi = xed_decoded_inst_inst(xedd);
	const xed_operand_t*          op = xed_inst_operand(xi, (unsigned)operand_index);
	const xed_operand_values_t*   ov = xed_decoded_inst_operands_const(xedd);
	const xed_operand_enum_t op_name = xed_operand_name(op);
	size_t                    offset = BN_INVALID_EXPR;
	const size_t            addrSize = xed_decoded_inst_get_machine_mode_bits(xedd) / 8;

	switch(op_name)
	{
	case XED_OPERAND_AGEN:
 	case XED_OPERAND_MEM0:
	{
		const int64_t disp = xed_decoded_inst_get_memory_displacement(xedd, 0);

		//  [reg] if reg != instruction_pointer
		const xed_reg_enum_t base = xed_decoded_inst_get_base_reg(xedd, 0);
		if ((base != XED_REG_INVALID) && !((base == XED_REG_RIP) || (base == XED_REG_EIP) || (base == XED_REG_IP)))
		{
			offset = il.Register(addrSize, base);
		}
		else if ((base == XED_REG_RIP) || (base == XED_REG_EIP) || (base == XED_REG_IP))  // Resolve RIP to a constant
		{
			if (xed_operand_values_has_memory_displacement(ov) && (disp != 0))
				return il.Operand(instruction_index, il.ConstPointer(addrSize, disp + addr + xed_decoded_inst_get_length(xedd)));
			else
				return il.Operand(instruction_index, il.ConstPointer(addrSize, addr + xed_decoded_inst_get_length(xedd)));
		}

		//  [...+reg] or [...+reg*const] or [reg*const]
		const xed_reg_enum_t index = xed_decoded_inst_get_index_reg(xedd, 0);
		bool constIsPointer = false;
		if (index != XED_REG_INVALID)
			if (!xed_decoded_inst_get_attribute(xedd, XED_ATTRIBUTE_INDEX_REG_IS_POINTER)) // MPX...TODO (extra registers)
			{
				const unsigned int scale = xed_decoded_inst_get_scale(xedd, 0);
				if (scale != 1)
				{
					unsigned short shift = 0;
					if (scale == 2)
						shift = 1;
					else if (scale == 4)
						shift = 2;
					else if (scale == 8)
						shift = 3;
					if (offset != BN_INVALID_EXPR)
						offset = il.Add(addrSize,
									offset,
									il.ShiftLeft(addrSize,
										il.Register(addrSize, index),
										il.Const(1, shift)));
					else
					{
						// case for [...+reg*const] so we know that the const must be a pointer
						constIsPointer = true;
						offset = il.ShiftLeft(addrSize,
									il.Register(addrSize, index),
									il.Const(1, shift));
					}
				}
				else
					if (offset != BN_INVALID_EXPR)
						offset = il.Add(addrSize,
									offset,
									il.Register(addrSize, index));
					else
						offset = il.Register(addrSize, index);
			}

		//  The [...+const] bit or just [const]
		bool isJmpClass = (XED_ICLASS_JMP == xed_decoded_inst_get_iclass(xedd)) || constIsPointer;
		if (xed_operand_values_has_memory_displacement(xed_decoded_inst_operands_const(xedd)) && (disp != 0))
		{
			if (offset != BN_INVALID_EXPR)
				offset = il.Add(addrSize, offset, isJmpClass ? il.ConstPointer(addrSize, disp) : il.Const(addrSize, disp));
			else
				offset = isJmpClass ? il.ConstPointer(addrSize, disp) : il.Const(addrSize, disp);
		}
		else if (xed_operand_values_has_memory_displacement(xed_decoded_inst_operands_const(xedd)) && (disp == 0) && (offset == BN_INVALID_EXPR))
		{
			offset = isJmpClass ? il.ConstPointer(addrSize, disp) : il.Const(addrSize, disp);
		}

		// If there's a non-default segment in use
		xed_reg_enum_t seg = xed_decoded_inst_get_seg_reg(xedd, 0);
		if (seg != XED_REG_INVALID && !xed_operand_values_using_default_segment(ov, 0))
		{
			// Remap FS/GS to FSbase/GSbase respectively
			if (seg == XED_REG_FS)
				seg = XED_REG_FSBASE;
			else if (seg == XED_REG_GS)
				seg = XED_REG_GSBASE;

			if (offset == BN_INVALID_EXPR)  // The only logical path that brings us here with an invalid offset is a disp of 0
				offset = il.Register(addrSize, seg);
			else
				offset = il.Add(addrSize, il.Register(addrSize, seg), offset);
		}

		break;
	}

	case XED_OPERAND_MEM1:
	{
		const xed_reg_enum_t base = xed_decoded_inst_get_base_reg(xedd, 1);
		if (base != XED_REG_INVALID)
		{
			if ((base == XED_REG_RIP) || (base == XED_REG_EIP) || (base == XED_REG_IP))
				offset = il.ConstPointer(addrSize, addr);
			else
				offset = il.Register(addrSize, base);
		}

		xed_reg_enum_t seg = xed_decoded_inst_get_seg_reg(xedd, 1);
		if (seg != XED_REG_INVALID && !xed_operand_values_using_default_segment(ov, 1))
		{
			if (seg == XED_REG_FS)
				seg = XED_REG_FSBASE;
			else if (seg == XED_REG_GS)
				seg = XED_REG_GSBASE;

			offset = il.Add(addrSize,
					 	il.Register(addrSize, seg),
						offset);
		}
		break;
	}

	default:
		LogError("%s not implemented in GetILOperandMemoryAddress at address 0x%" PRIx64 ".", xed_operand_enum_t2str(op_name), addr);
	}

	return il.Operand(instruction_index, offset);
}


// For most instructions, instruction_index == operand_index, but some instructions (floating point, some others) have an implicit first operand (st0), so we have to remap things a bit
// Instruction index represents the 'nth' argument/opcode in the instruction, whereas the operand index is index that XED holds that operand in the instruction
static size_t ReadILOperand(LowLevelILFunction& il, const xed_decoded_inst_t* const xedd,
							const size_t addr, const size_t instruction_index,
							const size_t operand_index, size_t sizeToRead = 0)
{
	if (sizeToRead == 0)
		sizeToRead = xed_decoded_inst_operand_length_bits(xedd, (unsigned)operand_index) / 8;
	const unsigned int immediateSize = xed_decoded_inst_get_operand_width(xedd) / 8;
	const int64_t              relbr = xed_decoded_inst_get_branch_displacement(xedd) + addr + xed_decoded_inst_get_length(xedd);
	const xed_operand_enum_t op_name = xed_operand_name(xed_inst_operand(xed_decoded_inst_inst(xedd), (unsigned)operand_index));
	const auto                  reg1 = xed_decoded_inst_get_reg(xedd, op_name);
	const size_t            addrSize = xed_decoded_inst_get_machine_mode_bits(xedd) / 8;

	switch (op_name)
	{
	// Register cases
	case XED_OPERAND_REG0:
	case XED_OPERAND_REG1:
	case XED_OPERAND_REG2:
	case XED_OPERAND_REG3:
	case XED_OPERAND_REG4:
	case XED_OPERAND_REG5:
	case XED_OPERAND_REG6:
	case XED_OPERAND_REG7:
	case XED_OPERAND_REG8:
	case XED_OPERAND_BASE0:
	case XED_OPERAND_BASE1:
		if ((reg1 == XED_REG_RIP) || (reg1 == XED_REG_EIP) || (reg1 == XED_REG_IP))
			return il.Operand(instruction_index, il.ConstPointer(sizeToRead, addr));
		return il.Operand(instruction_index, il.Register(sizeToRead, (uint32_t)reg1));

	// Immediates:
	case XED_OPERAND_IMM0:
		if (xed_decoded_inst_get_immediate_is_signed(xedd))
			return il.Operand(instruction_index, il.Const(immediateSize, xed_decoded_inst_get_signed_immediate(xedd)));
		else
			return il.Operand(instruction_index, il.Const(immediateSize, xed_decoded_inst_get_unsigned_immediate(xedd)));

	// Second Immdiate Value
	case XED_OPERAND_IMM1:
		return il.Operand(instruction_index, il.Const(1, xed_decoded_inst_get_second_immediate(xedd)));

	// Immediate Address Value
	case XED_OPERAND_PTR:
	case XED_OPERAND_RELBR:
		return il.Operand(instruction_index, il.ConstPointer(addrSize, relbr));

	// Memory Acesses
	case XED_OPERAND_AGEN:
	case XED_OPERAND_MEM0:
	case XED_OPERAND_MEM1:
		return il.Operand(instruction_index, il.Load(sizeToRead, GetILOperandMemoryAddress(il, xedd, addr, instruction_index, operand_index)));

	// Not implimented or error
	default:
		return il.Undefined();
	}
}


// For most instructions, instruction_index == operand_index, but some instructions (floating point, some others) have an implicit first operand (st0), so we have to remap things a bit
// Instruction index represents the 'nth' argument/opcode in the instruction, whereas the operand index is index that XED holds that operand in the instruction
static size_t ReadFloatILOperand(LowLevelILFunction& il, const xed_decoded_inst_t* xedd, const size_t addr, const size_t instruction_index, const size_t operand_index, size_t opLen = 10)
{
	const unsigned int   operandSize = xed_decoded_inst_operand_length_bits(xedd, (unsigned)operand_index) / 8;
	const xed_operand_enum_t op_name = xed_operand_name(xed_inst_operand(xed_decoded_inst_inst(xedd), (unsigned)operand_index));

	switch (op_name)
	{
	// Register cases
	case XED_OPERAND_REG0:
	case XED_OPERAND_REG1:
	case XED_OPERAND_REG2:
	case XED_OPERAND_REG3:
	case XED_OPERAND_REG4:
	case XED_OPERAND_REG5:
	case XED_OPERAND_REG6:
	case XED_OPERAND_REG7:
	case XED_OPERAND_REG8:
	case XED_OPERAND_BASE0:
	case XED_OPERAND_BASE1:
		return il.Operand(instruction_index, il.Register(operandSize, (uint32_t)xed_decoded_inst_get_reg(xedd, op_name)));

	// Immediates
	case XED_OPERAND_IMM0:
	case XED_OPERAND_PTR:
	case XED_OPERAND_RELBR:
		if (xed_decoded_inst_get_immediate_is_signed(xedd))
			return il.Operand(instruction_index, il.FloatConvert(opLen, il.FloatConstRaw(operandSize, xed_decoded_inst_get_signed_immediate(xedd))));
		else
			return il.Operand(instruction_index, il.FloatConvert(opLen, il.FloatConstRaw(operandSize, xed_decoded_inst_get_unsigned_immediate(xedd))));
	case XED_OPERAND_IMM1:
		return il.Operand(instruction_index, il.FloatConvert(opLen, il.FloatConstRaw(operandSize, xed_decoded_inst_get_second_immediate(xedd))));

	// Memory Acesses
	case XED_OPERAND_AGEN:
	case XED_OPERAND_MEM0:
	case XED_OPERAND_MEM1:  // In what case would the memory address size be 10?? (floating point ops?)
		if (operandSize != opLen)
			return il.Operand(instruction_index, il.FloatConvert(opLen, il.Load(operandSize, GetILOperandMemoryAddress(il, xedd, addr, instruction_index, operand_index))));
		return il.Operand(instruction_index, il.Load(opLen, GetILOperandMemoryAddress(il, xedd, addr, instruction_index, operand_index)));

	default:
		return il.Undefined();
	}
}


// For most instructions, instruction_index == operand_index, but some instructions (floating point, some others) have an implicit first operand (st0), so we have to remap things a bit
// Instruction index represents the 'nth' argument/opcode in the instruction, whereas the operand index is index that XED holds that operand in the instruction
static size_t WriteILOperand(LowLevelILFunction& il, const xed_decoded_inst_t* const xedd, const size_t addr,
							const size_t instruction_index, const size_t operand_index,
							const size_t value, size_t sizeToWrite = 0)
{
	// sizeToWrite allows one to specify a part of the operand to write
	// other than the whole
	// this solves some of the problems we have; but not all
	// we still need the ability to read and write a slice of the operand
	if (sizeToWrite == 0)
		sizeToWrite = xed_decoded_inst_operand_length(xedd, operand_index);

	const xed_operand_enum_t op_name = xed_operand_name(xed_inst_operand(xed_decoded_inst_inst(xedd), operand_index));

	switch (op_name)
	{
	// Register cases
	case XED_OPERAND_REG0:
	case XED_OPERAND_REG1:
	case XED_OPERAND_REG2:
	case XED_OPERAND_REG3:
	case XED_OPERAND_REG4:
	case XED_OPERAND_REG5:
	case XED_OPERAND_REG6:
	case XED_OPERAND_REG7:
	case XED_OPERAND_REG8:
	case XED_OPERAND_BASE0:
	case XED_OPERAND_BASE1:
		return il.Operand(instruction_index, il.SetRegister(sizeToWrite, xed_decoded_inst_get_reg(xedd, op_name), value));

	// Memory Accesses
	case XED_OPERAND_AGEN:
	case XED_OPERAND_MEM0:
	case XED_OPERAND_MEM1:
		return il.Operand(instruction_index, il.Store(sizeToWrite, GetILOperandMemoryAddress(il, xedd, addr, instruction_index, operand_index), value));

	default:
		return il.Undefined();
	}
}


static void ConditionalJump(Architecture* arch, LowLevelILFunction& il, size_t cond, size_t addrSize, uint64_t t, uint64_t f)
{
	BNLowLevelILLabel* trueLabel = il.GetLabelForAddress(arch, t);
	BNLowLevelILLabel* falseLabel = il.GetLabelForAddress(arch, f);

	if (trueLabel && falseLabel)
	{
		il.AddInstruction(il.If(cond, *trueLabel, *falseLabel));
		return;
	}

	LowLevelILLabel trueCode, falseCode;

	if (trueLabel)
	{
		il.AddInstruction(il.If(cond, *trueLabel, falseCode));
		il.MarkLabel(falseCode);
		il.AddInstruction(il.Jump(il.ConstPointer(addrSize, f)));
		return;
	}

	if (falseLabel)
	{
		il.AddInstruction(il.If(cond, trueCode, *falseLabel));
		il.MarkLabel(trueCode);
		il.AddInstruction(il.Jump(il.ConstPointer(addrSize, t)));
		return;
	}

	il.AddInstruction(il.If(cond, trueCode, falseCode));
	il.MarkLabel(trueCode);
	il.AddInstruction(il.Jump(il.ConstPointer(addrSize, t)));
	il.MarkLabel(falseCode);
	il.AddInstruction(il.Jump(il.ConstPointer(addrSize, f)));
}


static void DirFlagIf(LowLevelILFunction& il,
	std::function<void()> addPreTestIl,
	std::function<void()> addDirFlagSetIl,
	std::function<void()> addDirFlagClearIl)
{
	LowLevelILLabel dirFlagSet, dirFlagClear, dirFlagDone;

	addPreTestIl();

	il.AddInstruction(il.If(il.Flag(IL_FLAG_D), dirFlagSet, dirFlagClear));
	il.MarkLabel(dirFlagSet);

	addDirFlagSetIl();

	il.AddInstruction(il.Goto(dirFlagDone));
	il.MarkLabel(dirFlagClear);

	addDirFlagClearIl();

	il.AddInstruction(il.Goto(dirFlagDone));
	il.MarkLabel(dirFlagDone);
}


static void Repeat(
	const xed_decoded_inst_t* const xedd,
	LowLevelILFunction& il,
	std::function<void ()> addil)
{
	const size_t addrSize = xed_decoded_inst_get_machine_mode_bits(xedd) / 8;
	LowLevelILLabel trueLabel, falseLabel, doneLabel;
	const xed_operand_values_t* const ov = xed_decoded_inst_operands_const(xedd);

	if (xed_operand_values_has_real_rep(ov))
	{
		il.AddInstruction(il.Goto(trueLabel));
		il.MarkLabel(trueLabel);
		il.AddInstruction(il.If(
			il.CompareNotEqual(addrSize,
				il.Register(addrSize, GetCountRegister(addrSize)),
				il.Const(addrSize, 0)), falseLabel, doneLabel));
		il.MarkLabel(falseLabel);
	}

	addil();

	if (xed_operand_values_has_real_rep(ov))
	{
		il.AddInstruction(
			il.SetRegister(addrSize,
				GetCountRegister(addrSize),
				il.Sub(addrSize,
					il.Register(addrSize, GetCountRegister(addrSize)),
					il.Const(addrSize, 1))));

		const xed_iclass_enum_t xeddiClass = xed_decoded_inst_get_iclass(xedd);
		if (xed_operand_values_has_repne_prefix(ov))
			il.AddInstruction(il.If(il.FlagCondition(LLFC_NE), trueLabel, doneLabel));
		else if (xed_repe_map(xed_norep_map(xeddiClass)) == xeddiClass)
			il.AddInstruction(il.If(il.FlagCondition(LLFC_E), trueLabel, doneLabel));
		else
			il.AddInstruction(il.Goto(trueLabel));
		il.MarkLabel(doneLabel);
	}
}


static void CMovFlagCond(const int64_t addr, const xed_decoded_inst_t* xedd, LowLevelILFunction& il, BNLowLevelILFlagCondition flag)
{
	// keep the true branch but let the false branch goto doneLabel directly
	LowLevelILLabel trueLabel, doneLabel;

	il.AddInstruction(
		il.If(
			il.FlagCondition(flag),
		trueLabel, doneLabel));

	il.MarkLabel(trueLabel);

	il.AddInstruction(
		WriteILOperand(il, xedd, addr, 0, 0,
			ReadILOperand(il, xedd, addr, 1, 1)));

	il.AddInstruction(il.Goto(doneLabel));
	il.MarkLabel(doneLabel);
}


static void CMovFlagGroup(const int64_t addr, const xed_decoded_inst_t* xedd, LowLevelILFunction& il, uint32_t flag)
{
	// keep the true branch but let the false branch goto doneLabel directly
	LowLevelILLabel trueLabel, doneLabel;

	il.AddInstruction(
		il.If(
			il.FlagGroup(flag),
			trueLabel, doneLabel
		)
	);

	il.MarkLabel(trueLabel);

	il.AddInstruction(
		WriteILOperand(il, xedd, addr, 0, 0,
			ReadILOperand(il, xedd, addr, 1, 1)));

	il.AddInstruction(il.Goto(doneLabel));
	il.MarkLabel(doneLabel);
}


bool GetLowLevelILForInstruction(Architecture* arch, const uint64_t addr, LowLevelILFunction& il, const xed_decoded_inst_t* const xedd)
{
	LowLevelILLabel trueLabel, falseLabel, doneLabel, dirFlagSet, dirFlagClear, dirFlagDone, startLabel;
	LowLevelILLabel trueLabel2, falseLabel2;

    const xed_iclass_enum_t 		xedd_iClass = xed_decoded_inst_get_iclass(xedd);
    const xed_iform_enum_t   		xedd_iForm = xed_decoded_inst_get_iform_enum(xedd);
    const xed_inst_t* const			xi = xed_decoded_inst_inst(xedd);
	// const xed_operand_values_t* const ov = xed_decoded_inst_operands_const(xedd);
    const unsigned short        	instLen = xed_decoded_inst_get_length(xedd);
	// mode_bits can be used to determine whether the current instruciton is in 16/32/64 bit mode
	const size_t                	mode_bits = xed_decoded_inst_get_machine_mode_bits(xedd);
	const size_t                	addrSize = mode_bits / 8;

    const unsigned short			opOneLen = xed_decoded_inst_operand_length_bits(xedd, 0) / 8;
    const unsigned short			opTwoLen = xed_decoded_inst_operand_length_bits(xedd, 1) / 8;
    [[maybe_unused]] const unsigned short
									opTreLen = xed_decoded_inst_operand_length_bits(xedd, 2) / 8;
    const xed_operand_t* const    	opOne = xed_inst_operand(xi, 0);
    const xed_operand_t* const    	opTwo = xed_inst_operand(xi, 1);
	// this is problematic as operand three may or may not exist at all
	// latest version of xed will complain about this
    const xed_operand_t* const    	opTre = xed_inst_operand(xi, 2);
    const xed_operand_enum_t 		opOne_name = xed_operand_name(opOne);
    const xed_operand_enum_t 		opTwo_name = xed_operand_name(opTwo);
    const xed_operand_enum_t 		opTre_name = xed_operand_name(opTre);
	const xed_reg_enum_t         	regOne = xed_decoded_inst_get_reg(xedd, opOne_name);
	const xed_reg_enum_t         	regTwo = xed_decoded_inst_get_reg(xedd, opTwo_name);
	// const xed_reg_enum_t         regTre = xed_decoded_inst_get_reg(xedd, opTre_name);
	// const xed_reg_enum_t       	baseReg1 = xed_decoded_inst_get_base_reg(xedd, 0);
	// const xed_reg_enum_t       	baseReg2 = xed_decoded_inst_get_base_reg(xedd, 1);
	const xed_reg_enum_t        	segReg1 = xed_decoded_inst_get_seg_reg (xedd, 0);
	// const xed_reg_enum_t        	segReg2 = xed_decoded_inst_get_seg_reg (xedd, 1);

    const uint64_t         			immediateOne = xed_decoded_inst_get_unsigned_immediate(xedd);
 	const int64_t     				branchDestination = xed_decoded_inst_get_branch_displacement(xedd) + addr + instLen;

	auto LiftAsIntrinsic = [& il, xi, xedd, addr, xedd_iForm] () mutable {

		typedef struct
		{
			uint32_t index;
			size_t width;
		} MemoryOperandWriteInfo;

		vector<RegisterOrFlag> outputs = {};
		vector<ExprId> parameters = {};
		size_t noperands = xed_inst_noperands(xi);
		vector<MemoryOperandWriteInfo> memoryOperandWrites = {};
		size_t numTempRegUsed = 0;
		for (uint32_t i = 0; i < noperands; i++)
		{
			const xed_operand_t* op = xed_inst_operand(xi, i);
			xed_operand_enum_t op_name = xed_operand_name(op);
			if (xed_operand_written(op))
			{
				switch(op_name)
				{
				case XED_OPERAND_REG0:
				case XED_OPERAND_REG1:
				case XED_OPERAND_REG2:
				case XED_OPERAND_REG3:
				case XED_OPERAND_REG4:
				case XED_OPERAND_REG5:
				case XED_OPERAND_REG6:
				case XED_OPERAND_REG7:
				case XED_OPERAND_REG8:
				case XED_OPERAND_BASE0:
				case XED_OPERAND_BASE1:
				{
					xed_reg_enum_t r = xed_decoded_inst_get_reg(xedd, op_name);
					outputs.push_back(RegisterOrFlag::Register(r));
					break;
				}
				default:
					// The intrinsic system can only accept registers or flags as outputs,
					// since it might be strange to write to an arbitrary ExprId.
					// In order to handle intrinsics that write to memory, we create a temp IL register and
					// later generate another il intrustion to write the register value to the memory
					// An example of this is:
					// 	vmovss  dword [eax], k1, xmm0 (bytes: 6762f17e091100)
					// which lifts to:
					// temp0 = _mm_mask_store_ss(k1, xmm0)
					// [eax.q].d = temp0.d
					// Note, however, it is quite rare for an intrinsic to write to memory
					size_t operandWidth = (xed_decoded_inst_operand_length_bits(xedd, i) + 7) >> 3;
					memoryOperandWrites.push_back({i, operandWidth});
					outputs.push_back(RegisterOrFlag::Register(LLIL_TEMP(numTempRegUsed)));
					numTempRegUsed++;
					break;
				}
			}
			if (xed_operand_read(op))
			{
				switch(op_name)
				{
				case XED_OPERAND_REG0:
				case XED_OPERAND_REG1:
				case XED_OPERAND_REG2:
				case XED_OPERAND_REG3:
				case XED_OPERAND_REG4:
				case XED_OPERAND_REG5:
				case XED_OPERAND_REG6:
				case XED_OPERAND_REG7:
				case XED_OPERAND_REG8:
				case XED_OPERAND_BASE0:
				case XED_OPERAND_BASE1:
				{
					// XED includes some things that are not actual registers in
					// xed_reg_enum_t. We'll just omit those special cases here.
					xed_reg_enum_t r = xed_decoded_inst_get_reg(xedd, op_name);
					switch(r)
					{
					case XED_REG_INVALID:
					case XED_REG_MSRS:
					case XED_REG_STACKPUSH:
					case XED_REG_STACKPOP:
					case XED_REG_ERROR:
					case XED_REG_LAST:
						continue;
					default:
						break;
					}
				}
				default:
					break;
				}

				parameters.push_back(ReadILOperand(il, xedd, addr, i, i));
			}
		}
		X86_INTRINSIC intrinsic = (X86_INTRINSIC)(xedd_iForm + 1000);
		il.AddInstruction(il.Intrinsic(outputs, intrinsic, parameters));
		// Generate IL instruction for memory writes
		for (size_t i = 0; i < memoryOperandWrites.size(); i++)
		{
			uint32_t operand = memoryOperandWrites[i].index;
			size_t openradWidth = memoryOperandWrites[i].width;
			il.AddInstruction(WriteILOperand(il, xedd, addr, operand, operand,
				il.Register(openradWidth, LLIL_TEMP(i))));
		}
	};

	switch (xedd_iClass)
	{
	case XED_ICLASS_ADC_LOCK: // TODO: Add Lock construct
	case XED_ICLASS_ADC:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.AddCarry(opOneLen,
					ReadILOperand(il, xedd, addr, 0, 0),
					ReadILOperand(il, xedd, addr, 1, 1),
				il.Flag(IL_FLAG_C), IL_FLAGWRITE_ALL)));
		break;

	case XED_ICLASS_ADCX:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.AddCarry(opOneLen,
					ReadILOperand(il, xedd, addr, 0, 0),
					ReadILOperand(il, xedd, addr, 1, 1),
				il.Flag(IL_FLAG_C), IL_FLAG_C)));
		break;

	case XED_ICLASS_ADOX:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.AddCarry(opOneLen,
					ReadILOperand(il, xedd, addr, 0, 0),
					ReadILOperand(il, xedd, addr, 1, 1),
				il.Flag(IL_FLAG_O), IL_FLAG_O)));
		break;

	case XED_ICLASS_ADD_LOCK: // TODO: Add Lock construct
	case XED_ICLASS_ADD:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
			il.Add(opOneLen,
				ReadILOperand(il, xedd, addr, 0, 0),
				ReadILOperand(il, xedd, addr, 1, 1),
			IL_FLAGWRITE_ALL)));
		break;

	case XED_ICLASS_AND_LOCK: // TODO: Add Lock construct
	case XED_ICLASS_AND:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.And(opOneLen,
					ReadILOperand(il, xedd, addr, 0, 0),
					ReadILOperand(il, xedd, addr, 1, 1),
					IL_FLAGWRITE_ALL)));
		break;
	case XED_ICLASS_PAND:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.And(opOneLen,
					ReadILOperand(il, xedd, addr, 0, 0),
					ReadILOperand(il, xedd, addr, 1, 1),
				0))); // PAND doesn't modify any flag.
		break;

	case XED_ICLASS_VPAND:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.And(opOneLen,
					ReadILOperand(il, xedd, addr, 1, 1),
					ReadILOperand(il, xedd, addr, 2, 2),
				0))); // VPAND doesn't modify any flag
		break;

	case XED_ICLASS_ANDN:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.And(opOneLen,
					ReadILOperand(il, xedd, addr, 0, 0),
					il.Not(
						opTwoLen,
						ReadILOperand(il, xedd, addr, 1, 1)
					),
					IL_FLAGWRITE_ALL)));
		break;
	case XED_ICLASS_PANDN:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.And(opOneLen,
					ReadILOperand(il, xedd, addr, 0, 0),
					il.Not(
						opTwoLen,
						ReadILOperand(il, xedd, addr, 1, 1)
					),
					0))); // Does not affect flags
		break;
	case XED_ICLASS_VPANDN:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.And(opOneLen,
					ReadILOperand(il, xedd, addr, 1, 1),
					il.Not(
						opTwoLen,
						ReadILOperand(il, xedd, addr, 2, 2)
					),
				IL_FLAGWRITE_ALL)));
		break;

	case XED_ICLASS_BT:
		il.AddInstruction(il.SetFlag(IL_FLAG_C,
			il.TestBit(opOneLen,
				ReadILOperand(il, xedd, addr, 0, 0),
				ReadILOperand(il, xedd, addr, 1, 1))));
		break;

	case XED_ICLASS_BTC_LOCK:
	case XED_ICLASS_BTC:
		// TODO: Handle lock prefix
		il.AddInstruction(il.SetFlag(IL_FLAG_C,
			il.TestBit(opOneLen,
				ReadILOperand(il, xedd, addr, 0, 0),
				ReadILOperand(il, xedd, addr, 1, 1))));

		// Complement the bit specified by operand[1] in operand[0]
		// operand[0] = operand[0] ^ (1 << operand[1])
		// or in the case operand[1] is a register
		// operand[0] = operand[0] ^ (1 << (operand[1] % operand[0].size))

        if (opTwo_name == XED_OPERAND_IMM0)
        {
            il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0,
                il.Xor(opOneLen,
                    ReadILOperand(il, xedd, addr, 0, 0),
                    il.ShiftLeft(opOneLen,
                        il.Const(opOneLen, 1),
                            ReadILOperand(il, xedd, addr, 1, 1)))));
        }
        else
        {
            il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0,
                il.Xor(opOneLen,
                    ReadILOperand(il, xedd, addr, 0, 0),
                    il.ShiftLeft(opOneLen,
                        il.Const(opOneLen, 1),
                            il.ModUnsigned(opTwoLen,
                                ReadILOperand(il, xedd, addr, 1, 1),
                                il.Const(1, opOneLen * 8))))));
        }

		break;

	case XED_ICLASS_BTR_LOCK:
	case XED_ICLASS_BTR:
		// TODO: Handle lock prefix
		il.AddInstruction(il.SetFlag(IL_FLAG_C,
			il.TestBit(opOneLen,
				ReadILOperand(il, xedd, addr, 0, 0),
				ReadILOperand(il, xedd, addr, 1, 1))));

		// Reset the bit specified by operand[1] in operand[0]
		// operand[0] = operand[0] & ~(1 << operand[1])
		// or in the case operand[1] is a register
		// operand[0] = operand[0] & ~(1 << (operand[1] % operand[0].size))
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0,
			il.And(opOneLen,
				ReadILOperand(il, xedd, addr, 0, 0),
				il.Not(opOneLen,
					il.ShiftLeft(opOneLen,
						il.Const(opOneLen, 1),
						(opTwo_name == XED_OPERAND_IMM0) ?
							ReadILOperand(il, xedd, addr, 1, 1) :
							il.ModUnsigned(opTwoLen,
								ReadILOperand(il, xedd, addr, 1, 1),
								il.Const(1, opOneLen * 8)))))));
		break;

	case XED_ICLASS_BTS_LOCK:
	case XED_ICLASS_BTS:
		// TODO: Handle lock prefix
		il.AddInstruction(il.SetFlag(IL_FLAG_C,
			il.TestBit(opOneLen,
				ReadILOperand(il, xedd, addr, 0, 0),
				ReadILOperand(il, xedd, addr, 1, 1))));

		// Complement the bit specified by operand[1] in operand[0]
		// operand[0] = operand[0] | (1 << operand[1])
		// or in the case operand[1] is a register
		// operand[0] = operand[0] | (1 << (operand[1] % operand[0].size))
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0,
			il.Or(opOneLen,
				ReadILOperand(il, xedd, addr, 0, 0),
				il.ShiftLeft(opOneLen,
					il.Const(opOneLen, 1),
					(opTwo_name == XED_OPERAND_IMM0) ?
						ReadILOperand(il, xedd, addr, 1, 1) :
						il.ModUnsigned(opTwoLen,
							ReadILOperand(il, xedd, addr, 1, 1),
							il.Const(1, opOneLen * 8))))));
		break;

	case XED_ICLASS_ADDSS:
	{
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0,
			il.FloatAdd(4,
				ReadFloatILOperand(il, xedd, addr, 0, 0, 4),
				ReadFloatILOperand(il, xedd, addr, 1, 1, 4)
			)));
		break;
	}

	case XED_ICLASS_VADDSS:
	{
		if (xed_classify_avx512(xedd))
		{
			LiftAsIntrinsic();
			break;
		}
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0,
			il.FloatAdd(4,
				ReadFloatILOperand(il, xedd, addr, 1, 1, 4),
				ReadFloatILOperand(il, xedd, addr, 2, 2, 4)
			)));
		break;
	}

	case XED_ICLASS_ADDSD:
	{
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0,
			il.FloatAdd(8,
				ReadFloatILOperand(il, xedd, addr, 0, 0, 8),
				ReadFloatILOperand(il, xedd, addr, 1, 1, 8)
			)));
		break;
	}

	case XED_ICLASS_VADDSD:
	{
		if (xed_classify_avx512(xedd))
		{
			LiftAsIntrinsic();
			break;
		}
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0,
			il.FloatAdd(8,
				ReadFloatILOperand(il, xedd, addr, 1, 1, 8),
				ReadFloatILOperand(il, xedd, addr, 2, 2, 8)
			)));
		break;
	}

	case XED_ICLASS_SUBSS:
	{
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0,
			il.FloatSub(4,
				ReadFloatILOperand(il, xedd, addr, 0, 0, 4),
				ReadFloatILOperand(il, xedd, addr, 1, 1, 4)
			)));
		break;
	}

	case XED_ICLASS_VSUBSS:
	{
		if (xed_classify_avx512(xedd))
		{
			LiftAsIntrinsic();
			break;
		}
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0,
			il.FloatSub(4,
				ReadFloatILOperand(il, xedd, addr, 1, 1, 4),
				ReadFloatILOperand(il, xedd, addr, 2, 2, 4)
			)));
		break;
	}

	case XED_ICLASS_SUBSD:
	{
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0,
			il.FloatSub(8,
				ReadFloatILOperand(il, xedd, addr, 0, 0, 8),
				ReadFloatILOperand(il, xedd, addr, 1, 1, 8)
			)));
		break;
	}

	case XED_ICLASS_VSUBSD:
	{
		if (xed_classify_avx512(xedd))
		{
			LiftAsIntrinsic();
			break;
		}
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0,
			il.FloatSub(8,
				ReadFloatILOperand(il, xedd, addr, 1, 1, 8),
				ReadFloatILOperand(il, xedd, addr, 2, 2, 8
			)))
		);
		break;
	}

	case XED_ICLASS_MULSS:
	{
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0,
			il.FloatMult(4,
				ReadFloatILOperand(il, xedd, addr, 0, 0, 4),
				ReadFloatILOperand(il, xedd, addr, 1, 1, 4)
			)));
		break;
	}

	case XED_ICLASS_VMULSS:
	{
		if (xed_classify_avx512(xedd))
		{
			LiftAsIntrinsic();
			break;
		}
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0,
			il.FloatMult(4,
				ReadFloatILOperand(il, xedd, addr, 1, 1, 4),
				ReadFloatILOperand(il, xedd, addr, 2, 2, 4)
			)));
		break;
	}

	case XED_ICLASS_MULSD:
	{
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0,
			il.FloatMult(8,
				ReadFloatILOperand(il, xedd, addr, 0, 0, 8),
				ReadFloatILOperand(il, xedd, addr, 1, 1, 8)
			)));
		break;
	}

	case XED_ICLASS_VMULSD:
	{
		if (xed_classify_avx512(xedd))
		{
			LiftAsIntrinsic();
			break;
		}
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0,
			il.FloatMult(8,
				ReadFloatILOperand(il, xedd, addr, 1, 1, 8),
				ReadFloatILOperand(il, xedd, addr, 2, 2, 8)
			)));
		break;
	}

	case XED_ICLASS_DIVSS:
	{
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0,
			il.FloatDiv(4,
				ReadFloatILOperand(il, xedd, addr, 0, 0, 4),
				ReadFloatILOperand(il, xedd, addr, 1, 1, 4)
			)));
		break;
	}

	case XED_ICLASS_VDIVSS:
	{
		if (xed_classify_avx512(xedd))
		{
			LiftAsIntrinsic();
			break;
		}
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0,
			il.FloatDiv(4,
				ReadFloatILOperand(il, xedd, addr, 1, 1, 4),
				ReadFloatILOperand(il, xedd, addr, 2, 2, 4)
			)));
		break;
	}

	case XED_ICLASS_DIVSD:
	{
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0,
			il.FloatDiv(8,
				ReadFloatILOperand(il, xedd, addr, 0, 0, 8),
				ReadFloatILOperand(il, xedd, addr, 1, 1, 8)
			)));
		break;
	}

	case XED_ICLASS_VDIVSD:
	{
		if (xed_classify_avx512(xedd))
		{
			LiftAsIntrinsic();
			break;
		}
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0,
			il.FloatDiv(8,
				ReadFloatILOperand(il, xedd, addr, 1, 1, 8),
				ReadFloatILOperand(il, xedd, addr, 2, 2, 8)
			)));
		break;
	}

	case XED_ICLASS_LDMXCSR:
	case XED_ICLASS_VLDMXCSR:
	{
		il.AddInstruction(
			il.SetRegister(4, XED_REG_MXCSR,
				ReadILOperand(il, xedd, addr, 0, 0)
			)
		);
		break;
	}

	case XED_ICLASS_STMXCSR:
	case XED_ICLASS_VSTMXCSR:
	{
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.Register(4, XED_REG_MXCSR)
			)
		);
		break;
	}

	case XED_ICLASS_CVTSI2SS:
	{
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.IntToFloat(4,
					ReadILOperand(il, xedd, addr, 1, 1)
				)
			)
		);
		break;
	}

	case XED_ICLASS_VCVTSI2SS:
	{
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				ReadILOperand(il, xedd, addr, 1, 1)
			)
		);
		il.AddInstruction(
			il.SetRegister(4, regOne,
				il.IntToFloat(4,
					ReadILOperand(il, xedd, addr, 2, 2)
				)
			)
		);
		break;
	}

	case XED_ICLASS_CVTSI2SD:
	{
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.IntToFloat(8,
					ReadILOperand(il, xedd, addr, 1, 1)
				)
			)
		);
		break;
	}

	case XED_ICLASS_VCVTSI2SD:
	{
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				ReadILOperand(il, xedd, addr, 1, 1)
			)
		);
		il.AddInstruction(
			il.SetRegister(8, regOne,
				il.IntToFloat(8,
					ReadILOperand(il, xedd, addr, 2, 2)
				)
			)
		);
		break;
	}

	case XED_ICLASS_CVTSS2SI:
	case XED_ICLASS_VCVTSS2SI:
	case XED_ICLASS_CVTSD2SI:
	case XED_ICLASS_VCVTSD2SI:
	{
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.FloatToInt(opOneLen,
					ReadFloatILOperand(il, xedd, addr, 1, 1)
				)
			)
		);
		break;
	}

	case XED_ICLASS_CVTTSD2SI:
	case XED_ICLASS_CVTTSS2SI:
	case XED_ICLASS_VCVTTSD2SI:
	case XED_ICLASS_VCVTTSS2SI:
	{
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.FloatToInt(opOneLen,
					ReadFloatILOperand(il, xedd, addr, 1, 1)
				)
			)
		);
		break;
	}

	case XED_ICLASS_CVTSS2SD:
	case XED_ICLASS_CVTSD2SS:
	{
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.FloatConvert(opOneLen,
					ReadFloatILOperand(il, xedd, addr, 1, 1)
				)
			)
		);
		break;
	}

	case XED_ICLASS_VCVTSS2SD:
	{
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				ReadILOperand(il, xedd, addr, 1, 1)
			)
		);
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.FloatConvert(8,
					ReadFloatILOperand(il, xedd, addr, 2, 2)
				),
				8
			)
		);
		break;
	}

	case XED_ICLASS_VCVTSD2SS:
	{
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				ReadILOperand(il, xedd, addr, 1, 1)
			)
		);
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.FloatConvert(4,
					ReadFloatILOperand(il, xedd, addr, 2, 2)
				),
				4
			)
		);
		break;
	}

	case XED_ICLASS_XLAT:
	{
		il.AddInstruction(
			il.SetRegister(
				1, XED_REG_AL,
				// the operand 0 is the MEM being read
				ReadILOperand(il, xedd, addr, 0, 0)
			)
		);
		break;
	}

	// This is a workaround to stop the type propagator from
	// making integers of size 576, which is mostly wrong
	// However, if we do implement these, it will in turn
	// cause problems with parameter resolution
	// So as for now, unimplemented is the best solution
	case XED_ICLASS_XRSTOR:
	case XED_ICLASS_XRSTOR64:
	case XED_ICLASS_XRSTORS:
	case XED_ICLASS_XRSTORS64:
	case XED_ICLASS_XSAVE:
	case XED_ICLASS_XSAVE64:
	case XED_ICLASS_XSAVEC:
	case XED_ICLASS_XSAVEC64:
	case XED_ICLASS_XSAVEOPT:
	case XED_ICLASS_XSAVEOPT64:
	case XED_ICLASS_XSAVES:
	case XED_ICLASS_XSAVES64:
		il.AddInstruction(il.Unimplemented());
		break;

	case XED_ICLASS_CALL_NEAR:
	case XED_ICLASS_CALL_FAR:
		if (
		   ((xedd_iForm == XED_IFORM_CALL_FAR_MEMp2) || (xedd_iForm == XED_IFORM_CALL_NEAR_MEMv)) &&
			(immediateOne == 0x10) &&
			(opOneLen == 4) &&
			(segReg1 == XED_REG_GS))
		{
			// Linux indirect system call (call dword [gs:0x10])
			// TODO: Implement this as a platform-specific lifting extension when such a thing
			// is possible
			il.AddInstruction(il.SystemCall());
			break;
		}

		// Turn 'call next' into a push
		if (((uint64_t)branchDestination == addr+instLen) && ((xedd_iForm == XED_IFORM_CALL_NEAR_RELBRz) || (xedd_iForm == XED_IFORM_CALL_NEAR_RELBRd)))
		{
			il.AddInstruction(
				il.Push(addrSize,
					il.ConstPointer(addrSize, addr + instLen)));
		}
		else
		{
			il.AddInstruction(
				il.Call(
					ReadILOperand(il, xedd, addr, 0, 0)));
		}
		break;

	case XED_ICLASS_CBW:
		il.AddInstruction(il.SetRegister(2, XED_REG_AX, il.SignExtend(2, il.Register(1, XED_REG_AL))));
		break;

	case XED_ICLASS_CDQ:
		il.AddInstruction(il.SetRegisterSplit(4, XED_REG_EDX, XED_REG_EAX, il.SignExtend(8, il.Register(4, XED_REG_EAX))));
		break;

	case XED_ICLASS_CLC:
		il.AddInstruction(il.SetFlag(IL_FLAG_C, il.Const(1, 0)));
		break;

	case XED_ICLASS_CLD:
		il.AddInstruction(il.SetFlag(IL_FLAG_D, il.Const(1, 0)));
		break;

	case XED_ICLASS_CMC:
		il.AddInstruction(il.SetFlag(IL_FLAG_C, il.Xor(1, il.Flag(IL_FLAG_C), il.Const(1, 1))));
		break;

	case XED_ICLASS_CMOVO:
		CMovFlagCond(addr, xedd, il, LLFC_O);
		break;

	case XED_ICLASS_CMOVNO:
		CMovFlagCond(addr, xedd, il, LLFC_NO);
		break;

	case XED_ICLASS_CMOVB:
	case XED_ICLASS_FCMOVB:
		CMovFlagGroup(addr, xedd, il, IL_FLAG_GROUP_LT);
		break;

	case XED_ICLASS_CMOVNB:
	case XED_ICLASS_FCMOVNB:
		CMovFlagGroup(addr, xedd, il, IL_FLAG_GROUP_GE);
		break;

	case XED_ICLASS_CMOVZ:
	case XED_ICLASS_FCMOVE:
		CMovFlagGroup(addr, xedd, il, IL_FLAG_GROUP_E);
		break;

	case XED_ICLASS_CMOVNZ:
	case XED_ICLASS_FCMOVNE:
		CMovFlagGroup(addr, xedd, il, IL_FLAG_GROUP_NE);
		break;

	case XED_ICLASS_CMOVBE:
	case XED_ICLASS_FCMOVBE:
		CMovFlagGroup(addr, xedd, il, IL_FLAG_GROUP_LE);
		break;

	case XED_ICLASS_CMOVNBE:
	case XED_ICLASS_FCMOVNBE:
		CMovFlagGroup(addr, xedd, il, IL_FLAG_GROUP_GT);
		break;

	case XED_ICLASS_CMOVS:
		CMovFlagCond(addr, xedd, il, LLFC_NEG);
		break;

	case XED_ICLASS_CMOVNS:
		CMovFlagCond(addr, xedd, il, LLFC_POS);
		break;

	case XED_ICLASS_CMOVP:
	case XED_ICLASS_FCMOVU:
		CMovFlagGroup(addr, xedd, il, IL_FLAG_GROUP_PE);
		break;

	case XED_ICLASS_CMOVNP:
	case XED_ICLASS_FCMOVNU:
		CMovFlagGroup(addr, xedd, il, IL_FLAG_GROUP_PO);
		break;

	case XED_ICLASS_CMOVL:
		CMovFlagCond(addr, xedd, il, LLFC_SLT);
		break;

	case XED_ICLASS_CMOVNL:
		CMovFlagCond(addr, xedd, il, LLFC_SGE);
		break;

	case XED_ICLASS_CMOVLE:
		CMovFlagCond(addr, xedd, il, LLFC_SLE);
		break;

	case XED_ICLASS_CMOVNLE:
		CMovFlagCond(addr, xedd, il, LLFC_SGT);
		break;

	case XED_ICLASS_CMP:
		il.AddInstruction(
			il.Sub(opOneLen,
				ReadILOperand(il, xedd, addr, 0, 0),
				ReadILOperand(il, xedd, addr, 1, 1),
			IL_FLAGWRITE_ALL));
		break;

	case XED_ICLASS_REPE_CMPSQ:
	case XED_ICLASS_REPNE_CMPSQ:
	case XED_ICLASS_CMPSQ:
	case XED_ICLASS_REPE_CMPSD:
	case XED_ICLASS_REPNE_CMPSD:
	case XED_ICLASS_CMPSD:
	case XED_ICLASS_REPE_CMPSW:
	case XED_ICLASS_REPNE_CMPSW:
	case XED_ICLASS_CMPSW:
	case XED_ICLASS_REPE_CMPSB:
	case XED_ICLASS_REPNE_CMPSB:
	case XED_ICLASS_CMPSB:
	{
		size_t argSize = 1;
		uint32_t srcReg = addrSize == 4 ? XED_REG_ESI : XED_REG_RSI;
		uint32_t dstReg = addrSize == 4 ? XED_REG_EDI : XED_REG_RDI;
		switch (xedd_iClass)
		{
		case XED_ICLASS_REPE_CMPSB:
		case XED_ICLASS_REPNE_CMPSB:
		case XED_ICLASS_CMPSB:
			argSize = 1;
			break;
		case XED_ICLASS_REPE_CMPSW:
		case XED_ICLASS_REPNE_CMPSW:
		case XED_ICLASS_CMPSW:
			argSize = 2;
			break;
		case XED_ICLASS_REPE_CMPSD:
		case XED_ICLASS_REPNE_CMPSD:
		case XED_ICLASS_CMPSD:
			argSize = 4;
			break;
		case XED_ICLASS_REPE_CMPSQ:
		case XED_ICLASS_REPNE_CMPSQ:
		case XED_ICLASS_CMPSQ:
			argSize = 8;
			break;
		default:
			break;
		}

		Repeat(xedd, il, [&] (){
			DirFlagIf(il,
				[&] ()
				{
					il.AddInstruction(il.Sub(argSize, il.Load(argSize, il.Register(addrSize, srcReg)), il.Load(argSize, il.Register(addrSize, dstReg)), IL_FLAGWRITE_ALL));
				},
				[&] () // Dirflag is 1
				{
					il.AddInstruction(il.SetRegister(addrSize, srcReg, il.Sub(addrSize, il.Register(addrSize, srcReg), il.Const(1, argSize))));
					il.AddInstruction(il.SetRegister(addrSize, dstReg, il.Sub(addrSize, il.Register(addrSize, dstReg), il.Const(1, argSize))));
				},
				[&] () // Dirflag is 0
				{
					il.AddInstruction(il.SetRegister(addrSize, srcReg, il.Add(addrSize, il.Register(addrSize, srcReg), il.Const(1, argSize))));
					il.AddInstruction(il.SetRegister(addrSize, dstReg, il.Add(addrSize, il.Register(addrSize, dstReg), il.Const(1, argSize))));
				});
		});
		break;
	}

	case XED_ICLASS_PALIGNR:
	{
		// the immediate for palignr is smaller than 32
		u_char nshiftBytes = (u_char)xed_decoded_inst_get_unsigned_immediate(xedd);
		size_t nShiftBits = 8 * nshiftBytes;
		size_t regSize = opOneLen;
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.Or(regSize,
					il.LogicalShiftRight(regSize, ReadILOperand(il, xedd, addr, 1, 1), il.Const(1, nShiftBits)),
					il.ShiftLeft(regSize,
						ReadILOperand(il, xedd, addr, 0, 0),
						il.Const(1, 8 * (regSize - nshiftBytes))
					)
				)
			)
		);
		break;
	}
	case XED_ICLASS_VPALIGNR:
	{
		if (xed_classify_avx512(xedd))
		{
			LiftAsIntrinsic();
			break;
		}
		// the immediate for palignr is smaller than 32
		u_char nshiftBytes = (u_char)xed_decoded_inst_get_unsigned_immediate(xedd);
		size_t nShiftBits = 8 * nshiftBytes;
		size_t regSize = opOneLen;
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.Or(regSize,
					il.LogicalShiftRight(regSize, ReadILOperand(il, xedd, addr, 2, 2), il.Const(1, nShiftBits)),
					il.ShiftLeft(regSize,
						ReadILOperand(il, xedd, addr, 1, 1),
						il.Const(1, 8 * (regSize - nshiftBytes))
					)
				)
			)
		);
		break;
	}

	case XED_ICLASS_CQO:
		il.AddInstruction(il.SetRegisterSplit(8, XED_REG_RDX, XED_REG_RAX, il.SignExtend(16, il.Register(8, XED_REG_RAX))));
		break;

	case XED_ICLASS_CWD:
		il.AddInstruction(il.SetRegisterSplit(2, XED_REG_DX, XED_REG_AX, il.SignExtend(4, il.Register(2, XED_REG_AX))));
		break;

	case XED_ICLASS_CWDE:
		il.AddInstruction(il.SetRegister(4, XED_REG_EAX, il.SignExtend(4, il.Register(2, XED_REG_AX))));
		break;

	case XED_ICLASS_CDQE:
		il.AddInstruction(il.SetRegister(8, XED_REG_RAX, il.SignExtend(8, il.Register(4, XED_REG_EAX))));
		break;

	case XED_ICLASS_DEC_LOCK: // TODO: Handle lock prefix
	case XED_ICLASS_DEC:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.Sub(opOneLen,
					ReadILOperand(il, xedd, addr, 0, 0),
					il.Const(opOneLen, 1),
				IL_FLAGWRITE_NOCARRY)
			)
		);
		break;

	case XED_ICLASS_DIV:
		il.AddInstruction(
			il.SetRegister(opOneLen,
				LLIL_TEMP(2),
				ReadILOperand(il, xedd, addr, 0, 0)));

		switch (opOneLen)
		{
		case 1:
			il.AddInstruction(
				il.SetRegister(1,
					LLIL_TEMP(0),
					il.DivDoublePrecUnsigned(1,
						il.Register(2, XED_REG_AX),
						il.Register(opOneLen, LLIL_TEMP(2)))));

			il.AddInstruction(il.SetRegister(1,
				LLIL_TEMP(1),
				il.ModDoublePrecUnsigned(1,
					il.Register(2, XED_REG_AX),
					il.Register(opOneLen, LLIL_TEMP(2)))));

			il.AddInstruction(
				il.SetRegister(1,
					XED_REG_AL,
					il.Register(1, LLIL_TEMP(0))));

			il.AddInstruction(
				il.SetRegister(1,
					XED_REG_AH,
					il.Register(1, LLIL_TEMP(1))));
			break;

		case 2:
			il.AddInstruction(
				il.SetRegister(2,
					LLIL_TEMP(0),
					il.DivDoublePrecUnsigned(2,
						il.RegisterSplit(2,
							XED_REG_DX,
							XED_REG_AX),
						il.Register(opOneLen, LLIL_TEMP(2)))));

			il.AddInstruction(
				il.SetRegister(2,
					LLIL_TEMP(1),
					il.ModDoublePrecUnsigned(2,
						il.RegisterSplit(2,
							XED_REG_DX,
							XED_REG_AX),
						il.Register(opOneLen, LLIL_TEMP(2)))));

			il.AddInstruction(
				il.SetRegister(2,
					XED_REG_AX,
					il.Register(2, LLIL_TEMP(0))));

			il.AddInstruction(
				il.SetRegister(2,
					XED_REG_DX,
					il.Register(2, LLIL_TEMP(1))));
			break;

		case 4:
			il.AddInstruction(
				il.SetRegister(4,
					LLIL_TEMP(0),
					il.DivDoublePrecUnsigned(4,
						il.RegisterSplit(4,
							XED_REG_EDX,
							XED_REG_EAX),
						il.Register(opOneLen, LLIL_TEMP(2)))));

			il.AddInstruction(
				il.SetRegister(4,
					LLIL_TEMP(1),
					il.ModDoublePrecUnsigned(4,
						il.RegisterSplit(4,
							XED_REG_EDX,
							XED_REG_EAX),
						il.Register(opOneLen, LLIL_TEMP(2)))));

			il.AddInstruction(
				il.SetRegister(4,
					XED_REG_EAX,
					il.Register(4, LLIL_TEMP(0))));

			il.AddInstruction(
				il.SetRegister(4,
					XED_REG_EDX,
					il.Register(4, LLIL_TEMP(1))));
			break;

		case 8:
			il.AddInstruction(il.SetRegister(8,
				LLIL_TEMP(0),
				il.DivDoublePrecUnsigned(8,
					il.RegisterSplit(8,
						XED_REG_RDX,
						XED_REG_RAX),
					il.Register(opOneLen, LLIL_TEMP(2)))));

			il.AddInstruction(
				il.SetRegister(8,
					LLIL_TEMP(1),
					il.ModDoublePrecUnsigned(8,
						il.RegisterSplit(8,
							XED_REG_RDX,
							XED_REG_RAX),
						il.Register(opOneLen, LLIL_TEMP(2)))));

			il.AddInstruction(
				il.SetRegister(8,
					XED_REG_RAX,
					il.Register(8, LLIL_TEMP(0))));

			il.AddInstruction(
				il.SetRegister(8,
					XED_REG_RDX,
					il.Register(8, LLIL_TEMP(1))));
			break;

		default:
			il.AddInstruction(il.Undefined());
			break;
		}
		break;

	case XED_ICLASS_ENTER:
	{
		uint32_t baseReg = addrSize == 4 ? XED_REG_EBP : XED_REG_RBP;
		uint32_t stackReg = addrSize == 4 ? XED_REG_ESP : XED_REG_RSP;
		if (xed_decoded_inst_get_second_immediate(xedd) != 0)
		{
			il.AddInstruction(il.Unimplemented());
			break;
		}
		il.AddInstruction(il.Push(addrSize, il.Register(addrSize, baseReg)));
		il.AddInstruction(il.SetRegister(addrSize, baseReg, il.Register(addrSize, stackReg)));
		if (immediateOne)
			il.AddInstruction(il.SetRegister(addrSize, stackReg,
				il.Sub(addrSize,
					il.Register(addrSize, stackReg),
					il.Const(2, immediateOne))));
		break;
	}

	case XED_ICLASS_IDIV:
		switch (opOneLen)
		{
		case 1:
			il.AddInstruction(il.SetRegister(1,
				LLIL_TEMP(0),
				il.DivDoublePrecSigned(1,
					il.Register(2, XED_REG_AX),
					ReadILOperand(il, xedd, addr, 0, 0))));

			il.AddInstruction(il.SetRegister(1,
				LLIL_TEMP(1),
				il.ModDoublePrecSigned(1,
					il.Register(2, XED_REG_AX),
					ReadILOperand(il, xedd, addr, 0, 0))));

			il.AddInstruction(
				il.SetRegister(1,
					XED_REG_AL,
					il.Register(1, LLIL_TEMP(0))));

			il.AddInstruction(
				il.SetRegister(1,
					XED_REG_AH,
					il.Register(1, LLIL_TEMP(1))));
			break;

		case 2:
			il.AddInstruction(
				il.SetRegister(2,
					LLIL_TEMP(0),
					il.DivDoublePrecSigned(2,
						il.RegisterSplit(2,
							XED_REG_DX,
							XED_REG_AX),
						ReadILOperand(il, xedd, addr, 0, 0))));

			il.AddInstruction(
				il.SetRegister(2,
					LLIL_TEMP(1),
					il.ModDoublePrecSigned(2,
						il.RegisterSplit(2,
							XED_REG_DX,
							XED_REG_AX),
						ReadILOperand(il, xedd, addr, 0, 0))));

			il.AddInstruction(
				il.SetRegister(2,
					XED_REG_AX,
					il.Register(2, LLIL_TEMP(0))));

			il.AddInstruction(
				il.SetRegister(2,
					XED_REG_DX,
					il.Register(2, LLIL_TEMP(1))));
			break;

		case 4:
			il.AddInstruction(il.SetRegister(4,
				LLIL_TEMP(0),
				il.DivDoublePrecSigned(4,
					il.RegisterSplit(4,
						XED_REG_EDX,
						XED_REG_EAX),
					ReadILOperand(il, xedd, addr, 0, 0))));

			il.AddInstruction(
				il.SetRegister(4,
					LLIL_TEMP(1),
					il.ModDoublePrecSigned(4,
						il.RegisterSplit(4,
							XED_REG_EDX,
							XED_REG_EAX),
						ReadILOperand(il, xedd, addr, 0, 0))));

			il.AddInstruction(
				il.SetRegister(4,
					XED_REG_EAX,
					il.Register(4, LLIL_TEMP(0))));

			il.AddInstruction(
				il.SetRegister(4,
					XED_REG_EDX,
					il.Register(4, LLIL_TEMP(1))));
			break;

		case 8:
			il.AddInstruction(
				il.SetRegister(8,
					LLIL_TEMP(0),
					il.DivDoublePrecSigned(8,
						il.RegisterSplit(8,
							XED_REG_RDX,
							XED_REG_RAX),
						ReadILOperand(il, xedd, addr, 0, 0))));

			il.AddInstruction(
				il.SetRegister(8,
					LLIL_TEMP(1),
					il.ModDoublePrecSigned(8,
						il.RegisterSplit(8,
							XED_REG_RDX,
							XED_REG_RAX),
						ReadILOperand(il, xedd, addr, 0, 0))));

			il.AddInstruction(
				il.SetRegister(8,
					XED_REG_RAX,
					il.Register(8, LLIL_TEMP(0))));

			il.AddInstruction(
				il.SetRegister(8,
					XED_REG_RDX,
					il.Register(8, LLIL_TEMP(1))));
			break;

		default:
			il.AddInstruction(il.Undefined());
			break;
		}
		break;

	case XED_ICLASS_IMUL:
		switch (xedd_iForm)
		{
		case XED_IFORM_IMUL_GPR8:
		case XED_IFORM_IMUL_GPRv:
		case XED_IFORM_IMUL_MEMb:
		case XED_IFORM_IMUL_MEMv:
			switch (opOneLen)
			{
			case 1:
				il.AddInstruction(
					il.SetRegister(2,
						XED_REG_AX,
						il.MultDoublePrecSigned(1,
							il.Register(1, XED_REG_AL),
							ReadILOperand(il, xedd, addr, 0, 0),
						IL_FLAGWRITE_CO)));
				break;
			case 2:
				il.AddInstruction(
					il.SetRegisterSplit(2,
						XED_REG_DX,
						XED_REG_AX,
						il.MultDoublePrecSigned(2,
							il.Register(2, XED_REG_AX),
							ReadILOperand(il, xedd, addr, 0, 0),
						IL_FLAGWRITE_CO)));
				break;
			case 4:
				il.AddInstruction(
					il.SetRegisterSplit(4,
						XED_REG_EDX,
						XED_REG_EAX,
						il.MultDoublePrecSigned(4,
							il.Register(4, XED_REG_EAX),
							ReadILOperand(il, xedd, addr, 0, 0),
						IL_FLAGWRITE_CO)));
				break;
			case 8:
				il.AddInstruction(
					il.SetRegisterSplit(8,
						XED_REG_RDX,
						XED_REG_RAX,
						il.MultDoublePrecSigned(8,
							il.Register(8, XED_REG_RAX),
							ReadILOperand(il, xedd, addr, 0, 0),
						IL_FLAGWRITE_CO)));
				break;
			default:
				il.AddInstruction(il.Undefined());
				break;
			}
			break;

  	case XED_IFORM_IMUL_GPRv_GPRv:
  	case XED_IFORM_IMUL_GPRv_MEMv:
			il.AddInstruction(
				WriteILOperand(il, xedd, addr, 0, 0,
					il.Mult(opOneLen,
						ReadILOperand(il, xedd, addr, 0, 0),
						ReadILOperand(il, xedd, addr, 1, 1),
					IL_FLAGWRITE_CO)));
			break;

  	case XED_IFORM_IMUL_GPRv_GPRv_IMMb:
  	case XED_IFORM_IMUL_GPRv_GPRv_IMMz:
  	case XED_IFORM_IMUL_GPRv_MEMv_IMMb:
  	case XED_IFORM_IMUL_GPRv_MEMv_IMMz:
		default:
			il.AddInstruction(
				WriteILOperand(il, xedd, addr, 0, 0,
					il.Mult(opOneLen,
						ReadILOperand(il, xedd, addr, 1, 1),
						ReadILOperand(il, xedd, addr, 2, 2),
					IL_FLAGWRITE_CO)));
		}
		break;


	case XED_ICLASS_INC_LOCK: // TODO: Handle lock prefix
	case XED_ICLASS_INC:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.Add(opOneLen,
					ReadILOperand(il, xedd, addr, 0, 0),
					il.Const(opOneLen, 1),
				IL_FLAGWRITE_NOCARRY)));
		break;

	case XED_ICLASS_INT:
		switch (immediateOne)
		{
			case 0x29:
				il.AddInstruction(il.Trap(TRAP_GPF));
				break;
			case 0x80:
				il.AddInstruction(il.SystemCall());
				break;
			default:
				il.AddInstruction(il.Trap(immediateOne));
				break;
		}
		break;

	case XED_ICLASS_INT3:
		il.AddInstruction(il.Breakpoint());
		break;

	case XED_ICLASS_JMP:
		if (opOne_name == XED_OPERAND_RELBR)
		{
			BNLowLevelILLabel* label = il.GetLabelForAddress(arch, branchDestination);
			if (label)
				il.AddInstruction(il.Goto(*label));
			else
				il.AddInstruction(il.Jump(il.ConstPointer(addrSize, branchDestination)));
		}
		else
			il.AddInstruction(il.Jump(ReadILOperand(il, xedd, addr, 0, 0)));
		return false;

	case XED_ICLASS_JO:
		ConditionalJump(arch, il, il.FlagCondition(LLFC_O), addrSize, branchDestination, addr + instLen);
		return false;

	case XED_ICLASS_JNO:
		ConditionalJump(arch, il, il.FlagCondition(LLFC_NO), addrSize, branchDestination, addr + instLen);
		return false;

	case XED_ICLASS_JB:
		ConditionalJump(arch, il, il.FlagGroup(IL_FLAG_GROUP_LT), addrSize, branchDestination, addr + instLen);
		return false;

	case XED_ICLASS_JNB:
		ConditionalJump(arch, il, il.FlagGroup(IL_FLAG_GROUP_GE), addrSize, branchDestination, addr + instLen);
		return false;

	case XED_ICLASS_JZ:
		ConditionalJump(arch, il, il.FlagGroup(IL_FLAG_GROUP_E), addrSize, branchDestination, addr + instLen);
		return false;

	case XED_ICLASS_JNZ:
		ConditionalJump(arch, il, il.FlagGroup(IL_FLAG_GROUP_NE), addrSize, branchDestination, addr + instLen);
		return false;

	case XED_ICLASS_JBE:
		ConditionalJump(arch, il, il.FlagGroup(IL_FLAG_GROUP_LE), addrSize, branchDestination, addr + instLen);
		return false;

	case XED_ICLASS_JNBE:
		ConditionalJump(arch, il, il.FlagGroup(IL_FLAG_GROUP_GT), addrSize, branchDestination, addr + instLen);
		return false;

	case XED_ICLASS_JS:
		ConditionalJump(arch, il, il.FlagCondition(LLFC_NEG), addrSize, branchDestination, addr + instLen);
		return false;

	case XED_ICLASS_JNS:
		ConditionalJump(arch, il, il.FlagCondition(LLFC_POS), addrSize, branchDestination, addr + instLen);
		return false;

	case XED_ICLASS_JP:
		ConditionalJump(arch, il, il.FlagGroup(IL_FLAG_GROUP_PE), addrSize, branchDestination, addr + instLen);
		return false;

	case XED_ICLASS_JNP:
		ConditionalJump(arch, il, il.FlagGroup(IL_FLAG_GROUP_PO), addrSize, branchDestination, addr + instLen);
		return false;

	case XED_ICLASS_JL:
		ConditionalJump(arch, il, il.FlagCondition(LLFC_SLT), addrSize, branchDestination, addr + instLen);
		return false;

	case XED_ICLASS_JNL:
		ConditionalJump(arch, il, il.FlagCondition(LLFC_SGE), addrSize, branchDestination, addr + instLen);
		return false;

	case XED_ICLASS_JLE:
		ConditionalJump(arch, il, il.FlagCondition(LLFC_SLE), addrSize, branchDestination, addr + instLen);
		return false;

	case XED_ICLASS_JNLE:
		ConditionalJump(arch, il, il.FlagCondition(LLFC_SGT), addrSize, branchDestination, addr + instLen);
		return false;

	case XED_ICLASS_JCXZ:
		ConditionalJump(arch, il, il.CompareEqual(2, il.Register(2, XED_REG_CX), il.Const(2, 0)), addrSize, branchDestination, addr + instLen);
		return false;

	case XED_ICLASS_JECXZ:
		ConditionalJump(arch, il, il.CompareEqual(4, il.Register(4, XED_REG_ECX), il.Const(4, 0)), addrSize, branchDestination, addr + instLen);
		return false;

	case XED_ICLASS_JRCXZ:
		ConditionalJump(arch, il, il.CompareEqual(8, il.Register(8, XED_REG_RCX), il.Const(8, 0)), addrSize, branchDestination, addr + instLen);
		return false;

	case XED_ICLASS_LAHF:
		il.AddInstruction(il.SetRegister(1, XED_REG_AH,
			il.Or(1, il.FlagBit(1, IL_FLAG_S, 7),
			il.Or(1, il.FlagBit(1, IL_FLAG_Z, 6),
			il.Or(1, il.FlagBit(1, IL_FLAG_A, 4),
			il.Or(1, il.FlagBit(1, IL_FLAG_P, 2), il.FlagBit(1, IL_FLAG_C, 0)))))));
		break;

	case XED_ICLASS_LEAVE:
		il.AddInstruction(
			il.SetRegister(addrSize,
				GetStackPointer(addrSize),
				il.Register(addrSize, GetFramePointer(addrSize))));

		il.AddInstruction(
			il.SetRegister(addrSize,
				GetFramePointer(addrSize),
				il.Pop(addrSize)));
		break;

	case XED_ICLASS_LOOP:
		if (addrSize == 4)
		{
			il.AddInstruction(il.SetRegister(4, XED_REG_ECX, il.Sub(4, il.Register(4, XED_REG_ECX), il.Const(4, 1))));
			ConditionalJump(arch, il,
				il.CompareNotEqual(4,
					il.Register(4, XED_REG_ECX),
					il.Const(4, 0)),
				addrSize, branchDestination, addr + instLen);
		}
		else
		{
			il.AddInstruction(il.SetRegister(8, XED_REG_RCX, il.Sub(8, il.Register(8, XED_REG_RCX), il.Const(8, 1))));
			ConditionalJump(arch, il,
				il.CompareNotEqual(8,
					il.Register(8, XED_REG_RCX),
					il.Const(8, 0)),
				addrSize, branchDestination, addr + instLen);
		}
		return false;

	case XED_ICLASS_LOOPE:
		if (addrSize == 4)
		{
			il.AddInstruction(il.SetRegister(4, XED_REG_ECX, il.Sub(4, il.Register(4, XED_REG_ECX), il.Const(4, 1))));
			ConditionalJump(arch, il,
				il.Or(0,
					il.FlagGroup(IL_FLAG_GROUP_E),
					il.CompareNotEqual(4,
						il.Register(4, XED_REG_ECX),
						il.Const(4, 0))),
				addrSize, branchDestination, addr + instLen);
		}
		else
		{
			il.AddInstruction(il.SetRegister(8, XED_REG_RCX, il.Sub(8, il.Register(8, XED_REG_RCX), il.Const(8, 1))));
			ConditionalJump(arch, il,
				il.Or(0,
					il.FlagGroup(IL_FLAG_GROUP_E),
					il.CompareNotEqual(8,
						il.Register(8, XED_REG_RCX),
						il.Const(8, 0))),
				addrSize, branchDestination, addr + instLen);
		}
		return false;

	case XED_ICLASS_LOOPNE:
		if (addrSize == 4)
		{
			il.AddInstruction(il.SetRegister(4, XED_REG_ECX, il.Sub(4, il.Register(4, XED_REG_ECX), il.Const(4, 1))));
			ConditionalJump(arch, il,
				il.And(0,
					il.FlagGroup(IL_FLAG_GROUP_NE),
					il.CompareNotEqual(4,
						il.Register(4, XED_REG_ECX),
						il.Const(4, 0))),
				addrSize, branchDestination, addr + instLen);
		}
		else
		{
			il.AddInstruction(il.SetRegister(8, XED_REG_RCX, il.Sub(8, il.Register(8, XED_REG_RCX), il.Const(8, 1))));
			ConditionalJump(arch, il,
				il.And(0,
					il.FlagGroup(IL_FLAG_GROUP_NE),
					il.CompareNotEqual(8,
						il.Register(8, XED_REG_RCX),
						il.Const(8, 0))),
				addrSize, branchDestination, addr + instLen);
		}
		return false;

	case XED_ICLASS_LEA:
		if (opOneLen != opTwoLen)
		{
			il.AddInstruction(
				WriteILOperand(il, xedd, addr, 0, 0,
					il.LowPart(opOneLen,
						GetILOperandMemoryAddress(il, xedd, addr, 1, 1))));
		}
		else
		{
			il.AddInstruction(
				WriteILOperand(il, xedd, addr, 0, 0,
					GetILOperandMemoryAddress(il, xedd, addr, 1, 1)));
		}
		break;

	case XED_ICLASS_REP_LODSB:
	case XED_ICLASS_REP_LODSD:
	case XED_ICLASS_REP_LODSQ:
	case XED_ICLASS_REP_LODSW:
	case XED_ICLASS_LODSB:
	case XED_ICLASS_LODSW:
	case XED_ICLASS_LODSD:
	case XED_ICLASS_LODSQ:
	{
		size_t loadSize;
		uint32_t dstReg;
		uint32_t srcReg = addrSize == 4 ? XED_REG_ESI : XED_REG_RSI;
		switch (xedd_iClass)
		{
		case XED_ICLASS_LODSW:
		case XED_ICLASS_REP_LODSW:
			loadSize = 2; dstReg = XED_REG_AX; break;
		case XED_ICLASS_LODSD:
		case XED_ICLASS_REP_LODSD:
			loadSize = 4; dstReg = XED_REG_EAX; break;
		case XED_ICLASS_LODSQ:
		case XED_ICLASS_REP_LODSQ:
			loadSize = 8; dstReg = XED_REG_RAX; break;
		case XED_ICLASS_REP_LODSB:
		default:
			loadSize = 1; dstReg = XED_REG_AL;
		}

		Repeat(xedd, il, [&] (){
			DirFlagIf(il,
				[&] ()
				{
					il.AddInstruction(il.SetRegister(loadSize, dstReg, il.Load(loadSize, il.Register(addrSize, srcReg))));
				},
				[&] () // Dirflag is 1
				{
					il.AddInstruction(il.SetRegister(addrSize, srcReg, il.Sub(addrSize, il.Register(addrSize, srcReg), il.Const(1, loadSize))));
				},
				[&] () // Dirflag is 0
				{
					il.AddInstruction(il.SetRegister(addrSize, srcReg, il.Add(addrSize, il.Register(addrSize, srcReg), il.Const(1, loadSize))));
				});
		});
		break;
	}

	case XED_ICLASS_MOV:
			il.AddInstruction(
				WriteILOperand(il, xedd, addr, 0, 0,
					ReadILOperand(il, xedd, addr, 1, 1)));
		break;

	case XED_ICLASS_MOVD:
	case XED_ICLASS_MOVQ:
	case XED_ICLASS_VMOVD:
	case XED_ICLASS_VMOVQ:
	case XED_ICLASS_MOVDIRI:
		if (opOneLen > opTwoLen)
		{
			// This may add unneeded zero-extends, but MLIL will optimize them out
			il.AddInstruction(
				WriteILOperand(il, xedd, addr, 0, 0,
					il.ZeroExtend(opOneLen,
						ReadILOperand(il, xedd, addr, 1, 1, opTwoLen)),
				opOneLen));
		}
		else
		{
			il.AddInstruction(
				WriteILOperand(il, xedd, addr, 0, 0,
					ReadILOperand(il, xedd, addr, 1, 1, opTwoLen),
				opOneLen));
		}
		break;

	case XED_ICLASS_MOVDIR64B:
		// Special case:
		// Moves 64-bytes as direct-store with 64-byte write atomicity from source memory address to destination memory address.
		// The source operand is a normal memory operand. The destination operand is a memory location specified in a general-purpose register.
		// ...
		// MOVDIR64B requires the destination address to be 64-byte aligned. No alignment restriction is enforced for source operand.
		//
		// Lifting to the intrinsic is still semantically inaccurate, but we don't currently have a way to represent atomic writes:
		// movdir64b rax, zmmword [rbx]
		//
		// temp0 = _movdir64b(rax, [rbx].64, rax)
		// [rax].64 = temp0.64
		LiftAsIntrinsic();
		break;

	case XED_ICLASS_MOVSX:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.SignExtend(opOneLen,
					ReadILOperand(il, xedd, addr, 1, 1))));
		break;

	case XED_ICLASS_MOVSXD:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.SignExtend(opOneLen,
					ReadILOperand(il, xedd, addr, 1, 1))));
		break;

	case XED_ICLASS_MOVZX:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.ZeroExtend(opOneLen,
					ReadILOperand(il, xedd, addr, 1, 1))));
		break;

	case XED_ICLASS_MOVUPS:
	case XED_ICLASS_MOVAPS:
	case XED_ICLASS_MOVDQA:
	case XED_ICLASS_MOVDQU:
	case XED_ICLASS_VMOVUPS:
	case XED_ICLASS_VMOVAPS:
	case XED_ICLASS_VMOVDQA:
	case XED_ICLASS_VMOVDQU:
	case XED_ICLASS_LDDQU:
	case XED_ICLASS_MOVAPD:
	case XED_ICLASS_VMOVAPD:
	case XED_ICLASS_MOVUPD:
	case XED_ICLASS_VMOVUPD:
	{
		if (xed_classify_avx512(xedd))
		{
			LiftAsIntrinsic();
			break;
		}
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0, ReadILOperand(il, xedd, addr, 1, 1)));
		break;
	}

	// despite MOVSS and VMOVSS both move floating point values,
	// the move is the same as an ordinary move
	case XED_ICLASS_MOVSS:
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0, ReadILOperand(il, xedd, addr, 1, 1)));
		break;

	case XED_ICLASS_VMOVSS:
	{
		uint32_t noperands = xed_inst_noperands(xi);
		if (noperands == 2)
			// nothing special here
			il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0, ReadILOperand(il, xedd, addr, 1, 1)));
		else
		{
			if (xed_classify_avx512(xedd))
			{
				LiftAsIntrinsic();
				break;
			}
			// the three operands form
			// DEST[31:0] <- SRC2[31:0]
			// DEST[127:32] <- SRC1[127:32]
			// DEST[MAXVL-1:128] <- 0
			il.AddInstruction(
				WriteILOperand(il, xedd, addr, 0, 0,
					il.And(4, ReadILOperand(il, xedd, addr, 2, 2), il.Const(4, 0xffffffff))
				)
			);
			// il.Const() only supports constant up to uint64_t so far so I cannot use this mask
			// here I first shift right and then shift left
			// __uint128_t mask = (__uint128_t)0xffffffffffffffffffffffff00000000;
			il.AddInstruction(
				WriteILOperand(il, xedd, addr, 0, 0,
					il.Or(opOneLen,
						ReadILOperand(il, xedd, addr, 0, 0),
						il.ShiftLeft(
							opOneLen,
							il.LogicalShiftRight(opOneLen,
								ReadFloatILOperand(il, xedd, addr, 1, 1, opOneLen),
								// vmovss ONLY suppors xmm, so we do not need to branch on operand size
								il.Const(1, 32)
							),
							il.Const(1, 32)
						)
					)
				)
			);
		}
		break;
	}

	case XED_ICLASS_MOVNTDQ:
	case XED_ICLASS_MOVNTDQA:
	case XED_ICLASS_MOVNTI:
	case XED_ICLASS_MOVNTPD:
	case XED_ICLASS_MOVNTPS:
	case XED_ICLASS_MOVNTQ:
	case XED_ICLASS_MOVNTSD:
	case XED_ICLASS_MOVNTSS:

	case XED_ICLASS_VMOVNTDQ:
	case XED_ICLASS_VMOVNTDQA:
	case XED_ICLASS_VMOVNTPD:
	case XED_ICLASS_VMOVNTPS:

		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0, ReadILOperand(il, xedd, addr, 1, 1)));
		break;

	case XED_ICLASS_MOVLPD:
	case XED_ICLASS_MOVLPS:
	case XED_ICLASS_VMOVLPD:
	case XED_ICLASS_VMOVLPS:
	{
		if (xed_inst_noperands(xi) == 2)
		{
			// MOVLPD xmm1, m64
			// VMOVLPD m64, xmm1
			// DEST[63:0] ← SRC[63:0]
			// DEST[MAXVL-1:64] (Unmodified)
			il.AddInstruction(
				WriteILOperand(il, xedd, addr, 0, 0,
					ReadILOperand(il, xedd, addr, 1, 1, 8),
					8
				)
			);
		}
		else
		{
			// VMOVLPD xmm2, xmm1, m64
			// DEST[63:0] ← SRC2[63:0]
			// DEST[127:64] ← SRC1[127:64]
			// DEST[MAXVL-1:128] ← 0

			il.AddInstruction(
				WriteILOperand(il, xedd, addr, 0, 0,
					il.Or(
						16,
						ReadILOperand(il, xedd, addr, 2, 2, 8),
						il.And(
							16,
							ReadILOperand(il, xedd, addr, 1, 1, 16),
							il.ShiftLeft(16,
								il.Const(8, 0xffffffffffffffff),
								il.Const(1, 64))
						)
					),
					16
				)
			);
		}
		break;
	}

	case XED_ICLASS_MOVHPD:
	case XED_ICLASS_MOVHPS:
	case XED_ICLASS_VMOVHPD:
	case XED_ICLASS_VMOVHPS:
	{
		if (xed_inst_noperands(xi) == 2)
		{
			// MOVHPD xmm1, m64
			// DEST[63:0] (Unmodified)
			// DEST[127:64] ← SRC[63:0]
			// DEST[MAXVL-1:128] (Unmodified)

			il.AddInstruction(
				WriteILOperand(il, xedd, addr, 0, 0,
					il.Or(
						16,
						ReadILOperand(il, xedd, addr, 0, 0, 8),
						il.ShiftLeft(
							16,
							ReadILOperand(il, xedd, addr, 1, 1, 8),
							il.Const(1, 64)
						)
					),
					16
				)
			);
		}
		else
		{
			// VMOVHPD xmm2, xmm1, m64
			// DEST[63:0] ← SRC1[63:0]
			// DEST[127:64] ← SRC2[63:0]
			// DEST[MAXVL-1:128] ← 0

			il.AddInstruction(
				WriteILOperand(il, xedd, addr, 0, 0,
					il.Or(
						16,
						ReadILOperand(il, xedd, addr, 1, 1, 8),
						il.ShiftLeft(
							16,
							ReadILOperand(il, xedd, addr, 2, 2, 8),
							il.Const(1, 64)
						)
					),
					16
				)
			);
		}
		break;
	}

	case XED_ICLASS_MOVHLPS:
	{
		// MOVHLPS xmm1, xmm2
		// DEST[63:0] ← SRC[127:64]
		// DEST[MAXVL-1:64] (Unmodified)

		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.LogicalShiftRight(
					16,
					ReadILOperand(il, xedd, addr, 1, 1, 16),
					il.Const(1, 64)
				),
				8
			)
		);
		break;
	}

	case XED_ICLASS_VMOVHLPS:
	{
		// VMOVHLPS xmm1, xmm2, xmm3
		// DEST[63:0] ← SRC2[127:64]
		// DEST[127:64] ← SRC1[127:64]
		// DEST[MAXVL-1:128] ← 0

		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.Or(
					16,
					il.And(
						16,
						ReadILOperand(il, xedd, addr, 1, 1, 16),
						il.ShiftLeft(16,
							il.Const(8, 0xffffffffffffffff),
							il.Const(1, 64))
					),
					il.LogicalShiftRight(
						16,
						ReadILOperand(il, xedd, addr, 2, 2, 16),
						il.Const(1, 64)
					)
				),
				16
			)
		);

		break;
	}

	case XED_ICLASS_MOVLHPS:
	{
		// MOVLHPS xmm1, xmm2
		// DEST[63:0] (Unmodified)
		// DEST[127:64] ← SRC[63:0]
		// DEST[MAXVL-1:128] (Unmodified)

		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.Or(
					16,
					ReadILOperand(il, xedd, addr, 0, 0, 8),
					il.ShiftLeft(
						16,
						ReadILOperand(il, xedd, addr, 1, 1, 8),
						il.Const(1, 64)
					)
				),
				16
			)
		);

		break;
	}

	case XED_ICLASS_VMOVLHPS:
	{
		// VMOVLHPS xmm1, xmm2, xmm3
		// DEST[63:0] ← SRC1[63:0]
		// DEST[127:64] ← SRC2[63:0]
		// DEST[MAXVL-1:128] ← 0

		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.Or(
					16,
					ReadILOperand(il, xedd, addr, 1, 1, 8),
					il.ShiftLeft(
						16,
						ReadILOperand(il, xedd, addr, 2, 2, 8),
						il.Const(1, 64)
					)
				),
				16
			)
		);

		break;
	}

	case XED_ICLASS_MOVSD_XMM:
		// SSE instruction MOVSD
		if (xed_operand_is_register(opTwo_name))
		{
			// movsd xmm, xmm
			// movsd mem, xmm
			// 64 bits at dst equals low part src xmm reg
			il.AddInstruction(
				WriteILOperand(il, xedd, addr, 0, 0,
					il.LowPart(8, il.Register(16, regTwo))));
		}
		else // movsd xmm, mem
		{
			// low part of dst xmm reg equals 64 bits from src
			// high part is zerod
			il.AddInstruction(
				WriteILOperand(il, xedd, addr, 0, 0,
					il.ZeroExtend(16,
						il.Load(8,
							GetILOperandMemoryAddress(il, xedd, addr, 1, 1)))));
		}
		break;

	case XED_ICLASS_REP_MOVSB:
	case XED_ICLASS_REP_MOVSW:
	case XED_ICLASS_REP_MOVSD:
	case XED_ICLASS_REP_MOVSQ:
	case XED_ICLASS_MOVSB:
	case XED_ICLASS_MOVSW:
	case XED_ICLASS_MOVSD:
	case XED_ICLASS_MOVSQ:
	{
		size_t shift = 0;
		uint32_t intrinsic = INTRINSIC_XED_IFORM_REP_MOVSB;
		uint32_t srcReg = addrSize == 4 ? XED_REG_ESI : XED_REG_RSI;
		uint32_t dstReg = addrSize == 4 ? XED_REG_EDI : XED_REG_RDI;
		size_t moveSize;
		switch (xedd_iClass)
		{
		case XED_ICLASS_REP_MOVSW:
		case XED_ICLASS_MOVSW:
			intrinsic = INTRINSIC_XED_IFORM_REP_MOVSW;
			moveSize = 2;
			shift = 1;
			break;
		case XED_ICLASS_REP_MOVSD:
		case XED_ICLASS_MOVSD:
			intrinsic = INTRINSIC_XED_IFORM_REP_MOVSD;
			moveSize = 4;
			shift = 2;
			break;
		case XED_ICLASS_REP_MOVSQ:
		case XED_ICLASS_MOVSQ:
			intrinsic = INTRINSIC_XED_IFORM_REP_MOVSQ;
			moveSize = 8;
			shift = 3;
			break;
		default:
			moveSize = 1;
			break;
		}

		if (xed_operand_values_has_real_rep(xed_decoded_inst_operands_const(xedd)))
		{
			ExprId numBytesExpr;
			if (shift)
				numBytesExpr = il.ShiftLeft(addrSize, il.Register(addrSize, GetCountRegister(addrSize)), il.Const(addrSize, shift));
			else
				numBytesExpr = il.Register(addrSize, GetCountRegister(addrSize));
			ExprId countExpr = il.Register(addrSize, GetCountRegister(addrSize));

			DirFlagIf(il,
				[&](){},
				[&]() // Direction flag 1
				{
					auto dstExpr = il.Sub(addrSize, il.Register(addrSize, dstReg), numBytesExpr);
					auto srcExpr = il.Sub(addrSize, il.Register(addrSize, srcReg), numBytesExpr);
					il.AddInstruction(il.Intrinsic(
						vector<RegisterOrFlag> { RegisterOrFlag::Register(dstReg), RegisterOrFlag::Register(srcReg), RegisterOrFlag::Register(GetCountRegister(addrSize)) },
						intrinsic,
						vector<ExprId> { dstExpr, srcExpr, countExpr }
					));
				},
				[&]() // Direction flag 0
				{
					auto dstExpr = il.Register(addrSize, dstReg);
					auto srcExpr = il.Register(addrSize, srcReg);
					il.AddInstruction(il.Intrinsic(
						vector<RegisterOrFlag> { RegisterOrFlag::Register(dstReg), RegisterOrFlag::Register(srcReg), RegisterOrFlag::Register(GetCountRegister(addrSize)) },
						intrinsic,
						vector<ExprId> { dstExpr, srcExpr, countExpr }
					));
				}
			);
			break;
		}

		Repeat(xedd, il, [&] (){
			DirFlagIf(il,
				[&](){}, // Pre check direction flag check
				[&]() // Direction flag true
				{
					il.AddInstruction(il.Store(moveSize, il.Register(addrSize, dstReg),
						il.Load(moveSize, il.Register(addrSize, srcReg))));

					il.AddInstruction(
						il.SetRegister(addrSize,
							dstReg,
							il.Sub(addrSize,
								il.Register(addrSize, dstReg),
								il.Const(addrSize, moveSize))));

					il.AddInstruction(
						il.SetRegister(addrSize,
							srcReg,
							il.Sub(addrSize,
								il.Register(addrSize, srcReg),
								il.Const(addrSize, moveSize))));
				},
				[&]() // Direction flag false
				{
					il.AddInstruction(
						il.Store(moveSize,
							il.Register(addrSize, dstReg),
							il.Load(moveSize,
								il.Register(addrSize, srcReg))));

					il.AddInstruction(
						il.SetRegister(addrSize,
							dstReg,
							il.Add(addrSize,
								il.Register(addrSize, dstReg),
								il.Const(addrSize, moveSize))));

					il.AddInstruction(
						il.SetRegister(addrSize,
							srcReg,
							il.Add(addrSize,
								il.Register(addrSize, srcReg),
								il.Const(addrSize, moveSize))));
				});
		});
		break;
	}
	case XED_ICLASS_MUL:
		switch (opOneLen)
		{
		case 1:
			il.AddInstruction(
				il.SetRegister(2,
					XED_REG_AX,
					il.MultDoublePrecUnsigned(1,
						il.Register(1, XED_REG_AL),
						ReadILOperand(il, xedd, addr, 0, 0),
					IL_FLAGWRITE_CO)));
			break;
		case 2:
			il.AddInstruction(
				il.SetRegisterSplit(2,
					XED_REG_DX,
					XED_REG_AX,
					il.MultDoublePrecUnsigned(2,
						il.Register(2, XED_REG_AX),
						ReadILOperand(il, xedd, addr, 0, 0),
					IL_FLAGWRITE_CO)));
			break;
		case 4:
			il.AddInstruction(
				il.SetRegisterSplit(4,
					XED_REG_EDX,
					XED_REG_EAX,
					il.MultDoublePrecUnsigned(4,
						il.Register(4, XED_REG_EAX),
						ReadILOperand(il, xedd, addr, 0, 0),
					IL_FLAGWRITE_CO)));
			break;
		case 8:
			il.AddInstruction(
				il.SetRegisterSplit(8,
					XED_REG_RDX,
					XED_REG_RAX,
					il.MultDoublePrecUnsigned(8,
						il.Register(8, XED_REG_RAX),
						ReadILOperand(il, xedd, addr, 0, 0),
					IL_FLAGWRITE_CO)));
			break;
		default:
			il.AddInstruction(il.Undefined());
			break;
		}
		break;

	case XED_ICLASS_NEG_LOCK: // TODO: Handle lock prefix
	case XED_ICLASS_NEG:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.Neg(opOneLen,
					ReadILOperand(il, xedd, addr, 0, 0),
				IL_FLAGWRITE_ALL)));
		break;

	case XED_ICLASS_NOP:
	case XED_ICLASS_NOP2:
	case XED_ICLASS_NOP3:
	case XED_ICLASS_NOP4:
	case XED_ICLASS_NOP5:
	case XED_ICLASS_NOP6:
	case XED_ICLASS_NOP7:
	case XED_ICLASS_NOP8:
	case XED_ICLASS_NOP9:
	case XED_ICLASS_FNOP:
	case XED_ICLASS_FDISI8087_NOP:
	case XED_ICLASS_FENI8087_NOP:
	case XED_ICLASS_FSETPM287_NOP:

	case XED_ICLASS_PAUSE:

	case XED_ICLASS_PREFETCHNTA:
	case XED_ICLASS_PREFETCHT0:
	case XED_ICLASS_PREFETCHT1:
	case XED_ICLASS_PREFETCHT2:
	case XED_ICLASS_PREFETCHW:
	case XED_ICLASS_PREFETCHWT1:
	case XED_ICLASS_PREFETCH_EXCLUSIVE:
	case XED_ICLASS_PREFETCH_RESERVED:

	case XED_ICLASS_FWAIT:

	case XED_ICLASS_LFENCE:
	case XED_ICLASS_MFENCE:
	case XED_ICLASS_SFENCE:

	case XED_ICLASS_ENDBR32:
	case XED_ICLASS_ENDBR64:
		il.AddInstruction(il.Nop());
		break;

	case XED_ICLASS_NOT_LOCK: // TODO: Handle lock prefix
	case XED_ICLASS_NOT:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.Not(opOneLen,
					ReadILOperand(il, xedd, addr, 0, 0))));
		break;

	case XED_ICLASS_OR_LOCK: // TODO: Handle lock prefix
	case XED_ICLASS_OR:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.Or(opOneLen,
					ReadILOperand(il, xedd, addr, 0, 0),
					ReadILOperand(il, xedd, addr, 1, 1),
				IL_FLAGWRITE_ALL)));
		break;
	case XED_ICLASS_POR:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
			il.Or(opOneLen,
				ReadILOperand(il, xedd, addr, 0, 0),
				ReadILOperand(il, xedd, addr, 1, 1),
			0))); // POR doesn't modify any flag
		break;
	case XED_ICLASS_VPOR:
		if (xed_classify_avx512(xedd))
		{
			LiftAsIntrinsic();
			break;
		}
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
			il.Or(opOneLen,
				ReadILOperand(il, xedd, addr, 1, 1),
				ReadILOperand(il, xedd, addr, 2, 2),
			0))); // VPOR doesn't modify flags
		break;

	case XED_ICLASS_POP:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.Pop(opOneLen)));
		break;

	case XED_ICLASS_POPA:
		il.AddInstruction(il.SetRegister(2, XED_REG_DI, il.Pop(2)));
		il.AddInstruction(il.SetRegister(2, XED_REG_SI, il.Pop(2)));
		il.AddInstruction(il.SetRegister(2, XED_REG_BP, il.Pop(2)));
		il.AddInstruction(il.SetRegister(2, XED_REG_SP, il.Add(2, il.Register(2, XED_REG_SP), il.Const(2, 2))));
		il.AddInstruction(il.SetRegister(2, XED_REG_BX, il.Pop(2)));
		il.AddInstruction(il.SetRegister(2, XED_REG_DX, il.Pop(2)));
		il.AddInstruction(il.SetRegister(2, XED_REG_CX, il.Pop(2)));
		il.AddInstruction(il.SetRegister(2, XED_REG_AX, il.Pop(2)));
		break;

	case XED_ICLASS_POPAD:
		il.AddInstruction(il.SetRegister(4, XED_REG_EDI, il.Pop(4)));
		il.AddInstruction(il.SetRegister(4, XED_REG_ESI, il.Pop(4)));
		il.AddInstruction(il.SetRegister(4, XED_REG_EBP, il.Pop(4)));
		il.AddInstruction(il.SetRegister(4, XED_REG_ESP, il.Add(4, il.Register(4, XED_REG_ESP), il.Const(4, 4))));
		il.AddInstruction(il.SetRegister(4, XED_REG_EBX, il.Pop(4)));
		il.AddInstruction(il.SetRegister(4, XED_REG_EDX, il.Pop(4)));
		il.AddInstruction(il.SetRegister(4, XED_REG_ECX, il.Pop(4)));
		il.AddInstruction(il.SetRegister(4, XED_REG_EAX, il.Pop(4)));
		break;

	case XED_ICLASS_POPF:
		il.AddInstruction(il.SetRegister(2, LLIL_TEMP(0), il.Pop(2)));
		il.AddInstruction(il.SetFlag(IL_FLAG_C, il.TestBit(2, il.Register(2, LLIL_TEMP(0)), il.Const(1, 0))));
		il.AddInstruction(il.SetFlag(IL_FLAG_P, il.TestBit(2, il.Register(2, LLIL_TEMP(0)), il.Const(1, 2))));
		il.AddInstruction(il.SetFlag(IL_FLAG_A, il.TestBit(2, il.Register(2, LLIL_TEMP(0)), il.Const(1, 4))));
		il.AddInstruction(il.SetFlag(IL_FLAG_Z, il.TestBit(2, il.Register(2, LLIL_TEMP(0)), il.Const(1, 6))));
		il.AddInstruction(il.SetFlag(IL_FLAG_S, il.TestBit(2, il.Register(2, LLIL_TEMP(0)), il.Const(1, 7))));
		il.AddInstruction(il.SetFlag(IL_FLAG_D, il.TestBit(2, il.Register(2, LLIL_TEMP(0)), il.Const(1, 10))));
		il.AddInstruction(il.SetFlag(IL_FLAG_O, il.TestBit(2, il.Register(2, LLIL_TEMP(0)), il.Const(1, 11))));
		break;

	case XED_ICLASS_POPFD:
		il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0), il.Pop(4)));
		il.AddInstruction(il.SetFlag(IL_FLAG_C, il.TestBit(4, il.Register(4, LLIL_TEMP(0)), il.Const(1, 0))));
		il.AddInstruction(il.SetFlag(IL_FLAG_P, il.TestBit(4, il.Register(4, LLIL_TEMP(0)), il.Const(1, 2))));
		il.AddInstruction(il.SetFlag(IL_FLAG_A, il.TestBit(4, il.Register(4, LLIL_TEMP(0)), il.Const(1, 4))));
		il.AddInstruction(il.SetFlag(IL_FLAG_Z, il.TestBit(4, il.Register(4, LLIL_TEMP(0)), il.Const(1, 6))));
		il.AddInstruction(il.SetFlag(IL_FLAG_S, il.TestBit(4, il.Register(4, LLIL_TEMP(0)), il.Const(1, 7))));
		il.AddInstruction(il.SetFlag(IL_FLAG_D, il.TestBit(4, il.Register(4, LLIL_TEMP(0)), il.Const(1, 10))));
		il.AddInstruction(il.SetFlag(IL_FLAG_O, il.TestBit(4, il.Register(4, LLIL_TEMP(0)), il.Const(1, 11))));
		break;

	case XED_ICLASS_POPFQ:
		il.AddInstruction(il.SetRegister(8, LLIL_TEMP(0), il.Pop(8)));
		il.AddInstruction(il.SetFlag(IL_FLAG_C, il.TestBit(8, il.Register(8, LLIL_TEMP(0)), il.Const(1, 0))));
		il.AddInstruction(il.SetFlag(IL_FLAG_P, il.TestBit(8, il.Register(8, LLIL_TEMP(0)), il.Const(1, 2))));
		il.AddInstruction(il.SetFlag(IL_FLAG_A, il.TestBit(8, il.Register(8, LLIL_TEMP(0)), il.Const(1, 4))));
		il.AddInstruction(il.SetFlag(IL_FLAG_Z, il.TestBit(8, il.Register(8, LLIL_TEMP(0)), il.Const(1, 6))));
		il.AddInstruction(il.SetFlag(IL_FLAG_S, il.TestBit(8, il.Register(8, LLIL_TEMP(0)), il.Const(1, 7))));
		il.AddInstruction(il.SetFlag(IL_FLAG_D, il.TestBit(8, il.Register(8, LLIL_TEMP(0)), il.Const(1, 10))));
		il.AddInstruction(il.SetFlag(IL_FLAG_O, il.TestBit(8, il.Register(8, LLIL_TEMP(0)), il.Const(1, 11))));
		break;

	case XED_ICLASS_PUSHA:
		il.AddInstruction(il.Push(2, il.Register(2, XED_REG_AX)));
		il.AddInstruction(il.Push(2, il.Register(2, XED_REG_CX)));
		il.AddInstruction(il.Push(2, il.Register(2, XED_REG_DX)));
		il.AddInstruction(il.Push(2, il.Register(2, XED_REG_BX)));
		il.AddInstruction(il.Push(2, il.Register(2, XED_REG_SP)));
		il.AddInstruction(il.Push(2, il.Register(2, XED_REG_BP)));
		il.AddInstruction(il.Push(2, il.Register(2, XED_REG_SI)));
		il.AddInstruction(il.Push(2, il.Register(2, XED_REG_DI)));
		break;

	case XED_ICLASS_PUSHAD:
		il.AddInstruction(il.Push(4, il.Register(4, XED_REG_EAX)));
		il.AddInstruction(il.Push(4, il.Register(4, XED_REG_ECX)));
		il.AddInstruction(il.Push(4, il.Register(4, XED_REG_EDX)));
		il.AddInstruction(il.Push(4, il.Register(4, XED_REG_EBX)));
		il.AddInstruction(il.Push(4, il.Register(4, XED_REG_ESP)));
		il.AddInstruction(il.Push(4, il.Register(4, XED_REG_EBP)));
		il.AddInstruction(il.Push(4, il.Register(4, XED_REG_ESI)));
		il.AddInstruction(il.Push(4, il.Register(4, XED_REG_EDI)));
		break;

	case XED_ICLASS_PUSHF:
		il.AddInstruction(il.Push(2,
			il.Or(2, il.FlagBit(2, IL_FLAG_O, 11),
			il.Or(2, il.FlagBit(2, IL_FLAG_D, 10),
			il.Or(2, il.FlagBit(2, IL_FLAG_S, 7),
			il.Or(2, il.FlagBit(2, IL_FLAG_Z, 6),
			il.Or(2, il.FlagBit(2, IL_FLAG_A, 4),
			il.Or(2, il.FlagBit(2, IL_FLAG_P, 2),
						il.FlagBit(2, IL_FLAG_C, 0)))))))));
		break;

	case XED_ICLASS_PUSHFD:
		il.AddInstruction(il.Push(4,
			il.Or(4, il.FlagBit(4, IL_FLAG_O, 11),
			il.Or(4, il.FlagBit(4, IL_FLAG_D, 10),
			il.Or(4, il.FlagBit(4, IL_FLAG_S, 7),
			il.Or(4, il.FlagBit(4, IL_FLAG_Z, 6),
			il.Or(4, il.FlagBit(4, IL_FLAG_A, 4),
			il.Or(4, il.FlagBit(4, IL_FLAG_P, 2),
						il.FlagBit(4, IL_FLAG_C, 0)))))))));
		break;

	case XED_ICLASS_PUSHFQ:
		il.AddInstruction(
			il.Push(8,
				il.Or(8,
					il.FlagBit(8, IL_FLAG_O, 11),
					il.Or(8,
						il.FlagBit(8, IL_FLAG_D, 10),
						il.Or(8,
							il.FlagBit(8, IL_FLAG_S, 7),
							il.Or(8,
								il.FlagBit(8, IL_FLAG_Z, 6),
								il.Or(8,
									il.FlagBit(8, IL_FLAG_A, 4),
									il.Or(8,
										il.FlagBit(8, IL_FLAG_P, 2),
										il.FlagBit(8, IL_FLAG_C, 0)
									)
								)
							)
						)
					)
				)
			)
		);
		break;

	case XED_ICLASS_PUSH:
	{
		// Whe the stack adjustment is different from the operand one size, zero-extend it. Note, a "push r16" in either
		// x86 or x64 pushes the 2-byte register onto the stack, and there is no need to extend. See
		// https://github.com/Vector35/binaryninja-api/issues/4028 and
		// https://stackoverflow.com/questions/43435764/64-bit-mode-does-not-support-32-bit-push-and-pop-instructions
		// for more details
		const unsigned int stackAdjustment = xed_decoded_inst_get_memory_operand_length(xedd, 0);
		if (opOneLen != stackAdjustment)
		{
			il.AddInstruction(
				il.Push(stackAdjustment,
					il.ZeroExtend(stackAdjustment,
						ReadILOperand(il, xedd, addr, 0, 0))));
		}
		else
			il.AddInstruction(
				il.Push(stackAdjustment,
					ReadILOperand(il, xedd, addr, 0, 0)));
		break;
	}

	case XED_ICLASS_RCL:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.RotateLeftCarry(opOneLen,
					ReadILOperand(il, xedd, addr, 0, 0),
					ReadILOperand(il, xedd, addr, 1, 1),
				il.Flag(IL_FLAG_C), IL_FLAGWRITE_ALL)));
		break;

	case XED_ICLASS_RCR:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.RotateRightCarry(opOneLen,
					ReadILOperand(il, xedd, addr, 0, 0),
					ReadILOperand(il, xedd, addr, 1, 1),
				il.Flag(IL_FLAG_C), IL_FLAGWRITE_ALL)));
		break;

	case XED_ICLASS_RET_NEAR:
		if ((opOne_name != XED_OPERAND_IMM0) || (immediateOne == 0))
			il.AddInstruction(il.Return(il.Pop(addrSize)));
		else
		{
			il.AddInstruction(il.SetRegister(addrSize, LLIL_TEMP(0), il.Pop(addrSize)));
			il.AddInstruction(
				il.SetRegister(addrSize,
					GetStackPointer(addrSize),
					il.Add(addrSize,
						il.Register(addrSize, GetStackPointer(addrSize)),
						il.Const(addrSize, immediateOne))));

			il.AddInstruction(il.Return(il.Register(addrSize, LLIL_TEMP(0))));
		}
		break;

	case XED_ICLASS_ROL:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.RotateLeft(opOneLen,
					ReadILOperand(il, xedd, addr, 0, 0),
					ReadILOperand(il, xedd, addr, 1, 1),
				IL_FLAGWRITE_ALL)));
		break;

	case XED_ICLASS_ROR:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.RotateRight(opOneLen,
					ReadILOperand(il, xedd, addr, 0, 0),
					ReadILOperand(il, xedd, addr, 1, 1),
				IL_FLAGWRITE_ALL)));
		break;

	// there is no ROLX instruciton
	case XED_ICLASS_RORX:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.RotateRight(opOneLen,
					ReadILOperand(il, xedd, addr, 1, 1),
					ReadILOperand(il, xedd, addr, 2, 2)
				)));
		break;

	case XED_ICLASS_SAR:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.ArithShiftRight(opOneLen,
					ReadILOperand(il, xedd, addr, 0, 0),
					ReadILOperand(il, xedd, addr, 1, 1),
				IL_FLAGWRITE_ALL)));
		break;

	case XED_ICLASS_SARX:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.ArithShiftRight(opOneLen,
					ReadILOperand(il, xedd, addr, 1, 1),
					ReadILOperand(il, xedd, addr, 2, 2)
				)));
		break;

	case XED_ICLASS_SAHF:
		il.AddInstruction(il.SetFlag(IL_FLAG_C, il.TestBit(1, il.Register(1, XED_REG_AH), il.Const(1, 0))));
		il.AddInstruction(il.SetFlag(IL_FLAG_P, il.TestBit(1, il.Register(1, XED_REG_AH), il.Const(1, 2))));
		il.AddInstruction(il.SetFlag(IL_FLAG_A, il.TestBit(1, il.Register(1, XED_REG_AH), il.Const(1, 4))));
		il.AddInstruction(il.SetFlag(IL_FLAG_Z, il.TestBit(1, il.Register(1, XED_REG_AH), il.Const(1, 6))));
		il.AddInstruction(il.SetFlag(IL_FLAG_S, il.TestBit(1, il.Register(1, XED_REG_AH), il.Const(1, 7))));
		break;

	case XED_ICLASS_SBB_LOCK: // TODO: Handle lock prefix
	case XED_ICLASS_SBB:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.SubBorrow(opOneLen,
					ReadILOperand(il, xedd, addr, 0, 0),
					ReadILOperand(il, xedd, addr, 1, 1),
				il.Flag(IL_FLAG_C), IL_FLAGWRITE_ALL)));
		break;

	case XED_ICLASS_REPE_SCASB:
	case XED_ICLASS_REPE_SCASD:
	case XED_ICLASS_REPE_SCASQ:
	case XED_ICLASS_REPE_SCASW:
	case XED_ICLASS_REPNE_SCASB:
	case XED_ICLASS_REPNE_SCASD:
	case XED_ICLASS_REPNE_SCASQ:
	case XED_ICLASS_REPNE_SCASW:
	case XED_ICLASS_SCASB:
	case XED_ICLASS_SCASW:
	case XED_ICLASS_SCASD:
	case XED_ICLASS_SCASQ:
	{
		size_t searchSize;
		uint32_t cmpReg;
		uint32_t srcReg = addrSize == 4 ? XED_REG_EDI : XED_REG_RDI;
		switch (xedd_iClass)
		{
		case XED_ICLASS_REPE_SCASW:
		case XED_ICLASS_REPNE_SCASW:
		case XED_ICLASS_SCASW:
			searchSize = 2;
			cmpReg = XED_REG_AX;
			break;
		case XED_ICLASS_REPE_SCASD:
		case XED_ICLASS_REPNE_SCASD:
		case XED_ICLASS_SCASD:
			searchSize = 4;
			cmpReg = XED_REG_EAX;
			break;
		case XED_ICLASS_REPE_SCASQ:
		case XED_ICLASS_REPNE_SCASQ:
		case XED_ICLASS_SCASQ:
			searchSize = 8;
			cmpReg = XED_REG_RAX;
			break;
		default:
			searchSize = 1;
			cmpReg = XED_REG_AL;
			break;
		}

		Repeat(xedd, il, [&]() {
			DirFlagIf(il, [&]()
			{
				(void)addrSize;
				il.AddInstruction(il.Sub(searchSize, il.Register(searchSize, cmpReg), il.Load(searchSize, il.Register(addrSize, srcReg)), IL_FLAGWRITE_ALL));
			},
			[&] () // Direction flag is 1
			{
				il.AddInstruction(il.SetRegister(addrSize, srcReg, il.Sub(addrSize, il.Register(addrSize, srcReg), il.Const(addrSize, searchSize))));
			},
			[&] () // Direction flag is 0
			{
				il.AddInstruction(il.SetRegister(addrSize, srcReg, il.Add(addrSize, il.Register(addrSize, srcReg), il.Const(addrSize, searchSize))));
			});
		});
		break;
	}

	case XED_ICLASS_SETO:
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0, il.Flag(IL_FLAG_O)));
		break;

	case XED_ICLASS_SETNO:
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0, il.Not(0, il.Flag(IL_FLAG_O))));
		break;

	case XED_ICLASS_SETB:
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0, il.Flag(IL_FLAG_C)));
		break;

	case XED_ICLASS_SETNB:
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0, il.FlagGroup(IL_FLAG_GROUP_GE)));
		break;

	case XED_ICLASS_SETZ:
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0, il.FlagGroup(IL_FLAG_GROUP_E)));
		break;

	case XED_ICLASS_SETNZ:
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0, il.FlagGroup(IL_FLAG_GROUP_NE)));
		break;

	case XED_ICLASS_SETBE:
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0, il.FlagGroup(IL_FLAG_GROUP_LE)));
		break;

	case XED_ICLASS_SETNBE:
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0, il.FlagGroup(IL_FLAG_GROUP_GT)));
		break;

	case XED_ICLASS_SETS:
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0, il.FlagCondition(LLFC_NEG)));
		break;

	case XED_ICLASS_SETNS:
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0, il.FlagCondition(LLFC_POS)));
		break;

	case XED_ICLASS_SETP:
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0, il.FlagGroup(IL_FLAG_GROUP_PE)));
		break;

	case XED_ICLASS_SETNP:
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0, il.FlagGroup(IL_FLAG_GROUP_PO)));
		break;

	case XED_ICLASS_SETL:
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0, il.FlagCondition(LLFC_SLT)));
		break;

	case XED_ICLASS_SETNL:
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0, il.FlagCondition(LLFC_SGE)));
		break;

	case XED_ICLASS_SETLE:
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0, il.FlagCondition(LLFC_SLE)));
		break;

	case XED_ICLASS_SETNLE:
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0, il.FlagCondition(LLFC_SGT)));
		break;

	case XED_ICLASS_SHL:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.ShiftLeft(opOneLen,
					ReadILOperand(il, xedd, addr, 0, 0),
					ReadILOperand(il, xedd, addr, 1, 1),
				IL_FLAGWRITE_ALL)));
		break;

	// This is imprecise since it does NOT move the last shifted bit into CF
	// the same problem also happens on SHL, SAR
	case XED_ICLASS_SHR:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.LogicalShiftRight(opOneLen,
					ReadILOperand(il, xedd, addr, 0, 0),
					ReadILOperand(il, xedd, addr, 1, 1),
				IL_FLAGWRITE_ALL)));
		break;

	case XED_ICLASS_SHLX:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.ShiftLeft(opOneLen,
					ReadILOperand(il, xedd, addr, 1, 1),
					ReadILOperand(il, xedd, addr, 2, 2)
				)));
		break;

	case XED_ICLASS_SHRX:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.LogicalShiftRight(opOneLen,
					ReadILOperand(il, xedd, addr, 1, 1),
					ReadILOperand(il, xedd, addr, 2, 2)
				)));
		break;

	case XED_ICLASS_SHLD:
	{
		size_t opSize = opOneLen;
		size_t mask = opSize == 4 ? 31 : 63;

		// Shift left double: operand[0] = operand[0]:operand[1] << operand[3]
		// this since we can't easily operation on a combined register we do it like this
		// operand[0] = (operand[0] << operand[3]) | (operand[1] >> (63|32 - operand[3]))
		// One final cevate operand[3] must be masked with 63|32
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0,
			il.Or(opSize,
				il.ShiftLeft(opSize,
					ReadILOperand(il, xedd, addr, 0, 0),
					il.And(opSize,
						il.Const(1, mask),
						ReadILOperand(il, xedd, addr, 2, 2)),
					IL_FLAGWRITE_ALL),
				il.LogicalShiftRight(opSize,
					ReadILOperand(il, xedd, addr, 1, 1),
					il.Sub(opSize,
						il.And(opSize,
							il.Const(1, mask),
							ReadILOperand(il, xedd, addr, 2, 2)),
						il.Const(1, opSize * 8))))));
		break;
	}
	case XED_ICLASS_SHRD:
	{
		size_t opSize = opOneLen;
		size_t mask = opSize == 4 ? 31 : 63;

		// Shift right double: operand[0] = operand[0]:operand[1] >> operand[3]
		// this since we can't easily operation on a combined register we do it like this
		// operand[0] = (operand[0] >> operand[3]) | (operand[1] << (63|31 - operand[3]))
		// One final cevate operand[3] must be masked with 63|31
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0,
			il.Or(opSize,
				il.LogicalShiftRight(opSize,
					ReadILOperand(il, xedd, addr, 0, 0),
					il.And(opSize,
						il.Const(1, mask),
						ReadILOperand(il, xedd, addr, 2, 2)),
					IL_FLAGWRITE_ALL),
				il.ShiftLeft(opSize,
					ReadILOperand(il, xedd, addr, 1, 1),
					il.Sub(opSize,
						il.Const(1, opSize * 8),
						il.And(opSize,
							il.Const(1, mask),
							ReadILOperand(il, xedd, addr, 2, 2)))))));
		break;
	}
	case XED_ICLASS_STOSB:
	case XED_ICLASS_STOSW:
	case XED_ICLASS_STOSD:
	case XED_ICLASS_STOSQ:
	case XED_ICLASS_REP_STOSB:
	case XED_ICLASS_REP_STOSW:
	case XED_ICLASS_REP_STOSD:
	case XED_ICLASS_REP_STOSQ:
	{
		size_t shift = 0;
		uint32_t intrinsic = INTRINSIC_XED_IFORM_REP_STOSB;
		size_t moveSize = 1;
		ExprId moveReg = 0;
		uint32_t ilDestReg = addrSize == 4 ? XED_REG_EDI : XED_REG_RDI;
		switch (xedd_iClass)
		{
		case XED_ICLASS_STOSB:
		case XED_ICLASS_REP_STOSB:
			intrinsic = INTRINSIC_XED_IFORM_REP_STOSB;
			moveSize = 1; moveReg = il.Register(moveSize, XED_REG_AL);
			shift = 0;
			break;
		case XED_ICLASS_STOSW:
		case XED_ICLASS_REP_STOSW:
			intrinsic = INTRINSIC_XED_IFORM_REP_STOSW;
			moveSize = 2; moveReg = il.Register(moveSize, XED_REG_AX);
			shift = 1;
			break;
		case XED_ICLASS_STOSD:
		case XED_ICLASS_REP_STOSD:
			intrinsic = INTRINSIC_XED_IFORM_REP_STOSD;
			moveSize = 4; moveReg = il.Register(moveSize, XED_REG_EAX);
			shift = 2;
			break;
		case XED_ICLASS_STOSQ:
		case XED_ICLASS_REP_STOSQ:
			intrinsic = INTRINSIC_XED_IFORM_REP_STOSQ;
			moveSize = 8; moveReg = il.Register(moveSize, XED_REG_RAX);
			shift = 3;
			break;
		default: break;
		}

		if (xed_operand_values_has_real_rep(xed_decoded_inst_operands_const(xedd)))
		{
			ExprId numBytesExpr;
			if (shift)
				numBytesExpr = il.ShiftLeft(addrSize, il.Register(addrSize, GetCountRegister(addrSize)), il.Const(addrSize, shift));
			else
				numBytesExpr = il.Register(addrSize, GetCountRegister(addrSize));
			ExprId countExpr = il.Register(addrSize, GetCountRegister(addrSize));
			DirFlagIf(il,
				[&](){},
				[&]() // Direction flag 1
				{
					il.AddInstruction(il.Intrinsic(
						vector<RegisterOrFlag> { RegisterOrFlag::Register(ilDestReg), RegisterOrFlag::Register(GetCountRegister(addrSize)) },
						intrinsic,
						vector<ExprId> { il.Sub(addrSize, il.Register(addrSize, ilDestReg), numBytesExpr), moveReg, countExpr }
					));
				},
				[&]() // Direction flag 0
				{
					il.AddInstruction(il.Intrinsic(
						vector<RegisterOrFlag> { RegisterOrFlag::Register(ilDestReg), RegisterOrFlag::Register(GetCountRegister(addrSize)) },
						intrinsic,
						vector<ExprId> { il.Register(addrSize, ilDestReg), moveReg, countExpr }
					));
				}
			);
			break;
		}

		Repeat(xedd, il, [&](){
			DirFlagIf(il,
				[&](){},
				[&]() // Direction flag 1
				{
					il.AddInstruction(
						il.Store(moveSize,
							il.Register(addrSize, ilDestReg),
							moveReg));

					il.AddInstruction(
						il.SetRegister(addrSize,
							ilDestReg,
							il.Sub(addrSize,
								il.Register(addrSize, ilDestReg),
								il.Const(addrSize, moveSize))));
				},
				[&]() // Direction flag 0
				{
					il.AddInstruction(
						il.Store(moveSize,
							il.Register(addrSize, ilDestReg),
							moveReg));

					il.AddInstruction(
						il.SetRegister(addrSize,
							ilDestReg,
							il.Add(addrSize,
								il.Register(addrSize, ilDestReg),
								il.Const(addrSize, moveSize))));
				}
			);
		});
		break;
	}

	case XED_ICLASS_STC:
		il.AddInstruction(il.SetFlag(IL_FLAG_C, il.Const(1, 1)));
		break;

	case XED_ICLASS_STD:
		il.AddInstruction(il.SetFlag(IL_FLAG_D, il.Const(1, 1)));
		break;

	case XED_ICLASS_SUB_LOCK: // TODO: Handle lock prefix
	case XED_ICLASS_SUB:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.Sub(opOneLen,
					ReadILOperand(il, xedd, addr, 0, 0),
					ReadILOperand(il, xedd, addr, 1, 1),
				IL_FLAGWRITE_ALL)));
		break;

	case XED_ICLASS_TEST:
		il.AddInstruction(
			il.And(opOneLen,
				ReadILOperand(il, xedd, addr, 0, 0),
				ReadILOperand(il, xedd, addr, 1, 1),
			IL_FLAGWRITE_ALL));
		break;

	case XED_ICLASS_PTEST:
	case XED_ICLASS_VPTEST:
		il.AddInstruction(
			il.SetFlag(IL_FLAG_Z,
				il.BoolToInt(
					1,
					il.CompareEqual(
						opOneLen,
						il.And(
							opOneLen,
							ReadILOperand(il, xedd, addr, 0, 0),
							ReadILOperand(il, xedd, addr, 1, 1)
						),
						il.Const(opOneLen, 0)
					)
				)
			)
		);
		il.AddInstruction(
			il.SetFlag(IL_FLAG_C,
				il.BoolToInt(
					1,
					il.CompareEqual(
						opOneLen,
						il.And(
							opOneLen,
							ReadILOperand(il, xedd, addr, 0, 0),
							il.Not(opTwoLen,
								ReadILOperand(il, xedd, addr, 1, 1)
							)
						),
						il.Const(opOneLen, 0)
					)
				)
			)
		);
		break;

	case XED_ICLASS_XCHG:
		il.AddInstruction(il.SetRegister(opOneLen, LLIL_TEMP(0), ReadILOperand(il, xedd, addr, 0, 0)));
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0, ReadILOperand(il, xedd, addr, 1, 1)));
		il.AddInstruction(WriteILOperand(il, xedd, addr, 1, 1, il.Register(opOneLen, LLIL_TEMP(0))));
		break;

	case XED_ICLASS_CMPXCHG:
	case XED_ICLASS_CMPXCHG_LOCK:
	{
		LowLevelILLabel trueLabel, falseLabel, doneLabel;
		size_t cmpGranularity = xed_decoded_inst_operand_element_size_bits(xedd, 0) / 8;
		xed_reg_enum_t cmpReg = xed_decoded_inst_get_reg(xedd, opTre_name);

		il.AddInstruction(
			il.If(
				il.CompareEqual(
					cmpGranularity,
					il.Register(cmpGranularity, cmpReg),
					ReadILOperand(il, xedd, addr, 0, 0)
				), trueLabel, falseLabel
			)
		);

		il.MarkLabel(trueLabel);

		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				ReadILOperand(il, xedd, addr, 1, 1)
			)
		);
		il.AddInstruction(il.SetFlag(IL_FLAG_Z, il.Const(1, 1)));

		il.AddInstruction(il.Goto(doneLabel));

		il.MarkLabel(falseLabel);

		il.AddInstruction(
			il.SetRegister(
				cmpGranularity, cmpReg,
				ReadILOperand(il, xedd, addr, 0, 0)
			)
		);
		il.AddInstruction(il.SetFlag(IL_FLAG_Z, il.Const(1, 0)));

		il.MarkLabel(doneLabel);

		break;
	}

	case XED_ICLASS_CMPXCHG8B:
	case XED_ICLASS_CMPXCHG8B_LOCK:
	case XED_ICLASS_CMPXCHG16B:
	case XED_ICLASS_CMPXCHG16B_LOCK:
	{
	// assembly: cmpxchg8b qword [rdi]
	// $ ./xed-ex1 0fc70f
	// Attempting to decode: 0f c7 0f
	// iclass CMPXCHG8B	category SEMAPHORE	ISA-extension BASE	ISA-set PENTIUMREAL
	// instruction-length 3
	// operand-width 32
	// Operands
	// #   TYPE               DETAILS        VIS  RW       OC2 BITS BYTES NELEM ELEMSZ   ELEMTYPE   REGCLASS
	// #   ====               =======        ===  ==       === ==== ===== ===== ======   ========   ========
	// 0   MEM0           (see below)   EXPLICIT RCW         Q   64     8     1     64        INT    INVALID
	// 1   REG0              REG0=EDX SUPPRESSED RCW         D   32     4     1     32        INT        GPR
	// 2   REG1              REG1=EAX SUPPRESSED RCW         D   32     4     1     32        INT        GPR
	// 3   REG2              REG2=ECX SUPPRESSED   R         D   32     4     1     32        INT        GPR
	// 4   REG3              REG3=EBX SUPPRESSED   R         D   32     4     1     32        INT        GPR
	// 5   REG4           REG4=EFLAGS SUPPRESSED   W         Y   32     4     1     32        INT      FLAGS
	// Memory Operands
	//   0    read written SEG= DS BASE= EDI/GPR  ASZ0=32
	//   MemopBytes = 8

		LowLevelILLabel trueLabel, falseLabel, doneLabel;
		size_t cmpGranularity = xed_decoded_inst_operand_element_size_bits(xedd, 1) / 8 * 2;

		xed_reg_enum_t cmpRegHigh = xed_decoded_inst_get_reg(xedd, opTwo_name);
		xed_reg_enum_t cmpRegLow = xed_decoded_inst_get_reg(xedd, opTre_name);

		const xed_operand_t* const    opFour = xed_inst_operand(xi, 3);
		const xed_operand_enum_t opFour_name = xed_operand_name(opFour);
		xed_reg_enum_t resultRegHigh = xed_decoded_inst_get_reg(xedd, opFour_name);

		const xed_operand_t* const    opFive = xed_inst_operand(xi, 4);
		const xed_operand_enum_t opFive_name = xed_operand_name(opFive);
		xed_reg_enum_t resultRegLow = xed_decoded_inst_get_reg(xedd, opFive_name);

		il.AddInstruction(
			il.If(
				il.CompareEqual(
					cmpGranularity,
					il.RegisterSplit(cmpGranularity / 2, cmpRegHigh, cmpRegLow),
					ReadILOperand(il, xedd, addr, 0, 0)
				),
				trueLabel, falseLabel
			)
		);

		il.MarkLabel(trueLabel);

		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.RegisterSplit(cmpGranularity / 2, resultRegHigh, resultRegLow)
			)
		);
		il.AddInstruction(il.SetFlag(IL_FLAG_Z, il.Const(1, 1)));

		il.AddInstruction(il.Goto(doneLabel));

		il.MarkLabel(falseLabel);

		il.AddInstruction(
			il.SetRegisterSplit(cmpGranularity / 2, cmpRegHigh, cmpRegLow,
				ReadILOperand(il, xedd, addr, 0, 0)
			)
		);
		il.AddInstruction(il.SetFlag(IL_FLAG_Z, il.Const(1, 0)));

		il.MarkLabel(doneLabel);

		break;
	}
	case XED_ICLASS_XORPS:
	case XED_ICLASS_PXOR:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.Xor(opOneLen,
					ReadILOperand(il, xedd, addr, 0, 0),
					ReadILOperand(il, xedd, addr, 1, 1),
					0)));
		break;
	case XED_ICLASS_XOR_LOCK: // TODO: Handle lock prefix
	case XED_ICLASS_XOR:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.Xor(opOneLen,
					ReadILOperand(il, xedd, addr, 0, 0),
					ReadILOperand(il, xedd, addr, 1, 1),
				IL_FLAGWRITE_ALL)));
		break;
	case XED_ICLASS_VPXOR:
		if (xed_classify_avx512(xedd))
		{
			LiftAsIntrinsic();
			break;
		}
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.Xor(opOneLen,
					ReadILOperand(il, xedd, addr, 1, 1),
					ReadILOperand(il, xedd, addr, 2, 2),
				0)));
		break;

	case XED_ICLASS_XADD:
	case XED_ICLASS_XADD_LOCK:
		il.AddInstruction(
			il.SetRegister(opOneLen, LLIL_TEMP(0),
				il.Add(opOneLen,
					ReadILOperand(il, xedd, addr, 0, 0),
					ReadILOperand(il, xedd, addr, 1, 1),
				IL_FLAGWRITE_ALL)));
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 1, 1, ReadILOperand(il, xedd, addr, 0, 0)));
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0, il.Register(opOneLen, LLIL_TEMP(0))));
		break;
	case XED_ICLASS_JMP_FAR:
	case XED_ICLASS_RET_FAR:
	case XED_ICLASS_IRET:
	case XED_ICLASS_IRETD:
	case XED_ICLASS_IRETQ:
		il.AddInstruction(il.Undefined());
		return false;

	case XED_ICLASS_UD2:
		il.AddInstruction(il.Trap(TRAP_ILL));
		return false;

	case XED_ICLASS_SYSCALL:
	case XED_ICLASS_SYSENTER:
		il.AddInstruction(il.SystemCall());
		break;

	case XED_ICLASS_SYSEXIT:
	case XED_ICLASS_SYSRET:
	case XED_ICLASS_HLT:
		il.AddInstruction(il.Trap(TRAP_GPF));
		return false;

	case XED_ICLASS_FLD:
		il.AddInstruction(
			il.RegisterStackPush(10,
				REG_STACK_X87,
				ReadFloatILOperand(il, xedd, addr, 1, 1)));
		break;

	case XED_ICLASS_FILD:
		il.AddInstruction(
			il.RegisterStackPush(10,
				REG_STACK_X87,
				il.IntToFloat(10,
					ReadILOperand(il, xedd, addr, 1, 1)),
			IL_FLAGWRITE_X87C1Z));
		break;

	case XED_ICLASS_FLDZ:
		il.AddInstruction(
			il.RegisterStackPush(10,
				REG_STACK_X87,
				il.IntToFloat(10, il.Const(4, 0)),
			IL_FLAGWRITE_X87C1Z));
		break;

	case XED_ICLASS_FLD1:
		il.AddInstruction(
			il.RegisterStackPush(10,
				REG_STACK_X87,
				il.IntToFloat(10, il.Const(4, 1)),
			IL_FLAGWRITE_X87C1Z));
		break;

	case XED_ICLASS_FLDPI:
		// Load 66-bit precision constant with two 33-bit components
		il.AddInstruction(
			il.RegisterStackPush(10,
				REG_STACK_X87,
				il.FloatAdd(10,
					il.FloatConvert(10, il.FloatConstRaw(8, 0x400921fb54400000LL)),
					il.FloatConvert(10, il.FloatConstRaw(8, 0x3de0b4611a600000LL))),
			IL_FLAGWRITE_X87C1Z));
		break;

	case XED_ICLASS_FLDL2T:
		// Load 66-bit precision constant with two 33-bit components
		il.AddInstruction(
			il.RegisterStackPush(10,
				REG_STACK_X87,
				il.FloatAdd(10,
					il.FloatConvert(10, il.FloatConstRaw(8, 0x400a934f09700000LL)),
					il.FloatConvert(10, il.FloatConstRaw(8, 0x3df346e2bf900000LL))),
			IL_FLAGWRITE_X87C1Z));
		break;

	case XED_ICLASS_FLDL2E:
		// Load 66-bit precision constant with two 33-bit components
		il.AddInstruction(
			il.RegisterStackPush(10,
				REG_STACK_X87,
				il.FloatAdd(10,
					il.FloatConvert(10, il.FloatConstRaw(8, 0x3ff7154765200000LL)),
					il.FloatConvert(10, il.FloatConstRaw(8, 0x3de705fc2ee00000LL))),
			IL_FLAGWRITE_X87C1Z));
		break;

	case XED_ICLASS_FLDLG2:
		// Load 66-bit precision constant with two 33-bit components
		il.AddInstruction(
			il.RegisterStackPush(10,
				REG_STACK_X87,
				il.FloatAdd(10,
					il.FloatConvert(10, il.FloatConstRaw(8, 0x3fd3441350900000LL)),
					il.FloatConvert(10, il.FloatConstRaw(8, 0x3dcef3fde6200000LL))),
			IL_FLAGWRITE_X87C1Z));
		break;

	case XED_ICLASS_FLDLN2:
		// Load 66-bit precision constant with two 33-bit components
		il.AddInstruction(
			il.RegisterStackPush(10,
				REG_STACK_X87,
				il.FloatAdd(10,
					il.FloatConvert(10, il.FloatConstRaw(8, 0x3fe62e42fef00000LL)),
					il.FloatConvert(10, il.FloatConstRaw(8, 0x3dd473de6af00000LL))),
			IL_FLAGWRITE_X87C1Z));
		break;

	case XED_ICLASS_FST:
		if (opOneLen != 10)
		{
			il.AddInstruction(
				WriteILOperand(il, xedd, addr, 0, 0,
					il.FloatConvert(opOneLen,
						il.Register(10, XED_REG_ST0),
					IL_FLAGWRITE_X87RND)));
		}
		else
		{
			il.AddInstruction(
				WriteILOperand(il, xedd, addr, 0, 0,
					il.Register(10, XED_REG_ST0)));
		}
		break;

	case XED_ICLASS_FSTP:
		if (opOneLen != 10)
		{
			il.AddInstruction(
				WriteILOperand(il, xedd, addr, 0, 0,
					il.FloatConvert(opOneLen,
						il.RegisterStackPop(10, REG_STACK_X87),
					IL_FLAGWRITE_X87RND)));
		}
		else
		{
			il.AddInstruction(
					WriteILOperand(il, xedd, addr, 0, 0,
						il.RegisterStackPop(10, REG_STACK_X87, IL_FLAGWRITE_X87C1Z)));
		}
		break;

	case XED_ICLASS_FIST:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.FloatToInt(opOneLen,
					il.Register(10, XED_REG_ST0),
				IL_FLAGWRITE_X87RND)));
		break;

	case XED_ICLASS_FISTP:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.FloatToInt(opOneLen,
					il.RegisterStackPop(10, REG_STACK_X87),
				IL_FLAGWRITE_X87RND)));
		break;

	case XED_ICLASS_FISTTP:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.FloatToInt(opOneLen,
						il.RegisterStackPop(10, REG_STACK_X87),
						IL_FLAGWRITE_X87RND)));
		break;

	case XED_ICLASS_FADD:
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0,
			il.FloatAdd(10,
				ReadFloatILOperand(il, xedd, addr, 0, 0),
				ReadFloatILOperand(il, xedd, addr, 1, 1),
			IL_FLAGWRITE_X87RND)));
		break;

	case XED_ICLASS_FADDP:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.FloatAdd(10,
					ReadFloatILOperand(il, xedd, addr, 0, 0),
					ReadFloatILOperand(il, xedd, addr, 1, 1),
				IL_FLAGWRITE_X87RND)));
		il.AddInstruction(il.RegisterStackFreeReg(XED_REG_ST0));
		il.AddInstruction(
			il.SetRegister(2,
				REG_X87_TOP,
				il.Add(2,
					il.Register(2, REG_X87_TOP),
					il.Const(2, 1))));
		break;

	case XED_ICLASS_FIADD:
		il.AddInstruction(
			il.SetRegister(10, XED_REG_ST0,
				il.FloatAdd(10,
					il.Register(10, XED_REG_ST0),
					il.IntToFloat(10,
						ReadILOperand(il, xedd, addr, 1, 1)),
			IL_FLAGWRITE_X87RND)));
		break;

	case XED_ICLASS_FSUB:
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0,
			il.FloatSub(10,
				ReadFloatILOperand(il, xedd, addr, 0, 0),
				ReadFloatILOperand(il, xedd, addr, 1, 1),
			IL_FLAGWRITE_X87RND)));
		break;

	case XED_ICLASS_FSUBP:
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0,
			il.FloatSub(10,
				ReadFloatILOperand(il, xedd, addr, 0, 0),
				ReadFloatILOperand(il, xedd, addr, 1, 1),
			IL_FLAGWRITE_X87RND)));
		il.AddInstruction(il.RegisterStackFreeReg(XED_REG_ST0));
		il.AddInstruction(il.SetRegister(2, REG_X87_TOP, il.Add(2, il.Register(2, REG_X87_TOP), il.Const(2, 1))));
		break;

	case XED_ICLASS_FISUB:
		il.AddInstruction(il.SetRegister(10, XED_REG_ST0,
			il.FloatSub(10,
				il.Register(10, XED_REG_ST0),
				il.IntToFloat(10, ReadILOperand(il, xedd, addr, 1, 1)),
			IL_FLAGWRITE_X87RND)));
		break;

	case XED_ICLASS_FSUBR:
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0,
			il.FloatSub(10,
				ReadFloatILOperand(il, xedd, addr, 1, 1),
				ReadFloatILOperand(il, xedd, addr, 0, 0),
			IL_FLAGWRITE_X87RND)));
		break;

	case XED_ICLASS_FSUBRP:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.FloatSub(10,
					ReadFloatILOperand(il, xedd, addr, 1, 1),
					ReadFloatILOperand(il, xedd, addr, 0, 0),
			IL_FLAGWRITE_X87RND)));
		il.AddInstruction(il.RegisterStackFreeReg(XED_REG_ST0));
		il.AddInstruction(il.SetRegister(2, REG_X87_TOP, il.Add(2, il.Register(2, REG_X87_TOP), il.Const(2, 1))));
		break;

	case XED_ICLASS_FISUBR:
		il.AddInstruction(
			il.SetRegister(10,
			  XED_REG_ST0,
					il.FloatSub(10,
						il.IntToFloat(10,
							ReadILOperand(il, xedd, addr, 1, 1)),
						il.Register(10, XED_REG_ST0),
			IL_FLAGWRITE_X87RND)));
		break;

	case XED_ICLASS_FMUL:
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0,
			il.FloatMult(10,
				ReadFloatILOperand(il, xedd, addr, 0, 0),
				ReadFloatILOperand(il, xedd, addr, 1, 1),
			IL_FLAGWRITE_X87RND)));
		break;

	case XED_ICLASS_FMULP:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
			il.FloatMult(10,
				ReadFloatILOperand(il, xedd, addr, 0, 0),
				ReadFloatILOperand(il, xedd, addr, 1, 1),
			IL_FLAGWRITE_X87RND)));
		il.AddInstruction(il.RegisterStackFreeReg(XED_REG_ST0));
		il.AddInstruction(il.SetRegister(2, REG_X87_TOP, il.Add(2, il.Register(2, REG_X87_TOP), il.Const(2, 1))));
		break;

	case XED_ICLASS_FIMUL:
		il.AddInstruction(
			il.SetRegister(10, XED_REG_ST0,
				il.FloatMult(10,
					il.Register(10, XED_REG_ST0),
					il.IntToFloat(10,
						ReadILOperand(il, xedd, addr, 1, 1)),
			IL_FLAGWRITE_X87RND)));
		break;

	case XED_ICLASS_FDIV:
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0,
			il.FloatDiv(10,
				ReadFloatILOperand(il, xedd, addr, 0, 0),
				ReadFloatILOperand(il, xedd, addr, 1, 1),
			IL_FLAGWRITE_X87RND)));
		break;

	case XED_ICLASS_FDIVP:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.FloatDiv(10,
					ReadFloatILOperand(il, xedd, addr, 0, 0),
					ReadFloatILOperand(il, xedd, addr, 1, 1),
			IL_FLAGWRITE_X87RND)));
		il.AddInstruction(il.RegisterStackFreeReg(XED_REG_ST0));
		il.AddInstruction(il.SetRegister(2, REG_X87_TOP, il.Add(2, il.Register(2, REG_X87_TOP), il.Const(2, 1))));
		break;

	case XED_ICLASS_FIDIV:
		il.AddInstruction(
			il.SetRegister(10, XED_REG_ST0,
			il.FloatDiv(10,
				il.Register(10, XED_REG_ST0),
				il.IntToFloat(10,
					ReadILOperand(il, xedd, addr, 1, 1)),
			IL_FLAGWRITE_X87RND)));
		break;

	case XED_ICLASS_FDIVR:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
			il.FloatDiv(10,
				ReadFloatILOperand(il, xedd, addr, 1, 1),
				ReadFloatILOperand(il, xedd, addr, 0, 0),
			IL_FLAGWRITE_X87RND)));
		break;

	case XED_ICLASS_FDIVRP:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.FloatDiv(10,
					ReadFloatILOperand(il, xedd, addr, 1, 1),
					il.Register(10, XED_REG_ST0))));
		il.AddInstruction(il.RegisterStackFreeReg(XED_REG_ST0));
		il.AddInstruction(il.SetRegister(2, REG_X87_TOP, il.Add(2, il.Register(2, REG_X87_TOP), il.Const(2, 1))));
		break;

	case XED_ICLASS_FIDIVR:
		il.AddInstruction(
			il.SetRegister(10, XED_REG_ST0,
				il.FloatDiv(10,
					il.IntToFloat(10,
						ReadILOperand(il, xedd, addr, 1, 1)),
						il.Register(10, XED_REG_ST0),
			IL_FLAGWRITE_X87RND)));
		break;

	case XED_ICLASS_FABS:
		il.AddInstruction(il.SetRegister(10, XED_REG_ST0, il.FloatAbs(10, il.Register(10, XED_REG_ST0), IL_FLAGWRITE_X87C1Z)));
		break;

	case XED_ICLASS_FCHS:
		il.AddInstruction(il.SetRegister(10, XED_REG_ST0, il.FloatNeg(10, il.Register(10, XED_REG_ST0), IL_FLAGWRITE_X87C1Z)));
		break;

	case XED_ICLASS_FDECSTP:
		il.AddInstruction(il.SetRegister(2, REG_X87_TOP, il.Sub(2, il.Register(2, REG_X87_TOP), il.Const(2, 1),
			IL_FLAGWRITE_X87C1Z)));
		break;

	case XED_ICLASS_FINCSTP:
		il.AddInstruction(il.SetRegister(2, REG_X87_TOP, il.Add(2, il.Register(2, REG_X87_TOP), il.Const(2, 1),
			IL_FLAGWRITE_X87C1Z)));
		break;

	case XED_ICLASS_FFREE:
		il.AddInstruction(il.RegisterStackFreeReg(regOne));
		break;

	case XED_ICLASS_EMMS:
		for (uint32_t i = 0; i < 8; i++)
			il.AddInstruction(il.RegisterStackFreeReg(REG_X87_r(i)));
		break;

	case XED_ICLASS_FNINIT:
		for (uint32_t i = 0; i < 8; i++)
			il.AddInstruction(il.RegisterStackFreeReg(REG_X87_r(i)));
		il.AddInstruction(il.SetRegister(2, REG_X87_TOP, il.Const(2, 0)));
		break;

	case XED_ICLASS_FSQRT:
		il.AddInstruction(il.SetRegister(10, XED_REG_ST0, il.FloatSqrt(10, il.Register(10, XED_REG_ST0), IL_FLAGWRITE_X87RND)));
		break;

	case XED_ICLASS_FXCH:
		il.AddInstruction(il.SetRegister(10, LLIL_TEMP(0), ReadFloatILOperand(il, xedd, addr, 0, 0), IL_FLAGWRITE_X87C1Z));
		il.AddInstruction(WriteILOperand(il, xedd, addr, 0, 0, ReadFloatILOperand(il, xedd, addr, 1, 1)));
		il.AddInstruction(WriteILOperand(il, xedd, addr, 1, 1, il.Register(10, LLIL_TEMP(0))));
		break;

	case XED_ICLASS_VUCOMISS:
	case XED_ICLASS_UCOMISS:
	case XED_ICLASS_COMISS:
		il.AddInstruction(
			il.FloatSub(4,
				ReadFloatILOperand(il, xedd, addr, 0, 0, 4),
				ReadFloatILOperand(il, xedd, addr, 1, 1, 4),
			IL_FLAGWRITE_VCOMI));
		break;

	case XED_ICLASS_VUCOMISD:
	case XED_ICLASS_UCOMISD:
	case XED_ICLASS_COMISD:
		il.AddInstruction(
			il.FloatSub(8,
				ReadFloatILOperand(il, xedd, addr, 0, 0, 8),
				ReadFloatILOperand(il, xedd, addr, 1, 1, 8),
			IL_FLAGWRITE_VCOMI));
		break;

	case XED_ICLASS_FCOMI:
	case XED_ICLASS_FUCOMI:
		il.AddInstruction(
			il.FloatSub(10,
				ReadFloatILOperand(il, xedd, addr, 0, 0),
				ReadFloatILOperand(il, xedd, addr, 1, 1),
			IL_FLAGWRITE_X87COMI));
		break;

	case XED_ICLASS_FCOMIP:
	case XED_ICLASS_FUCOMIP:
		il.AddInstruction(
			il.FloatSub(10,
				ReadFloatILOperand(il, xedd, addr, 0, 0),
				ReadFloatILOperand(il, xedd, addr, 1, 1),
			IL_FLAGWRITE_X87COMI));
		il.AddInstruction(il.RegisterStackFreeReg(XED_REG_ST0));
		il.AddInstruction(il.SetRegister(2, REG_X87_TOP, il.Add(2, il.Register(2, REG_X87_TOP), il.Const(2, 1))));
		break;

	case XED_ICLASS_FCOM:
	case XED_ICLASS_FUCOM:
		il.AddInstruction(
			il.FloatSub(10,
				il.Register(10, XED_REG_ST0),
				ReadFloatILOperand(il, xedd, addr, 1, 1),
			IL_FLAGWRITE_X87COM));
		break;

	case XED_ICLASS_FICOM:
		il.AddInstruction(
			il.FloatSub(10,
				il.Register(10, XED_REG_ST0),
				il.IntToFloat(10,
					ReadILOperand(il, xedd, addr, 1, 1)),
			IL_FLAGWRITE_X87COM));
		break;

	case XED_ICLASS_FCOMP:
	case XED_ICLASS_FUCOMP:
		il.AddInstruction(
			il.FloatSub(10,
				il.Register(10, XED_REG_ST0),
				ReadFloatILOperand(il, xedd, addr, 1, 1),
			IL_FLAGWRITE_X87COM));
		il.AddInstruction(il.RegisterStackFreeReg(XED_REG_ST0));
		il.AddInstruction(il.SetRegister(2, REG_X87_TOP, il.Add(2, il.Register(2, REG_X87_TOP), il.Const(2, 1))));
		break;

	case XED_ICLASS_FICOMP:
		il.AddInstruction(
			il.FloatSub(10,
				il.Register(10, XED_REG_ST0),
				il.IntToFloat(10,
					ReadILOperand(il, xedd, addr, 1, 1)),
			IL_FLAGWRITE_X87COM));
		il.AddInstruction(il.RegisterStackFreeReg(XED_REG_ST0));
		il.AddInstruction(il.SetRegister(2, REG_X87_TOP, il.Add(2, il.Register(2, REG_X87_TOP), il.Const(2, 1))));
		break;

	case XED_ICLASS_FCOMPP:
	case XED_ICLASS_FUCOMPP:
		il.AddInstruction(il.FloatSub(10, il.Register(10, XED_REG_ST0), il.Register(10, XED_REG_ST1),
			IL_FLAGWRITE_X87COM));
		il.AddInstruction(il.RegisterStackFreeReg(XED_REG_ST0));
		il.AddInstruction(il.RegisterStackFreeReg(XED_REG_ST1));
		il.AddInstruction(il.SetRegister(2, REG_X87_TOP, il.Add(2, il.Register(2, REG_X87_TOP), il.Const(2, 2))));
		break;

	case XED_ICLASS_FTST:
		il.AddInstruction(il.FloatSub(10, il.Register(10, XED_REG_ST0),
			il.IntToFloat(10, il.Const(4, 0)), IL_FLAGWRITE_X87COM));
		break;

	case XED_ICLASS_FNSTSW:
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.Or(2,
					il.FlagBit(2, IL_FLAG_C0, 8),
					il.Or(2,
						il.FlagBit(2, IL_FLAG_C1, 9),
						il.Or(2,
							il.FlagBit(2, IL_FLAG_C2, 10),
							il.Or(2,
								il.FlagBit(2, IL_FLAG_C3, 14),
								il.ShiftLeft(2,
									il.And(2,
										il.Register(2, REG_X87_TOP),
										il.Const(2, 7)),
									il.Const(2, 11))))))));
		break;

	case XED_ICLASS_F2XM1:
		il.AddInstruction(il.Intrinsic(vector<RegisterOrFlag> { RegisterOrFlag::Register(XED_REG_ST0) },
			INTRINSIC_F2XM1, vector<ExprId> { il.Register(10, XED_REG_ST0) }, IL_FLAGWRITE_X87RND));
		break;

	case XED_ICLASS_FBLD:
		il.AddInstruction(il.SetRegister(2, REG_X87_TOP, il.Sub(2, il.Register(2, REG_X87_TOP), il.Const(2, 1))));
		il.AddInstruction(il.Intrinsic(vector<RegisterOrFlag> { RegisterOrFlag::Register(XED_REG_ST0) },
			INTRINSIC_FBLD, vector<ExprId> { ReadILOperand(il, xedd, addr, 1, 1) }, IL_FLAGWRITE_X87C1Z));
		break;

	case XED_ICLASS_FBSTP:
		il.AddInstruction(il.Intrinsic(vector<RegisterOrFlag> { RegisterOrFlag::Register(LLIL_TEMP(0)) },
			INTRINSIC_FBST, vector<ExprId> { il.Register(10, XED_REG_ST0) }, IL_FLAGWRITE_X87RND));
		il.AddInstruction(
			WriteILOperand(il, xedd, addr, 0, 0,
				il.Register(10, LLIL_TEMP(0))));
		il.AddInstruction(il.RegisterStackFreeReg(XED_REG_ST0));
		il.AddInstruction(il.SetRegister(2, REG_X87_TOP, il.Add(2, il.Register(2, REG_X87_TOP), il.Const(2, 1))));
		break;

	case XED_ICLASS_FSIN:
		il.AddInstruction(il.Intrinsic(vector<RegisterOrFlag> { RegisterOrFlag::Register(XED_REG_ST0),
			RegisterOrFlag::Flag(IL_FLAG_C2) }, INTRINSIC_FSIN, vector<ExprId> { il.Register(10, XED_REG_ST0) },
			IL_FLAGWRITE_X87RND));
		break;

	case XED_ICLASS_FCOS:
		il.AddInstruction(il.Intrinsic(vector<RegisterOrFlag> { RegisterOrFlag::Register(XED_REG_ST0),
			RegisterOrFlag::Flag(IL_FLAG_C2) }, INTRINSIC_FCOS, vector<ExprId> { il.Register(10, XED_REG_ST0) },
			IL_FLAGWRITE_X87RND));
		break;

	case XED_ICLASS_FSINCOS:
		il.AddInstruction(il.SetRegister(2, REG_X87_TOP, il.Sub(2, il.Register(2, REG_X87_TOP), il.Const(2, 1))));
		il.AddInstruction(il.Intrinsic(vector<RegisterOrFlag> { RegisterOrFlag::Register(XED_REG_ST1),
			RegisterOrFlag::Register(XED_REG_ST0), RegisterOrFlag::Flag(IL_FLAG_C2) }, INTRINSIC_FSINCOS,
			vector<ExprId> { il.Register(10, XED_REG_ST1) }, IL_FLAGWRITE_X87RND));
		break;

	case XED_ICLASS_FPATAN:
		il.AddInstruction(il.Intrinsic(vector<RegisterOrFlag> { RegisterOrFlag::Register(XED_REG_ST1) },
			INTRINSIC_FPATAN, vector<ExprId> { il.Register(10, XED_REG_ST0), il.Register(10, XED_REG_ST1) }, IL_FLAGWRITE_X87RND));
		il.AddInstruction(il.RegisterStackFreeReg(XED_REG_ST0));
		il.AddInstruction(il.SetRegister(2, REG_X87_TOP, il.Add(2, il.Register(2, REG_X87_TOP), il.Const(2, 1))));
		break;

	case XED_ICLASS_FPREM:
		il.AddInstruction(il.Intrinsic(vector<RegisterOrFlag> { RegisterOrFlag::Register(XED_REG_ST0),
			RegisterOrFlag::Flag(IL_FLAG_C2), RegisterOrFlag::Register(LLIL_TEMP(0)) }, INTRINSIC_FPREM,
			vector<ExprId> { il.Register(10, XED_REG_ST0), il.Register(10, XED_REG_ST1) }));
		il.AddInstruction(il.If(il.Flag(IL_FLAG_C2), doneLabel, falseLabel));
		il.MarkLabel(falseLabel);
		il.AddInstruction(il.SetFlag(IL_FLAG_C0, il.CompareNotEqual(1,
			il.And(1, il.Register(1, LLIL_TEMP(0)), il.Const(1, 4)), il.Const(1, 0))));
		il.AddInstruction(il.SetFlag(IL_FLAG_C1, il.CompareNotEqual(1,
			il.And(1, il.Register(1, LLIL_TEMP(0)), il.Const(1, 1)), il.Const(1, 0))));
		il.AddInstruction(il.SetFlag(IL_FLAG_C3, il.CompareNotEqual(1,
			il.And(1, il.Register(1, LLIL_TEMP(0)), il.Const(1, 2)), il.Const(1, 0))));
		il.AddInstruction(il.Goto(doneLabel));
		il.MarkLabel(doneLabel);
		break;

	case XED_ICLASS_FPREM1:
		il.AddInstruction(il.Intrinsic(vector<RegisterOrFlag> { RegisterOrFlag::Register(XED_REG_ST0),
			RegisterOrFlag::Flag(IL_FLAG_C2), RegisterOrFlag::Register(LLIL_TEMP(0)) }, INTRINSIC_FPREM1,
			vector<ExprId> { il.Register(10, XED_REG_ST0), il.Register(10, XED_REG_ST1) }));
		il.AddInstruction(il.If(il.Flag(IL_FLAG_C2), doneLabel, falseLabel));
		il.MarkLabel(falseLabel);
		il.AddInstruction(il.SetFlag(IL_FLAG_C0, il.CompareNotEqual(1,
			il.And(1, il.Register(1, LLIL_TEMP(0)), il.Const(1, 4)), il.Const(1, 0))));
		il.AddInstruction(il.SetFlag(IL_FLAG_C1, il.CompareNotEqual(1,
			il.And(1, il.Register(1, LLIL_TEMP(0)), il.Const(1, 1)), il.Const(1, 0))));
		il.AddInstruction(il.SetFlag(IL_FLAG_C3, il.CompareNotEqual(1,
			il.And(1, il.Register(1, LLIL_TEMP(0)), il.Const(1, 2)), il.Const(1, 0))));
		il.AddInstruction(il.Goto(doneLabel));
		il.MarkLabel(doneLabel);
		break;

	case XED_ICLASS_FPTAN:
		il.AddInstruction(il.Intrinsic(vector<RegisterOrFlag> { RegisterOrFlag::Register(XED_REG_ST0),
			RegisterOrFlag::Flag(IL_FLAG_C2) }, INTRINSIC_FPTAN, vector<ExprId> { il.Register(10, XED_REG_ST0) },
			IL_FLAGWRITE_X87RND));
		il.AddInstruction(il.If(il.Flag(IL_FLAG_C2), doneLabel, falseLabel));
		il.MarkLabel(falseLabel);
		il.AddInstruction(il.RegisterStackPush(10, REG_STACK_X87, il.IntToFloat(10, il.Const(4, 1))));
		il.AddInstruction(il.Goto(doneLabel));
		il.MarkLabel(doneLabel);
		break;

	case XED_ICLASS_FRNDINT:
		il.AddInstruction(il.SetRegister(10, XED_REG_ST0, il.RoundToInt(10, il.Register(10, XED_REG_ST0), IL_FLAGWRITE_X87RND)));
		break;

	case XED_ICLASS_FSCALE:
		il.AddInstruction(il.Intrinsic(vector<RegisterOrFlag> { RegisterOrFlag::Register(XED_REG_ST0) },
			INTRINSIC_FSCALE, vector<ExprId> { il.Register(10, XED_REG_ST0), il.Register(10, XED_REG_ST1) },
			IL_FLAGWRITE_X87RND));
		break;

	case XED_ICLASS_FXAM:
		il.AddInstruction(il.Intrinsic(vector<RegisterOrFlag> { RegisterOrFlag::Flag(IL_FLAG_C0),
			RegisterOrFlag::Flag(IL_FLAG_C1), RegisterOrFlag::Flag(IL_FLAG_C2), RegisterOrFlag::Flag(IL_FLAG_C3) },
			INTRINSIC_FXAM, vector<ExprId> { il.Register(10, XED_REG_ST0) }));
		break;

	case XED_ICLASS_FXTRACT:
		il.AddInstruction(il.SetRegister(2, REG_X87_TOP, il.Sub(2, il.Register(2, REG_X87_TOP), il.Const(2, 1))));
		il.AddInstruction(il.Intrinsic(vector<RegisterOrFlag> { RegisterOrFlag::Register(XED_REG_ST0),
			RegisterOrFlag::Register(XED_REG_ST1) }, INTRINSIC_FXTRACT, vector<ExprId> { il.Register(10, XED_REG_ST1) },
			IL_FLAGWRITE_X87C1Z));
		break;

	case XED_ICLASS_FYL2X:
		il.AddInstruction(il.Intrinsic(vector<RegisterOrFlag> { RegisterOrFlag::Register(XED_REG_ST1) },
			INTRINSIC_FYL2X, vector<ExprId> { il.Register(10, XED_REG_ST0), il.Register(10, XED_REG_ST1) },
			IL_FLAGWRITE_X87RND));
		il.AddInstruction(il.RegisterStackFreeReg(XED_REG_ST0));
		il.AddInstruction(il.SetRegister(2, REG_X87_TOP, il.Add(2, il.Register(2, REG_X87_TOP), il.Const(2, 1))));
		break;

	case XED_ICLASS_FYL2XP1:
		il.AddInstruction(il.Intrinsic(vector<RegisterOrFlag> { RegisterOrFlag::Register(XED_REG_ST1) },
			INTRINSIC_FYL2XP1, vector<ExprId> { il.Register(10, XED_REG_ST0), il.Register(10, XED_REG_ST1) },
			IL_FLAGWRITE_X87RND));
		il.AddInstruction(il.RegisterStackFreeReg(XED_REG_ST0));
		il.AddInstruction(il.SetRegister(2, REG_X87_TOP, il.Add(2, il.Register(2, REG_X87_TOP), il.Const(2, 1))));
		break;

	case XED_ICLASS_TZCNT:
	{
		if (opOneLen == 8)
			il.AddInstruction(
				il.Intrinsic(
					vector<RegisterOrFlag> { RegisterOrFlag::Register(regOne) },
					INTRINSIC_XED_IFORM_TZCNT_GPR64_GPRMEM64,
					vector<ExprId> { ReadILOperand(il, xedd, addr, 1, 1) } ));
		else if (opOneLen == 4)
			il.AddInstruction(
				il.Intrinsic(
					vector<RegisterOrFlag> { RegisterOrFlag::Register(regOne) },
					INTRINSIC_XED_IFORM_TZCNT_GPR32_GPRMEM32,
					vector<ExprId> { ReadILOperand(il, xedd, addr, 1, 1) } ));
		else
			il.AddInstruction(
				il.Intrinsic(
					vector<RegisterOrFlag> { RegisterOrFlag::Register(regOne) },
					INTRINSIC_XED_IFORM_TZCNT_GPR16_GPRMEM16,
					vector<ExprId> { ReadILOperand(il, xedd, addr, 1, 1) } ));

		break;
	}

	case XED_ICLASS_LZCNT:
	{
		if (opOneLen == 8)
			il.AddInstruction(
				il.Intrinsic(
					vector<RegisterOrFlag> { RegisterOrFlag::Register(regOne) },
					INTRINSIC_XED_IFORM_LZCNT_GPR64_GPRMEM64,
					vector<ExprId> { ReadILOperand(il, xedd, addr, 1, 1) }
				)
			);
		else if (opOneLen == 4)
			il.AddInstruction(
				il.Intrinsic(
					vector<RegisterOrFlag> { RegisterOrFlag::Register(regOne) },
					INTRINSIC_XED_IFORM_LZCNT_GPR32_GPRMEM32,
					vector<ExprId> { ReadILOperand(il, xedd, addr, 1, 1) } ));
		else
			il.AddInstruction(
				il.Intrinsic(
					vector<RegisterOrFlag> { RegisterOrFlag::Register(regOne) },
					INTRINSIC_XED_IFORM_LZCNT_GPR16_GPRMEM16,
					vector<ExprId> { ReadILOperand(il, xedd, addr, 1, 1) } ));

		break;
	}

	case XED_ICLASS_POPCNT:
	{
		if (opOneLen == 8)
			il.AddInstruction(
				il.Intrinsic(
					vector<RegisterOrFlag> { RegisterOrFlag::Register(regOne) },
					INTRINSIC_XED_IFORM_POPCNT_GPR64_GPRMEM64,
					vector<ExprId> { ReadILOperand(il, xedd, addr, 1, 1) }
				)
			);
		else if (opOneLen == 4)
			il.AddInstruction(
				il.Intrinsic(
					vector<RegisterOrFlag> { RegisterOrFlag::Register(regOne) },
					INTRINSIC_XED_IFORM_POPCNT_GPR32_GPRMEM32,
					vector<ExprId> { ReadILOperand(il, xedd, addr, 1, 1) } ));
		else
			il.AddInstruction(
				il.Intrinsic(
					vector<RegisterOrFlag> { RegisterOrFlag::Register(regOne) },
					INTRINSIC_XED_IFORM_POPCNT_GPR16_GPRMEM16,
					vector<ExprId> { ReadILOperand(il, xedd, addr, 1, 1) } ));

		break;
	}

	default:
		LiftAsIntrinsic();
		break;
	}

	return true;
}
