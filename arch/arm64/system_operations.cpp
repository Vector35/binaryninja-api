#include "system_operations.h"

#include "base/assertions.h"

#include <algorithm>
#include <string>
#include <vector>


using namespace BinaryNinja;
using namespace std;

namespace {
// The distinct instructions in exarmo's system operation table, in order of first appearance.
const vector<exarmo_aarch64_mnemonic>& Instructions()
{
	static vector<exarmo_aarch64_mnemonic> instructions = [] {
		vector<exarmo_aarch64_mnemonic> found;
		for (const exarmo_aarch64_sysop_def& op : exarmo_aarch64_sysops)
		{
			// op0 is 1 for an operation SYS encodes and 0 for a PSTATE field that MSR sets.
			if (op.op0 != 1)
				continue;

			if (std::find(found.begin(), found.end(), op.instruction) == found.end())
				found.push_back(op.instruction);
		}

		BN_RELEASE_ASSERT(found.size() == EXARMO_AARCH64_SYSOP_INSTRUCTION_COUNT);
		return found;
	}();

	return instructions;
}


string InstructionName(exarmo_aarch64_mnemonic instruction)
{
	exarmo_aarch64_str name = exarmo_aarch64_mnemonic_name(instruction);
	return string(name.data, name.length);
}


// The first of the instruction's operations that takes a register, or null if none does. exarmo
// guarantees they all take it the same way.
const exarmo_aarch64_sysop_def* RegisterRow(exarmo_aarch64_mnemonic instruction)
{
	for (const exarmo_aarch64_sysop_def& op : exarmo_aarch64_sysops)
	{
		if (op.op0 == 1 && op.instruction == instruction && op.reg_use != EXARMO_AARCH64_SYSOP_REG_NONE)
			return &op;
	}

	return nullptr;
}


exarmo_aarch64_mnemonic IntrinsicInstruction(uint32_t intrinsic)
{
	return Instructions()[(intrinsic - SysOpIntrinsicBase) / SysOpIntrinsicsPerInstruction];
}


bool IntrinsicTakesRegister(uint32_t intrinsic)
{
	return (intrinsic - SysOpIntrinsicBase) % SysOpIntrinsicsPerInstruction;
}
}


uint32_t SysOpIntrinsic(exarmo_aarch64_mnemonic instruction, bool withRegister)
{
	const vector<exarmo_aarch64_mnemonic>& instructions = Instructions();
	auto found = std::find(instructions.begin(), instructions.end(), instruction);
	if (found == instructions.end())
		return ARM64_INTRIN_INVALID;

	size_t index = found - instructions.begin();
	return SysOpIntrinsicBase + (uint32_t)index * SysOpIntrinsicsPerInstruction + (withRegister ? 1 : 0);
}


const vector<uint32_t>& SysOpLiftedIntrinsics()
{
	static vector<uint32_t> lifted = [] {
		const vector<exarmo_aarch64_mnemonic>& instructions = Instructions();
		vector<bool> reached(instructions.size() * SysOpIntrinsicsPerInstruction);
		for (const exarmo_aarch64_sysop_def& op : exarmo_aarch64_sysops)
		{
			if (op.op0 != 1)
				continue;

			size_t index = std::find(instructions.begin(), instructions.end(), op.instruction)
			    - instructions.begin();

			// An operation that writes XZR lifts to the intrinsic without the register.
			if (op.reg_use != EXARMO_AARCH64_SYSOP_REG_REQUIRED
			    || op.reg_access == EXARMO_AARCH64_SYSOP_REG_WRITE)
				reached[index * SysOpIntrinsicsPerInstruction] = true;
			if (op.reg_use != EXARMO_AARCH64_SYSOP_REG_NONE)
				reached[index * SysOpIntrinsicsPerInstruction + 1] = true;
		}

		vector<uint32_t> ids;
		for (size_t i = 0; i < reached.size(); i++)
		{
			if (reached[i])
				ids.push_back(SysOpIntrinsicBase + (uint32_t)i);
		}

		return ids;
	}();

	return lifted;
}


string SysOpIntrinsicName(uint32_t intrinsic)
{
	if (!IsSysOpIntrinsic(intrinsic))
		return "";

	return "__" + InstructionName(IntrinsicInstruction(intrinsic));
}


vector<NameAndType> SysOpIntrinsicInputs(Architecture* arch, uint32_t intrinsic)
{
	if (!IsSysOpIntrinsic(intrinsic))
		return {};

	exarmo_aarch64_mnemonic instruction = IntrinsicInstruction(intrinsic);

	vector<NameAndType> inputs {NameAndType(InstructionName(instruction) + "_op",
	    Confidence<Ref<Type>>(
	        Type::EnumerationType(arch, SystemOperationEnumeration(instruction), 4, false),
	        BN_FULL_CONFIDENCE))};

	const exarmo_aarch64_sysop_def* row = RegisterRow(instruction);
	if (IntrinsicTakesRegister(intrinsic) && row && row->reg_access == EXARMO_AARCH64_SYSOP_REG_READ)
		inputs.push_back(NameAndType(Type::IntegerType(row->reg_bits / 8, false)));

	return inputs;
}


vector<Confidence<Ref<Type>>> SysOpIntrinsicOutputs(uint32_t intrinsic)
{
	if (!IsSysOpIntrinsic(intrinsic))
		return {};

	const exarmo_aarch64_sysop_def* row = RegisterRow(IntrinsicInstruction(intrinsic));
	if (IntrinsicTakesRegister(intrinsic) && row && row->reg_access == EXARMO_AARCH64_SYSOP_REG_WRITE)
		return {Type::IntegerType(row->reg_bits / 8, false)};

	return {};
}


Ref<Enumeration> SystemOperationEnumeration(exarmo_aarch64_mnemonic instruction)
{
	// One per instruction, in the order Instructions() gives them.
	static vector<Ref<Enumeration>> enumerations = [] {
		vector<Ref<Enumeration>> built;
		for (exarmo_aarch64_mnemonic each : Instructions())
		{
			EnumerationBuilder builder;
			for (const exarmo_aarch64_sysop_def& op : exarmo_aarch64_sysops)
			{
				if (op.op0 != 1 || op.instruction != each)
					continue;

				builder.AddMemberWithValue(string(op.name.data, op.name.length), op.encoding);
			}
			built.push_back(builder.Finalize());
		}
		return built;
	}();

	const vector<exarmo_aarch64_mnemonic>& instructions = Instructions();
	auto found = std::find(instructions.begin(), instructions.end(), instruction);
	if (found == instructions.end())
		return EnumerationBuilder().Finalize();

	return enumerations[found - instructions.begin()];
}


Ref<Enumeration> PstateFieldEnumeration()
{
	static Ref<Enumeration> fields = [] {
		EnumerationBuilder builder;
		for (const exarmo_aarch64_sysop_def& op : exarmo_aarch64_sysops)
		{
			if (op.op0 != 0)
				continue;

			builder.AddMemberWithValue(string(op.name.data, op.name.length), op.encoding);
		}
		return builder.Finalize();
	}();

	return fields;
}


bool SystemOperationAt(
    uint32_t op1, uint32_t crn, uint32_t crm, uint32_t op2, exarmo_aarch64_sysop_def& out)
{
	for (const exarmo_aarch64_sysop_def& def : exarmo_aarch64_sysops)
	{
		if (def.op0 != 1 || def.op1 != op1 || def.crn != crn || def.crm != crm || def.op2 != op2)
			continue;

		out = def;
		return true;
	}

	return false;
}


uint32_t SystemOperationNumber(const exarmo_aarch64_operand& operand)
{
	if (operand.kind != EXARMO_AARCH64_OPERAND_SYSOP
	    || operand.sysop.index >= EXARMO_AARCH64_SYSOP_COUNT)
		return 0;

	return exarmo_aarch64_sysops[operand.sysop.index].encoding;
}
