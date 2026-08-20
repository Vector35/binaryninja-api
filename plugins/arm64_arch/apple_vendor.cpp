// Copyright (c) 2026 Vector 35 Inc
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

#include "apple_vendor.h"

#include <string.h>

#include "disassembler/regs.h"

using namespace BinaryNinja;
using namespace std;

namespace {

enum AppleVendorOp
{
	AV_NONE,
	AV_GENTER,
	AV_GEXIT,
	AV_SDSB,
	AV_WKDMC,
	AV_WKDMD,
	AV_AT_AS1ELX,
	AV_MUL53LO,
	AV_MUL53HI,
	AV_AMX,
	AV_APPLE_UNKNOWN_SPTM,
};

struct AppleVendorInsn
{
	AppleVendorOp op = AV_NONE;
	uint32_t imm = 0;  // genter selector, sdsb domain
	uint32_t rd = 0;   // destination register field, or the single operand of at
	uint32_t rs = 0;   // source register field
};

const char* const SDSB_DOMAIN[4] = {"osh", "nsh", "ish", "sy"};

// AMX operation names indexed by the op field (bits [9:5])
// Op 17 is the enable/disable pair (set/clr) and is rendered specially.
// https://github.com/corsix/amx
const char* const AMX_OPS[23] = {
	"ldx", "ldy", "stx", "sty", "ldz", "stz", "ldzi", "stzi", "extrx", "extry", "fma64", "fms64",
	"fma32", "fms32", "mac16", "fma16", "fms16", "set", "vecint", "vecfp", "matint", "matfp", "genlut",
};

bool Decode(uint32_t insn, AppleVendorInsn& out)
{
	if ((insn & 0xffffffe0) == 0x00201420)  // genter #imm5
	{
		out.op = AV_GENTER;
		out.imm = insn & 0x1f;
		return true;
	}
	if (insn == 0x00201400)  // gexit
	{
		out.op = AV_GEXIT;
		return true;
	}
	if ((insn & 0xfffffffc) == 0x00201460)  // sdsb <domain>
	{
		out.op = AV_SDSB;
		out.imm = insn & 0x3;
		return true;
	}
	if ((insn & 0xffffffe0) == 0x00201440)  // at_as1elx <Xt>
	{
		out.op = AV_AT_AS1ELX;
		out.rd = insn & 0x1f;
		return true;
	}
	if ((insn & 0xfffffc00) == 0x00200800)  // wkdmc <Xd>, <Xs>
	{
		out.op = AV_WKDMC;
		out.rd = (insn >> 5) & 0x1f;
		out.rs = insn & 0x1f;
		return true;
	}
	if ((insn & 0xfffffc00) == 0x00200c00)  // wkdmd <Xd>, <Xs>
	{
		out.op = AV_WKDMD;
		out.rd = (insn >> 5) & 0x1f;
		out.rs = insn & 0x1f;
		return true;
	}
	if ((insn & 0xfffffc00) == 0x00201000)  // AMX: 0x00201000 | op<<5 | operand
	{
		uint32_t op = (insn >> 5) & 0x1f;
		if (op <= 22)  // ops 23-31 are reserved holes that fault as undefined
		{
			out.op = AV_AMX;
			out.imm = op;           // AMX operation number
			out.rd = insn & 0x1f;   // GPR operand (or set/clr selector for op 17)
			return true;
		}
	}
	if ((insn & 0xfffff800) == 0x00200000)  // mul53lo/mul53hi <Vd>.2d, <Vm>.2d
	{
		// Bit 10 selects hi vs lo. The source field is at bits [9:5]. This placement (rather than
		// [12:8]) is the only one consistent with bit 10 acting as the lo/hi selector.
		//
		// TODO: Confirm how the source vector register is encoded.
		out.op = (insn & 0x400) ? AV_MUL53HI : AV_MUL53LO;
		out.rd = insn & 0x1f;
		out.rs = (insn >> 5) & 0x1f;
		return true;
	}
	if ((insn & 0xffe0001f) == 0xd4e00000)  // Apple exception-generation instruction (opc 0b111)
	{
		// An SPTM/TXM monitor entry, per kernelcache symbols such as _txm_enter. It is an
		// exception-based alternative to genter, chosen at runtime by _libsptm_has_perms_overlay, and
		// occupies the opc == 0b111 slot that ARM leaves unallocated in the encoding class holding
		// svc/hvc/smc/brk. The imm16 at bits [20:5] is zero in every observed use, with the selector
		// passed in x16 as it is for genter.
		//
		// TODO: `apple_unknown_sptm` is a temporary name. Replace it and add lifting once there's more
		// information available.
		out.op = AV_APPLE_UNKNOWN_SPTM;
		out.imm = (insn >> 5) & 0xffff;
		return true;
	}
	return false;
}

// Immediates render the way the base disassembler's `%#x` format does: a bare `0` for zero, and a
// `0x` prefix otherwise.
string ImmText(uint32_t imm)
{
	return imm ? fmt::format("{:#x}", imm) : "0";
}

string GprName(uint32_t field)
{
	return field == 31 ? "xzr" : "x" + to_string(field);
}

string VecName(uint32_t field)
{
	return "v" + to_string(field);
}

uint32_t GprReg(uint32_t field)
{
	return field == 31 ? REG_XZR : (REG_X0 + field);
}

uint32_t VecReg(uint32_t field)
{
	return REG_V0 + field;
}

void EmitMnemonic(const char* mnemonic, vector<InstructionTextToken>& result)
{
	result.emplace_back(InstructionToken, mnemonic);
	size_t len = strlen(mnemonic);
	string pad = len < 8 ? string(8 - len, ' ') : string(1, ' ');
	result.emplace_back(TextToken, pad);
}

void EmitRegister(const string& name, vector<InstructionTextToken>& result)
{
	result.emplace_back(RegisterToken, name);
}

}  // namespace

bool AppleVendorGetInstructionInfo(uint32_t insn, uint64_t addr, InstructionInfo& result)
{
	(void)addr;
	AppleVendorInsn decoded;
	if (!Decode(insn, decoded))
		return false;

	result.length = 4;
	switch (decoded.op)
	{
	case AV_GENTER:
	case AV_APPLE_UNKNOWN_SPTM:
		// These enter the monitor like an exception entry. Control returns after the handler for the
		// common (non-terminal) selectors.
		result.AddBranch(SystemCall);
		break;
	case AV_GEXIT:
		// gexit returns from guarded mode and does not fall through, like eret.
		result.AddBranch(FunctionReturn);
		break;
	default:
		break;
	}
	return true;
}

bool AppleVendorGetInstructionText(uint32_t insn, vector<InstructionTextToken>& result)
{
	AppleVendorInsn decoded;
	if (!Decode(insn, decoded))
		return false;

	switch (decoded.op)
	{
	case AV_GENTER:
		EmitMnemonic("genter", result);
		result.emplace_back(TextToken, "#");
		result.emplace_back(IntegerToken, ImmText(decoded.imm), decoded.imm);
		break;
	case AV_GEXIT:
		EmitMnemonic("gexit", result);
		break;
	case AV_SDSB:
		EmitMnemonic("sdsb", result);
		result.emplace_back(TextToken, SDSB_DOMAIN[decoded.imm]);
		break;
	case AV_WKDMC:
	case AV_WKDMD:
		EmitMnemonic(decoded.op == AV_WKDMC ? "wkdmc" : "wkdmd", result);
		EmitRegister(GprName(decoded.rd), result);
		result.emplace_back(OperandSeparatorToken, ", ");
		EmitRegister(GprName(decoded.rs), result);
		break;
	case AV_AT_AS1ELX:
		EmitMnemonic("at_as1elx", result);
		EmitRegister(GprName(decoded.rd), result);
		break;
	case AV_MUL53LO:
	case AV_MUL53HI:
		EmitMnemonic(decoded.op == AV_MUL53LO ? "mul53lo" : "mul53hi", result);
		EmitRegister(VecName(decoded.rd), result);
		result.emplace_back(TextToken, ".2d");
		result.emplace_back(OperandSeparatorToken, ", ");
		EmitRegister(VecName(decoded.rs), result);
		result.emplace_back(TextToken, ".2d");
		break;
	case AV_AMX:
	{
		// Op 17 is the enable/disable pair (amx_set/amx_clr) and carries no register operand.
		// Every other op takes a single GPR that holds a packed pointer/configuration word.
		string mnemonic = decoded.imm == 17 ? (decoded.rd == 1 ? "amx_clr" : "amx_set")
		                                    : string("amx_") + AMX_OPS[decoded.imm];
		EmitMnemonic(mnemonic.c_str(), result);
		if (decoded.imm != 17)
			EmitRegister(GprName(decoded.rd), result);
		break;
	}
	case AV_APPLE_UNKNOWN_SPTM:
		EmitMnemonic("apple_unknown_sptm", result);
		result.emplace_back(TextToken, "#");
		result.emplace_back(IntegerToken, ImmText(decoded.imm), decoded.imm);
		break;
	default:
		return false;
	}
	return true;
}

optional<bool> AppleVendorGetInstructionLowLevelIL(uint32_t insn, LowLevelILFunction& il)
{
	AppleVendorInsn decoded;
	if (!Decode(insn, decoded))
		return nullopt;

	switch (decoded.op)
	{
	case AV_GENTER:
		il.AddInstruction(il.Intrinsic({}, APPLE_INTRIN_GENTER, {il.Const(4, decoded.imm)}));
		break;
	case AV_GEXIT:
		// gexit returns from guarded mode like eret and does not fall through.
		il.AddInstruction(il.Intrinsic({}, APPLE_INTRIN_GEXIT, {}));
		il.AddInstruction(il.Trap(0));
		return false;
	case AV_SDSB:
		il.AddInstruction(il.Intrinsic({}, APPLE_INTRIN_SDSB, {il.Const(4, decoded.imm)}));
		break;
	case AV_WKDMC:
	case AV_WKDMD:
		// Xd and Xs are addresses. The result is written to the memory at Xd, and the only register
		// written is Xs, which receives a status word.
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(GprReg(decoded.rs))},
		    decoded.op == AV_WKDMC ? APPLE_INTRIN_WKDMC : APPLE_INTRIN_WKDMD,
		    {il.Register(8, GprReg(decoded.rd)), il.Register(8, GprReg(decoded.rs))}));
		break;
	case AV_AT_AS1ELX:
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(GprReg(decoded.rd))}, APPLE_INTRIN_AT_AS1ELX,
		    {il.Register(8, GprReg(decoded.rd))}));
		break;
	case AV_MUL53LO:
	case AV_MUL53HI:
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(VecReg(decoded.rd))},
		    decoded.op == AV_MUL53LO ? APPLE_INTRIN_MUL53LO : APPLE_INTRIN_MUL53HI,
		    {il.Register(16, VecReg(decoded.rd)), il.Register(16, VecReg(decoded.rs))}));
		break;
	case AV_AMX:
	case AV_APPLE_UNKNOWN_SPTM:
		// Not yet lifted.
		il.AddInstruction(il.Unimplemented());
		break;
	default:
		break;
	}
	return true;
}

bool AppleVendorIsIntrinsic(uint32_t intrinsic)
{
	return intrinsic >= APPLE_INTRIN_GENTER && intrinsic < APPLE_INTRIN_END;
}

void AppleVendorGetAllIntrinsics(vector<uint32_t>& result)
{
	for (uint32_t id = APPLE_INTRIN_GENTER; id < APPLE_INTRIN_END; id++)
		result.push_back(id);
}

string AppleVendorGetIntrinsicName(uint32_t intrinsic)
{
	switch (intrinsic)
	{
	case APPLE_INTRIN_GENTER:
		return "__genter";
	case APPLE_INTRIN_GEXIT:
		return "__gexit";
	case APPLE_INTRIN_SDSB:
		return "__sdsb";
	case APPLE_INTRIN_WKDMC:
		return "__wkdmc";
	case APPLE_INTRIN_WKDMD:
		return "__wkdmd";
	case APPLE_INTRIN_AT_AS1ELX:
		return "__at_as1elx";
	case APPLE_INTRIN_MUL53LO:
		return "__mul53lo";
	case APPLE_INTRIN_MUL53HI:
		return "__mul53hi";
	default:
		return "";
	}
}

BNIntrinsicClass AppleVendorGetIntrinsicClass(uint32_t intrinsic)
{
	switch (intrinsic)
	{
	case APPLE_INTRIN_WKDMC:
	case APPLE_INTRIN_WKDMD:
		return MemoryIntrinsicClass;
	default:
		return GeneralIntrinsicClass;
	}
}

vector<NameAndType> AppleVendorGetIntrinsicInputs(uint32_t intrinsic)
{
	switch (intrinsic)
	{
	case APPLE_INTRIN_GENTER:
		return {NameAndType("imm", Type::IntegerType(4, false))};
	case APPLE_INTRIN_SDSB:
		return {NameAndType("domain", Type::IntegerType(4, false))};
	case APPLE_INTRIN_WKDMC:
	case APPLE_INTRIN_WKDMD:
		return {NameAndType("dest", Type::PointerType(8, Type::VoidType())),
		    NameAndType("src", Type::PointerType(8, Type::VoidType()))};
	case APPLE_INTRIN_AT_AS1ELX:
		return {NameAndType(Type::IntegerType(8, false))};
	case APPLE_INTRIN_MUL53LO:
	case APPLE_INTRIN_MUL53HI:
		return {NameAndType(Type::IntegerType(16, false)), NameAndType(Type::IntegerType(16, false))};
	default:
		return {};
	}
}

vector<Confidence<Ref<Type>>> AppleVendorGetIntrinsicOutputs(uint32_t intrinsic)
{
	switch (intrinsic)
	{
	case APPLE_INTRIN_WKDMC:
	case APPLE_INTRIN_WKDMD:
	case APPLE_INTRIN_AT_AS1ELX:
		return {Type::IntegerType(8, false)};
	case APPLE_INTRIN_MUL53LO:
	case APPLE_INTRIN_MUL53HI:
		return {Type::IntegerType(16, false)};
	default:
		return {};
	}
}
