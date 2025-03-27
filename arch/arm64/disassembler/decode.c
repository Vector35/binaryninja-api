#include "decode.h"
#include "feature_flags.h"

int decode_spec(context* ctx, Instruction* dec);        // from decode0.cpp
int decode_scratchpad(context* ctx, Instruction* dec);  // from decode_scratchpad.c

const char* tlbi_op(int32_t op)
{
	switch (op)
	{
	case TLBI_INVALID: return "invalid";
	case TLBI_VMALLE1OS: return "vmalle1os";
	case TLBI_VAE1OS: return "vae1os";
	case TLBI_ASIDE1OS: return "aside1os";
	case TLBI_VAAE1OS: return "vaae1os";
	case TLBI_VALE1OS: return "vale1os";
	case TLBI_VAALE1OS: return "vaale1os";
	case TLBI_RVAE1IS: return "rvae1is";
	case TLBI_RVAAE1IS: return "rvaae1is";
	case TLBI_RVALE1IS: return "rvale1is";
	case TLBI_RVAALE1IS: return "rvaale1is";
	case TLBI_VMALLE1IS: return "vmalle1is";
	case TLBI_VAE1IS: return "vae1is";
	case TLBI_ASIDE1IS: return "aside1is";
	case TLBI_VAAE1IS: return "vaae1is";
	case TLBI_VALE1IS: return "vale1is";
	case TLBI_VAALE1IS: return "vaale1is";
	case TLBI_RVAE1OS: return "rvae1os";
	case TLBI_RVAAE1OS: return "rvaae1os";
	case TLBI_RVALE1OS: return "rvale1os";
	case TLBI_RVAALE1OS: return "rvaale1os";
	case TLBI_RVAE1: return "rvae1";
	case TLBI_RVAAE1: return "rvaae1";
	case TLBI_RVALE1: return "rvale1";
	case TLBI_RVAALE1: return "rvaale1";
	case TLBI_VMALLE1: return "vmalle1";
	case TLBI_VAE1: return "vae1";
	case TLBI_ASIDE1: return "aside1";
	case TLBI_VAAE1: return "vaae1";
	case TLBI_VALE1: return "vale1";
	case TLBI_VAALE1: return "vaale1";
	case TLBI_VMALLE1OSNXS: return "vmalle1osnxs";
	case TLBI_VAE1OSNXS: return "vae1osnxs";
	case TLBI_ASIDE1OSNXS: return "aside1osnxs";
	case TLBI_VAAE1OSNXS: return "vaae1osnxs";
	case TLBI_VALE1OSNXS: return "vale1osnxs";
	case TLBI_VAALE1OSNXS: return "vaale1osnxs";
	case TLBI_RVAE1ISNXS: return "rvae1isnxs";
	case TLBI_RVAAE1ISNXS: return "rvaae1isnxs";
	case TLBI_RVALE1ISNXS: return "rvale1isnxs";
	case TLBI_RVAALE1ISNXS: return "rvaale1isnxs";
	case TLBI_VMALLE1ISNXS: return "vmalle1isnxs";
	case TLBI_VAE1ISNXS: return "vae1isnxs";
	case TLBI_ASIDE1ISNXS: return "aside1isnxs";
	case TLBI_VAAE1ISNXS: return "vaae1isnxs";
	case TLBI_VALE1ISNXS: return "vale1isnxs";
	case TLBI_VAALE1ISNXS: return "vaale1isnxs";
	case TLBI_RVAE1OSNXS: return "rvae1osnxs";
	case TLBI_RVAAE1OSNXS: return "rvaae1osnxs";
	case TLBI_RVALE1OSNXS: return "rvale1osnxs";
	case TLBI_RVAALE1OSNXS: return "rvaale1osnxs";
	case TLBI_RVAE1NXS: return "rvae1nxs";
	case TLBI_RVAAE1NXS: return "rvaae1nxs";
	case TLBI_RVALE1NXS: return "rvale1nxs";
	case TLBI_RVAALE1NXS: return "rvaale1nxs";
	case TLBI_VMALLE1NXS: return "vmalle1nxs";
	case TLBI_VAE1NXS: return "vae1nxs";
	case TLBI_ASIDE1NXS: return "aside1nxs";
	case TLBI_VAAE1NXS: return "vaae1nxs";
	case TLBI_VALE1NXS: return "vale1nxs";
	case TLBI_VAALE1NXS: return "vaale1nxs";
	case TLBI_IPAS2E1IS: return "ipas2e1is";
	case TLBI_RIPAS2E1IS: return "ripas2e1is";
	case TLBI_IPAS2LE1IS: return "ipas2le1is";
	case TLBI_RIPAS2LE1IS: return "ripas2le1is";
	case TLBI_ALLE2OS: return "alle2os";
	case TLBI_VAE2OS: return "vae2os";
	case TLBI_ALLE1OS: return "alle1os";
	case TLBI_VALE2OS: return "vale2os";
	case TLBI_VMALLS12E1OS: return "vmalls12e1os";
	case TLBI_RVAE2IS: return "rvae2is";
	case TLBI_VMALLWS2E1IS: return "vmallws2e1is";
	case TLBI_RVALE2IS: return "rvale2is";
	case TLBI_ALLE2IS: return "alle2is";
	case TLBI_VAE2IS: return "vae2is";
	case TLBI_ALLE1IS: return "alle1is";
	case TLBI_VALE2IS: return "vale2is";
	case TLBI_VMALLS12E1IS: return "vmalls12e1is";
	case TLBI_IPAS2E1OS: return "ipas2e1os";
	case TLBI_IPAS2E1: return "ipas2e1";
	case TLBI_RIPAS2E1: return "ripas2e1";
	case TLBI_RIPAS2E1OS: return "ripas2e1os";
	case TLBI_IPAS2LE1OS: return "ipas2le1os";
	case TLBI_IPAS2LE1: return "ipas2le1";
	case TLBI_RIPAS2LE1: return "ripas2le1";
	case TLBI_RIPAS2LE1OS: return "ripas2le1os";
	case TLBI_RVAE2OS: return "rvae2os";
	case TLBI_VMALLWS2E1OS: return "vmallws2e1os";
	case TLBI_RVALE2OS: return "rvale2os";
	case TLBI_RVAE2: return "rvae2";
	case TLBI_VMALLWS2E1: return "vmallws2e1";
	case TLBI_RVALE2: return "rvale2";
	case TLBI_ALLE2: return "alle2";
	case TLBI_VAE2: return "vae2";
	case TLBI_ALLE1: return "alle1";
	case TLBI_VALE2: return "vale2";
	case TLBI_VMALLS12E1: return "vmalls12e1";
	case TLBI_IPAS2E1ISNXS: return "ipas2e1isnxs";
	case TLBI_RIPAS2E1ISNXS: return "ripas2e1isnxs";
	case TLBI_IPAS2LE1ISNXS: return "ipas2le1isnxs";
	case TLBI_RIPAS2LE1ISNXS: return "ripas2le1isnxs";
	case TLBI_ALLE2OSNXS: return "alle2osnxs";
	case TLBI_VAE2OSNXS: return "vae2osnxs";
	case TLBI_ALLE1OSNXS: return "alle1osnxs";
	case TLBI_VALE2OSNXS: return "vale2osnxs";
	case TLBI_VMALLS12E1OSNXS: return "vmalls12e1osnxs";
	case TLBI_RVAE2ISNXS: return "rvae2isnxs";
	case TLBI_VMALLWS2E1ISNXS: return "vmallws2e1isnxs";
	case TLBI_RVALE2ISNXS: return "rvale2isnxs";
	case TLBI_ALLE2ISNXS: return "alle2isnxs";
	case TLBI_VAE2ISNXS: return "vae2isnxs";
	case TLBI_ALLE1ISNXS: return "alle1isnxs";
	case TLBI_VALE2ISNXS: return "vale2isnxs";
	case TLBI_VMALLS12E1ISNXS: return "vmalls12e1isnxs";
	case TLBI_IPAS2E1OSNXS: return "ipas2e1osnxs";
	case TLBI_IPAS2E1NXS: return "ipas2e1nxs";
	case TLBI_RIPAS2E1NXS: return "ripas2e1nxs";
	case TLBI_RIPAS2E1OSNXS: return "ripas2e1osnxs";
	case TLBI_IPAS2LE1OSNXS: return "ipas2le1osnxs";
	case TLBI_IPAS2LE1NXS: return "ipas2le1nxs";
	case TLBI_RIPAS2LE1NXS: return "ripas2le1nxs";
	case TLBI_RIPAS2LE1OSNXS: return "ripas2le1osnxs";
	case TLBI_RVAE2OSNXS: return "rvae2osnxs";
	case TLBI_VMALLWS2E1OSNXS: return "vmallws2e1osnxs";
	case TLBI_RVALE2OSNXS: return "rvale2osnxs";
	case TLBI_RVAE2NXS: return "rvae2nxs";
	case TLBI_VMALLWS2E1NXS: return "vmallws2e1nxs";
	case TLBI_RVALE2NXS: return "rvale2nxs";
	case TLBI_ALLE2NXS: return "alle2nxs";
	case TLBI_VAE2NXS: return "vae2nxs";
	case TLBI_ALLE1NXS: return "alle1nxs";
	case TLBI_VALE2NXS: return "vale2nxs";
	case TLBI_VMALLS12E1NXS: return "vmalls12e1nxs";
	case TLBI_ALLE3OS: return "alle3os";
	case TLBI_VAE3OS: return "vae3os";
	case TLBI_PAALLOS: return "paallos";
	case TLBI_VALE3OS: return "vale3os";
	case TLBI_RVAE3IS: return "rvae3is";
	case TLBI_RVALE3IS: return "rvale3is";
	case TLBI_ALLE3IS: return "alle3is";
	case TLBI_VAE3IS: return "vae3is";
	case TLBI_VALE3IS: return "vale3is";
	case TLBI_RPAOS: return "rpaos";
	case TLBI_RPALOS: return "rpalos";
	case TLBI_RVAE3OS: return "rvae3os";
	case TLBI_RVALE3OS: return "rvale3os";
	case TLBI_RVAE3: return "rvae3";
	case TLBI_RVALE3: return "rvale3";
	case TLBI_ALLE3: return "alle3";
	case TLBI_VAE3: return "vae3";
	case TLBI_PAALL: return "paall";
	case TLBI_VALE3: return "vale3";
	case TLBI_ALLE3OSNXS: return "alle3osnxs";
	case TLBI_VAE3OSNXS: return "vae3osnxs";
	case TLBI_VALE3OSNXS: return "vale3osnxs";
	case TLBI_RVAE3ISNXS: return "rvae3isnxs";
	case TLBI_RVALE3ISNXS: return "rvale3isnxs";
	case TLBI_ALLE3ISNXS: return "alle3isnxs";
	case TLBI_VAE3ISNXS: return "vae3isnxs";
	case TLBI_VALE3ISNXS: return "vale3isnxs";
	case TLBI_RVAE3OSNXS: return "rvae3osnxs";
	case TLBI_RVALE3OSNXS: return "rvale3osnxs";
	case TLBI_RVAE3NXS: return "rvae3nxs";
	case TLBI_RVALE3NXS: return "rvale3nxs";
	case TLBI_ALLE3NXS: return "alle3nxs";
	case TLBI_VAE3NXS: return "vae3nxs";
	case TLBI_VALE3NXS: return "vale3nxs";
	default: return "error";
	}
}

const char* at_op(int32_t op)
{
	switch (op)
	{
	case AT_OP_INVALID: return "invalid";
	case AT_OP(0b000, 0b1000, 0b000): return "S1E1R";
	case AT_OP(0b000, 0b1000, 0b001): return "S1E1W";
	case AT_OP(0b000, 0b1000, 0b010): return "S1E0R";
	case AT_OP(0b000, 0b1000, 0b011): return "S1E0W";
	case AT_OP(0b000, 0b1001, 0b000): return "S1E1RP";
	case AT_OP(0b000, 0b1001, 0b001): return "S1E1WP";
	case AT_OP(0b000, 0b1001, 0b010): return "S1E1A";
	case AT_OP(0b100, 0b1000, 0b000): return "S1E2R";
	case AT_OP(0b100, 0b1000, 0b001): return "S1E2W";
	case AT_OP(0b100, 0b1000, 0b100): return "S12E1R";
	case AT_OP(0b100, 0b1000, 0b101): return "S12E1W";
	case AT_OP(0b100, 0b1000, 0b110): return "S12E0R";
	case AT_OP(0b100, 0b1000, 0b111): return "S12E0W";
	case AT_OP(0b100, 0b1001, 0b010): return "S1E2A";
	case AT_OP(0b110, 0b1000, 0b000): return "S1E3R";
	case AT_OP(0b110, 0b1000, 0b001): return "S1E3W";
	case AT_OP(0b110, 0b1001, 0b010): return "S1E3A";
	default: return "error";
	}
}

int aarch64_decompose(uint32_t instructionValue, Instruction* instr, uint64_t address)
{
	context ctx = {0};
	ctx.halted = 1;  // enable disassembly of exception instructions like DCPS1
	ctx.insword = instructionValue;
	ctx.address = address;
	ctx.features0 = ARCH_FEATURES_ALL;
	ctx.features1 = ARCH_FEATURES_ALL;
	ctx.EDSCR_HDE = 1;

	/* have the spec-generated code populate all the pcode variables */
	int rc = decode_spec(&ctx, instr);

	if (rc != DECODE_STATUS_OK)
	{
		/* exceptional cases where we accept a non-OK decode status */
		if (rc == DECODE_STATUS_END_OF_INSTRUCTION && instr->encoding == ENC_HINT_HM_HINTS)
		{
			while (0)
				;
		}
		/* no exception! fail! */
		else
			return rc;
	}

	/* if UDF encoding, return undefined */
	// if(instr->encoding == ENC_UDF_ONLY_PERM_UNDEF)
	//	return DECODE_STATUS_UNDEFINED;

	/* convert the pcode variables to list of operands, etc. */
	return decode_scratchpad(&ctx, instr);
}
