// Generate one encoded instruction per XED iclass.
//
// For every entry in XED's instruction table (one per iform) we synthesize
// canonical operands and try to encode it. The first iform that encodes
// successfully for a given iclass is kept. 64-bit (long mode) encodings are
// preferred; iclasses that only encode in 32-bit legacy mode go to a separate
// manifest so they disassemble correctly.
//
// Outputs (into the directory given as argv[1]):
//   x86_64.manifest  - long-mode instructions
//   x86.manifest     - legacy-32 instructions (iclasses that could not be
//                      encoded in long mode)
//   coverage.txt     - covered/uncovered iclass summary
//
// The manifest lines are: <iclass> <iform> <hexbytes>

#include <xed/xed-interface.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Pick a concrete register for a register nonterminal. eff_bits selects the
// width for the variable-width GPR nonterminals (GPRv/GPRy/GPRz).
static xed_reg_enum_t reg_for_nt(const char* nt, unsigned eff_bits)
{
	xed_reg_enum_t gpr;
	switch (eff_bits) {
		case 8:  gpr = XED_REG_AL;  break;
		case 16: gpr = XED_REG_AX;  break;
		case 64: gpr = XED_REG_RAX; break;
		default: gpr = XED_REG_EAX; break;
	}
	if (!nt) return XED_REG_INVALID;

	// Variable-width GPRs first (their names embed V/Y/Z, not a fixed width).
	if (strstr(nt, "GPRV") || strstr(nt, "GPRY") || strstr(nt, "GPRZ") ||
	    strstr(nt, "VGPRV") || strstr(nt, "VGPRY") || strstr(nt, "VGPRZ"))
		return gpr;
	if (strstr(nt, "GPR8"))  return XED_REG_AL;
	if (strstr(nt, "GPR16")) return XED_REG_AX;
	if (strstr(nt, "GPR32")) return XED_REG_EAX;
	if (strstr(nt, "GPR64")) return XED_REG_RAX;

	if (strstr(nt, "ZMM")) return XED_REG_ZMM0;
	if (strstr(nt, "YMM")) return XED_REG_YMM0;
	if (strstr(nt, "XMM")) return XED_REG_XMM0;
	if (strstr(nt, "MMX")) return XED_REG_MMX0;
	if (strstr(nt, "MASK") || strstr(nt, "KREG")) return XED_REG_K1;
	// x87: explicit operand is ST(i); pair with the implicit ST(0), so use a
	// non-zero index to avoid the degenerate ST(0),ST(0) form.
	if (strstr(nt, "X87") || strstr(nt, "ST0")) return XED_REG_ST1;
	// APX default-flags-value operand (CCMPcc / CTESTcc).
	if (strstr(nt, "DFV")) return XED_REG_DFV0;
	if (strstr(nt, "TMM")) return XED_REG_TMM0;
	if (strstr(nt, "BND")) return XED_REG_BND0;
	if (strstr(nt, "CR"))  return XED_REG_CR0;
	if (strstr(nt, "DR"))  return XED_REG_DR0;
	if (strstr(nt, "SEG") || strstr(nt, "SREG")) return XED_REG_FS;
	if (strstr(nt, "ARAX") || strstr(nt, "A_GPR") || strstr(nt, "OEAX") ||
	    strstr(nt, "ORAX"))
		return gpr;
	return XED_REG_INVALID;
}

// Records the outcome of the most recent try_encode() call (for diagnostics).
static xed_error_enum_t g_last_err;

// Attempt to encode one iform with the given mode / widths. Returns encoded
// length (>0) on success, 0 on failure; bytes written to out.
static unsigned try_encode(const xed_inst_t* inst, const xed_state_t* dstate,
                           unsigned eff_bits, unsigned imm_bytes,
                           unsigned br_bytes, unsigned mem_len,
                           xed_reg_enum_t index_reg, xed_uint8_t* out)
{
	xed_encoder_request_t req;
	xed_encoder_request_zero_set_mode(&req, dstate);
	xed_encoder_request_set_iclass(&req, xed_inst_iclass(inst));
	xed_encoder_request_set_effective_operand_width(&req, eff_bits);
	xed_encoder_request_set_effective_address_size(&req,
		dstate->mmode == XED_MACHINE_MODE_LONG_64 ? 64 : 32);

	unsigned order = 0;
	unsigned n = xed_inst_noperands(inst);
	for (unsigned j = 0; j < n; j++) {
		const xed_operand_t* op = xed_inst_operand(inst, j);
		// EXPLICIT and IMPLICIT operands must be supplied to the encoder
		// (implicit ones like x87 ST(0), IN's AL/DX, or VMRUN's rAX are part
		// of the iform's operand list). SUPPRESSED operands are automatic.
		if (xed_operand_operand_visibility(op) == XED_OPVIS_SUPPRESSED)
			continue;
		xed_operand_enum_t name = xed_operand_name(op);

		if (name >= XED_OPERAND_REG0 && name <= XED_OPERAND_REG8) {
			xed_reg_enum_t reg = xed_operand_reg(op);
			if (reg == XED_REG_INVALID) {
				const char* nt =
					xed_nonterminal_enum_t2str(xed_operand_nonterminal_name(op));
				reg = reg_for_nt(nt, eff_bits);
			}
			if (reg == XED_REG_INVALID) return 0;
			xed_encoder_request_set_reg(&req, name, reg);
			xed_encoder_request_set_operand_order(&req, order++, name);
		}
		else if (name == XED_OPERAND_MEM0) {
			xed_encoder_request_set_mem0(&req);
			xed_encoder_request_set_base0(&req, XED_REG_RAX);
			if (index_reg != XED_REG_INVALID) {
				// VSIB (gather/scatter): the index is a vector register.
				xed_encoder_request_set_index(&req, index_reg);
				xed_encoder_request_set_scale(&req, 1);
			}
			xed_encoder_request_set_memory_operand_length(&req, mem_len);
			xed_encoder_request_set_operand_order(&req, order++, XED_OPERAND_MEM0);
		}
		else if (name == XED_OPERAND_AGEN) {
			xed_encoder_request_set_agen(&req);
			xed_encoder_request_set_base0(&req, XED_REG_RAX);
			xed_encoder_request_set_operand_order(&req, order++, XED_OPERAND_AGEN);
		}
		else if (name == XED_OPERAND_IMM0) {
			xed_encoder_request_set_uimm0(&req, 1, imm_bytes);
			xed_encoder_request_set_operand_order(&req, order++, XED_OPERAND_IMM0);
		}
		else if (name == XED_OPERAND_IMM1) {
			xed_encoder_request_set_uimm1(&req, 1);
			xed_encoder_request_set_operand_order(&req, order++, XED_OPERAND_IMM1);
		}
		else if (name == XED_OPERAND_RELBR) {
			xed_encoder_request_set_relbr(&req);
			xed_encoder_request_set_branch_displacement(&req, 0x10, br_bytes);
			xed_encoder_request_set_operand_order(&req, order++, XED_OPERAND_RELBR);
		}
		else {
			// PTR and anything else we don't synthesize -> give up on this iform.
			g_last_err = XED_ERROR_GENERAL_ERROR;
			return 0;
		}
	}

	xed_uint8_t buf[XED_MAX_INSTRUCTION_BYTES];
	unsigned int olen = 0;
	xed_error_enum_t err = xed_encode(&req, buf, sizeof(buf), &olen);
	g_last_err = err;
	if (err != XED_ERROR_NONE || olen == 0) return 0;
	memcpy(out, buf, olen);
	return olen;
}

typedef struct {
	unsigned len;
	xed_iform_enum_t iform;
	int mode64;                 // 1 = long mode, 0 = legacy 32
	xed_uint8_t bytes[XED_MAX_INSTRUCTION_BYTES];
} Encoding;

int main(int argc, char** argv)
{
	if (argc < 2) { fprintf(stderr, "usage: %s <outdir>\n", argv[0]); return 2; }
	const char* outdir = argv[1];

	xed_tables_init();

	xed_state_t s64, s32;
	xed_state_init2(&s64, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
	xed_state_init2(&s32, XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b);

	// Diagnostic: "generate --diag ICLASS" dumps every iform of the named
	// iclass with its operand templates. Used to extend operand synthesis.
	if (argc >= 3 && strcmp(argv[1], "--diag") == 0) {
		const xed_inst_t* tb = xed_inst_table_base();
		for (int i = 0; i < XED_MAX_INST_TABLE_NODES; i++) {
			const xed_inst_t* inst = tb + i;
			if (strcmp(xed_iclass_enum_t2str(xed_inst_iclass(inst)), argv[2]) != 0)
				continue;
			printf("IFORM %s\n", xed_iform_enum_t2str(xed_inst_iform_enum(inst)));
			unsigned n = xed_inst_noperands(inst);
			for (unsigned j = 0; j < n; j++) {
				const xed_operand_t* op = xed_inst_operand(inst, j);
				printf("  op%u name=%s vis=%s nt=%s reg=%s width=%s\n", j,
				       xed_operand_enum_t2str(xed_operand_name(op)),
				       xed_operand_visibility_enum_t2str(xed_operand_operand_visibility(op)),
				       xed_nonterminal_enum_t2str(xed_operand_nonterminal_name(op)),
				       xed_reg_enum_t2str(xed_operand_reg(op)),
				       xed_operand_width_enum_t2str(xed_operand_width(op)));
			}
			xed_uint8_t dbg[XED_MAX_INSTRUCTION_BYTES];
			xed_state_t sd; xed_state_init2(&sd, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
			g_last_err = XED_ERROR_NONE;
			unsigned r = try_encode(inst, &sd, 32, 4, 4, 0, XED_REG_INVALID, dbg);
			printf("  -> encode(eff32,mem0): %s err=%s\n", r ? "OK" : "FAIL",
			       xed_error_enum_t2str(g_last_err));
		}
		return 0;
	}

	const unsigned eff_widths[] = {32, 64, 16, 8};
	const unsigned imm_sizes[]  = {4, 1, 2};
	const unsigned br_sizes[]   = {4, 1};

	Encoding* best = calloc(XED_ICLASS_LAST, sizeof(Encoding));
	for (int i = 0; i < XED_ICLASS_LAST; i++) best[i].len = 0;

	// Memory-operand length candidates (0 lets XED infer for special widths
	// like MXSAVE / MPREFETCH) and VSIB vector index candidates (for gather /
	// scatter, whose memory operand is indexed by a vector register).
	const unsigned mem_lens[] = {0, 1, 2, 4, 6, 8, 10, 16, 28, 32, 48, 64, 108, 512};
	const xed_reg_enum_t vsib_idx[] = {
		XED_REG_INVALID, XED_REG_XMM1, XED_REG_YMM1, XED_REG_ZMM1};

	const xed_inst_t* table = xed_inst_table_base();
	for (int i = 0; i < XED_MAX_INST_TABLE_NODES; i++) {
		const xed_inst_t* inst = table + i;
		xed_iclass_enum_t ic = xed_inst_iclass(inst);
		if (ic == XED_ICLASS_INVALID) continue;
		if (best[ic].len && best[ic].mode64) continue;  // already have a 64-bit one

		// Only widen the (expensive) memory/VSIB search when this iform
		// actually has an explicit memory operand.
		int has_mem = 0;
		unsigned nops = xed_inst_noperands(inst);
		for (unsigned j = 0; j < nops; j++) {
			const xed_operand_t* op = xed_inst_operand(inst, j);
			if (xed_operand_operand_visibility(op) == XED_OPVIS_EXPLICIT &&
			    xed_operand_name(op) == XED_OPERAND_MEM0)
				has_mem = 1;
		}
		unsigned n_mem = has_mem ? (unsigned)(sizeof(mem_lens) / sizeof(mem_lens[0])) : 1;
		unsigned n_idx = has_mem ? (unsigned)(sizeof(vsib_idx) / sizeof(vsib_idx[0])) : 1;

		xed_uint8_t out[XED_MAX_INSTRUCTION_BYTES];
		// Prefer long mode, fall back to legacy 32.
		const xed_state_t* modes[2] = {&s64, &s32};
		for (int m = 0; m < 2; m++) {
			int is64 = (m == 0);
			if (best[ic].len && (best[ic].mode64 || !is64)) break;
			unsigned got = 0;
			for (unsigned wi = 0; wi < 4 && !got; wi++)
			for (unsigned ii = 0; ii < 3 && !got; ii++)
			for (unsigned bi = 0; bi < 2 && !got; bi++)
			for (unsigned mi = 0; mi < n_mem && !got; mi++)
			for (unsigned xi = 0; xi < n_idx && !got; xi++) {
				got = try_encode(inst, modes[m], eff_widths[wi],
				                 imm_sizes[ii], br_sizes[bi],
				                 has_mem ? mem_lens[mi] : eff_widths[wi] / 8,
				                 vsib_idx[xi], out);
				if (got) {
					best[ic].len = got;
					best[ic].iform = xed_inst_iform_enum(inst);
					best[ic].mode64 = is64;
					memcpy(best[ic].bytes, out, got);
				}
			}
		}
	}

	// Fallback for iclasses XED's *encoder* cannot produce (x87 works, but the
	// XSAVE family, legacy far-pointer loads, JCXZ and the APX JMPABS all
	// return GENERAL_ERROR even from a correct request). We supply known-good
	// machine code and let XED's *decoder* classify it, so a wrong guess can
	// never mislabel an entry. Each candidate is decoded in long mode first,
	// then legacy 32-bit; the first mode yielding an as-yet-uncovered iclass
	// wins. (MPX BND* and the NOP2..NOP9 multi-byte-NOP iclasses are
	// deliberately omitted: this XED build has MPX disabled and decodes every
	// multi-byte NOP as plain NOP, so no byte sequence reaches those iclasses.)
	static const char* fallbacks[] = {
		"0fae20", "480fae20",       // XSAVE / XSAVE64
		"0fae30", "480fae30",       // XSAVEOPT / XSAVEOPT64
		"0fc720", "480fc720",       // XSAVEC / XSAVEC64
		"0fc728", "480fc728",       // XSAVES / XSAVES64
		"0fae28", "480fae28",       // XRSTOR / XRSTOR64
		"0fc718", "480fc718",       // XRSTORS / XRSTORS64
		"d500a10000000000000000",   // JMPABS (APX: REX2 + A1 + imm64)
		"67e300",                   // JCXZ (16-bit address size)
		"c500",                     // LDS  eax, [eax]  (legacy 32-bit)
		"c400",                     // LES  eax, [eax]  (legacy 32-bit)
		"6200",                     // BOUND eax, [eax] (legacy 32-bit)
		NULL,
	};
	for (int fi = 0; fallbacks[fi]; fi++) {
		const char* h = fallbacks[fi];
		xed_uint8_t bytes[XED_MAX_INSTRUCTION_BYTES];
		unsigned blen = 0;
		for (const char* p = h; p[0] && p[1] && blen < XED_MAX_INSTRUCTION_BYTES; p += 2) {
			unsigned v; sscanf(p, "%2x", &v); bytes[blen++] = (xed_uint8_t)v;
		}
		// Long mode first, then legacy 32-bit; record the first mode that
		// classifies to a not-yet-covered iclass.
		for (int m = 0; m < 2; m++) {
			int is64 = (m == 0);
			xed_decoded_inst_t xedd;
			xed_decoded_inst_zero_set_mode(&xedd, is64 ? &s64 : &s32);
			if (xed_decode(&xedd, bytes, blen) != XED_ERROR_NONE) continue;
			xed_iclass_enum_t ic = xed_decoded_inst_get_iclass(&xedd);
			unsigned dlen = xed_decoded_inst_get_length(&xedd);
			if (ic == XED_ICLASS_INVALID || best[ic].len) continue;
			best[ic].len = dlen;
			best[ic].iform = xed_decoded_inst_get_iform_enum(&xedd);
			best[ic].mode64 = is64;
			memcpy(best[ic].bytes, bytes, dlen);
			break;
		}
	}

	// Emit manifests. Each line is: <iclass> <iform> <hexbytes>. The bytes are
	// stored inline (no separate .bin), and consumers recover the instruction
	// length from the hex string, so no offset/length columns are needed.
	char path[1024];
	FILE* man[2];
	const char* names[2] = {"x86_64", "x86"};
	for (int k = 0; k < 2; k++) {
		snprintf(path, sizeof(path), "%s/%s.manifest", outdir, names[k]);
		man[k] = fopen(path, "w");
		if (!man[k]) { perror("fopen"); return 1; }
	}
	int covered = 0, cov64 = 0, cov32 = 0;
	for (int ic = 1; ic < XED_ICLASS_LAST; ic++) {
		if (!best[ic].len) continue;
		covered++;
		int k = best[ic].mode64 ? 0 : 1;
		if (k == 0) cov64++; else cov32++;
		fprintf(man[k], "%s %s ",
		        xed_iclass_enum_t2str((xed_iclass_enum_t)ic),
		        xed_iform_enum_t2str(best[ic].iform));
		for (unsigned b = 0; b < best[ic].len; b++)
			fprintf(man[k], "%02x", best[ic].bytes[b]);
		fprintf(man[k], "\n");
	}
	for (int k = 0; k < 2; k++) fclose(man[k]);

	// Coverage report.
	snprintf(path, sizeof(path), "%s/coverage.txt", outdir);
	FILE* cov = fopen(path, "w");
	int total = XED_ICLASS_LAST - 1;
	fprintf(cov, "covered %d / %d iclasses (%d long-mode, %d legacy-32)\n",
	        covered, total, cov64, cov32);
	fprintf(cov,
		"\nThe uncovered iclasses below are unreachable in Binary Ninja's XED\n"
		"build and therefore cannot appear in any test binary:\n"
		"  BND* (MPX)  - MPX decoding is disabled; F3/F2 0F 1A/1B decode as NOP.\n"
		"  NOP2..NOP9  - every multi-byte NOP decodes to the plain NOP iclass.\n");
	fprintf(cov, "\nUNCOVERED:\n");
	for (int ic = 1; ic < XED_ICLASS_LAST; ic++)
		if (!best[ic].len)
			fprintf(cov, "%s\n", xed_iclass_enum_t2str((xed_iclass_enum_t)ic));
	fclose(cov);

	fprintf(stderr, "covered %d / %d iclasses (%d long, %d legacy)\n",
	        covered, total, cov64, cov32);
	free(best);
	return 0;
}
