#include "decode.h"

// the hope is to avoid having to manipulate strings in something that's
// somewhat hot, so we create a bunch of lookup tables for each mnemonic

// for "OP" and "OP."
#define DEFINE_SUBMNEM_RC(_identifier, base)    \
	const char* _identifier[2] =            \
	{                                       \
		base,                           \
		base ".",                       \
	};

// for "OP", "OP.", "OPo", and "OPo."
#define DEFINE_SUBMNEM_OE_RC(_identifier, base) \
	const char* _identifier[4] =            \
	{                                       \
		base,                           \
		base ".",                       \
		base "o",                       \
		base "o.",                      \
	};

// for "OP" and "OPl"
#define DEFINE_SUBMNEM_LK(_identifier, base) \
	const char* _identifier[2] =            \
	{                                       \
		base,                           \
		base "l",                       \
	};

// for "OP" and "OPl" and +/- hints
#define DEFINE_SUBMNEM_LK_HINT(_identifier, base) \
	const char* _identifier[8] =            \
	{                                       \
		base,                           \
		base "l",                       \
		base,                           \
		base "l",                       \
		base "-",                       \
		base "l-",                      \
		base "+",                       \
		base "l+",                      \
	};

// for "OP", "OPl", "OPa", and "OPla"
#define DEFINE_SUBMNEM_AA_LK(_identifier, base) \
	const char* _identifier[4] =            \
	{                                       \
		base,                           \
		base "l",                       \
		base "a",                       \
		base "la",                      \
	};

// for "OP", "OPl", "OPa", "OPla" and +/- hints
#define DEFINE_SUBMNEM_AA_LK_HINT(_identifier, base) \
	const char* _identifier[16] =            \
	{                                       \
		base,                           \
		base "l",                       \
		base "a",                       \
		base "la",                      \
		base,                           \
		base "l",                       \
		base "a",                       \
		base "la",                      \
		base "-",                       \
		base "l-",                      \
		base "a-",                      \
		base "la-",                     \
		base "+",                       \
		base "l+",                      \
		base "a+",                      \
		base "la+"                      \
	};

#define DEFINE_SUBMNEM_ROUND2ODD(_identifier, base)    \
	const char* _identifier[2] =            \
	{                                       \
		base,                           \
		base "o",                       \
	};

#define DEFINE_SUBMNEM_INEXACT(_identifier, base)    \
	const char* _identifier[2] =            \
	{                                       \
		base,                           \
		base "x",                       \
	};

DEFINE_SUBMNEM_OE_RC(SubMnemADDx, "add")
DEFINE_SUBMNEM_OE_RC(SubMnemADDCx, "addc")
DEFINE_SUBMNEM_OE_RC(SubMnemADDEx, "adde")
DEFINE_SUBMNEM_RC(SubMnemADDICx, "addic")
DEFINE_SUBMNEM_OE_RC(SubMnemADDMEx, "addme")
DEFINE_SUBMNEM_OE_RC(SubMnemADDZEx, "addze")
DEFINE_SUBMNEM_RC(SubMnemANDx, "and")
DEFINE_SUBMNEM_RC(SubMnemANDCx, "andc")
DEFINE_SUBMNEM_AA_LK(SubMnemBx, "b")
DEFINE_SUBMNEM_AA_LK(SubMnemBCx, "bc")
DEFINE_SUBMNEM_LK(SubMnemBCTRx, "bctr")
DEFINE_SUBMNEM_LK(SubMnemBCCTRx, "bcctr")
DEFINE_SUBMNEM_LK(SubMnemBCLRx, "bclr")
DEFINE_SUBMNEM_AA_LK_HINT(SubMnemBDZx, "bdz")
DEFINE_SUBMNEM_LK_HINT(SubMnemBDZLRx, "bdzlr")
DEFINE_SUBMNEM_AA_LK_HINT(SubMnemBDNZx, "bdnz")
DEFINE_SUBMNEM_LK_HINT(SubMnemBDNZLRx, "bdnzlr")
DEFINE_SUBMNEM_AA_LK(SubMnemBDNZFx, "bdnzf")
DEFINE_SUBMNEM_LK(SubMnemBDNZFLRx, "bdnzflr")
DEFINE_SUBMNEM_AA_LK(SubMnemBDNZTx, "bdnzt")
DEFINE_SUBMNEM_LK(SubMnemBDNZTLRx, "bdnztlr")
DEFINE_SUBMNEM_AA_LK(SubMnemBDZFx, "bdzf")
DEFINE_SUBMNEM_LK(SubMnemBDZFLRx, "bdzflr")
DEFINE_SUBMNEM_LK(SubMnemBDFLRx, "bdzlr")
DEFINE_SUBMNEM_AA_LK(SubMnemBDZTx, "bdzt")
DEFINE_SUBMNEM_LK(SubMnemBDZTLRx, "bdztlr")
DEFINE_SUBMNEM_AA_LK_HINT(SubMnemBEQx, "beq")
DEFINE_SUBMNEM_LK_HINT(SubMnemBEQCTRx, "beqctr")
DEFINE_SUBMNEM_LK_HINT(SubMnemBEQLRx, "beqlr")
DEFINE_SUBMNEM_AA_LK(SubMnemBFx, "bf")
DEFINE_SUBMNEM_AA_LK(SubMnemBFLRx, "bflr")
DEFINE_SUBMNEM_AA_LK_HINT(SubMnemBGEx, "bge")
DEFINE_SUBMNEM_LK_HINT(SubMnemBGECTRx, "bgectr")
DEFINE_SUBMNEM_LK_HINT(SubMnemBGELRx, "bgelr")
DEFINE_SUBMNEM_AA_LK_HINT(SubMnemBGTx, "bgt")
DEFINE_SUBMNEM_LK_HINT(SubMnemBGTCTRx, "bgtctr")
DEFINE_SUBMNEM_LK_HINT(SubMnemBGTLRx, "bgtlr")
DEFINE_SUBMNEM_AA_LK_HINT(SubMnemBLEx, "ble")
DEFINE_SUBMNEM_LK_HINT(SubMnemBLECTRx, "blectr")
DEFINE_SUBMNEM_LK_HINT(SubMnemBLELRx, "blelr")
DEFINE_SUBMNEM_AA_LK_HINT(SubMnemBLTx, "blt")
DEFINE_SUBMNEM_LK_HINT(SubMnemBLTCTRx, "bltctr")
DEFINE_SUBMNEM_LK_HINT(SubMnemBLTLRx, "bltlr")
DEFINE_SUBMNEM_LK_HINT(SubMnemBLRx, "blr")
DEFINE_SUBMNEM_AA_LK_HINT(SubMnemBNEx, "bne")
DEFINE_SUBMNEM_LK_HINT(SubMnemBNECTRx, "bnectr")
DEFINE_SUBMNEM_LK_HINT(SubMnemBNELRx, "bnelr")
DEFINE_SUBMNEM_AA_LK_HINT(SubMnemBNSx, "bns")
DEFINE_SUBMNEM_LK_HINT(SubMnemBNSCTRx, "bnsctr")
DEFINE_SUBMNEM_LK_HINT(SubMnemBNSLRx, "bnslr")
DEFINE_SUBMNEM_AA_LK_HINT(SubMnemBSOx, "bso")
DEFINE_SUBMNEM_LK_HINT(SubMnemBSOCTRx, "bsoctr")
DEFINE_SUBMNEM_LK_HINT(SubMnemBSOLRx, "bsolr")
DEFINE_SUBMNEM_AA_LK(SubMnemBTx, "bt")
DEFINE_SUBMNEM_AA_LK(SubMnemBTLRx, "btlr")
DEFINE_SUBMNEM_RC(SubMnemCLRLDIx, "clrldi")
DEFINE_SUBMNEM_RC(SubMnemCLRLWIx, "clrlwi")
DEFINE_SUBMNEM_RC(SubMnemCLRRWIx, "clrrwi")
DEFINE_SUBMNEM_RC(SubMnemCNTLZDx, "cntlzd")
DEFINE_SUBMNEM_RC(SubMnemCNTLZWx, "cntlzw")
DEFINE_SUBMNEM_RC(SubMnemCNTTZDx, "cnttzd")
DEFINE_SUBMNEM_RC(SubMnemCNTTZWx, "cnttzw")
DEFINE_SUBMNEM_OE_RC(SubMnemDIVDx, "divd")
DEFINE_SUBMNEM_OE_RC(SubMnemDIVDEx, "divde")
DEFINE_SUBMNEM_OE_RC(SubMnemDIVDEUx, "divdeu")
DEFINE_SUBMNEM_OE_RC(SubMnemDIVDUx, "divdu")
DEFINE_SUBMNEM_OE_RC(SubMnemDIVWx, "divw")
DEFINE_SUBMNEM_OE_RC(SubMnemDIVWEx, "divwe")
DEFINE_SUBMNEM_OE_RC(SubMnemDIVWEUx, "divweu")
DEFINE_SUBMNEM_OE_RC(SubMnemDIVWUx, "divwu")
DEFINE_SUBMNEM_RC(SubMnemEQVx, "eqv")
DEFINE_SUBMNEM_RC(SubMnemEXTSBx, "extsb")
DEFINE_SUBMNEM_RC(SubMnemEXTSHx, "extsh")
DEFINE_SUBMNEM_RC(SubMnemEXTSWx, "extsw")
DEFINE_SUBMNEM_RC(SubMnemEXTSWSLIx, "extswsli")
DEFINE_SUBMNEM_RC(SubMnemFABSx, "fabs")
DEFINE_SUBMNEM_RC(SubMnemFADDx, "fadd")
DEFINE_SUBMNEM_RC(SubMnemFADDSx, "fadds")
DEFINE_SUBMNEM_RC(SubMnemFCFIDx, "fcfid")
DEFINE_SUBMNEM_RC(SubMnemFCFIDSx, "fcfids")
DEFINE_SUBMNEM_RC(SubMnemFCFIDUx, "fcfidu")
DEFINE_SUBMNEM_RC(SubMnemFCFIDUSx, "fcfidus")
DEFINE_SUBMNEM_RC(SubMnemFCPSGNx, "fcpsgn")
DEFINE_SUBMNEM_RC(SubMnemFCTIDx, "fctid")
DEFINE_SUBMNEM_RC(SubMnemFCTIDUx, "fctidu")
DEFINE_SUBMNEM_RC(SubMnemFCTIDUZx, "fctiduz")
DEFINE_SUBMNEM_RC(SubMnemFCTIDZx, "fctidz")
DEFINE_SUBMNEM_RC(SubMnemFCTIWx, "fctiw")
DEFINE_SUBMNEM_RC(SubMnemFCTIWUx, "fctiwu")
DEFINE_SUBMNEM_RC(SubMnemFCTIWUZx, "fctiwuz")
DEFINE_SUBMNEM_RC(SubMnemFCTIWZx, "fctiwz")
DEFINE_SUBMNEM_RC(SubMnemFDIVx, "fdiv")
DEFINE_SUBMNEM_RC(SubMnemFDIVSx, "fdivs")
DEFINE_SUBMNEM_RC(SubMnemFMADDx, "fmadd")
DEFINE_SUBMNEM_RC(SubMnemFMADDSx, "fmadds")
DEFINE_SUBMNEM_RC(SubMnemFMRx, "fmr")
DEFINE_SUBMNEM_RC(SubMnemFMSUBx, "fmsub")
DEFINE_SUBMNEM_RC(SubMnemFMSUBSx, "fmsubs")
DEFINE_SUBMNEM_RC(SubMnemFMULx, "fmul")
DEFINE_SUBMNEM_RC(SubMnemFMULSx, "fmuls")
DEFINE_SUBMNEM_RC(SubMnemFNABSx, "fnabs")
DEFINE_SUBMNEM_RC(SubMnemFNEGx, "fneg")
DEFINE_SUBMNEM_RC(SubMnemFNMADDx, "fnmadd")
DEFINE_SUBMNEM_RC(SubMnemFNMADDSx, "fnmadds")
DEFINE_SUBMNEM_RC(SubMnemFNMSUBx, "fnmsub")
DEFINE_SUBMNEM_RC(SubMnemFNMSUBSx, "fnmsubs")
DEFINE_SUBMNEM_RC(SubMnemFREx, "fre")
DEFINE_SUBMNEM_RC(SubMnemFRESx, "fres")
DEFINE_SUBMNEM_RC(SubMnemFRIMx, "frim")
DEFINE_SUBMNEM_RC(SubMnemFRINx, "frin")
DEFINE_SUBMNEM_RC(SubMnemFRIPx, "frip")
DEFINE_SUBMNEM_RC(SubMnemFRIZx, "friz")
DEFINE_SUBMNEM_RC(SubMnemFRSPx, "frsp")
DEFINE_SUBMNEM_RC(SubMnemFRSQRTEx, "frsqrte")
DEFINE_SUBMNEM_RC(SubMnemFRSQRTESx, "frsqrtes")
DEFINE_SUBMNEM_RC(SubMnemFSELx, "fsel")
DEFINE_SUBMNEM_RC(SubMnemFSQRTx, "fsqrt")
DEFINE_SUBMNEM_RC(SubMnemFSQRTSx, "fsqrts")
DEFINE_SUBMNEM_RC(SubMnemFSUBx, "fsub")
DEFINE_SUBMNEM_RC(SubMnemFSUBSx, "fsubs")
DEFINE_SUBMNEM_RC(SubMnemMFFSx, "mffs")
DEFINE_SUBMNEM_RC(SubMnemMTFSB0x, "mtfsb0")
DEFINE_SUBMNEM_RC(SubMnemMTFSB1x, "mtfsb1")
DEFINE_SUBMNEM_RC(SubMnemMTFSFx, "mtfsf")
DEFINE_SUBMNEM_RC(SubMnemMTFSFIx, "mtfsfi")
DEFINE_SUBMNEM_RC(SubMnemMRx, "mr")
DEFINE_SUBMNEM_RC(SubMnemMULHDx, "mulhd")
DEFINE_SUBMNEM_RC(SubMnemMULHDUx, "mulhdu")
DEFINE_SUBMNEM_RC(SubMnemMULHWx, "mulhw")
DEFINE_SUBMNEM_RC(SubMnemMULHWUx, "mulhwu")
DEFINE_SUBMNEM_OE_RC(SubMnemMULLDx, "mulld")
DEFINE_SUBMNEM_OE_RC(SubMnemMULLWx, "mullw")
DEFINE_SUBMNEM_RC(SubMnemNANDx, "nand")
DEFINE_SUBMNEM_OE_RC(SubMnemNEGx, "neg")
DEFINE_SUBMNEM_RC(SubMnemNORx, "nor")
DEFINE_SUBMNEM_RC(SubMnemORx, "or")
DEFINE_SUBMNEM_RC(SubMnemORCx, "orc")
DEFINE_SUBMNEM_RC(SubMnemRLDICLx, "rldicl")
DEFINE_SUBMNEM_RC(SubMnemRLDICRx, "rldicr")
DEFINE_SUBMNEM_RC(SubMnemRLDICx, "rldic")
DEFINE_SUBMNEM_RC(SubMnemRLDIMIx, "rldimi")
DEFINE_SUBMNEM_RC(SubMnemRLDCLx, "rldcl")
DEFINE_SUBMNEM_RC(SubMnemRLDCRx, "rldcr")
DEFINE_SUBMNEM_RC(SubMnemRLWIMIx, "rlwimi")
DEFINE_SUBMNEM_RC(SubMnemRLWINMx, "rlwinm")
DEFINE_SUBMNEM_RC(SubMnemRLWNMx, "rlwnm")
DEFINE_SUBMNEM_RC(SubMnemROTLDx, "rotld")
DEFINE_SUBMNEM_RC(SubMnemROTLDIx, "rotldi")
DEFINE_SUBMNEM_RC(SubMnemROTLWx, "rotlw")
DEFINE_SUBMNEM_RC(SubMnemROTLWIx, "rotlwi")
DEFINE_SUBMNEM_RC(SubMnemSLDx, "sld")
DEFINE_SUBMNEM_RC(SubMnemSLDIx, "sldi")
DEFINE_SUBMNEM_RC(SubMnemSLWx, "slw")
DEFINE_SUBMNEM_RC(SubMnemSLWIx, "slwi")
DEFINE_SUBMNEM_RC(SubMnemSRADx, "srad")
DEFINE_SUBMNEM_RC(SubMnemSRADIx, "sradi")
DEFINE_SUBMNEM_RC(SubMnemSRAWx, "sraw")
DEFINE_SUBMNEM_RC(SubMnemSRAWIx, "srawi")
DEFINE_SUBMNEM_RC(SubMnemSRDx, "srd")
DEFINE_SUBMNEM_RC(SubMnemSRDIx, "srdi")
DEFINE_SUBMNEM_RC(SubMnemSRWx, "srw")
DEFINE_SUBMNEM_RC(SubMnemSRWIx, "srwi")
DEFINE_SUBMNEM_OE_RC(SubMnemSUBFx, "subf")
DEFINE_SUBMNEM_OE_RC(SubMnemSUBFCx, "subfc")
DEFINE_SUBMNEM_OE_RC(SubMnemSUBFEx, "subfe")
DEFINE_SUBMNEM_OE_RC(SubMnemSUBFMEx, "subfme")
DEFINE_SUBMNEM_OE_RC(SubMnemSUBFZEx, "subfze")
DEFINE_SUBMNEM_RC(SubMnemXORx, "xor")

// ALTIVEC MNEMONICS
DEFINE_SUBMNEM_RC(SubMnemVCMPBFPx, "vcmpbfp");
DEFINE_SUBMNEM_RC(SubMnemVCMPEQFPx, "vcmpeqfp");
DEFINE_SUBMNEM_RC(SubMnemVCMPEQUBx, "vcmpequb");
DEFINE_SUBMNEM_RC(SubMnemVCMPEQUDx, "vcmpequd");
DEFINE_SUBMNEM_RC(SubMnemVCMPEQUHx, "vcmpequh");
DEFINE_SUBMNEM_RC(SubMnemVCMPEQUWx, "vcmpequw");
DEFINE_SUBMNEM_RC(SubMnemVCMPGEFPx, "vcmpgefp");
DEFINE_SUBMNEM_RC(SubMnemVCMPGTFPx, "vcmpgtfp");
DEFINE_SUBMNEM_RC(SubMnemVCMPGTSBx, "vcmpgtsb");
DEFINE_SUBMNEM_RC(SubMnemVCMPGTSDx, "vcmpgtsd");
DEFINE_SUBMNEM_RC(SubMnemVCMPGTSHx, "vcmpgtsh");
DEFINE_SUBMNEM_RC(SubMnemVCMPGTSWx, "vcmpgtsw");
DEFINE_SUBMNEM_RC(SubMnemVCMPGTUBx, "vcmpgtub");
DEFINE_SUBMNEM_RC(SubMnemVCMPGTUDx, "vcmpgtud");
DEFINE_SUBMNEM_RC(SubMnemVCMPGTUHx, "vcmpgtuh");
DEFINE_SUBMNEM_RC(SubMnemVCMPGTUWx, "vcmpgtuw");
DEFINE_SUBMNEM_RC(SubMnemVCMPNEBx, "vcmpneb");
DEFINE_SUBMNEM_RC(SubMnemVCMPNEHx, "vcmpneh");
DEFINE_SUBMNEM_RC(SubMnemVCMPNEWx, "vcmpnew");
DEFINE_SUBMNEM_RC(SubMnemVCMPNEZBx, "vcmpnezb");
DEFINE_SUBMNEM_RC(SubMnemVCMPNEZHx, "vcmpnezh");
DEFINE_SUBMNEM_RC(SubMnemVCMPNEZWx, "vcmpnezw");

// VSX MNEMONICS
DEFINE_SUBMNEM_RC(SubMnemXVCMPEQDPx, "xvcmpeqdp");
DEFINE_SUBMNEM_RC(SubMnemXVCMPEQSPx, "xvcmpeqsp");
DEFINE_SUBMNEM_RC(SubMnemXVCMPGEDPx, "xvcmpgedp");
DEFINE_SUBMNEM_RC(SubMnemXVCMPGESPx, "xvcmpgesp");
DEFINE_SUBMNEM_RC(SubMnemXVCMPGTDPx, "xvcmpgtdp");
DEFINE_SUBMNEM_RC(SubMnemXVCMPGTSPx, "xvcmpgtsp");
DEFINE_SUBMNEM_ROUND2ODD(SubMnemXSADDQPx, "xsaddqp");
DEFINE_SUBMNEM_ROUND2ODD(SubMnemXSCVQPDPx, "xscvqpdp");
DEFINE_SUBMNEM_ROUND2ODD(SubMnemXSDIVQPx, "xsdivqp");
DEFINE_SUBMNEM_ROUND2ODD(SubMnemXSMADDQPx, "xsmaddqp");
DEFINE_SUBMNEM_ROUND2ODD(SubMnemXSMULQPx, "xsmulqp");
DEFINE_SUBMNEM_ROUND2ODD(SubMnemXSMSUBQPx, "xsmsubqp");
DEFINE_SUBMNEM_ROUND2ODD(SubMnemXSNMADDQPx, "xsnmaddqp");
DEFINE_SUBMNEM_ROUND2ODD(SubMnemXSNMSUBQPx, "xsnmsubqp");
DEFINE_SUBMNEM_ROUND2ODD(SubMnemXSSQRTQPx, "xssqrtqp");
DEFINE_SUBMNEM_ROUND2ODD(SubMnemXSSUBQPx, "xssubqp");
DEFINE_SUBMNEM_INEXACT(SubMnemXSRQPIx, "xsrqpi");

static const char* RcMnemonic(const Instruction* instruction, const char* names[2])
{
	return names[instruction->flags.rc];
}

static const char* OeRcMnemonic(const Instruction* instruction, const char* names[4])
{
	return names[2*instruction->flags.oe + instruction->flags.rc];
}

static const char* LkMnemonic(const Instruction* instruction, const char* names[2])
{
	return names[instruction->flags.lk];
}

static const char* LkHintMnemonic(const Instruction* instruction, const char* names[8])
{
	return names[2*instruction->flags.branchLikelyHint + instruction->flags.lk];
}

static const char* AaLkMnemonic(const Instruction* instruction, const char* names[4])
{
	return names[2*instruction->flags.aa + instruction->flags.lk];
}

static const char* AaLkHintMnemonic(const Instruction* instruction, const char* names[16])
{
	return names[4*instruction->flags.branchLikelyHint + 2*instruction->flags.aa + instruction->flags.lk];
}

static const char* Round2OddMnemonic(const Instruction* instruction, const char* names[2])
{
	return names[instruction->flags.round2odd];
}

static const char* InexactMnemonic(const Instruction* instruction, const char* names[2])
{
	return names[instruction->flags.inexact];
}

const char* GetMnemonic(const Instruction* instruction)
{
	switch (instruction->id)
	{
		case PPC_ID_ADDx: return OeRcMnemonic(instruction, SubMnemADDx);
		case PPC_ID_ADDCx: return OeRcMnemonic(instruction, SubMnemADDCx);
		case PPC_ID_ADDEx: return OeRcMnemonic(instruction, SubMnemADDEx);
		case PPC_ID_ADDI: return "addi";
		case PPC_ID_ADDICx: return RcMnemonic(instruction, SubMnemADDICx);
		case PPC_ID_ADDIS: return "addis";
		case PPC_ID_ADDMEx: return OeRcMnemonic(instruction, SubMnemADDMEx);
		case PPC_ID_ADDPCIS: return "addpcis";
		case PPC_ID_ADDZEx: return OeRcMnemonic(instruction, SubMnemADDZEx);
		case PPC_ID_ANDx: return RcMnemonic(instruction, SubMnemANDx);
		case PPC_ID_ANDCx: return RcMnemonic(instruction, SubMnemANDCx);
		case PPC_ID_ANDI: return "andi.";
		case PPC_ID_ANDIS: return "andis.";
		case PPC_ID_ATTN: return "attn";
		case PPC_ID_Bx: return AaLkMnemonic(instruction, SubMnemBx);
		case PPC_ID_BCx:
		{
			uint32_t bo = instruction->operands[0].uimm;
			uint32_t bi = instruction->operands[1].uimm;

			const char** mnemonics = NULL;
			const char** mnemonicsHint = NULL;

			// mask away the "y" bit
			switch (bo & 0x1e)
			{
				case 0:
					mnemonics = SubMnemBDNZFx;
					break;

				case 2:
					mnemonics = SubMnemBDZFx;
					break;

				case 4:
				case 6:
					switch (bi & 0x3)
					{
						case 0:
							mnemonicsHint = SubMnemBGEx;
							break;
						case 1:
							mnemonicsHint = SubMnemBLEx;
							break;
						case 2:
							mnemonicsHint = SubMnemBNEx;
							break;
						case 3:
							mnemonicsHint = SubMnemBNSx;
							break;

						// should be unreachable
						default:
							return NULL;
					}

					break;

				case 8:
					mnemonics = SubMnemBDNZTx;
					break;

				case 10:
					mnemonics = SubMnemBDZTx;
					break;

				case 12:
				case 14:
					switch (bi & 0x3)
					{
						case 0:
						       mnemonicsHint = SubMnemBLTx;
						       break;

						case 1:
						       mnemonicsHint = SubMnemBGTx;
						       break;

						case 2:
						       mnemonicsHint = SubMnemBEQx;
						       break;

						case 3:
						       mnemonicsHint = SubMnemBSOx;
						       break;

						// should be unreachable
						default:
						       return NULL;
					}
					break;

				// technically these aren't terribly well defined
				// when BI != 0, since these BOs don't involve
				// a condition bit to test in BI to test against
				case 16:
				case 24:
					mnemonicsHint = SubMnemBDNZx;
					break;

				// these represent "branch always" in the BO field, so it's
				// not super clear why these disassemble to bdnz
				case 20:
				case 28:
					 mnemonicsHint = SubMnemBDNZx;
					 break;

				case 18:
				case 22:
				case 26:
					mnemonicsHint = SubMnemBDZx;
					break;

				// these represent "branch always" in the BO field, so it's
				// not super clear why these disassemble to bdz
				case 30:
					mnemonicsHint = SubMnemBDZx;
					break;

				default:
					mnemonics = SubMnemBCx;
			}

			if (mnemonicsHint)
				return AaLkHintMnemonic(instruction, mnemonicsHint);

			if (mnemonics)
				return AaLkMnemonic(instruction, mnemonics);

			// should be unreachable
			return NULL;
		}

		case PPC_ID_BCCTRx:
		{
			uint32_t bo = instruction->operands[0].uimm;
			uint32_t bi = instruction->operands[1].uimm;

			// mask away the "y" bit
			switch (bo & 0x1e)
			{
				case 4:
				case 6:
					switch (bi & 0x3)
					{
						case 0: return LkHintMnemonic(instruction, SubMnemBGECTRx);
						case 1: return LkHintMnemonic(instruction, SubMnemBLECTRx);
						case 2: return LkHintMnemonic(instruction, SubMnemBNECTRx);
						case 3: return LkHintMnemonic(instruction, SubMnemBNSCTRx);

						// should be unreachable
						default: return NULL;
					}

					break;

				case 12:
				case 14:
					switch (bi & 0x3)
					{
						case 0: return LkHintMnemonic(instruction, SubMnemBLTCTRx);
						case 1: return LkHintMnemonic(instruction, SubMnemBGTCTRx);
						case 2: return LkHintMnemonic(instruction, SubMnemBEQCTRx);
						case 3: return LkHintMnemonic(instruction, SubMnemBSOCTRx);

						// should be unreachable
						default: return NULL;
					}

					break;

				case 20:
					return LkMnemonic(instruction, SubMnemBCTRx);

				default:
					return LkMnemonic(instruction, SubMnemBCCTRx);
			}
		}

		case PPC_ID_BCLRx:
		{
			uint32_t bo = instruction->operands[0].uimm;
			uint32_t bi = instruction->operands[1].uimm;

			// mask away the "y" bit
			switch (bo & 0x1e)
			{
				case 0:
					return LkMnemonic(instruction, SubMnemBDNZFLRx);

				case 2:
					return LkMnemonic(instruction, SubMnemBDZFLRx);

				case 4:
				case 6:
					switch (bi & 0x3)
					{
						case 0: return LkHintMnemonic(instruction, SubMnemBGELRx);
						case 1: return LkHintMnemonic(instruction, SubMnemBLELRx);
						case 2: return LkHintMnemonic(instruction, SubMnemBNELRx);
						case 3: return LkHintMnemonic(instruction, SubMnemBNSLRx);

						// should be unreachable
						default: return NULL;
					}

				case 8:
					return LkMnemonic(instruction, SubMnemBDNZTLRx);

				case 10:
					return LkMnemonic(instruction, SubMnemBDZTLRx);

				case 12:
				case 14:
					switch (bi & 0x3)
					{
						case 0: return LkHintMnemonic(instruction, SubMnemBLTLRx);
						case 1: return LkHintMnemonic(instruction, SubMnemBGTLRx);
						case 2: return LkHintMnemonic(instruction, SubMnemBEQLRx);
						case 3: return LkHintMnemonic(instruction, SubMnemBSOLRx);

						// should be unreachable
						default: return NULL;
					}

				// technically these aren't terribly well defined
				// when BI != 0, since these BOs don't involve
				// a condition bit to test in BI to test against
				case 16:
				case 24:
					return LkHintMnemonic(instruction, SubMnemBDNZLRx);

				case 18:
				case 26:
					return LkHintMnemonic(instruction, SubMnemBDZLRx);

				case 20:
					return LkHintMnemonic(instruction, SubMnemBLRx);

				default:
					return LkMnemonic(instruction, SubMnemBCLRx);
			}
		}

		case PPC_ID_BPERMD: return "bpermd";
		case PPC_ID_CLRBHRB: return "clrbhrb";
		case PPC_ID_CLRLDIx: return RcMnemonic(instruction, SubMnemCLRLDIx);
		case PPC_ID_CLRLWIx: return RcMnemonic(instruction, SubMnemCLRLWIx);
		case PPC_ID_CLRRWIx: return RcMnemonic(instruction, SubMnemCLRRWIx);
		case PPC_ID_CMPB: return "cmpb";
		case PPC_ID_CMPD: return "cmpd";
		case PPC_ID_CMPDI: return "cmpdi";
		case PPC_ID_CMPEQB: return "cmpeqb";
		case PPC_ID_CMPRB: return "cmprb";
		case PPC_ID_CMPW: return "cmpw";
		case PPC_ID_CMPWI: return "cmpwi";
		case PPC_ID_CMPLD: return "cmpld";
		case PPC_ID_CMPLDI: return "cmpldi";
		case PPC_ID_CMPLW: return "cmplw";
		case PPC_ID_CMPLWI: return "cmplwi";
		case PPC_ID_CNTLZDx: return RcMnemonic(instruction, SubMnemCNTLZDx);
		case PPC_ID_CNTLZWx: return RcMnemonic(instruction, SubMnemCNTLZWx);
		case PPC_ID_CNTTZDx: return RcMnemonic(instruction, SubMnemCNTTZDx);
		case PPC_ID_CNTTZWx: return RcMnemonic(instruction, SubMnemCNTTZWx);
		case PPC_ID_COPY: return "copy";
		case PPC_ID_CP_ABORT: return "cp_abort";
		case PPC_ID_CRAND: return "crand";
		case PPC_ID_CRANDC: return "crandc";
		case PPC_ID_CRCLR: return "crclr";
		case PPC_ID_CREQV: return "creqv";
		case PPC_ID_CRMOVE: return "crmove";
		case PPC_ID_CRNAND: return "crnand";
		case PPC_ID_CRNOR: return "crnor";
		case PPC_ID_CRNOT: return "crnot";
		case PPC_ID_CROR: return "cror";
		case PPC_ID_CRORC: return "crorc";
		case PPC_ID_CRSET: return "crset";
		case PPC_ID_CRXOR: return "crxor";
		case PPC_ID_DARN: return "darn";
		case PPC_ID_DCBA: return "dcba";
		case PPC_ID_DCBF: return "dcbf";
		case PPC_ID_DCBFEP: return "dcbfep";
		case PPC_ID_DCBFL: return "dcbfl";
		case PPC_ID_DCBFLP: return "dcbflp";
		case PPC_ID_DCBI: return "dcbi";
		case PPC_ID_DCBST: return "dcbst";
		case PPC_ID_DCBSTEP: return "dcbstep";
		case PPC_ID_DCBT: return "dcbt";
		case PPC_ID_DCBTT: return "dcbtt";
		case PPC_ID_DCBTEP: return "dcbtep";
		case PPC_ID_DCBTST: return "dcbtst";
		case PPC_ID_DCBTSTEP: return "dcbtstep";
		case PPC_ID_DCBTSTT: return "dcbtstt";
		case PPC_ID_DCBZ: return "dcbz";
		case PPC_ID_DCBZEP: return "dcbzep";
		case PPC_ID_DCBZL: return "dcbzl";
		case PPC_ID_DCCCI: return "dccci";
		case PPC_ID_DCI: return "dci";
		case PPC_ID_DIVDx: return OeRcMnemonic(instruction, SubMnemDIVDx);
		case PPC_ID_DIVDEx: return OeRcMnemonic(instruction, SubMnemDIVDEx);
		case PPC_ID_DIVDEUx: return OeRcMnemonic(instruction, SubMnemDIVDEUx);
		case PPC_ID_DIVDUx: return OeRcMnemonic(instruction, SubMnemDIVDUx);
		case PPC_ID_DIVWx: return OeRcMnemonic(instruction, SubMnemDIVWx);
		case PPC_ID_DIVWEx: return OeRcMnemonic(instruction, SubMnemDIVWEx);
		case PPC_ID_DIVWEUx: return OeRcMnemonic(instruction, SubMnemDIVWEUx);
		case PPC_ID_DIVWUx: return OeRcMnemonic(instruction, SubMnemDIVWUx);
		case PPC_ID_ECIWX: return "eciwx";
		case PPC_ID_ECOWX: return "ecowx";
		case PPC_ID_EIEIO: return "eieio";
		case PPC_ID_EQVx: return RcMnemonic(instruction, SubMnemEQVx);
		case PPC_ID_EXTSBx: return RcMnemonic(instruction, SubMnemEXTSBx);
		case PPC_ID_EXTSHx: return RcMnemonic(instruction, SubMnemEXTSHx);
		case PPC_ID_EXTSWx: return RcMnemonic(instruction, SubMnemEXTSWx);
		case PPC_ID_EXTSWSLIx: return RcMnemonic(instruction, SubMnemEXTSWSLIx);
		case PPC_ID_FABSx: return RcMnemonic(instruction, SubMnemFABSx);
		case PPC_ID_FADDx: return RcMnemonic(instruction, SubMnemFADDx);
		case PPC_ID_FADDSx: return RcMnemonic(instruction, SubMnemFADDSx);
		case PPC_ID_FCFIDx: return RcMnemonic(instruction, SubMnemFCFIDx);
		case PPC_ID_FCFIDSx: return RcMnemonic(instruction, SubMnemFCFIDSx);
		case PPC_ID_FCFIDUx: return RcMnemonic(instruction, SubMnemFCFIDUx);
		case PPC_ID_FCFIDUSx: return RcMnemonic(instruction, SubMnemFCFIDUSx);
		case PPC_ID_FCMPO: return "fcmpo";
		case PPC_ID_FCMPU: return "fcmpu";
		case PPC_ID_FCPSGNx: return RcMnemonic(instruction, SubMnemFCPSGNx);
		case PPC_ID_FCTIDx: return RcMnemonic(instruction, SubMnemFCTIDx);
		case PPC_ID_FCTIDUx: return RcMnemonic(instruction, SubMnemFCTIDUx);
		case PPC_ID_FCTIDUZx: return RcMnemonic(instruction, SubMnemFCTIDUZx);
		case PPC_ID_FCTIDZx: return RcMnemonic(instruction, SubMnemFCTIDZx);
		case PPC_ID_FCTIWx: return RcMnemonic(instruction, SubMnemFCTIWx);
		case PPC_ID_FCTIWUx: return RcMnemonic(instruction, SubMnemFCTIWUx);
		case PPC_ID_FCTIWUZx: return RcMnemonic(instruction, SubMnemFCTIWUZx);
		case PPC_ID_FCTIWZx: return RcMnemonic(instruction, SubMnemFCTIWZx);
		case PPC_ID_FDIVx: return RcMnemonic(instruction, SubMnemFDIVx);
		case PPC_ID_FDIVSx: return RcMnemonic(instruction, SubMnemFDIVSx);
		case PPC_ID_FMADDx: return RcMnemonic(instruction, SubMnemFMADDx);
		case PPC_ID_FMADDSx: return RcMnemonic(instruction, SubMnemFMADDSx);
		case PPC_ID_FMRx: return RcMnemonic(instruction, SubMnemFMRx);
		case PPC_ID_FMSUBx: return RcMnemonic(instruction, SubMnemFMSUBx);
		case PPC_ID_FMSUBSx: return RcMnemonic(instruction, SubMnemFMSUBSx);
		case PPC_ID_FMULx: return RcMnemonic(instruction, SubMnemFMULx);
		case PPC_ID_FMULSx: return RcMnemonic(instruction, SubMnemFMULSx);
		case PPC_ID_FNABSx: return RcMnemonic(instruction, SubMnemFNABSx);
		case PPC_ID_FNEGx: return RcMnemonic(instruction, SubMnemFNEGx);
		case PPC_ID_FNMADDx: return RcMnemonic(instruction, SubMnemFNMADDx);
		case PPC_ID_FNMADDSx: return RcMnemonic(instruction, SubMnemFNMADDSx);
		case PPC_ID_FNMSUBx: return RcMnemonic(instruction, SubMnemFNMSUBx);
		case PPC_ID_FNMSUBSx: return RcMnemonic(instruction, SubMnemFNMSUBSx);
		case PPC_ID_FREx: return RcMnemonic(instruction, SubMnemFREx);
		case PPC_ID_FRESx: return RcMnemonic(instruction, SubMnemFRESx);
		case PPC_ID_FRIMx: return RcMnemonic(instruction, SubMnemFRIMx);
		case PPC_ID_FRINx: return RcMnemonic(instruction, SubMnemFRINx);
		case PPC_ID_FRIPx: return RcMnemonic(instruction, SubMnemFRIPx);
		case PPC_ID_FRIZx: return RcMnemonic(instruction, SubMnemFRIZx);
		case PPC_ID_FRSPx:  return RcMnemonic(instruction, SubMnemFRSPx);
		case PPC_ID_FRSQRTEx:  return RcMnemonic(instruction, SubMnemFRSQRTEx);
		case PPC_ID_FRSQRTESx:  return RcMnemonic(instruction, SubMnemFRSQRTESx);
		case PPC_ID_FSELx:  return RcMnemonic(instruction, SubMnemFSELx);
		case PPC_ID_FSQRTx:  return RcMnemonic(instruction, SubMnemFSQRTx);
		case PPC_ID_FSQRTSx:  return RcMnemonic(instruction, SubMnemFSQRTSx);
		case PPC_ID_FSUBx:  return RcMnemonic(instruction, SubMnemFSUBx);
		case PPC_ID_FSUBSx:  return RcMnemonic(instruction, SubMnemFSUBSx);
		case PPC_ID_FTDIV: return "ftdiv";
		case PPC_ID_FTSQRT: return "ftsqrt";
		case PPC_ID_ICBI: return "icbi";
		case PPC_ID_ICBIEP: return "icbiep";
		case PPC_ID_ICBLC: return "icblc";
		case PPC_ID_ICBLQ: return "icblq.";
		case PPC_ID_ICBT: return "icbt";
		case PPC_ID_ICBTLS: return "icbtls";
		case PPC_ID_ICCCI: return "iccci";
		case PPC_ID_ICI: return "ici";
		case PPC_ID_ISEL: return "isel";
		case PPC_ID_ISYNC: return "isync";
		case PPC_ID_LBARX: return "lbarx";
		case PPC_ID_LBEPX: return "lbepx";
		case PPC_ID_LBZ: return "lbz";
		case PPC_ID_LBZCIX: return "lbzcix";
		case PPC_ID_LBZU: return "lbzu";
		case PPC_ID_LBZUX: return "lbzux";
		case PPC_ID_LBZX: return "lbzx";
		case PPC_ID_LDARX: return "ldarx";
		case PPC_ID_LDAT: return "ldat";
		case PPC_ID_LDBRX: return "ldbrx";
		case PPC_ID_LDCIX: return "ldcix";
		case PPC_ID_LD: return "ld";
		case PPC_ID_LDU: return "ldu";
		case PPC_ID_LDUX: return "ldux";
		case PPC_ID_LDX: return "ldx";
		case PPC_ID_LFD: return "lfd";
		case PPC_ID_LFDEPX: return "lfdepx";
		case PPC_ID_LFDU: return "lfdu";
		case PPC_ID_LFDUX: return "lfdux";
		case PPC_ID_LFDX: return "lfdx";
		case PPC_ID_LFIWAX: return "lfiwax";
		case PPC_ID_LFIWZX: return "lfiwzx";
		case PPC_ID_LFS: return "lfs";
		case PPC_ID_LFSU: return "lfsu";
		case PPC_ID_LFSUX: return "lfsux";
		case PPC_ID_LFSX: return "lfsx";
		case PPC_ID_LHA: return "lha";
		case PPC_ID_LHARX: return "lharx";
		case PPC_ID_LHAU: return "lhau";
		case PPC_ID_LHAUX: return "lhaux";
		case PPC_ID_LHAX: return "lhax";
		case PPC_ID_LHBRX: return "lhbrx";
		case PPC_ID_LHEPX: return "lhepx";
		case PPC_ID_LHZ: return "lhz";
		case PPC_ID_LHZCIX: return "lhzcix";
		case PPC_ID_LHZU: return "lhzu";
		case PPC_ID_LHZUX: return "lhzux";
		case PPC_ID_LHZX: return "lhzx";
		case PPC_ID_LI: return "li";
		case PPC_ID_LIS: return "lis";
		case PPC_ID_LMW: return "lmw";
		case PPC_ID_LNIA: return "lnia";
		case PPC_ID_LSWI: return "lswi";
		case PPC_ID_LSWX: return "lswx";
		case PPC_ID_LWA: return "lwa";
		case PPC_ID_LWAT: return "lwat";
		case PPC_ID_LWAX: return "lwax";
		case PPC_ID_LWARX: return "lwarx";
		case PPC_ID_LWAUX: return "lwaux";
		case PPC_ID_LWBRX: return "lwbrx";
		case PPC_ID_LWEPX: return "lwepx";
		case PPC_ID_LWSYNC: return "lwsync";
		case PPC_ID_LWZ: return "lwz";
		case PPC_ID_LWZCIX: return "lwzcix";
		case PPC_ID_LWZU: return "lwzu";
		case PPC_ID_LWZUX: return "lwzux";
		case PPC_ID_LWZX: return "lwzx";
		case PPC_ID_MBAR: return "mbar";
		case PPC_ID_MCRF: return "mcrf";
		case PPC_ID_MCRFS: return "mcrfs";
		case PPC_ID_MCRXR: return "mcrxr";
		case PPC_ID_MCRXRX: return "mcrxrx";
		case PPC_ID_MFBHRBE: return "mfbhrbe";
		case PPC_ID_MFBR0: return "mfbr0";
		case PPC_ID_MFBR1: return "mfbr1";
		case PPC_ID_MFBR2: return "mfbr2";
		case PPC_ID_MFBR3: return "mfbr3";
		case PPC_ID_MFBR4: return "mfbr4";
		case PPC_ID_MFBR5: return "mfbr5";
		case PPC_ID_MFBR6: return "mfbr6";
		case PPC_ID_MFBR7: return "mfbr7";
		case PPC_ID_MFCR: return "mfcr";
		case PPC_ID_MFCTR: return "mfctr";
		case PPC_ID_MFDCR: return "mfdcr";
		case PPC_ID_MFDCRUX: return "mfdcrux";
		case PPC_ID_MFDCRX: return "mfdcrx";
		case PPC_ID_MFFSx: return RcMnemonic(instruction, SubMnemMFFSx);
		case PPC_ID_MFFSCDRN: return "mffscdrn";
		case PPC_ID_MFFSCDRNI: return "mffscdrni";
		case PPC_ID_MFFSCE: return "mffsce";
		case PPC_ID_MFFSCRN: return "mffscrn";
		case PPC_ID_MFFSCRNI: return "mffscrni";
		case PPC_ID_MFFSL: return "mffsl";
		case PPC_ID_MFLR: return "mflr";
		case PPC_ID_MFMSR: return "mfmsr";
		case PPC_ID_MFOCRF: return "mfocrf";
		case PPC_ID_MFPMR: return "mfpmr";
		case PPC_ID_MFSPR: return "mfspr";
		case PPC_ID_MFSR: return "mfsr";
		case PPC_ID_MFSRIN: return "mfsrin";
		case PPC_ID_MFTB: return "mftb";
		case PPC_ID_MFTBU: return "mftbu";
		case PPC_ID_MFXER: return "mfxer";
		case PPC_ID_MRx: return RcMnemonic(instruction, SubMnemMRx);
		case PPC_ID_MSGSYNC: return "msgsync";
		case PPC_ID_MTAMR: return "mtamr";
		case PPC_ID_MTBR0: return "mtbr0";
		case PPC_ID_MTBR1: return "mtbr1";
		case PPC_ID_MTBR2: return "mtbr2";
		case PPC_ID_MTBR3: return "mtbr3";
		case PPC_ID_MTBR4: return "mtbr4";
		case PPC_ID_MTBR5: return "mtbr5";
		case PPC_ID_MTBR6: return "mtbr6";
		case PPC_ID_MTBR7: return "mtbr7";
		case PPC_ID_MTCRF: return "mtcrf";
		case PPC_ID_MTCTR: return "mtctr";
		case PPC_ID_MTDCR: return "mtdcr";
		case PPC_ID_MTDCRUX: return "mtdcrux";
		case PPC_ID_MTDCRX: return "mtdcrx";
		case PPC_ID_MTFSB0x: return RcMnemonic(instruction, SubMnemMTFSB0x);
		case PPC_ID_MTFSB1x: return RcMnemonic(instruction, SubMnemMTFSB1x);
		case PPC_ID_MTFSFx: return RcMnemonic(instruction, SubMnemMTFSFx);
		case PPC_ID_MTFSFIx: return RcMnemonic(instruction, SubMnemMTFSFIx);
		case PPC_ID_MODSD: return "modsd";
		case PPC_ID_MODSW: return "modsw";
		case PPC_ID_MODUD: return "modud";
		case PPC_ID_MODUW: return "moduw";
		case PPC_ID_MTLR: return "mtlr";
		case PPC_ID_MTMSR: return "mtmsr";
		case PPC_ID_MTMSRD: return "mtmsrd";
		case PPC_ID_MTOCRF: return "mtocrf";
		case PPC_ID_MTPMR: return "mtpmr";
		case PPC_ID_MTSPR: return "mtspr";
		case PPC_ID_MTSR: return "mtsr";
		case PPC_ID_MTSRIN: return "mtsrin";
		case PPC_ID_MTXER: return "mtxer";
		case PPC_ID_MULHDx: return RcMnemonic(instruction, SubMnemMULHDx);
		case PPC_ID_MULHDUx: return RcMnemonic(instruction, SubMnemMULHDUx);
		case PPC_ID_MULHWx: return RcMnemonic(instruction, SubMnemMULHWx);
		case PPC_ID_MULHWUx: return RcMnemonic(instruction, SubMnemMULHWUx);
		case PPC_ID_MULLI: return "mulli";
		case PPC_ID_MULLDx: return OeRcMnemonic(instruction, SubMnemMULLDx);
		case PPC_ID_MULLWx: return OeRcMnemonic(instruction, SubMnemMULLWx);
		case PPC_ID_NANDx: return RcMnemonic(instruction, SubMnemNANDx);
		case PPC_ID_NEGx: return OeRcMnemonic(instruction, SubMnemNEGx);
		case PPC_ID_NOP: return "nop";
		case PPC_ID_NORx: return RcMnemonic(instruction, SubMnemNORx);
		case PPC_ID_ORx: return RcMnemonic(instruction, SubMnemORx);
		case PPC_ID_ORCx: return RcMnemonic(instruction, SubMnemORCx);
		case PPC_ID_ORI: return "ori";
		case PPC_ID_ORIS: return "oris";
		case PPC_ID_PASTE: return "paste.";
		case PPC_ID_POPCNTB: return "popcntb";
		case PPC_ID_POPCNTD: return "popcntd";
		case PPC_ID_POPCNTW: return "popcntw";
		case PPC_ID_PTESYNC: return "ptesync";
		case PPC_ID_RFCI: return "rfci";
		case PPC_ID_RFDI: return "rfdi";
		case PPC_ID_RFI: return "rfi";
		case PPC_ID_RFID: return "rfid";
		case PPC_ID_RFMCI: return "rfmci";
		case PPC_ID_RLDICLx: return RcMnemonic(instruction, SubMnemRLDICLx);
		case PPC_ID_RLDICRx: return RcMnemonic(instruction, SubMnemRLDICRx);
		case PPC_ID_RLDICx: return RcMnemonic(instruction, SubMnemRLDICx);
		case PPC_ID_RLDIMIx: return RcMnemonic(instruction, SubMnemRLDIMIx);
		case PPC_ID_RLDCLx: return RcMnemonic(instruction, SubMnemRLDCLx);
		case PPC_ID_RLDCRx: return RcMnemonic(instruction, SubMnemRLDCRx);
		case PPC_ID_RLWIMIx: return RcMnemonic(instruction, SubMnemRLWIMIx);
		case PPC_ID_RLWINMx: return RcMnemonic(instruction, SubMnemRLWINMx);
		case PPC_ID_RLWNMx: return RcMnemonic(instruction, SubMnemRLWNMx);
		case PPC_ID_ROTLDx: return RcMnemonic(instruction, SubMnemROTLDx);
		case PPC_ID_ROTLDIx: return RcMnemonic(instruction, SubMnemROTLDIx);
		case PPC_ID_ROTLWx: return RcMnemonic(instruction, SubMnemROTLWx);
		case PPC_ID_ROTLWIx: return RcMnemonic(instruction, SubMnemROTLWIx);
		case PPC_ID_SC: return "sc";
		case PPC_ID_SETB: return "setb";
		case PPC_ID_SLBIA: return "slbia";
		case PPC_ID_SLBIE: return "slbie";
		case PPC_ID_SLBIEG: return "slbieg";
		case PPC_ID_SLBMFEE: return "slbmfee";
		case PPC_ID_SLBMFEV: return "slbmfev";
		case PPC_ID_SLBMTE: return "slbmte";
		case PPC_ID_SLBSYNC: return "slbsync";
		case PPC_ID_SLDx: return RcMnemonic(instruction, SubMnemSLDx);
		case PPC_ID_SLDIx: return RcMnemonic(instruction, SubMnemSLDIx);
		case PPC_ID_SLWx: return RcMnemonic(instruction, SubMnemSLWx);
		case PPC_ID_SLWIx: return RcMnemonic(instruction, SubMnemSLWIx);
		case PPC_ID_SRADx: return RcMnemonic(instruction, SubMnemSRADx);
		case PPC_ID_SRADIx: return RcMnemonic(instruction, SubMnemSRADIx);
		case PPC_ID_SRAWx: return RcMnemonic(instruction, SubMnemSRAWx);
		case PPC_ID_SRAWIx: return RcMnemonic(instruction, SubMnemSRAWIx);
		case PPC_ID_SRDx: return RcMnemonic(instruction, SubMnemSRDx);
		case PPC_ID_SRDIx: return RcMnemonic(instruction, SubMnemSRDIx);
		case PPC_ID_SRWx: return RcMnemonic(instruction, SubMnemSRWx);
		case PPC_ID_SRWIx: return RcMnemonic(instruction, SubMnemSRWIx);
		case PPC_ID_STB: return "stb";
		case PPC_ID_STBCIX: return "stbcix";
		case PPC_ID_STBCX: return "stbcx.";
		case PPC_ID_STBEPX: return "stbepx";
		case PPC_ID_STBU: return "stbu";
		case PPC_ID_STBUX: return "stbux";
		case PPC_ID_STBX: return "stbx";
		case PPC_ID_STD: return "std";
		case PPC_ID_STDAT: return "stdat";
		case PPC_ID_STDBRX: return "stdbrx";
		case PPC_ID_STDCIX: return "stdcix";
		case PPC_ID_STDCX: return "stdcx.";
		case PPC_ID_STDEPX: return "stdepx";
		case PPC_ID_STDU: return "stdu";
		case PPC_ID_STDUX: return "stdux";
		case PPC_ID_STDX: return "stdx";
		case PPC_ID_STFD: return "stfd";
		case PPC_ID_STFDEPX: return "stfdepx";
		case PPC_ID_STFDU: return "stfdu";
		case PPC_ID_STFDUX: return "stfdux";
		case PPC_ID_STFDX: return "stfdx";
		case PPC_ID_STFIWX: return "stfiwx";
		case PPC_ID_STFS: return "stfs";
		case PPC_ID_STFSU: return "stfsu";
		case PPC_ID_STFSUX: return "stfsux";
		case PPC_ID_STFSX: return "stfsx";
		case PPC_ID_STH: return "sth";
		case PPC_ID_STHBRX: return "sthbrx";
		case PPC_ID_STHCIX: return "sthcix";
		case PPC_ID_STHCX: return "sthcx.";
		case PPC_ID_STHEPX: return "sthepx";
		case PPC_ID_STHU: return "sthu";
		case PPC_ID_STHUX: return "sthux";
		case PPC_ID_STHX: return "sthx";
		case PPC_ID_STMW: return "stmw";
		case PPC_ID_STSWI: return "stswi";
		case PPC_ID_STSWX: return "stswx";
		case PPC_ID_STW: return "stw";
		case PPC_ID_STWAT: return "stwat";
		case PPC_ID_STWBRX: return "stwbrx";
		case PPC_ID_STWCIX: return "stwcix";
		case PPC_ID_STWCX: return "stwcx.";
		case PPC_ID_STWEPX: return "stwepx";
		case PPC_ID_STWU: return "stwu";
		case PPC_ID_STWUX: return "stwux";
		case PPC_ID_STWX: return "stwx";
		case PPC_ID_SUBFx: return OeRcMnemonic(instruction, SubMnemSUBFx);
		case PPC_ID_SUBFCx: return OeRcMnemonic(instruction, SubMnemSUBFCx);
		case PPC_ID_SUBFEx: return OeRcMnemonic(instruction, SubMnemSUBFEx);
		case PPC_ID_SUBFIC: return "subfic";
		case PPC_ID_SUBFMEx: return OeRcMnemonic(instruction, SubMnemSUBFMEx);
		case PPC_ID_SUBFZEx: return OeRcMnemonic(instruction, SubMnemSUBFZEx);
		case PPC_ID_SYNC: return "sync";
		case PPC_ID_TABORT: return "tabort.";
		case PPC_ID_TABORTDC: return "tabortdc.";
		case PPC_ID_TABORTDCI: return "tabortdci.";
		case PPC_ID_TABORTWC: return "tabortwc.";
		case PPC_ID_TABORTWCI: return "tabortwci.";
		case PPC_ID_TBEGIN: return "tbegin.";
		case PPC_ID_TCHECK: return "tcheck";
		case PPC_ID_TD: return "td";
		case PPC_ID_TDEQ: return "tdeq";
		case PPC_ID_TDEQI: return "tdeqi";
		case PPC_ID_TDGT: return "tdgt";
		case PPC_ID_TDGTI: return "tdgti";
		case PPC_ID_TDI: return "tdi";
		case PPC_ID_TDLGT: return "tdlgt";
		case PPC_ID_TDLGTI: return "tdlgti";
		case PPC_ID_TDLLT: return "tdllt";
		case PPC_ID_TDLLTI: return "tdllti";
		case PPC_ID_TDLT: return "tdlt";
		case PPC_ID_TDLTI: return "tdlti";
		case PPC_ID_TDNE: return "tdne";
		case PPC_ID_TDNEI: return "tdnei";
		case PPC_ID_TDU: return "tdu";
		case PPC_ID_TDUI: return "tdui";
		case PPC_ID_TEND: return "tend.";
		case PPC_ID_TLBIA: return "tlbia";
		case PPC_ID_TLBIE: return "tlbie";
		case PPC_ID_TLBIEL: return "tlbiel";
		case PPC_ID_TLBIVAX: return "tlbivax";
		case PPC_ID_TLBLI: return "tlbli";
		case PPC_ID_TLBSX: return "tlbsx";
		case PPC_ID_TLBSYNC: return "tlbsync";
		case PPC_ID_TLBRE: return "tlbre";
		case PPC_ID_TLBRELO: return "tlbrehi";
		case PPC_ID_TLBREHI: return "tlbrelo";
		case PPC_ID_TLBWE: return "tlbwe";
		case PPC_ID_TLBWEHI: return "tlbwehi";
		case PPC_ID_TLBWELO: return "tlbwelo";
		case PPC_ID_TRAP: return "trap";
		case PPC_ID_TRECHKPT: return "trechkpt.";
		case PPC_ID_TRECLAIM: return "treclaim.";
		case PPC_ID_TSR: return "tsr.";
		case PPC_ID_TW: return "tw";
		case PPC_ID_TWEQ: return "tweq";
		case PPC_ID_TWEQI: return "tweqi";
		case PPC_ID_TWGT: return "twgt";
		case PPC_ID_TWGTI: return "twgti";
		case PPC_ID_TWGEI: return "twgei";
		case PPC_ID_TWI: return "twi";
		case PPC_ID_TWLEI: return "twlei";
		case PPC_ID_TWLLEI: return "twllei";
		case PPC_ID_TWLGT: return "twlgt";
		case PPC_ID_TWLGTI: return "twlgti";
		case PPC_ID_TWLLT: return "twllt";
		case PPC_ID_TWLLTI: return "twllti";
		case PPC_ID_TWLT: return "twlt";
		case PPC_ID_TWLTI: return "twlti";
		case PPC_ID_TWNE: return "twne";
		case PPC_ID_TWNEI: return "twnei";
		case PPC_ID_TWU: return "twu";
		case PPC_ID_TWUI: return "twui";
		case PPC_ID_WAIT: return "wait";
		case PPC_ID_WAITIMPL: return "waitimpl";
		case PPC_ID_WAITRSV: return "waitrsv";
		case PPC_ID_WRTEE: return "wrtee";
		case PPC_ID_WRTEEI: return "wrteei";
		case PPC_ID_XNOP: return "xnop";
		case PPC_ID_XORx: return RcMnemonic(instruction, SubMnemXORx);
		case PPC_ID_XORI: return "xori";
		case PPC_ID_XORIS: return "xoris";

		case PPC_ID_AV_VABSDUB: return "vabsdub";
		case PPC_ID_AV_VABSDUH: return "vabsduh";
		case PPC_ID_AV_VABSDUW: return "vabsduw";
		case PPC_ID_AV_VADDUQM: return "vadduqm";
		case PPC_ID_AV_VADDCUQ: return "vaddcuq";
		case PPC_ID_AV_BCDADD: return "bcdadd.";
		case PPC_ID_AV_BCDCFN: return "bcdcfn.";
		case PPC_ID_AV_BCDCFSQ: return "bcdcfsq.";
		case PPC_ID_AV_BCDCFZ: return "bcdcfz.";
		case PPC_ID_AV_BCDCPSGN: return "bcdcpsgn.";
		case PPC_ID_AV_BCDCTN: return "bcdctn.";
		case PPC_ID_AV_BCDCTSQ: return "bcdctsq.";
		case PPC_ID_AV_BCDCTZ: return "bcdctz.";
		case PPC_ID_AV_BCDS: return "bcds.";
		case PPC_ID_AV_BCDSETSGN: return "bcdsetsgn.";
		case PPC_ID_AV_BCDSR: return "bcdsr.";
		case PPC_ID_AV_BCDSUB: return "bcdsub.";
		case PPC_ID_AV_BCDTRUNC: return "bcdtrunc.";
		case PPC_ID_AV_BCDUS: return "bcdus.";
		case PPC_ID_AV_BCDUTRUNC: return "bcdutrunc.";
		case PPC_ID_AV_DSS: return "dss";
		case PPC_ID_AV_DSSALL: return "dssall";
		case PPC_ID_AV_DST: return "dst";
		case PPC_ID_AV_DSTST: return "dstst";
		case PPC_ID_AV_DSTSTT: return "dststt";
		case PPC_ID_AV_DSTT: return "dstt";
		case PPC_ID_AV_LVEBX: return "lvebx";
		case PPC_ID_AV_LVEHX: return "lvehx";
		case PPC_ID_AV_LVEWX: return "lvewx";
		case PPC_ID_AV_LVSL: return "lvsl";
		case PPC_ID_AV_LVSR: return "lvsr";
		case PPC_ID_AV_LVX: return "lvx";
		case PPC_ID_AV_LVXL: return "lvxl";
		case PPC_ID_AV_MADDHD: return "maddhd";
		case PPC_ID_AV_MADDHDU: return "maddhdu";
		case PPC_ID_AV_MADDLD: return "maddld";
		case PPC_ID_AV_MFVSCR: return "mfvscr";
		case PPC_ID_AV_MTVSCR: return "mtvscr";
		case PPC_ID_AV_STVEBX: return "stvebx";
		case PPC_ID_AV_STVEHX: return "stvehx";
		case PPC_ID_AV_STVEWX: return "stvewx";
		case PPC_ID_AV_STVX: return "stvx";
		case PPC_ID_AV_STVXL: return "stvxl";
		case PPC_ID_AV_VADDCUW: return "vaddcuw";
		case PPC_ID_AV_VADDECUQ: return "vaddecuq";
		case PPC_ID_AV_VADDEUQM: return "vaddeuqm";
		case PPC_ID_AV_VADDFP: return "vaddfp";
		case PPC_ID_AV_VADDSBS: return "vaddsbs";
		case PPC_ID_AV_VADDSHS: return "vaddshs";
		case PPC_ID_AV_VADDSWS: return "vaddsws";
		case PPC_ID_AV_VADDUBM: return "vaddubm";
		case PPC_ID_AV_VADDUBS: return "vaddubs";
		case PPC_ID_AV_VADDUDM: return "vaddudm";
		case PPC_ID_AV_VADDUHM: return "vadduhm";
		case PPC_ID_AV_VADDUHS: return "vadduhs";
		case PPC_ID_AV_VADDUWM: return "vadduwm";
		case PPC_ID_AV_VADDUWS: return "vadduws";
		case PPC_ID_AV_VAND: return "vand";
		case PPC_ID_AV_VANDC: return "vandc";
		case PPC_ID_AV_VAVGSB: return "vavgsb";
		case PPC_ID_AV_VAVGSH: return "vavgsh";
		case PPC_ID_AV_VAVGSW: return "vavgsw";
		case PPC_ID_AV_VAVGUB: return "vavgub";
		case PPC_ID_AV_VAVGUH: return "vavguh";
		case PPC_ID_AV_VAVGUW: return "vavguw";
		case PPC_ID_AV_VBPERMD: return "vbpermd";
		case PPC_ID_AV_VBPERMQ: return "vbpermq";
		case PPC_ID_AV_VCFSX: return "vcfsx";
		case PPC_ID_AV_VCFUX: return "vcfux";
		case PPC_ID_AV_VCIPHER: return "vcipher";
		case PPC_ID_AV_VCIPHERLAST: return "vcipherlast";
		case PPC_ID_AV_VCLZB: return "vclzb";
		case PPC_ID_AV_VCLZD: return "vclzd";
		case PPC_ID_AV_VCLZH: return "vclzh";
		case PPC_ID_AV_VCLZLSBB: return "vclzlsbb";
		case PPC_ID_AV_VCLZW: return "vclzw";
		case PPC_ID_AV_VCMPBFPx: return RcMnemonic(instruction, SubMnemVCMPBFPx);
		case PPC_ID_AV_VCMPEQFPx: return RcMnemonic(instruction, SubMnemVCMPEQFPx);
		case PPC_ID_AV_VCMPEQUBx: return RcMnemonic(instruction, SubMnemVCMPEQUBx);
		case PPC_ID_AV_VCMPEQUDx: return RcMnemonic(instruction, SubMnemVCMPEQUDx);
		case PPC_ID_AV_VCMPEQUHx: return RcMnemonic(instruction, SubMnemVCMPEQUHx);
		case PPC_ID_AV_VCMPEQUWx: return RcMnemonic(instruction, SubMnemVCMPEQUWx);
		case PPC_ID_AV_VCMPGEFPx: return RcMnemonic(instruction, SubMnemVCMPGEFPx);
		case PPC_ID_AV_VCMPGTFPx: return RcMnemonic(instruction, SubMnemVCMPGTFPx);
		case PPC_ID_AV_VCMPGTSBx: return RcMnemonic(instruction, SubMnemVCMPGTSBx);
		case PPC_ID_AV_VCMPGTSDx: return RcMnemonic(instruction, SubMnemVCMPGTSDx);
		case PPC_ID_AV_VCMPGTSHx: return RcMnemonic(instruction, SubMnemVCMPGTSHx);
		case PPC_ID_AV_VCMPGTSWx: return RcMnemonic(instruction, SubMnemVCMPGTSWx);
		case PPC_ID_AV_VCMPGTUBx: return RcMnemonic(instruction, SubMnemVCMPGTUBx);
		case PPC_ID_AV_VCMPGTUDx: return RcMnemonic(instruction, SubMnemVCMPGTUDx);
		case PPC_ID_AV_VCMPGTUHx: return RcMnemonic(instruction, SubMnemVCMPGTUHx);
		case PPC_ID_AV_VCMPGTUWx: return RcMnemonic(instruction, SubMnemVCMPGTUWx);
		case PPC_ID_AV_VCMPNEBx: return RcMnemonic(instruction, SubMnemVCMPNEBx);
		case PPC_ID_AV_VCMPNEHx: return RcMnemonic(instruction, SubMnemVCMPNEHx);
		case PPC_ID_AV_VCMPNEWx: return RcMnemonic(instruction, SubMnemVCMPNEWx);
		case PPC_ID_AV_VCMPNEZBx: return RcMnemonic(instruction, SubMnemVCMPNEZBx);
		case PPC_ID_AV_VCMPNEZHx: return RcMnemonic(instruction, SubMnemVCMPNEZHx);
		case PPC_ID_AV_VCMPNEZWx: return RcMnemonic(instruction, SubMnemVCMPNEZWx);
		case PPC_ID_AV_VCTSXS: return "vctsxs";
		case PPC_ID_AV_VCTUXS: return "vctuxs";
		case PPC_ID_AV_VCTZB: return "vctzb";
		case PPC_ID_AV_VCTZD: return "vctzd";
		case PPC_ID_AV_VCTZH: return "vctzh";
		case PPC_ID_AV_VCTZLSBB: return "vctzlsbb";
		case PPC_ID_AV_VCTZW: return "vctzw";
		case PPC_ID_AV_VEQV: return "veqv";
		case PPC_ID_AV_VEXPTEFP: return "vexptefp";
		case PPC_ID_AV_VEXTRACTD: return "vextractd";
		case PPC_ID_AV_VEXTRACTUB: return "vextractub";
		case PPC_ID_AV_VEXTRACTUH: return "vextractuh";
		case PPC_ID_AV_VEXTRACTUW: return "vextractuw";
		case PPC_ID_AV_VEXTSB2D: return "vextsb2d";
		case PPC_ID_AV_VEXTSB2W: return "vextsb2w";
		case PPC_ID_AV_VEXTSH2D: return "vextsh2d";
		case PPC_ID_AV_VEXTSH2W: return "vextsh2w";
		case PPC_ID_AV_VEXTSW2D: return "vextsw2d";
		case PPC_ID_AV_VEXTUBLX: return "vextublx";
		case PPC_ID_AV_VEXTUHLX: return "vextuhlx";
		case PPC_ID_AV_VEXTUWLX: return "vextuwlx";
		case PPC_ID_AV_VEXTUBRX: return "vextubrx";
		case PPC_ID_AV_VEXTUHRX: return "vextuhrx";
		case PPC_ID_AV_VEXTUWRX: return "vextuwrx";
		case PPC_ID_AV_VGBBD: return "vgbbd";
		case PPC_ID_AV_VINSERTB: return "vinsertb";
		case PPC_ID_AV_VINSERTD: return "vinsertd";
		case PPC_ID_AV_VINSERTH: return "vinserth";
		case PPC_ID_AV_VINSERTW: return "vinsertw";
		case PPC_ID_AV_VLOGEFP: return "vlogefp";
		case PPC_ID_AV_VMADDFP: return "vmaddfp";
		case PPC_ID_AV_VMAXFP: return "vmaxfp";
		case PPC_ID_AV_VMAXSB: return "vmaxsb";
		case PPC_ID_AV_VMAXSD: return "vmaxsd";
		case PPC_ID_AV_VMAXSH: return "vmaxsh";
		case PPC_ID_AV_VMAXSW: return "vmaxsw";
		case PPC_ID_AV_VMAXUB: return "vmaxub";
		case PPC_ID_AV_VMAXUD: return "vmaxud";
		case PPC_ID_AV_VMAXUH: return "vmaxuh";
		case PPC_ID_AV_VMAXUW: return "vmaxuw";
		case PPC_ID_AV_VMHADDSHS: return "vmhaddshs";
		case PPC_ID_AV_VMHRADDSHS: return "vmhraddshs";
		case PPC_ID_AV_VMINFP: return "vminfp";
		case PPC_ID_AV_VMINSB: return "vminsb";
		case PPC_ID_AV_VMINSD: return "vminsd";
		case PPC_ID_AV_VMINSH: return "vminsh";
		case PPC_ID_AV_VMINSW: return "vminsw";
		case PPC_ID_AV_VMINUB: return "vminub";
		case PPC_ID_AV_VMINUD: return "vminud";
		case PPC_ID_AV_VMINUH: return "vminuh";
		case PPC_ID_AV_VMINUW: return "vminuw";
		case PPC_ID_AV_VMLADDUHM: return "vmladduhm";
		case PPC_ID_AV_VMR: return "vmr";
		case PPC_ID_AV_VMRGEW: return "vmrgew";
		case PPC_ID_AV_VMRGHB: return "vmrghb";
		case PPC_ID_AV_VMRGHH: return "vmrghh";
		case PPC_ID_AV_VMRGHW: return "vmrghw";
		case PPC_ID_AV_VMRGLB: return "vmrglb";
		case PPC_ID_AV_VMRGLH: return "vmrglh";
		case PPC_ID_AV_VMRGLW: return "vmrglw";
		case PPC_ID_AV_VMRGOW: return "vmrgow";
		case PPC_ID_AV_VMSUMMBM: return "vmsummbm";
		case PPC_ID_AV_VMSUMSHM: return "vmsumshm";
		case PPC_ID_AV_VMSUMSHS: return "vmsumshs";
		case PPC_ID_AV_VMSUMUBM: return "vmsumubm";
		case PPC_ID_AV_VMSUMUHM: return "vmsumuhm";
		case PPC_ID_AV_VMSUMUHS: return "vmsumuhs";
		case PPC_ID_AV_VMUL10CUQ: return "vmul10cuq";
		case PPC_ID_AV_VMUL10EUQ: return "vmul10euq";
		case PPC_ID_AV_VMUL10ECUQ: return "vmul10ecuq";
		case PPC_ID_AV_VMUL10UQ: return "vmul10uq";
		case PPC_ID_AV_VMULESB: return "vmulesb";
		case PPC_ID_AV_VMULESH: return "vmulesh";
		case PPC_ID_AV_VMULESW: return "vmulesw";
		case PPC_ID_AV_VMULEUB: return "vmuleub";
		case PPC_ID_AV_VMULEUH: return "vmuleuh";
		case PPC_ID_AV_VMULEUW: return "vmuleuw";
		case PPC_ID_AV_VMULOSB: return "vmulosb";
		case PPC_ID_AV_VMULOSH: return "vmulosh";
		case PPC_ID_AV_VMULOSW: return "vmulosw";
		case PPC_ID_AV_VMULOUB: return "vmuloub";
		case PPC_ID_AV_VMULOUH: return "vmulouh";
		case PPC_ID_AV_VMULOUW: return "vmulouw";
		case PPC_ID_AV_VMULUWM: return "vmuluwm";
		case PPC_ID_AV_VNAND: return "vnand";
		case PPC_ID_AV_VNCIPHER: return "vncipher";
		case PPC_ID_AV_VNCIPHERLAST: return "vncipherlast";
		case PPC_ID_AV_VNMSUBFP: return "vnmsubfp";
		case PPC_ID_AV_VNEGD: return "vnegd";
		case PPC_ID_AV_VNEGW: return "vnegw";
		case PPC_ID_AV_VNOR: return "vnor";
		case PPC_ID_AV_VNOT: return "vnot";
		case PPC_ID_AV_VOR: return "vor";
		case PPC_ID_AV_VORC: return "vorc";
		case PPC_ID_AV_VPERM: return "vperm";
		case PPC_ID_AV_VPERMR: return "vpermr";
		case PPC_ID_AV_VPERMXOR: return "vpermxor";
		case PPC_ID_AV_VPKPX: return "vpkpx";
		case PPC_ID_AV_VPKSDSS: return "vpksdss";
		case PPC_ID_AV_VPKSDUS: return "vpksdus";
		case PPC_ID_AV_VPKSHSS: return "vpkshss";
		case PPC_ID_AV_VPKSHUS: return "vpkshus";
		case PPC_ID_AV_VPKSWSS: return "vpkswss";
		case PPC_ID_AV_VPKSWUS: return "vpkswus";
		case PPC_ID_AV_VPKUDUM: return "vpkudum";
		case PPC_ID_AV_VPKUDUS: return "vpkudus";
		case PPC_ID_AV_VPKUHUM: return "vpkuhum";
		case PPC_ID_AV_VPKUHUS: return "vpkuhus";
		case PPC_ID_AV_VPKUWUM: return "vpkuwum";
		case PPC_ID_AV_VPKUWUS: return "vpkuwus";
		case PPC_ID_AV_VPMSUMB: return "vpmsumb";
		case PPC_ID_AV_VPMSUMD: return "vpmsumd";
		case PPC_ID_AV_VPMSUMH: return "vpmsumh";
		case PPC_ID_AV_VPMSUMW: return "vpmsumw";
		case PPC_ID_AV_VPOPCNTB: return "vpopcntb";
		case PPC_ID_AV_VPOPCNTD: return "vpopcntd";
		case PPC_ID_AV_VPOPCNTH: return "vpopcnth";
		case PPC_ID_AV_VPOPCNTW: return "vpopcntw";
		case PPC_ID_AV_VPRTYBD: return "vprtybd";
		case PPC_ID_AV_VPRTYBQ: return "vprtybq";
		case PPC_ID_AV_VPRTYBW: return "vprtybw";
		case PPC_ID_AV_VREFP: return "vrefp";
		case PPC_ID_AV_VRFIM: return "vrfim";
		case PPC_ID_AV_VRFIN: return "vrfin";
		case PPC_ID_AV_VRFIP: return "vrfip";
		case PPC_ID_AV_VRFIZ: return "vrfiz";
		case PPC_ID_AV_VRLB: return "vrlb";
		case PPC_ID_AV_VRLD: return "vrld";
		case PPC_ID_AV_VRLDNM: return "vrldnm";
		case PPC_ID_AV_VRLDMI: return "vrldmi";
		case PPC_ID_AV_VRLH: return "vrlh";
		case PPC_ID_AV_VRLW: return "vrlw";
		case PPC_ID_AV_VRLWMI: return "vrlwmi";
		case PPC_ID_AV_VRLWNM: return "vrlwnm";
		case PPC_ID_AV_VRSQRTEFP: return "vrsqrtefp";
		case PPC_ID_AV_VSBOX: return "vsbox";
		case PPC_ID_AV_VSEL: return "vsel";
		case PPC_ID_AV_VSHASIGMAD: return "vshasigmad";
		case PPC_ID_AV_VSHASIGMAW: return "vshasigmaw";
		case PPC_ID_AV_VSL: return "vsl";
		case PPC_ID_AV_VSLB: return "vslb";
		case PPC_ID_AV_VSLD: return "vsld";
		case PPC_ID_AV_VSLDOI: return "vsldoi";
		case PPC_ID_AV_VSLH: return "vslh";
		case PPC_ID_AV_VSLO: return "vslo";
		case PPC_ID_AV_VSLV: return "vslv";
		case PPC_ID_AV_VSLW: return "vslw";
		case PPC_ID_AV_VSPLTB: return "vspltb";
		case PPC_ID_AV_VSPLTH: return "vsplth";
		case PPC_ID_AV_VSPLTISB: return "vspltisb";
		case PPC_ID_AV_VSPLTISH: return "vspltish";
		case PPC_ID_AV_VSPLTISW: return "vspltisw";
		case PPC_ID_AV_VSPLTW: return "vspltw";
		case PPC_ID_AV_VSR: return "vsr";
		case PPC_ID_AV_VSRAB: return "vsrab";
		case PPC_ID_AV_VSRAD: return "vsrad";
		case PPC_ID_AV_VSRAH: return "vsrah";
		case PPC_ID_AV_VSRAW: return "vsraw";
		case PPC_ID_AV_VSRB: return "vsrb";
		case PPC_ID_AV_VSRD: return "vsrd";
		case PPC_ID_AV_VSRH: return "vsrh";
		case PPC_ID_AV_VSRO: return "vsro";
		case PPC_ID_AV_VSRV: return "vsrv";
		case PPC_ID_AV_VSRW: return "vsrw";
		case PPC_ID_AV_VSUBCUQ: return "vsubcuq";
		case PPC_ID_AV_VSUBCUW: return "vsubcuw";
		case PPC_ID_AV_VSUBECUQ: return "vsubecuq";
		case PPC_ID_AV_VSUBEUQM: return "vsubeuqm";
		case PPC_ID_AV_VSUBFP: return "vsubfp";
		case PPC_ID_AV_VSUBSBS: return "vsubsbs";
		case PPC_ID_AV_VSUBSHS: return "vsubshs";
		case PPC_ID_AV_VSUBSWS: return "vsubsws";
		case PPC_ID_AV_VSUBUBM: return "vsububm";
		case PPC_ID_AV_VSUBUBS: return "vsububs";
		case PPC_ID_AV_VSUBUDM: return "vsubudm";
		case PPC_ID_AV_VSUBUHM: return "vsubuhm";
		case PPC_ID_AV_VSUBUHS: return "vsubuhs";
		case PPC_ID_AV_VSUBUQM: return "vsubuqm";
		case PPC_ID_AV_VSUBUWM: return "vsubuwm";
		case PPC_ID_AV_VSUBUWS: return "vsubuws";
		case PPC_ID_AV_VSUMSWS: return "vsumsws";
		case PPC_ID_AV_VSUM2SWS: return "vsum2sws";
		case PPC_ID_AV_VSUM4SBS: return "vsum4sbs";
		case PPC_ID_AV_VSUM4SHS: return "vsum4shs";
		case PPC_ID_AV_VSUM4UBS: return "vsum4ubs";
		case PPC_ID_AV_VUPKHPX: return "vupkhpx";
		case PPC_ID_AV_VUPKHSB: return "vupkhsb";
		case PPC_ID_AV_VUPKHSH: return "vupkhsh";
		case PPC_ID_AV_VUPKHSW: return "vupkhsw";
		case PPC_ID_AV_VUPKLPX: return "vupklpx";
		case PPC_ID_AV_VUPKLSB: return "vupklsb";
		case PPC_ID_AV_VUPKLSH: return "vupklsh";
		case PPC_ID_AV_VUPKLSW: return "vupklsw";
		case PPC_ID_AV_VXOR: return "vxor";

		case PPC_ID_VSX_LXSDX: return "lxsdx";
		case PPC_ID_VSX_LXSIBZX: return "lxsibzx";
		case PPC_ID_VSX_LXSIHZX: return "lxsihzx";
		case PPC_ID_VSX_LXSIWAX: return "lxsiwax";
		case PPC_ID_VSX_LXSIWZX: return "lxsiwzx";
		case PPC_ID_VSX_LXSSPX: return "lxsspx";
		case PPC_ID_VSX_LXV: return "lxv";
		case PPC_ID_VSX_LXVB16X: return "lxvb16x";
		case PPC_ID_VSX_LXVD2X: return "lxvd2x";
		case PPC_ID_VSX_LXVDSX: return "lxvdsx";
		case PPC_ID_VSX_LXVH8X: return "lxvh8x";
		case PPC_ID_VSX_LXVL: return "lxvl";
		case PPC_ID_VSX_LXVLL: return "lxvll";
		case PPC_ID_VSX_LXVW4X: return "lxvw4x";
		case PPC_ID_VSX_LXVWSX: return "lxvwsx";
		case PPC_ID_VSX_LXVX: return "lxvx";
		case PPC_ID_VSX_MFFPRD: return "mffprd";
		case PPC_ID_VSX_MFVSRD: return "mfvsrd";
		case PPC_ID_VSX_MFVSRLD: return "mfvsrld";
		case PPC_ID_VSX_MFVSRWZ: return "mfvsrwz";
		case PPC_ID_VSX_MTVSRD: return "mtvsrd";
		case PPC_ID_VSX_MTVSRDD: return "mtvsrdd";
		case PPC_ID_VSX_MTVSRWA: return "mtvsrwa";
		case PPC_ID_VSX_MTVSRWS: return "mtvsrws";
		case PPC_ID_VSX_MTVSRWZ: return "mtvsrwz";
		case PPC_ID_VSX_STXSD: return "stxsd";
		case PPC_ID_VSX_STXSDX: return "stxsdx";
		case PPC_ID_VSX_STXSIBX: return "stxsibx";
		case PPC_ID_VSX_STXSIHX: return "stxsihx";
		case PPC_ID_VSX_STXSIWX: return "stxsiwx";
		case PPC_ID_VSX_STXSSP: return "stxssp";
		case PPC_ID_VSX_STXSSPX: return "stxsspx";
		case PPC_ID_VSX_STXVB16X: return "stxvb16x";
		case PPC_ID_VSX_STXVD2X: return "stxvd2x";
		case PPC_ID_VSX_STXVH8X: return "stxvh8x";
		case PPC_ID_VSX_STXV: return "stxv";
		case PPC_ID_VSX_STXVL: return "stxvl";
		case PPC_ID_VSX_STXVLL: return "stxvll";
		case PPC_ID_VSX_STXVW4X: return "stxvw4x";
		case PPC_ID_VSX_STXVX: return "stxvx";
		case PPC_ID_VSX_XSABSDP: return "xsabsdp";
		case PPC_ID_VSX_XSABSQP: return "xsabsqp";
		case PPC_ID_VSX_XSADDDP: return "xsadddp";
		case PPC_ID_VSX_XSADDSP: return "xsaddsp";
		case PPC_ID_VSX_XSADDQPx: return Round2OddMnemonic(instruction, SubMnemXSADDQPx);
		case PPC_ID_VSX_XSCMPEQDP: return "xscmpeqdp";
		case PPC_ID_VSX_XSCMPEXPDP: return "xscmpexpdp";
		case PPC_ID_VSX_XSCMPEXPQP: return "xscmpexpqp";
		case PPC_ID_VSX_XSCMPGEDP: return "xscmpgedp";
		case PPC_ID_VSX_XSCMPGTDP: return "xscmpgtdp";
		case PPC_ID_VSX_XSCMPODP: return "xscmpodp";
		case PPC_ID_VSX_XSCMPOQP: return "xscmpoqp";
		case PPC_ID_VSX_XSCMPUDP: return "xscmpudp";
		case PPC_ID_VSX_XSCMPUQP: return "xscmpuqp";
		case PPC_ID_VSX_XSCPSGNDP: return "xscpsgndp";
		case PPC_ID_VSX_XSCPSGNQP: return "xscpsgnqp";
		case PPC_ID_VSX_XSCVDPHP: return "xscvdphp";
		case PPC_ID_VSX_XSCVDPQP: return "xscvdpqp";
		case PPC_ID_VSX_XSCVDPSP: return "xscvdpsp";
		case PPC_ID_VSX_XSCVDPSPN: return "xscvdpspn";
		case PPC_ID_VSX_XSCVDPSXDS: return "xscvdpsxds";
		case PPC_ID_VSX_XSCVDPSXWS: return "xscvdpsxws";
		case PPC_ID_VSX_XSCVDPUXDS: return "xscvdpuxds";
		case PPC_ID_VSX_XSCVDPUXWS: return "xscvdpuxws";
		case PPC_ID_VSX_XSCVHPDP: return "xscvhpdp";
		case PPC_ID_VSX_XSCVQPDPx: return Round2OddMnemonic(instruction, SubMnemXSCVQPDPx);
		case PPC_ID_VSX_XSCVQPSDZ: return "xscvqpsdz";
		case PPC_ID_VSX_XSCVQPSWZ: return "xscvqpswz";
		case PPC_ID_VSX_XSCVQPUDZ: return "xscvqpudz";
		case PPC_ID_VSX_XSCVQPUWZ: return "xscvqpuwz";
		case PPC_ID_VSX_XSCVSDQP: return "xscvsdqp";
		case PPC_ID_VSX_XSCVSPDP: return "xscvspdp";
		case PPC_ID_VSX_XSCVSPDPN: return "xscvspdpn";
		case PPC_ID_VSX_XSCVSXDDP: return "xscvsxddp";
		case PPC_ID_VSX_XSCVSXDSP: return "xscvsxdsp";
		case PPC_ID_VSX_XSCVUDQP: return "xscvudqp";
		case PPC_ID_VSX_XSCVUXDDP: return "xscvuxddp";
		case PPC_ID_VSX_XSCVUXDSP: return "xscvuxdsp";
		case PPC_ID_VSX_XSDIVDP: return "xsdivdp";
		case PPC_ID_VSX_XSDIVSP: return "xsdivsp";
		case PPC_ID_VSX_XSDIVQPx: return Round2OddMnemonic(instruction, SubMnemXSDIVQPx);
		case PPC_ID_VSX_XSIEXPDP: return "xsiexpdp";
		case PPC_ID_VSX_XSIEXPQP: return "xsiexpqp";
		case PPC_ID_VSX_XSMADDADP: return "xsmaddadp";
		case PPC_ID_VSX_XSMADDASP: return "xsmaddasp";
		case PPC_ID_VSX_XSMADDMDP: return "xsmaddmdp";
		case PPC_ID_VSX_XSMADDMSP: return "xsmaddmsp";
		case PPC_ID_VSX_XSMADDQPx: return Round2OddMnemonic(instruction, SubMnemXSMADDQPx);
		case PPC_ID_VSX_XSMAXCDP: return "xsmaxcdp";
		case PPC_ID_VSX_XSMAXDP: return "xsmaxdp";
		case PPC_ID_VSX_XSMAXJDP: return "xsmaxjdp";
		case PPC_ID_VSX_XSMINDP: return "xsmindp";
		case PPC_ID_VSX_XSMINCDP: return "xsmincdp";
		case PPC_ID_VSX_XSMINJDP: return "xsminjdp";
		case PPC_ID_VSX_XSMSUBADP: return "xsmsubadp";
		case PPC_ID_VSX_XSMSUBASP: return "xsmsubasp";
		case PPC_ID_VSX_XSMSUBMDP: return "xsmsubmdp";
		case PPC_ID_VSX_XSMSUBMSP: return "xsmsubmsp";
		case PPC_ID_VSX_XSMSUBQPx: return Round2OddMnemonic(instruction, SubMnemXSMSUBQPx);
		case PPC_ID_VSX_XSMULDP: return "xsmuldp";
		case PPC_ID_VSX_XSMULSP: return "xsmulsp";
		case PPC_ID_VSX_XSMULQPx: return Round2OddMnemonic(instruction, SubMnemXSMULQPx);
		case PPC_ID_VSX_XSNABSDP: return "xsnabsdp";
		case PPC_ID_VSX_XSNABSQP: return "xsnabsqp";
		case PPC_ID_VSX_XSNEGDP: return "xsnegdp";
		case PPC_ID_VSX_XSNEGQP: return "xsnegqp";
		case PPC_ID_VSX_XSNMADDADP: return "xsnmaddadp";
		case PPC_ID_VSX_XSNMADDASP: return "xsnmaddasp";
		case PPC_ID_VSX_XSNMADDQPx: return Round2OddMnemonic(instruction, SubMnemXSNMADDQPx);
		case PPC_ID_VSX_XSNMADDMDP: return "xsnmaddmdp";
		case PPC_ID_VSX_XSNMADDMSP: return "xsnmaddmsp";
		case PPC_ID_VSX_XSNMSUBADP: return "xsnmsubadp";
		case PPC_ID_VSX_XSNMSUBASP: return "xsnmsubasp";
		case PPC_ID_VSX_XSNMSUBMDP: return "xsnmsubmdp";
		case PPC_ID_VSX_XSNMSUBMSP: return "xsnmsubmsp";
		case PPC_ID_VSX_XSNMSUBQPx: return Round2OddMnemonic(instruction, SubMnemXSNMSUBQPx);
		case PPC_ID_VSX_XSRDPI: return "xsrdpi";
		case PPC_ID_VSX_XSRDPIC: return "xsrdpic";
		case PPC_ID_VSX_XSRDPIM: return "xsrdpim";
		case PPC_ID_VSX_XSRDPIP: return "xsrdpip";
		case PPC_ID_VSX_XSRDPIZ: return "xsrdpiz";
		case PPC_ID_VSX_XSREDP: return "xsredp";
		case PPC_ID_VSX_XSRESP: return "xsresp";
		case PPC_ID_VSX_XSRSP: return "xsrsp";
		case PPC_ID_VSX_XSRSQRTEDP: return "xsrsqrtedp";
		case PPC_ID_VSX_XSRSQRTESP: return "xsrsqrtesp";
		case PPC_ID_VSX_XSSQRTDP: return "xssqrtdp";
		case PPC_ID_VSX_XSSQRTQPx: return Round2OddMnemonic(instruction, SubMnemXSSQRTQPx);
		case PPC_ID_VSX_XSSQRTSP: return "xssqrtsp";
		case PPC_ID_VSX_XSSUBDP: return "xssubdp";
		case PPC_ID_VSX_XSSUBSP: return "xssubsp";
		case PPC_ID_VSX_XSSUBQPx: return Round2OddMnemonic(instruction, SubMnemXSSUBQPx);
		case PPC_ID_VSX_XSRQPIx: return InexactMnemonic(instruction, SubMnemXSRQPIx);
		case PPC_ID_VSX_XSRQPXP: return "xsrqpxp";
		case PPC_ID_VSX_XSTDIVDP: return "xstdivdp";
		case PPC_ID_VSX_XSTDIVSP: return "xstdivsp";
		case PPC_ID_VSX_XSTSTDCDP: return "xststdcdp";
		case PPC_ID_VSX_XSTSTDCQP: return "xststdcqp";
		case PPC_ID_VSX_XSTSTDCSP: return "xststdcsp";
		case PPC_ID_VSX_XSTSQRTDP: return "xstsqrtdp";
		case PPC_ID_VSX_XSXEXPDP: return "xsxexpdp";
		case PPC_ID_VSX_XSXEXPQP: return "xsxexpqp";
		case PPC_ID_VSX_XSXSIGDP: return "xsxsigdp";
		case PPC_ID_VSX_XSXSIGQP: return "xsxsigqp";
		case PPC_ID_VSX_XVABSSP: return "xvabssp";
		case PPC_ID_VSX_XVABSDP: return "xvabsdp";
		case PPC_ID_VSX_XVADDSP: return "xvaddsp";
		case PPC_ID_VSX_XVADDDP: return "xvadddp";
		case PPC_ID_VSX_XVCMPEQDPx: return RcMnemonic(instruction, SubMnemXVCMPEQDPx);
		case PPC_ID_VSX_XVCMPEQSPx: return RcMnemonic(instruction, SubMnemXVCMPEQSPx);
		case PPC_ID_VSX_XVCMPGEDPx: return RcMnemonic(instruction, SubMnemXVCMPGEDPx);
		case PPC_ID_VSX_XVCMPGESPx: return RcMnemonic(instruction, SubMnemXVCMPGESPx);
		case PPC_ID_VSX_XVCMPGTDPx: return RcMnemonic(instruction, SubMnemXVCMPGTDPx);
		case PPC_ID_VSX_XVCMPGTSPx: return RcMnemonic(instruction, SubMnemXVCMPGTSPx);
		case PPC_ID_VSX_XVCPSGNDP: return "xvcpsgndp";
		case PPC_ID_VSX_XVCPSGNSP: return "xvcpsgnsp";
		case PPC_ID_VSX_XVCVDPSP: return "xvcvdpsp";
		case PPC_ID_VSX_XVCVDPSXDS: return "xvcvdpsxds";
		case PPC_ID_VSX_XVCVDPSXWS: return "xvcvdpsxws";
		case PPC_ID_VSX_XVCVDPUXDS: return "xvcvdpuxds";
		case PPC_ID_VSX_XVCVDPUXWS: return "xvcvdpuxws";
		case PPC_ID_VSX_XVCVHPSP: return "xvcvhpsp";
		case PPC_ID_VSX_XVCVSPDP: return "xvcvspdp";
		case PPC_ID_VSX_XVCVSPHP: return "xvcvsphp";
		case PPC_ID_VSX_XVCVSPSXDS: return "xvcvspsxds";
		case PPC_ID_VSX_XVCVSPSXWS: return "xvcvspsxws";
		case PPC_ID_VSX_XVCVSPUXDS: return "xvcvspuxds";
		case PPC_ID_VSX_XVCVSPUXWS: return "xvcvspuxws";
		case PPC_ID_VSX_XVCVSXDDP: return "xvcvsxddp";
		case PPC_ID_VSX_XVCVSXDSP: return "xvcvsxdsp";
		case PPC_ID_VSX_XVCVSXWDP: return "xvcvsxwdp";
		case PPC_ID_VSX_XVCVSXWSP: return "xvcvsxwsp";
		case PPC_ID_VSX_XVCVUXDDP: return "xvcvuxddp";
		case PPC_ID_VSX_XVCVUXDSP: return "xvcvuxdsp";
		case PPC_ID_VSX_XVCVUXWDP: return "xvcvuxwdp";
		case PPC_ID_VSX_XVCVUXWSP: return "xvcvuxwsp";
		case PPC_ID_VSX_XVDIVDP: return "xvdivdp";
		case PPC_ID_VSX_XVDIVSP: return "xvdivsp";
		case PPC_ID_VSX_XVIEXPDP: return "xviexpdp";
		case PPC_ID_VSX_XVIEXPSP: return "xviexpsp";
		case PPC_ID_VSX_XVMADDADP: return "xvmaddadp";
		case PPC_ID_VSX_XVMADDASP: return "xvmaddasp";
		case PPC_ID_VSX_XVMADDMDP: return "xvmaddmdp";
		case PPC_ID_VSX_XVMADDMSP: return "xvmaddmsp";
		case PPC_ID_VSX_XVMAXDP: return "xvmaxdp";
		case PPC_ID_VSX_XVMAXSP: return "xvmaxsp";
		case PPC_ID_VSX_XVMINDP: return "xvmindp";
		case PPC_ID_VSX_XVMINSP: return "xvminsp";
		case PPC_ID_VSX_XVMOVDP: return "xvmovdp";
		case PPC_ID_VSX_XVMOVSP: return "xvmovsp";
		case PPC_ID_VSX_XVMSUBADP: return "xvmsubadp";
		case PPC_ID_VSX_XVMSUBASP: return "xvmsubasp";
		case PPC_ID_VSX_XVMSUBMDP: return "xvmsubmdp";
		case PPC_ID_VSX_XVMSUBMSP: return "xvmsubmsp";
		case PPC_ID_VSX_XVMULSP: return "xvmulsp";
		case PPC_ID_VSX_XVMULDP: return "xvmuldp";
		case PPC_ID_VSX_XVNABSDP: return "xvnabsdp";
		case PPC_ID_VSX_XVNABSSP: return "xvnabssp";
		case PPC_ID_VSX_XVNMADDADP: return "xvnmaddadp";
		case PPC_ID_VSX_XVNMADDASP: return "xvnmaddasp";
		case PPC_ID_VSX_XVNMADDMDP: return "xvnmaddmdp";
		case PPC_ID_VSX_XVNMADDMSP: return "xvnmaddmsp";
		case PPC_ID_VSX_XVNEGDP: return "xvnegdp";
		case PPC_ID_VSX_XVNEGSP: return "xvnegsp";
		case PPC_ID_VSX_XVNMSUBADP: return "xvnmsubadp";
		case PPC_ID_VSX_XVNMSUBASP: return "xvnmsubasp";
		case PPC_ID_VSX_XVNMSUBMSP: return "xvnmsubmsp";
		case PPC_ID_VSX_XVNMSUBMDP: return "xvnmsubmdp";
		case PPC_ID_VSX_XVRDPI: return "xvrdpi";
		case PPC_ID_VSX_XVRDPIC: return "xvrdpic";
		case PPC_ID_VSX_XVRDPIM: return "xvrdpim";
		case PPC_ID_VSX_XVRDPIP: return "xvrdpip";
		case PPC_ID_VSX_XVRDPIZ: return "xvrdpiz";
		case PPC_ID_VSX_XVREDP: return "xvredp";
		case PPC_ID_VSX_XVRESP: return "xvresp";
		case PPC_ID_VSX_XVRSPI: return "xvrspi";
		case PPC_ID_VSX_XVRSPIC: return "xvrspic";
		case PPC_ID_VSX_XVRSPIM: return "xvrspim";
		case PPC_ID_VSX_XVRSPIP: return "xvrspip";
		case PPC_ID_VSX_XVRSPIZ: return "xvrspiz";
		case PPC_ID_VSX_XVRSQRTEDP: return "xvrsqrtedp";
		case PPC_ID_VSX_XVRSQRTESP: return "xvrsqrtesp";
		case PPC_ID_VSX_XVSQRTDP: return "xvsqrtdp";
		case PPC_ID_VSX_XVSQRTSP: return "xvsqrtsp";
		case PPC_ID_VSX_XVSUBSP: return "xvsubsp";
		case PPC_ID_VSX_XVSUBDP: return "xvsubdp";
		case PPC_ID_VSX_XVTDIVDP: return "xvtdivdp";
		case PPC_ID_VSX_XVTDIVSP: return "xvtdivsp";
		case PPC_ID_VSX_XVTSQRTDP: return "xvtsqrtdp";
		case PPC_ID_VSX_XVTSQRTSP: return "xvtsqrtsp";
		case PPC_ID_VSX_XVTSTDCDP: return "xvtstdcdp";
		case PPC_ID_VSX_XVTSTDCSP: return "xvtstdcsp";
		case PPC_ID_VSX_XVXEXPDP: return "xvxexpdp";
		case PPC_ID_VSX_XVXEXPSP: return "xvxexpsp";
		case PPC_ID_VSX_XVXSIGDP: return "xvxsigdp";
		case PPC_ID_VSX_XVXSIGSP: return "xvxsigsp";
		case PPC_ID_VSX_XXBRD: return "xxbrd";
		case PPC_ID_VSX_XXBRH: return "xxbrh";
		case PPC_ID_VSX_XXBRQ: return "xxbrq";
		case PPC_ID_VSX_XXBRW: return "xxbrw";
		case PPC_ID_VSX_XXEXTRACTUW: return "xxextractuw";
		case PPC_ID_VSX_XXINSERTW: return "xxinsertw";
		case PPC_ID_VSX_XXLAND: return "xxland";
		case PPC_ID_VSX_XXLANDC: return "xxlandc";
		case PPC_ID_VSX_XXLEQV: return "xxleqv";
		case PPC_ID_VSX_XXLNAND: return "xxlnand";
		case PPC_ID_VSX_XXLNOR: return "xxlnor";
		case PPC_ID_VSX_XXLORC: return "xxlorc";
		case PPC_ID_VSX_XXMRGHD: return "xxmrghd";
		case PPC_ID_VSX_XXMRGHW: return "xxmrghw";
		case PPC_ID_VSX_XXMRGLD: return "xxmrgld";
		case PPC_ID_VSX_XXMRGLW: return "xxmrglw";
		case PPC_ID_VSX_XXLOR: return "xxlor";
		case PPC_ID_VSX_XXLXOR: return "xxlxor";
		case PPC_ID_VSX_XXPERM: return "xxperm";
		case PPC_ID_VSX_XXPERMDI: return "xxpermdi";
		case PPC_ID_VSX_XXPERMR: return "xxpermr";
		case PPC_ID_VSX_XXSEL: return "xxsel";
		case PPC_ID_VSX_XXSLDWI: return "xxsldwi";
		case PPC_ID_VSX_XXSPLTD: return "xxspltd";
		case PPC_ID_VSX_XXSPLTIB: return "xxspltib";
		case PPC_ID_VSX_XXSPLTW: return "xxspltw";
		case PPC_ID_VSX_XXSWAPD: return "xxswapd";

		case PPC_ID_PSQ_L: return "psq_l";
		case PPC_ID_PSQ_LU: return "psq_lu";
		case PPC_ID_PSQ_LUX: return "psq_lux";
		case PPC_ID_PSQ_LX: return "psq_lx";
		case PPC_ID_PSQ_ST: return "psq_st";
		case PPC_ID_PSQ_STU: return "psq_stu";
		case PPC_ID_PSQ_STUX: return "psq_stux";
		case PPC_ID_PSQ_STX: return "psq_stx";

		case PPC_ID_SPE_BRINC: return "brinc";
		case PPC_ID_SPE_EFDABS: return "efdabs";
		case PPC_ID_SPE_EFDADD: return "efdadd";
		case PPC_ID_SPE_EFDCFS: return "efdcfs";
		case PPC_ID_SPE_EFDCFSF: return "efdcfsf";
		case PPC_ID_SPE_EFDCFSI: return "efdcfsi";
		case PPC_ID_SPE_EFDCFSID: return "efdcfsid";
		case PPC_ID_SPE_EFDCFUF: return "efdcfuf";
		case PPC_ID_SPE_EFDCFUI: return "efdcfui";
		case PPC_ID_SPE_EFDCFUID: return "efdcfuid";
		case PPC_ID_SPE_EFDCMPEQ: return "efdcmpeq";
		case PPC_ID_SPE_EFDCMPGT: return "efdcmpgt";
		case PPC_ID_SPE_EFDCMPLT: return "efdcmplt";
		case PPC_ID_SPE_EFDCTSF: return "efdctsf";
		case PPC_ID_SPE_EFDCTSI: return "efdctsi";
		case PPC_ID_SPE_EFDCTSIDZ: return "efdctsidz";
		case PPC_ID_SPE_EFDCTSIZ: return "efdctsiz";
		case PPC_ID_SPE_EFDCTUF: return "efdctuf";
		case PPC_ID_SPE_EFDCTUI: return "efdctui";
		case PPC_ID_SPE_EFDCTUIDZ: return "efdctuidz";
		case PPC_ID_SPE_EFDCTUIZ: return "efdctuiz";
		case PPC_ID_SPE_EFDDIV: return "efddiv";
		case PPC_ID_SPE_EFDMUL: return "efdmul";
		case PPC_ID_SPE_EFDNABS: return "efdnabs";
		case PPC_ID_SPE_EFDNEG: return "efdneg";
		case PPC_ID_SPE_EFDSUB: return "efdsub";
		case PPC_ID_SPE_EFDTSTEQ: return "efdtsteq";
		case PPC_ID_SPE_EFDTSTGT: return "efdtstgt";
		case PPC_ID_SPE_EFDTSTLT: return "efdtstlt";
		case PPC_ID_SPE_EFSABS: return "efsabs";
		case PPC_ID_SPE_EFSADD: return "efsadd";
		case PPC_ID_SPE_EFSCFD: return "efscfd";
		case PPC_ID_SPE_EFSCFSF: return "efscfsf";
		case PPC_ID_SPE_EFSCFSI: return "efscfsi";
		case PPC_ID_SPE_EFSCFUF: return "efscfuf";
		case PPC_ID_SPE_EFSCFUI: return "efscfui";
		case PPC_ID_SPE_EFSCMPEQ: return "efscmpeq";
		case PPC_ID_SPE_EFSCMPGT: return "efscmpgt";
		case PPC_ID_SPE_EFSCMPLT: return "efscmplt";
		case PPC_ID_SPE_EFSCTSF: return "efsctsf";
		case PPC_ID_SPE_EFSCTSI: return "efsctsi";
		case PPC_ID_SPE_EFSCTSIZ: return "efsctsiz";
		case PPC_ID_SPE_EFSCTUF: return "efsctuf";
		case PPC_ID_SPE_EFSCTUI: return "efsctui";
		case PPC_ID_SPE_EFSCTUIZ: return "efsctuiz";
		case PPC_ID_SPE_EFSDIV: return "efsdiv";
		case PPC_ID_SPE_EFSMUL: return "efsmul";
		case PPC_ID_SPE_EFSNABS: return "efsnabs";
		case PPC_ID_SPE_EFSNEG: return "efsneg";
		case PPC_ID_SPE_EFSSUB: return "efssub";
		case PPC_ID_SPE_EFSTSTEQ: return "efststeq";
		case PPC_ID_SPE_EFSTSTGT: return "efststgt";
		case PPC_ID_SPE_EFSTSTLT: return "efststlt";
		case PPC_ID_SPE_EVABS: return "evabs";
		case PPC_ID_SPE_EVADDIW: return "evaddiw";
		case PPC_ID_SPE_EVADDSMIAAW: return "evaddsmiaaw";
		case PPC_ID_SPE_EVADDSSIAAW: return "evaddssiaaw";
		case PPC_ID_SPE_EVADDUMIAAW: return "evaddumiaaw";
		case PPC_ID_SPE_EVADDUSIAAW: return "evaddusiaaw";
		case PPC_ID_SPE_EVADDW: return "evaddw";
		case PPC_ID_SPE_EVAND: return "evand";
		case PPC_ID_SPE_EVANDC: return "evandc";
		case PPC_ID_SPE_EVCMPEQ: return "evcmpeq";
		case PPC_ID_SPE_EVCMPGTS: return "evcmpgts";
		case PPC_ID_SPE_EVCMPGTU: return "evcmpgtu";
		case PPC_ID_SPE_EVCMPLTS: return "evcmplts";
		case PPC_ID_SPE_EVCMPLTU: return "evcmpltu";
		case PPC_ID_SPE_EVCNTLSW: return "evcntlsw";
		case PPC_ID_SPE_EVCNTLZW: return "evcntlzw";
		case PPC_ID_SPE_EVDIVWS: return "evdivws";
		case PPC_ID_SPE_EVDIVWU: return "evdivwu";
		case PPC_ID_SPE_EVEQV: return "eveqv";
		case PPC_ID_SPE_EVEXTSB: return "evextsb";
		case PPC_ID_SPE_EVEXTSH: return "evextsh";
		case PPC_ID_SPE_EVFSABS: return "evfsabs";
		case PPC_ID_SPE_EVFSADD: return "evfsadd";
		case PPC_ID_SPE_EVFSCFSF: return "evfscfsf";
		case PPC_ID_SPE_EVFSCFSI: return "evfscfsi";
		case PPC_ID_SPE_EVFSCFUF: return "evfscfuf";
		case PPC_ID_SPE_EVFSCFUI: return "evfscfui";
		case PPC_ID_SPE_EVSCFUI: return "evscfui";
		case PPC_ID_SPE_EVFSCMPEQ: return "evfscmpeq";
		case PPC_ID_SPE_EVFSCMPGT: return "evfscmpgt";
		case PPC_ID_SPE_EVFSCMPLT: return "evfscmplt";
		case PPC_ID_SPE_EVFSCTSF: return "evfsctsf";
		case PPC_ID_SPE_EVFSCTSI: return "evfsctsi";
		case PPC_ID_SPE_EVFSCTSIZ: return "evfsctsiz";
		case PPC_ID_SPE_EVFSCTUF: return "evfsctuf";
		case PPC_ID_SPE_EVFSCTUI: return "evfsctui";
		case PPC_ID_SPE_EVFSCTUIZ: return "evfsctuiz";
		case PPC_ID_SPE_EVFSDIV: return "evfsdiv";
		case PPC_ID_SPE_EVFSMUL: return "evfsmul";
		case PPC_ID_SPE_EVFSNABS: return "evfsnabs";
		case PPC_ID_SPE_EVFSNEG: return "evfsneg";
		case PPC_ID_SPE_EVFSSUB: return "evfssub";
		case PPC_ID_SPE_EVFSTSTEQ: return "evfststeq";
		case PPC_ID_SPE_EVFSTSTGT: return "evfststgt";
		case PPC_ID_SPE_EVFSTSTLT: return "evfststlt";
		case PPC_ID_SPE_EVLDD: return "evldd";
		case PPC_ID_SPE_EVLDDX: return "evlddx";
		case PPC_ID_SPE_EVLDH: return "evldh";
		case PPC_ID_SPE_EVLDHX: return "evldhx";
		case PPC_ID_SPE_EVLDW: return "evldw";
		case PPC_ID_SPE_EVLDWX: return "evldwx";
		case PPC_ID_SPE_EVLHHESPLAT: return "evlhhesplat";
		case PPC_ID_SPE_EVLHHESPLATX: return "evlhhesplatx";
		case PPC_ID_SPE_EVLHHOSSPLAT: return "evlhhossplat";
		case PPC_ID_SPE_EVLHHOSSPLATX: return "evlhhossplatx";
		case PPC_ID_SPE_EVLHHOUSPLAT: return "evlhhousplat";
		case PPC_ID_SPE_EVLHHOUSPLATX: return "evlhhousplatx";
		case PPC_ID_SPE_EVLWHE: return "evlwhe";
		case PPC_ID_SPE_EVLWHEX: return "evlwhex";
		case PPC_ID_SPE_EVLWHOS: return "evlwhos";
		case PPC_ID_SPE_EVLWHOSX: return "evlwhosx";
		case PPC_ID_SPE_EVLWHOU: return "evlwhou";
		case PPC_ID_SPE_EVLWHOUX: return "evlwhoux";
		case PPC_ID_SPE_EVLWHSPLAT: return "evlwhsplat";
		case PPC_ID_SPE_EVLWHSPLATX: return "evlwhsplatx";
		case PPC_ID_SPE_EVLWWSPLAT: return "evlwwsplat";
		case PPC_ID_SPE_EVLWWSPLATX: return "evlwwsplatx";
		case PPC_ID_SPE_EVMERGEHI: return "evmergehi";
		case PPC_ID_SPE_EVMERGEHILO: return "evmergehilo";
		case PPC_ID_SPE_EVMERGELO: return "evmergelo";
		case PPC_ID_SPE_EVMERGELOHI: return "evmergelohi";
		case PPC_ID_SPE_EVMHEGSMFAA: return "evmhegsmfaa";
		case PPC_ID_SPE_EVMHEGSMFAN: return "evmhegsmfan";
		case PPC_ID_SPE_EVMHEGSMIAA: return "evmhegsmiaa";
		case PPC_ID_SPE_EVMHEGSMIAN: return "evmhegsmian";
		case PPC_ID_SPE_EVMHEGUMIAA: return "evmhegumiaa";
		case PPC_ID_SPE_EVMHEGUMIAN: return "evmhegumian";
		case PPC_ID_SPE_EVMHESMF: return "evmhesmf";
		case PPC_ID_SPE_EVMHESMFA: return "evmhesmfa";
		case PPC_ID_SPE_EVMHESMFAAW: return "evmhesmfaaw";
		case PPC_ID_SPE_EVMHESMFANW: return "evmhesmfanw";
		case PPC_ID_SPE_EVMHESMI: return "evmhesmi";
		case PPC_ID_SPE_EVMHESMIA: return "evmhesmia";
		case PPC_ID_SPE_EVMHESMIAAW: return "evmhesmiaaw";
		case PPC_ID_SPE_EVMHESMIANW: return "evmhesmianw";
		case PPC_ID_SPE_EVMHESSF: return "evmhessf";
		case PPC_ID_SPE_EVMHESSFA: return "evmhessfa";
		case PPC_ID_SPE_EVMHESSFAAW: return "evmhessfaaw";
		case PPC_ID_SPE_EVMHESSFANW: return "evmhessfanw";
		case PPC_ID_SPE_EVMHESSIAAW: return "evmhessiaaw";
		case PPC_ID_SPE_EVMHESSIANW: return "evmhessianw";
		case PPC_ID_SPE_EVMHEUMI: return "evmheumi";
		case PPC_ID_SPE_EVMHEUMIA: return "evmheumia";
		case PPC_ID_SPE_EVMHEUMIAAW: return "evmheumiaaw";
		case PPC_ID_SPE_EVMHEUMIANW: return "evmheumianw";
		case PPC_ID_SPE_EVMHEUSIAAW: return "evmheusiaaw";
		case PPC_ID_SPE_EVMHEUSIANW: return "evmheusianw";
		case PPC_ID_SPE_EVMHOGSMFAA: return "evmhogsmfaa";
		case PPC_ID_SPE_EVMHOGSMFAN: return "evmhogsmfan";
		case PPC_ID_SPE_EVMHOGSMIAA: return "evmhogsmiaa";
		case PPC_ID_SPE_EVMHOGSMIAN: return "evmhogsmian";
		case PPC_ID_SPE_EVMHOGUMIAA: return "evmhogumiaa";
		case PPC_ID_SPE_EVMHOGUMIAN: return "evmhogumian";
		case PPC_ID_SPE_EVMHOSMF: return "evmhosmf";
		case PPC_ID_SPE_EVMHOSMFA: return "evmhosmfa";
		case PPC_ID_SPE_EVMHOSMFAAW: return "evmhosmfaaw";
		case PPC_ID_SPE_EVMHOSMFANW: return "evmhosmfanw";
		case PPC_ID_SPE_EVMHOSMI: return "evmhosmi";
		case PPC_ID_SPE_EVMHOSMIA: return "evmhosmia";
		case PPC_ID_SPE_EVMHOSMIAAW: return "evmhosmiaaw";
		case PPC_ID_SPE_EVMHOSMIANW: return "evmhosmianw";
		case PPC_ID_SPE_EVMHOSSF: return "evmhossf";
		case PPC_ID_SPE_EVMHOSSFA: return "evmhossfa";
		case PPC_ID_SPE_EVMHOSSFAAW: return "evmhossfaaw";
		case PPC_ID_SPE_EVMHOSSFANW: return "evmhossfanw";
		case PPC_ID_SPE_EVMHOSSIAAW: return "evmhossiaaw";
		case PPC_ID_SPE_EVMHOSSIANW: return "evmhossianw";
		case PPC_ID_SPE_EVMHOUMI: return "evmhoumi";
		case PPC_ID_SPE_EVMHOUMIA: return "evmhoumia";
		case PPC_ID_SPE_EVMHOUMIAAW: return "evmhoumiaaw";
		case PPC_ID_SPE_EVMHOUMIANW: return "evmhoumianw";
		case PPC_ID_SPE_EVMHOUSIAAW: return "evmhousiaaw";
		case PPC_ID_SPE_EVMHOUSIANW: return "evmhousianw";
		case PPC_ID_SPE_EVMR: return "evmr";
		case PPC_ID_SPE_EVMRA: return "evmra";
		case PPC_ID_SPE_EVMWHSMF: return "evmwhsmf";
		case PPC_ID_SPE_EVMWHSMFA: return "evmwhsmfa";
		case PPC_ID_SPE_EVMWHSMI: return "evmwhsmi";
		case PPC_ID_SPE_EVMWHSMIA: return "evmwhsmia";
		case PPC_ID_SPE_EVMWHSSF: return "evmwhssf";
		case PPC_ID_SPE_EVMWHSSFA: return "evmwhssfa";
		case PPC_ID_SPE_EVMWHUMI: return "evmwhumi";
		case PPC_ID_SPE_EVMWHUMIA: return "evmwhumia";
		case PPC_ID_SPE_EVMWHUSIAAW: return "evmwhusiaaw";
		case PPC_ID_SPE_EVMWHUSIANW: return "evmwhusianw";
		case PPC_ID_SPE_EVMWLSMIAAW: return "evmwlsmiaaw";
		case PPC_ID_SPE_EVMWLSMIANW: return "evmwlsmianw";
		case PPC_ID_SPE_EVMWLSSIANW: return "evmwlssianw";
		case PPC_ID_SPE_EVMWLSSIAAW: return "evmwlssiaaw";
		case PPC_ID_SPE_EVMWLUMI: return "evmwlumi";
		case PPC_ID_SPE_EVMWLUMIA: return "evmwlumia";
		case PPC_ID_SPE_EVMWLUMIAAW: return "evmwlumiaaw";
		case PPC_ID_SPE_EVMWLUMIANW: return "evmwlumianw";
		case PPC_ID_SPE_EVMWLUSIAAW: return "evmwlusiaaw";
		case PPC_ID_SPE_EVMWLUSIANW: return "evmwlusianw";
		case PPC_ID_SPE_EVMWSMF: return "evmwsmf";
		case PPC_ID_SPE_EVMWSMFA: return "evmwsmfa";
		case PPC_ID_SPE_EVMWSMFAA: return "evmwsmfaa";
		case PPC_ID_SPE_EVMWSMFAN: return "evmwsmfan";
		case PPC_ID_SPE_EVMWSMI: return "evmwsmi";
		case PPC_ID_SPE_EVMWSMIA: return "evmwsmia";
		case PPC_ID_SPE_EVMWSMIAA: return "evmwsmiaa";
		case PPC_ID_SPE_EVMWSMIAN: return "evmwsmian";
		case PPC_ID_SPE_EVMWSSF: return "evmwssf";
		case PPC_ID_SPE_EVMWSSFA: return "evmwssfa";
		case PPC_ID_SPE_EVMWSSFAA: return "evmwssfaa";
		case PPC_ID_SPE_EVMWSSFAN: return "evmwssfan";
		case PPC_ID_SPE_EVMWUMI: return "evmwumi";
		case PPC_ID_SPE_EVMWUMIA: return "evmwumia";
		case PPC_ID_SPE_EVMWUMIAA: return "evmwumiaa";
		case PPC_ID_SPE_EVMWUMIAN: return "evmwumian";
		case PPC_ID_SPE_EVNAND: return "evnand";
		case PPC_ID_SPE_EVNEG: return "evneg";
		case PPC_ID_SPE_EVNOR: return "evnor";
		case PPC_ID_SPE_EVNOT: return "evnot";
		case PPC_ID_SPE_EVOR: return "evor";
		case PPC_ID_SPE_EVORC: return "evorc";
		case PPC_ID_SPE_EVRLW: return "evrlw";
		case PPC_ID_SPE_EVRLWI: return "evrlwi";
		case PPC_ID_SPE_EVRNDW: return "evrndw";
		case PPC_ID_SPE_EVSEL: return "evsel";
		case PPC_ID_SPE_EVSLW: return "evslw";
		case PPC_ID_SPE_EVSLWI: return "evslwi";
		case PPC_ID_SPE_EVSPLATFI: return "evsplatfi";
		case PPC_ID_SPE_EVSPLATI: return "evsplati";
		case PPC_ID_SPE_EVSRWIS: return "evsrwis";
		case PPC_ID_SPE_EVSRWIU: return "evsrwiu";
		case PPC_ID_SPE_EVSRWS: return "evsrws";
		case PPC_ID_SPE_EVSRWU: return "evsrwu";
		case PPC_ID_SPE_EVSTDD: return "evstdd";
		case PPC_ID_SPE_EVSTDDX: return "evstddx";
		case PPC_ID_SPE_EVSTDH: return "evstdh";
		case PPC_ID_SPE_EVSTDHX: return "evstdhx";
		case PPC_ID_SPE_EVSTDW: return "evstdw";
		case PPC_ID_SPE_EVSTDWX: return "evstdwx";
		case PPC_ID_SPE_EVSTWHE: return "evstwhe";
		case PPC_ID_SPE_EVSTWHEX: return "evstwhex";
		case PPC_ID_SPE_EVSTWHO: return "evstwho";
		case PPC_ID_SPE_EVSTWHOX: return "evstwhox";
		case PPC_ID_SPE_EVSTWWE: return "evstwwe";
		case PPC_ID_SPE_EVSTWWEX: return "evstwwex";
		case PPC_ID_SPE_EVSTWWO: return "evstwwo";
		case PPC_ID_SPE_EVSTWWOX: return "evstwwox";
		case PPC_ID_SPE_EVSUBFSMIAAW: return "evsubfsmiaaw";
		case PPC_ID_SPE_EVSUBFSSIAAW: return "evsubfssiaaw";
		case PPC_ID_SPE_EVSUBFUMIAAW: return "evsubfumiaaw";
		case PPC_ID_SPE_EVSUBFUSIAAW: return "evsubfusiaaw";
		case PPC_ID_SPE_EVSUBFW: return "evsubfw";
		case PPC_ID_SPE_EVSUBIFW: return "evsubifw";
		case PPC_ID_SPE_EVXOR: return "evxor";

		default: return NULL;
	}
}
