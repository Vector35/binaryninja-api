#include "decode.h"

const char* PowerPCRegisterName(uint32_t regId)
{
	switch (regId)
	{
		case PPC_REG_GPR0: return "r0";
		case PPC_REG_GPR1: return "r1";
		case PPC_REG_GPR2: return "r2";
		case PPC_REG_GPR3: return "r3";
		case PPC_REG_GPR4: return "r4";
		case PPC_REG_GPR5: return "r5";
		case PPC_REG_GPR6: return "r6";
		case PPC_REG_GPR7: return "r7";
		case PPC_REG_GPR8: return "r8";
		case PPC_REG_GPR9: return "r9";
		case PPC_REG_GPR10: return "r10";
		case PPC_REG_GPR11: return "r11";
		case PPC_REG_GPR12: return "r12";
		case PPC_REG_GPR13: return "r13";
		case PPC_REG_GPR14: return "r14";
		case PPC_REG_GPR15: return "r15";
		case PPC_REG_GPR16: return "r16";
		case PPC_REG_GPR17: return "r17";
		case PPC_REG_GPR18: return "r18";
		case PPC_REG_GPR19: return "r19";
		case PPC_REG_GPR20: return "r20";
		case PPC_REG_GPR21: return "r21";
		case PPC_REG_GPR22: return "r22";
		case PPC_REG_GPR23: return "r23";
		case PPC_REG_GPR24: return "r24";
		case PPC_REG_GPR25: return "r25";
		case PPC_REG_GPR26: return "r26";
		case PPC_REG_GPR27: return "r27";
		case PPC_REG_GPR28: return "r28";
		case PPC_REG_GPR29: return "r29";
		case PPC_REG_GPR30: return "r30";
		case PPC_REG_GPR31: return "r31";

		case PPC_REG_XER: return "xer";
		case PPC_REG_LR: return "lr";
		case PPC_REG_CTR: return "ctr";

		case PPC_REG_FR0: return "f0";
		case PPC_REG_FR1: return "f1";
		case PPC_REG_FR2: return "f2";
		case PPC_REG_FR3: return "f3";
		case PPC_REG_FR4: return "f4";
		case PPC_REG_FR5: return "f5";
		case PPC_REG_FR6: return "f6";
		case PPC_REG_FR7: return "f7";
		case PPC_REG_FR8: return "f8";
		case PPC_REG_FR9: return "f9";
		case PPC_REG_FR10: return "f10";
		case PPC_REG_FR11: return "f11";
		case PPC_REG_FR12: return "f12";
		case PPC_REG_FR13: return "f13";
		case PPC_REG_FR14: return "f14";
		case PPC_REG_FR15: return "f15";
		case PPC_REG_FR16: return "f16";
		case PPC_REG_FR17: return "f17";
		case PPC_REG_FR18: return "f18";
		case PPC_REG_FR19: return "f19";
		case PPC_REG_FR20: return "f20";
		case PPC_REG_FR21: return "f21";
		case PPC_REG_FR22: return "f22";
		case PPC_REG_FR23: return "f23";
		case PPC_REG_FR24: return "f24";
		case PPC_REG_FR25: return "f25";
		case PPC_REG_FR26: return "f26";
		case PPC_REG_FR27: return "f27";
		case PPC_REG_FR28: return "f28";
		case PPC_REG_FR29: return "f29";
		case PPC_REG_FR30: return "f30";
		case PPC_REG_FR31: return "f31";

		case PPC_REG_CRF0: return "cr0";
		case PPC_REG_CRF1: return "cr1";
		case PPC_REG_CRF2: return "cr2";
		case PPC_REG_CRF3: return "cr3";
		case PPC_REG_CRF4: return "cr4";
		case PPC_REG_CRF5: return "cr5";
		case PPC_REG_CRF6: return "cr6";
		case PPC_REG_CRF7: return "cr7";

		case PPC_REG_AV_VR0: return "v0";
		case PPC_REG_AV_VR1: return "v1";
		case PPC_REG_AV_VR2: return "v2";
		case PPC_REG_AV_VR3: return "v3";
		case PPC_REG_AV_VR4: return "v4";
		case PPC_REG_AV_VR5: return "v5";
		case PPC_REG_AV_VR6: return "v6";
		case PPC_REG_AV_VR7: return "v7";
		case PPC_REG_AV_VR8: return "v8";
		case PPC_REG_AV_VR9: return "v9";
		case PPC_REG_AV_VR10: return "v10";
		case PPC_REG_AV_VR11: return "v11";
		case PPC_REG_AV_VR12: return "v12";
		case PPC_REG_AV_VR13: return "v13";
		case PPC_REG_AV_VR14: return "v14";
		case PPC_REG_AV_VR15: return "v15";
		case PPC_REG_AV_VR16: return "v16";
		case PPC_REG_AV_VR17: return "v17";
		case PPC_REG_AV_VR18: return "v18";
		case PPC_REG_AV_VR19: return "v19";
		case PPC_REG_AV_VR20: return "v20";
		case PPC_REG_AV_VR21: return "v21";
		case PPC_REG_AV_VR22: return "v22";
		case PPC_REG_AV_VR23: return "v23";
		case PPC_REG_AV_VR24: return "v24";
		case PPC_REG_AV_VR25: return "v25";
		case PPC_REG_AV_VR26: return "v26";
		case PPC_REG_AV_VR27: return "v27";
		case PPC_REG_AV_VR28: return "v28";
		case PPC_REG_AV_VR29: return "v29";
		case PPC_REG_AV_VR30: return "v30";
		case PPC_REG_AV_VR31: return "v31";

		case PPC_REG_VSX_VR0: return "vs0";
		case PPC_REG_VSX_VR1: return "vs1";
		case PPC_REG_VSX_VR2: return "vs2";
		case PPC_REG_VSX_VR3: return "vs3";
		case PPC_REG_VSX_VR4: return "vs4";
		case PPC_REG_VSX_VR5: return "vs5";
		case PPC_REG_VSX_VR6: return "vs6";
		case PPC_REG_VSX_VR7: return "vs7";
		case PPC_REG_VSX_VR8: return "vs8";
		case PPC_REG_VSX_VR9: return "vs9";
		case PPC_REG_VSX_VR10: return "vs10";
		case PPC_REG_VSX_VR11: return "vs11";
		case PPC_REG_VSX_VR12: return "vs12";
		case PPC_REG_VSX_VR13: return "vs13";
		case PPC_REG_VSX_VR14: return "vs14";
		case PPC_REG_VSX_VR15: return "vs15";
		case PPC_REG_VSX_VR16: return "vs16";
		case PPC_REG_VSX_VR17: return "vs17";
		case PPC_REG_VSX_VR18: return "vs18";
		case PPC_REG_VSX_VR19: return "vs19";
		case PPC_REG_VSX_VR20: return "vs20";
		case PPC_REG_VSX_VR21: return "vs21";
		case PPC_REG_VSX_VR22: return "vs22";
		case PPC_REG_VSX_VR23: return "vs23";
		case PPC_REG_VSX_VR24: return "vs24";
		case PPC_REG_VSX_VR25: return "vs25";
		case PPC_REG_VSX_VR26: return "vs26";
		case PPC_REG_VSX_VR27: return "vs27";
		case PPC_REG_VSX_VR28: return "vs28";
		case PPC_REG_VSX_VR29: return "vs29";
		case PPC_REG_VSX_VR30: return "vs30";
		case PPC_REG_VSX_VR31: return "vs31";
		case PPC_REG_VSX_VR32: return "vs32";
		case PPC_REG_VSX_VR33: return "vs33";
		case PPC_REG_VSX_VR34: return "vs34";
		case PPC_REG_VSX_VR35: return "vs35";
		case PPC_REG_VSX_VR36: return "vs36";
		case PPC_REG_VSX_VR37: return "vs37";
		case PPC_REG_VSX_VR38: return "vs38";
		case PPC_REG_VSX_VR39: return "vs39";
		case PPC_REG_VSX_VR40: return "vs40";
		case PPC_REG_VSX_VR41: return "vs41";
		case PPC_REG_VSX_VR42: return "vs42";
		case PPC_REG_VSX_VR43: return "vs43";
		case PPC_REG_VSX_VR44: return "vs44";
		case PPC_REG_VSX_VR45: return "vs45";
		case PPC_REG_VSX_VR46: return "vs46";
		case PPC_REG_VSX_VR47: return "vs47";
		case PPC_REG_VSX_VR48: return "vs48";
		case PPC_REG_VSX_VR49: return "vs49";
		case PPC_REG_VSX_VR50: return "vs50";
		case PPC_REG_VSX_VR51: return "vs51";
		case PPC_REG_VSX_VR52: return "vs52";
		case PPC_REG_VSX_VR53: return "vs53";
		case PPC_REG_VSX_VR54: return "vs54";
		case PPC_REG_VSX_VR55: return "vs55";
		case PPC_REG_VSX_VR56: return "vs56";
		case PPC_REG_VSX_VR57: return "vs57";
		case PPC_REG_VSX_VR58: return "vs58";
		case PPC_REG_VSX_VR59: return "vs59";
		case PPC_REG_VSX_VR60: return "vs60";
		case PPC_REG_VSX_VR61: return "vs61";
		case PPC_REG_VSX_VR62: return "vs62";
		case PPC_REG_VSX_VR63: return "vs63";

		case PPC_REG_GQR0: return "gqr0";
		case PPC_REG_GQR1: return "gqr1";
		case PPC_REG_GQR2: return "gqr2";
		case PPC_REG_GQR3: return "gqr3";
		case PPC_REG_GQR4: return "gqr4";
		case PPC_REG_GQR5: return "gqr5";
		case PPC_REG_GQR6: return "gqr6";
		case PPC_REG_GQR7: return "gqr7";

		default: return NULL;
	}
}

const char* OperandClassName(uint32_t cls)
{
	switch (cls)
	{
		case PPC_OP_NONE: return "<none>";
		case PPC_OP_UIMM: return "UIMM";
		case PPC_OP_SIMM: return "SIMM";
		case PPC_OP_LABEL: return "LABEL";
		case PPC_OP_MEM_RA: return "MEM(RA)";

		case PPC_OP_REG_RA: return "RA";
		case PPC_OP_REG_RB: return "RB";
		case PPC_OP_REG_RC: return "RC";
		case PPC_OP_REG_RD: return "RD";
		case PPC_OP_REG_RS: return "RS";

		case PPC_OP_REG_FRA: return "FRA";
		case PPC_OP_REG_FRB: return "FRB";
		case PPC_OP_REG_FRC: return "FRC";
		case PPC_OP_REG_FRD: return "FRD";
		case PPC_OP_REG_FRS: return "FRS";

		case PPC_OP_REG_CRFD: return "CRFD";
		case PPC_OP_REG_CRFD_IMPLY0: return "CRFD";
		case PPC_OP_REG_CRFS: return "CRFS";
		case PPC_OP_CRBIT: return "CRBIT";
		case PPC_OP_CRBIT_A: return "CRBIT_A";
		case PPC_OP_CRBIT_B: return "CRBIT_B";
		case PPC_OP_CRBIT_D: return "CRBIT_C";

		case PPC_OP_REG_AV_VA: return "ALTIVEC_VA";
		case PPC_OP_REG_AV_VB: return "ALTIVEC_VB";
		case PPC_OP_REG_AV_VC: return "ALTIVEC_VC";
		case PPC_OP_REG_AV_VD: return "ALTIVEC_VD";
		case PPC_OP_REG_AV_VS: return "ALTIVEC_VS";

		case PPC_OP_REG_VSX_RA: return "VSX_RA";
		case PPC_OP_REG_VSX_RA_DWORD0: return "VSX_RA0";

		case PPC_OP_REG_VSX_RB: return "VSX_RB";
		case PPC_OP_REG_VSX_RB_DWORD0: return "VSX_RB0";

		case PPC_OP_REG_VSX_RC: return "VSX_RC";
		case PPC_OP_REG_VSX_RC_DWORD0: return "VSX_RC0";

		case PPC_OP_REG_VSX_RD: return "VSX_RD";
		case PPC_OP_REG_VSX_RD_DWORD0: return "VSX_RD0";

		case PPC_OP_REG_VSX_RS: return "VSX_RS";
		case PPC_OP_REG_VSX_RS_DWORD0: return "VSX_RS0";

		default:
			return "???";
	}
}

// These match the names in the "Condition Register" section
const char* GetCRBitName(uint32_t crbit)
{
	switch (crbit)
	{
		case 0: return "lt";
		case 1: return "gt";
		case 2: return "eq";
		case 3: return "so";
		case 4: return "cr1lt";
		case 5: return "cr1gt";
		case 6: return "cr1eq";
		case 7: return "cr1so";
		case 8: return "cr2lt";
		case 9: return "cr2gt";
		case 10: return "cr2eq";
		case 11: return "cr2so";
		case 12: return "cr3lt";
		case 13: return "cr3gt";
		case 14: return "cr3eq";
		case 15: return "cr3so";
		case 16: return "cr4lt";
		case 17: return "cr4gt";
		case 18: return "cr4eq";
		case 19: return "cr4so";
		case 20: return "cr5lt";
		case 21: return "cr5gt";
		case 22: return "cr5eq";
		case 23: return "cr5so";
		case 24: return "cr6lt";
		case 25: return "cr6gt";
		case 26: return "cr6eq";
		case 27: return "cr6so";
		case 28: return "cr7lt";
		case 29: return "cr7gt";
		case 30: return "cr7eq";
		case 31: return "cr7so";
		default:
			return NULL;
	}
}
