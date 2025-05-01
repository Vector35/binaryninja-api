/* GENERATED FILE - DO NOT MODIFY - SUBMIT GITHUB ISSUE IF PROBLEM FOUND */

#include "sysregs_enum.h"

using namespace BinaryNinja;
using namespace std;

Ref<Enumeration> get_system_register_enum()
{
	static EnumerationBuilder builder;
	static std::once_flag once;
	std::call_once(once, []() {
		builder.AddMemberWithValue(get_system_register_name(REG_EDSCR), REG_EDSCR);
		builder.AddMemberWithValue(get_system_register_name(REG_EDPRCR), REG_EDPRCR);
		builder.AddMemberWithValue(get_system_register_name(REG_UAOIMM), REG_UAOIMM);
		builder.AddMemberWithValue(get_system_register_name(REG_PANIMM), REG_PANIMM);
		builder.AddMemberWithValue(get_system_register_name(REG_SPSELIMM), REG_SPSELIMM);
		builder.AddMemberWithValue(get_system_register_name(REG_DITIMM), REG_DITIMM);
		builder.AddMemberWithValue(get_system_register_name(REG_SVCRIMM), REG_SVCRIMM);
		builder.AddMemberWithValue(get_system_register_name(REG_ICIALLUIS), REG_ICIALLUIS);
		builder.AddMemberWithValue(get_system_register_name(REG_ICIALLU), REG_ICIALLU);
		builder.AddMemberWithValue(get_system_register_name(REG_DCIVAC), REG_DCIVAC);
		builder.AddMemberWithValue(get_system_register_name(REG_DCISW), REG_DCISW);
		builder.AddMemberWithValue(get_system_register_name(REG_ATS1E1R), REG_ATS1E1R);
		builder.AddMemberWithValue(get_system_register_name(REG_ATS1E1W), REG_ATS1E1W);
		builder.AddMemberWithValue(get_system_register_name(REG_ATS1E0R), REG_ATS1E0R);
		builder.AddMemberWithValue(get_system_register_name(REG_ATS1E0W), REG_ATS1E0W);
		builder.AddMemberWithValue(get_system_register_name(REG_DCCSW), REG_DCCSW);
		builder.AddMemberWithValue(get_system_register_name(REG_DCCISW), REG_DCCISW);
		builder.AddMemberWithValue(get_system_register_name(REG_TLBIVMALLE1IS), REG_TLBIVMALLE1IS);
		builder.AddMemberWithValue(get_system_register_name(REG_TLBIVAE1IS), REG_TLBIVAE1IS);
		builder.AddMemberWithValue(get_system_register_name(REG_TLBIASIDE1IS), REG_TLBIASIDE1IS);
		builder.AddMemberWithValue(get_system_register_name(REG_TLBIVAAE1IS), REG_TLBIVAAE1IS);
		builder.AddMemberWithValue(get_system_register_name(REG_TLBIVALE1IS), REG_TLBIVALE1IS);
		builder.AddMemberWithValue(get_system_register_name(REG_TLBIVAALE1IS), REG_TLBIVAALE1IS);
		builder.AddMemberWithValue(get_system_register_name(REG_TLBIVMALLE1), REG_TLBIVMALLE1);
		builder.AddMemberWithValue(get_system_register_name(REG_TLBIVAE1), REG_TLBIVAE1);
		builder.AddMemberWithValue(get_system_register_name(REG_TLBIASIDE1), REG_TLBIASIDE1);
		builder.AddMemberWithValue(get_system_register_name(REG_TLBIVAAE1), REG_TLBIVAAE1);
		builder.AddMemberWithValue(get_system_register_name(REG_TLBIVALE1), REG_TLBIVALE1);
		builder.AddMemberWithValue(get_system_register_name(REG_TLBIVAALE1), REG_TLBIVAALE1);
		builder.AddMemberWithValue(get_system_register_name(REG_DCZVA), REG_DCZVA);
		builder.AddMemberWithValue(get_system_register_name(REG_ICIVAU), REG_ICIVAU);
		builder.AddMemberWithValue(get_system_register_name(REG_DCCVAC), REG_DCCVAC);
		builder.AddMemberWithValue(get_system_register_name(REG_DCCVAU), REG_DCCVAU);
		builder.AddMemberWithValue(get_system_register_name(REG_DCCIVAC), REG_DCCIVAC);
		builder.AddMemberWithValue(get_system_register_name(REG_ATS1E2R), REG_ATS1E2R);
		builder.AddMemberWithValue(get_system_register_name(REG_ATS1E2W), REG_ATS1E2W);
		builder.AddMemberWithValue(get_system_register_name(REG_ATS12E1R), REG_ATS12E1R);
		builder.AddMemberWithValue(get_system_register_name(REG_ATS12E1W), REG_ATS12E1W);
		builder.AddMemberWithValue(get_system_register_name(REG_ATS12E0R), REG_ATS12E0R);
		builder.AddMemberWithValue(get_system_register_name(REG_ATS12E0W), REG_ATS12E0W);
		builder.AddMemberWithValue(get_system_register_name(REG_TLBIIPAS2E1IS), REG_TLBIIPAS2E1IS);
		builder.AddMemberWithValue(get_system_register_name(REG_TLBIIPAS2LE1IS), REG_TLBIIPAS2LE1IS);
		builder.AddMemberWithValue(get_system_register_name(REG_TLBIALLE2IS), REG_TLBIALLE2IS);
		builder.AddMemberWithValue(get_system_register_name(REG_TLBIVAE2IS), REG_TLBIVAE2IS);
		builder.AddMemberWithValue(get_system_register_name(REG_TLBIALLE1IS), REG_TLBIALLE1IS);
		builder.AddMemberWithValue(get_system_register_name(REG_TLBIVALE2IS), REG_TLBIVALE2IS);
		builder.AddMemberWithValue(get_system_register_name(REG_TLBIVMALLS12E1IS), REG_TLBIVMALLS12E1IS);
		builder.AddMemberWithValue(get_system_register_name(REG_TLBIIPAS2E1), REG_TLBIIPAS2E1);
		builder.AddMemberWithValue(get_system_register_name(REG_TLBIIPAS2LE1), REG_TLBIIPAS2LE1);
		builder.AddMemberWithValue(get_system_register_name(REG_TLBIALLE2), REG_TLBIALLE2);
		builder.AddMemberWithValue(get_system_register_name(REG_TLBIVAE2), REG_TLBIVAE2);
		builder.AddMemberWithValue(get_system_register_name(REG_TLBIALLE1), REG_TLBIALLE1);
		builder.AddMemberWithValue(get_system_register_name(REG_TLBIVALE2), REG_TLBIVALE2);
		builder.AddMemberWithValue(get_system_register_name(REG_TLBIVMALLS12E1), REG_TLBIVMALLS12E1);
		builder.AddMemberWithValue(get_system_register_name(REG_ATS1E3R), REG_ATS1E3R);
		builder.AddMemberWithValue(get_system_register_name(REG_ATS1E3W), REG_ATS1E3W);
		builder.AddMemberWithValue(get_system_register_name(REG_TLBIALLE3IS), REG_TLBIALLE3IS);
		builder.AddMemberWithValue(get_system_register_name(REG_TLBIVAE3IS), REG_TLBIVAE3IS);
		builder.AddMemberWithValue(get_system_register_name(REG_TLBIVALE3IS), REG_TLBIVALE3IS);
		builder.AddMemberWithValue(get_system_register_name(REG_TLBIALLE3), REG_TLBIALLE3);
		builder.AddMemberWithValue(get_system_register_name(REG_TLBIVAE3), REG_TLBIVAE3);
		builder.AddMemberWithValue(get_system_register_name(REG_TLBIVALE3), REG_TLBIVALE3);
		builder.AddMemberWithValue(get_system_register_name(REG_OSDTRRX_EL1), REG_OSDTRRX_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGBVR0_EL1), REG_DBGBVR0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGBCR0_EL1), REG_DBGBCR0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGWVR0_EL1), REG_DBGWVR0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGWCR0_EL1), REG_DBGWCR0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGBVR1_EL1), REG_DBGBVR1_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGBCR1_EL1), REG_DBGBCR1_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGWVR1_EL1), REG_DBGWVR1_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGWCR1_EL1), REG_DBGWCR1_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_MDCCINT_EL1), REG_MDCCINT_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_MDSCR_EL1), REG_MDSCR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGBVR2_EL1), REG_DBGBVR2_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGBCR2_EL1), REG_DBGBCR2_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGWVR2_EL1), REG_DBGWVR2_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGWCR2_EL1), REG_DBGWCR2_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_OSDTRTX_EL1), REG_OSDTRTX_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGBVR3_EL1), REG_DBGBVR3_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGBCR3_EL1), REG_DBGBCR3_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGWVR3_EL1), REG_DBGWVR3_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGWCR3_EL1), REG_DBGWCR3_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGBVR4_EL1), REG_DBGBVR4_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGBCR4_EL1), REG_DBGBCR4_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGWVR4_EL1), REG_DBGWVR4_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGWCR4_EL1), REG_DBGWCR4_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGBVR5_EL1), REG_DBGBVR5_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGBCR5_EL1), REG_DBGBCR5_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGWVR5_EL1), REG_DBGWVR5_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGWCR5_EL1), REG_DBGWCR5_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGWFAR), REG_DBGWFAR);
		builder.AddMemberWithValue(get_system_register_name(REG_OSECCR_EL1), REG_OSECCR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGBVR6_EL1), REG_DBGBVR6_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGBCR6_EL1), REG_DBGBCR6_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGWVR6_EL1), REG_DBGWVR6_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGWCR6_EL1), REG_DBGWCR6_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGBVR7_EL1), REG_DBGBVR7_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGBCR7_EL1), REG_DBGBCR7_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGWVR7_EL1), REG_DBGWVR7_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGWCR7_EL1), REG_DBGWCR7_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGBVR8_EL1), REG_DBGBVR8_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGBCR8_EL1), REG_DBGBCR8_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGWVR8_EL1), REG_DBGWVR8_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGWCR8_EL1), REG_DBGWCR8_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGBVR9_EL1), REG_DBGBVR9_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGBCR9_EL1), REG_DBGBCR9_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGWVR9_EL1), REG_DBGWVR9_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGWCR9_EL1), REG_DBGWCR9_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGBVR10_EL1), REG_DBGBVR10_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGBCR10_EL1), REG_DBGBCR10_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGWVR10_EL1), REG_DBGWVR10_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGWCR10_EL1), REG_DBGWCR10_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGBVR11_EL1), REG_DBGBVR11_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGBCR11_EL1), REG_DBGBCR11_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGWVR11_EL1), REG_DBGWVR11_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGWCR11_EL1), REG_DBGWCR11_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGBVR12_EL1), REG_DBGBVR12_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGBCR12_EL1), REG_DBGBCR12_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGWVR12_EL1), REG_DBGWVR12_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGWCR12_EL1), REG_DBGWCR12_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGBVR13_EL1), REG_DBGBVR13_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGBCR13_EL1), REG_DBGBCR13_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGWVR13_EL1), REG_DBGWVR13_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGWCR13_EL1), REG_DBGWCR13_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGBVR14_EL1), REG_DBGBVR14_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGBCR14_EL1), REG_DBGBCR14_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGWVR14_EL1), REG_DBGWVR14_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGWCR14_EL1), REG_DBGWCR14_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGBVR15_EL1), REG_DBGBVR15_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGBCR15_EL1), REG_DBGBCR15_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGWVR15_EL1), REG_DBGWVR15_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGWCR15_EL1), REG_DBGWCR15_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_MDRAR_EL1), REG_MDRAR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_OSLAR_EL1), REG_OSLAR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_OSLSR_EL1), REG_OSLSR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_OSDLR_EL1), REG_OSDLR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGPRCR_EL1), REG_DBGPRCR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGCLAIMSET_EL1), REG_DBGCLAIMSET_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGCLAIMCLR_EL1), REG_DBGCLAIMCLR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGAUTHSTAT_EL1), REG_DBGAUTHSTAT_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCTRACEIDR), REG_TRCTRACEIDR);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCVICTLR), REG_TRCVICTLR);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCSEQEVR0), REG_TRCSEQEVR0);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCCNTRLDVR0), REG_TRCCNTRLDVR0);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCIMSPEC0), REG_TRCIMSPEC0);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCPRGCTLR), REG_TRCPRGCTLR);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCQCTLR), REG_TRCQCTLR);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCVIIECTLR), REG_TRCVIIECTLR);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCSEQEVR1), REG_TRCSEQEVR1);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCCNTRLDVR1), REG_TRCCNTRLDVR1);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCIMSPEC1), REG_TRCIMSPEC1);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCPROCSELR), REG_TRCPROCSELR);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCVISSCTLR), REG_TRCVISSCTLR);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCSEQEVR2), REG_TRCSEQEVR2);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCCNTRLDVR2), REG_TRCCNTRLDVR2);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCIMSPEC2), REG_TRCIMSPEC2);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCVIPCSSCTLR), REG_TRCVIPCSSCTLR);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCCNTRLDVR3), REG_TRCCNTRLDVR3);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCIMSPEC3), REG_TRCIMSPEC3);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCCONFIGR), REG_TRCCONFIGR);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCCNTCTLR0), REG_TRCCNTCTLR0);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCIMSPEC4), REG_TRCIMSPEC4);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCCNTCTLR1), REG_TRCCNTCTLR1);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCIMSPEC5), REG_TRCIMSPEC5);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCAUXCTLR), REG_TRCAUXCTLR);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCSEQRSTEVR), REG_TRCSEQRSTEVR);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCCNTCTLR2), REG_TRCCNTCTLR2);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCIMSPEC6), REG_TRCIMSPEC6);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCSEQSTR), REG_TRCSEQSTR);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCCNTCTLR3), REG_TRCCNTCTLR3);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCIMSPEC7), REG_TRCIMSPEC7);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCEVENTCTL0R), REG_TRCEVENTCTL0R);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCVDCTLR), REG_TRCVDCTLR);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCEXTINSELR), REG_TRCEXTINSELR);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCCNTVR0), REG_TRCCNTVR0);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCEVENTCTL1R), REG_TRCEVENTCTL1R);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCVDSACCTLR), REG_TRCVDSACCTLR);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCEXTINSELR1), REG_TRCEXTINSELR1);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCCNTVR1), REG_TRCCNTVR1);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCRSR), REG_TRCRSR);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCVDARCCTLR), REG_TRCVDARCCTLR);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCEXTINSELR2), REG_TRCEXTINSELR2);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCCNTVR2), REG_TRCCNTVR2);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCSTALLCTLR), REG_TRCSTALLCTLR);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCEXTINSELR3), REG_TRCEXTINSELR3);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCCNTVR3), REG_TRCCNTVR3);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCTSCTLR), REG_TRCTSCTLR);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCSYNCPR), REG_TRCSYNCPR);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCCCCTLR), REG_TRCCCCTLR);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCBBCTLR), REG_TRCBBCTLR);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCRSCTLR16), REG_TRCRSCTLR16);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCSSCCR0), REG_TRCSSCCR0);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCSSPCICR0), REG_TRCSSPCICR0);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCOSLAR), REG_TRCOSLAR);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCRSCTLR17), REG_TRCRSCTLR17);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCSSCCR1), REG_TRCSSCCR1);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCSSPCICR1), REG_TRCSSPCICR1);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCRSCTLR2), REG_TRCRSCTLR2);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCRSCTLR18), REG_TRCRSCTLR18);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCSSCCR2), REG_TRCSSCCR2);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCSSPCICR2), REG_TRCSSPCICR2);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCRSCTLR3), REG_TRCRSCTLR3);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCRSCTLR19), REG_TRCRSCTLR19);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCSSCCR3), REG_TRCSSCCR3);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCSSPCICR3), REG_TRCSSPCICR3);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCRSCTLR4), REG_TRCRSCTLR4);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCRSCTLR20), REG_TRCRSCTLR20);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCSSCCR4), REG_TRCSSCCR4);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCSSPCICR4), REG_TRCSSPCICR4);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCPDCR), REG_TRCPDCR);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCRSCTLR5), REG_TRCRSCTLR5);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCRSCTLR21), REG_TRCRSCTLR21);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCSSCCR5), REG_TRCSSCCR5);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCSSPCICR5), REG_TRCSSPCICR5);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCRSCTLR6), REG_TRCRSCTLR6);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCRSCTLR22), REG_TRCRSCTLR22);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCSSCCR6), REG_TRCSSCCR6);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCSSPCICR6), REG_TRCSSPCICR6);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCRSCTLR7), REG_TRCRSCTLR7);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCRSCTLR23), REG_TRCRSCTLR23);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCSSCCR7), REG_TRCSSCCR7);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCSSPCICR7), REG_TRCSSPCICR7);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCRSCTLR8), REG_TRCRSCTLR8);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCRSCTLR24), REG_TRCRSCTLR24);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCSSCSR0), REG_TRCSSCSR0);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCRSCTLR9), REG_TRCRSCTLR9);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCRSCTLR25), REG_TRCRSCTLR25);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCSSCSR1), REG_TRCSSCSR1);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCRSCTLR10), REG_TRCRSCTLR10);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCRSCTLR26), REG_TRCRSCTLR26);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCSSCSR2), REG_TRCSSCSR2);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCRSCTLR11), REG_TRCRSCTLR11);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCRSCTLR27), REG_TRCRSCTLR27);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCSSCSR3), REG_TRCSSCSR3);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCRSCTLR12), REG_TRCRSCTLR12);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCRSCTLR28), REG_TRCRSCTLR28);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCSSCSR4), REG_TRCSSCSR4);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCRSCTLR13), REG_TRCRSCTLR13);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCRSCTLR29), REG_TRCRSCTLR29);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCSSCSR5), REG_TRCSSCSR5);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCRSCTLR14), REG_TRCRSCTLR14);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCRSCTLR30), REG_TRCRSCTLR30);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCSSCSR6), REG_TRCSSCSR6);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCRSCTLR15), REG_TRCRSCTLR15);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCRSCTLR31), REG_TRCRSCTLR31);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCSSCSR7), REG_TRCSSCSR7);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCACVR0), REG_TRCACVR0);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCACVR8), REG_TRCACVR8);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCACATR0), REG_TRCACATR0);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCACATR8), REG_TRCACATR8);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCDVCVR0), REG_TRCDVCVR0);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCDVCVR4), REG_TRCDVCVR4);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCDVCMR0), REG_TRCDVCMR0);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCDVCMR4), REG_TRCDVCMR4);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCACVR1), REG_TRCACVR1);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCACVR9), REG_TRCACVR9);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCACATR1), REG_TRCACATR1);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCACATR9), REG_TRCACATR9);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCACVR2), REG_TRCACVR2);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCACVR10), REG_TRCACVR10);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCACATR2), REG_TRCACATR2);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCACATR10), REG_TRCACATR10);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCDVCVR1), REG_TRCDVCVR1);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCDVCVR5), REG_TRCDVCVR5);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCDVCMR1), REG_TRCDVCMR1);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCDVCMR5), REG_TRCDVCMR5);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCACVR3), REG_TRCACVR3);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCACVR11), REG_TRCACVR11);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCACATR3), REG_TRCACATR3);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCACATR11), REG_TRCACATR11);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCACVR4), REG_TRCACVR4);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCACVR12), REG_TRCACVR12);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCACATR4), REG_TRCACATR4);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCACATR12), REG_TRCACATR12);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCDVCVR2), REG_TRCDVCVR2);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCDVCVR6), REG_TRCDVCVR6);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCDVCMR2), REG_TRCDVCMR2);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCDVCMR6), REG_TRCDVCMR6);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCACVR5), REG_TRCACVR5);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCACVR13), REG_TRCACVR13);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCACATR5), REG_TRCACATR5);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCACATR13), REG_TRCACATR13);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCACVR6), REG_TRCACVR6);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCACVR14), REG_TRCACVR14);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCACATR6), REG_TRCACATR6);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCACATR14), REG_TRCACATR14);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCDVCVR3), REG_TRCDVCVR3);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCDVCVR7), REG_TRCDVCVR7);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCDVCMR3), REG_TRCDVCMR3);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCDVCMR7), REG_TRCDVCMR7);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCACVR7), REG_TRCACVR7);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCACVR15), REG_TRCACVR15);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCACATR7), REG_TRCACATR7);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCACATR15), REG_TRCACATR15);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCCIDCVR0), REG_TRCCIDCVR0);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCVMIDCVR0), REG_TRCVMIDCVR0);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCCIDCCTLR0), REG_TRCCIDCCTLR0);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCCIDCCTLR1), REG_TRCCIDCCTLR1);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCCIDCVR1), REG_TRCCIDCVR1);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCVMIDCVR1), REG_TRCVMIDCVR1);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCVMIDCCTLR0), REG_TRCVMIDCCTLR0);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCVMIDCCTLR1), REG_TRCVMIDCCTLR1);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCCIDCVR2), REG_TRCCIDCVR2);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCVMIDCVR2), REG_TRCVMIDCVR2);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCCIDCVR3), REG_TRCCIDCVR3);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCVMIDCVR3), REG_TRCVMIDCVR3);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCCIDCVR4), REG_TRCCIDCVR4);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCVMIDCVR4), REG_TRCVMIDCVR4);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCCIDCVR5), REG_TRCCIDCVR5);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCVMIDCVR5), REG_TRCVMIDCVR5);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCCIDCVR6), REG_TRCCIDCVR6);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCVMIDCVR6), REG_TRCVMIDCVR6);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCCIDCVR7), REG_TRCCIDCVR7);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCVMIDCVR7), REG_TRCVMIDCVR7);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCITCTRL), REG_TRCITCTRL);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCCLAIMSET), REG_TRCCLAIMSET);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCCLAIMCLR), REG_TRCCLAIMCLR);
		builder.AddMemberWithValue(get_system_register_name(REG_TRCLAR), REG_TRCLAR);
		builder.AddMemberWithValue(get_system_register_name(REG_TEECR32_EL1), REG_TEECR32_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_TEEHBR32_EL1), REG_TEEHBR32_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_MDCCSR_EL0), REG_MDCCSR_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGDTR_EL0), REG_DBGDTR_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGDTRRX_EL0), REG_DBGDTRRX_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_DBGVCR32_EL2), REG_DBGVCR32_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_MIDR_EL1), REG_MIDR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_MPIDR_EL1), REG_MPIDR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_REVIDR_EL1), REG_REVIDR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_PFR0_EL1), REG_ID_PFR0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_PFR1_EL1), REG_ID_PFR1_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_DFR0_EL1), REG_ID_DFR0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AFR0_EL1), REG_ID_AFR0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_MMFR0_EL1), REG_ID_MMFR0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_MMFR1_EL1), REG_ID_MMFR1_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_MMFR2_EL1), REG_ID_MMFR2_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_MMFR3_EL1), REG_ID_MMFR3_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_ISAR0_EL1), REG_ID_ISAR0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_ISAR1_EL1), REG_ID_ISAR1_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_ISAR2_EL1), REG_ID_ISAR2_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_ISAR3_EL1), REG_ID_ISAR3_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_ISAR4_EL1), REG_ID_ISAR4_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_ISAR5_EL1), REG_ID_ISAR5_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_MMFR4_EL1), REG_ID_MMFR4_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_ISAR6_EL1), REG_ID_ISAR6_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_MVFR0_EL1), REG_MVFR0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_MVFR1_EL1), REG_MVFR1_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_MVFR2_EL1), REG_MVFR2_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AA32RES3_EL1), REG_ID_AA32RES3_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_PFR2_EL1), REG_ID_PFR2_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AA32RES5_EL1), REG_ID_AA32RES5_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AA32RES6_EL1), REG_ID_AA32RES6_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AA32RES7_EL1), REG_ID_AA32RES7_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AA64PFR0_EL1), REG_ID_AA64PFR0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AA64PFR1_EL1), REG_ID_AA64PFR1_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AA64PFR2_EL1), REG_ID_AA64PFR2_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AA64PFR3_EL1), REG_ID_AA64PFR3_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AA64ZFR0_EL1), REG_ID_AA64ZFR0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AA64SMFR0_EL1), REG_ID_AA64SMFR0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AA64ZFR2_EL1), REG_ID_AA64ZFR2_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AA64ZFR3_EL1), REG_ID_AA64ZFR3_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AA64DFR0_EL1), REG_ID_AA64DFR0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AA64DFR1_EL1), REG_ID_AA64DFR1_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AA64DFR2_EL1), REG_ID_AA64DFR2_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AA64DFR3_EL1), REG_ID_AA64DFR3_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AA64AFR0_EL1), REG_ID_AA64AFR0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AA64AFR1_EL1), REG_ID_AA64AFR1_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AA64AFR2_EL1), REG_ID_AA64AFR2_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AA64AFR3_EL1), REG_ID_AA64AFR3_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AA64ISAR0_EL1), REG_ID_AA64ISAR0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AA64ISAR1_EL1), REG_ID_AA64ISAR1_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AA64ISAR2_EL1), REG_ID_AA64ISAR2_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AA64ISAR3_EL1), REG_ID_AA64ISAR3_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AA64ISAR4_EL1), REG_ID_AA64ISAR4_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AA64ISAR5_EL1), REG_ID_AA64ISAR5_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AA64ISAR6_EL1), REG_ID_AA64ISAR6_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AA64ISAR7_EL1), REG_ID_AA64ISAR7_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AA64MMFR0_EL1), REG_ID_AA64MMFR0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AA64MMFR1_EL1), REG_ID_AA64MMFR1_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AA64MMFR2_EL1), REG_ID_AA64MMFR2_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AA64MMFR3_EL1), REG_ID_AA64MMFR3_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AA64MMFR4_EL1), REG_ID_AA64MMFR4_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AA64MMFR5_EL1), REG_ID_AA64MMFR5_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AA64MMFR6_EL1), REG_ID_AA64MMFR6_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ID_AA64MMFR7_EL1), REG_ID_AA64MMFR7_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_SCTLR_EL1), REG_SCTLR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ACTLR_EL1), REG_ACTLR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_CPACR_EL1), REG_CPACR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_RGSR_EL1), REG_RGSR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_GCR_EL1), REG_GCR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_TRFCR_EL1), REG_TRFCR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_SMPRI_EL1), REG_SMPRI_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_SMCR_EL1), REG_SMCR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_TTBR0_EL1), REG_TTBR0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_TTBR1_EL1), REG_TTBR1_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_TCR_EL1), REG_TCR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_APIAKEYLO_EL1), REG_APIAKEYLO_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_APIAKEYHI_EL1), REG_APIAKEYHI_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_APIBKEYLO_EL1), REG_APIBKEYLO_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_APIBKEYHI_EL1), REG_APIBKEYHI_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_APDAKEYLO_EL1), REG_APDAKEYLO_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_APDAKEYHI_EL1), REG_APDAKEYHI_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_APDBKEYLO_EL1), REG_APDBKEYLO_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_APDBKEYHI_EL1), REG_APDBKEYHI_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_APGAKEYLO_EL1), REG_APGAKEYLO_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_APGAKEYHI_EL1), REG_APGAKEYHI_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_SPSR_EL1), REG_SPSR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ELR_EL1), REG_ELR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_SP_EL0), REG_SP_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_SPSEL), REG_SPSEL);
		builder.AddMemberWithValue(get_system_register_name(REG_CURRENTEL), REG_CURRENTEL);
		builder.AddMemberWithValue(get_system_register_name(REG_PAN), REG_PAN);
		builder.AddMemberWithValue(get_system_register_name(REG_UAO), REG_UAO);
		builder.AddMemberWithValue(get_system_register_name(REG_ICV_PMR_EL1), REG_ICV_PMR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AFSR0_EL1), REG_AFSR0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AFSR1_EL1), REG_AFSR1_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ESR_EL1), REG_ESR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ERRIDR_EL1), REG_ERRIDR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ERRSELR_EL1), REG_ERRSELR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ERXCTLR_EL1), REG_ERXCTLR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ERXSTATUS_EL1), REG_ERXSTATUS_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ERXADDR_EL1), REG_ERXADDR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ERXPFGCTL_EL1), REG_ERXPFGCTL_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ERXPFGCDN_EL1), REG_ERXPFGCDN_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ERXMISC0_EL1), REG_ERXMISC0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ERXMISC1_EL1), REG_ERXMISC1_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ERXMISC2_EL1), REG_ERXMISC2_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ERXMISC3_EL1), REG_ERXMISC3_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ERXTS_EL1), REG_ERXTS_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_TFSR_EL1), REG_TFSR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_TFSRE0_EL1), REG_TFSRE0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_FAR_EL1), REG_FAR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PAR_EL1), REG_PAR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PMSCR_EL1), REG_PMSCR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PMSICR_EL1), REG_PMSICR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PMSIRR_EL1), REG_PMSIRR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PMSFCR_EL1), REG_PMSFCR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PMSEVFR_EL1), REG_PMSEVFR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PMSLATFR_EL1), REG_PMSLATFR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PMSIDR_EL1), REG_PMSIDR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PMBLIMITR_EL1), REG_PMBLIMITR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PMBPTR_EL1), REG_PMBPTR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PMBSR_EL1), REG_PMBSR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PMBIDR_EL1), REG_PMBIDR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_TRBLIMITR_EL1), REG_TRBLIMITR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_TRBPTR_EL1), REG_TRBPTR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_TRBBASER_EL1), REG_TRBBASER_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_TRBSR_EL1), REG_TRBSR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_TRBMAR_EL1), REG_TRBMAR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_TRBTRG_EL1), REG_TRBTRG_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PMINTENSET_EL1), REG_PMINTENSET_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PMINTENCLR_EL1), REG_PMINTENCLR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PMMIR_EL1), REG_PMMIR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_MAIR_EL1), REG_MAIR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AMAIR_EL1), REG_AMAIR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_LORSA_EL1), REG_LORSA_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_LOREA_EL1), REG_LOREA_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_LORN_EL1), REG_LORN_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_LORC_EL1), REG_LORC_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_LORID_EL1), REG_LORID_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_MPAM1_EL1), REG_MPAM1_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_MPAM0_EL1), REG_MPAM0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_CTRR_C_LWR_EL1), REG_CTRR_C_LWR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_CTRR_C_UPR_EL1), REG_CTRR_C_UPR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_CTRR_D_LWR_EL1), REG_CTRR_D_LWR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_CTRR_D_UPR_EL1), REG_CTRR_D_UPR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_CTRR_C_LWR_EL12), REG_CTRR_C_LWR_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_CTRR_C_UPR_EL12), REG_CTRR_C_UPR_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_CTRR_D_LWR_EL12), REG_CTRR_D_LWR_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_CTRR_D_UPR_EL12), REG_CTRR_D_UPR_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_CTRR_C_LWR_EL2), REG_CTRR_C_LWR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CTRR_C_UPR_EL2), REG_CTRR_C_UPR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CTRR_D_LWR_EL2), REG_CTRR_D_LWR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CTRR_D_UPR_EL2), REG_CTRR_D_UPR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CTRR_C_CTL_EL1), REG_CTRR_C_CTL_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_CTRR_D_CTL_EL1), REG_CTRR_D_CTL_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_CTRR_C_CTL_EL12), REG_CTRR_C_CTL_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_CTRR_D_CTL_EL12), REG_CTRR_D_CTL_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_CTRR_C_CTL_EL2), REG_CTRR_C_CTL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CTRR_D_CTL_EL2), REG_CTRR_D_CTL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CTXR_A_LWR_EL1), REG_CTXR_A_LWR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_CTXR_A_UPR_EL1), REG_CTXR_A_UPR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_CTXR_B_LWR_EL1), REG_CTXR_B_LWR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_CTXR_B_UPR_EL1), REG_CTXR_B_UPR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_CTXR_C_LWR_EL1), REG_CTXR_C_LWR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_CTXR_C_UPR_EL1), REG_CTXR_C_UPR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_CTXR_D_LWR_EL1), REG_CTXR_D_LWR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_CTXR_D_UPR_EL1), REG_CTXR_D_UPR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_CTXR_A_LWR_EL12), REG_CTXR_A_LWR_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_CTXR_A_UPR_EL12), REG_CTXR_A_UPR_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_CTXR_B_LWR_EL12), REG_CTXR_B_LWR_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_CTXR_B_UPR_EL12), REG_CTXR_B_UPR_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_CTXR_C_LWR_EL12), REG_CTXR_C_LWR_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_CTXR_C_UPR_EL12), REG_CTXR_C_UPR_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_CTXR_D_LWR_EL12), REG_CTXR_D_LWR_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_CTXR_D_UPR_EL12), REG_CTXR_D_UPR_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_CTXR_A_LWR_EL2), REG_CTXR_A_LWR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CTXR_A_UPR_EL2), REG_CTXR_A_UPR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CTXR_B_LWR_EL2), REG_CTXR_B_LWR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CTXR_B_UPR_EL2), REG_CTXR_B_UPR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CTXR_C_LWR_EL2), REG_CTXR_C_LWR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CTXR_C_UPR_EL2), REG_CTXR_C_UPR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CTXR_D_LWR_EL2), REG_CTXR_D_LWR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CTXR_D_UPR_EL2), REG_CTXR_D_UPR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CTXR_A_CTL_EL1), REG_CTXR_A_CTL_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_CTXR_B_CTL_EL1), REG_CTXR_B_CTL_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_CTXR_C_CTL_EL1), REG_CTXR_C_CTL_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_CTXR_D_CTL_EL1), REG_CTXR_D_CTL_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_CTXR_A_CTL_EL12), REG_CTXR_A_CTL_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_CTXR_B_CTL_EL12), REG_CTXR_B_CTL_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_CTXR_C_CTL_EL12), REG_CTXR_C_CTL_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_CTXR_D_CTL_EL12), REG_CTXR_D_CTL_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_CTXR_A_CTL_EL2), REG_CTXR_A_CTL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CTXR_B_CTL_EL2), REG_CTXR_B_CTL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CTXR_C_CTL_EL2), REG_CTXR_C_CTL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CTXR_D_CTL_EL2), REG_CTXR_D_CTL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ACC_CTRR_C_LWR_EL2), REG_ACC_CTRR_C_LWR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ACC_CTRR_C_UPR_EL2), REG_ACC_CTRR_C_UPR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ACC_CTRR_D_LWR_EL2), REG_ACC_CTRR_D_LWR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ACC_CTRR_D_UPR_EL2), REG_ACC_CTRR_D_UPR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ACC_CTXR_A_LWR_EL2), REG_ACC_CTXR_A_LWR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ACC_CTXR_A_UPR_EL2), REG_ACC_CTXR_A_UPR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ACC_CTXR_B_LWR_EL2), REG_ACC_CTXR_B_LWR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ACC_CTXR_B_UPR_EL2), REG_ACC_CTXR_B_UPR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ACC_CTXR_C_LWR_EL2), REG_ACC_CTXR_C_LWR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ACC_CTXR_C_UPR_EL2), REG_ACC_CTXR_C_UPR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ACC_CTXR_D_LWR_EL2), REG_ACC_CTXR_D_LWR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ACC_CTXR_D_UPR_EL2), REG_ACC_CTXR_D_UPR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ACC_CTRR_C_CTL_EL2), REG_ACC_CTRR_C_CTL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ACC_CTRR_D_CTL_EL2), REG_ACC_CTRR_D_CTL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ACC_CTXR_A_CTL_EL2), REG_ACC_CTXR_A_CTL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ACC_CTXR_B_CTL_EL2), REG_ACC_CTXR_B_CTL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ACC_CTXR_C_CTL_EL2), REG_ACC_CTXR_C_CTL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ACC_CTXR_D_CTL_EL2), REG_ACC_CTXR_D_CTL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_VBAR_EL1), REG_VBAR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_RVBAR_EL1), REG_RVBAR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_RMR_EL1), REG_RMR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ISR_EL1), REG_ISR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DISR_EL1), REG_DISR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ICV_IAR0_EL1), REG_ICV_IAR0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ICV_EOIR0_EL1), REG_ICV_EOIR0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ICV_HPPIR0_EL1), REG_ICV_HPPIR0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ICV_BPR0_EL1), REG_ICV_BPR0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ICC_AP0R0_EL1), REG_ICC_AP0R0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ICC_AP0R1_EL1), REG_ICC_AP0R1_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ICC_AP0R2_EL1), REG_ICC_AP0R2_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ICC_AP0R3_EL1), REG_ICC_AP0R3_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ICC_AP1R0_EL1), REG_ICC_AP1R0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ICC_AP1R1_EL1), REG_ICC_AP1R1_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ICC_AP1R2_EL1), REG_ICC_AP1R2_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ICC_AP1R3_EL1), REG_ICC_AP1R3_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ICV_DIR_EL1), REG_ICV_DIR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ICV_RPR_EL1), REG_ICV_RPR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ICC_SGI1R_EL1), REG_ICC_SGI1R_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ICC_ASGI1R_EL1), REG_ICC_ASGI1R_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ICC_SGI0R_EL1), REG_ICC_SGI0R_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ICV_IAR1_EL1), REG_ICV_IAR1_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ICV_EOIR1_EL1), REG_ICV_EOIR1_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ICV_HPPIR1_EL1), REG_ICV_HPPIR1_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ICV_BPR1CBPR_EL1), REG_ICV_BPR1CBPR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ICV_CTLR_EL1), REG_ICV_CTLR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ICC_SRE_EL1), REG_ICC_SRE_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ICV_IGRPEN0_EL1), REG_ICV_IGRPEN0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ICV_IGRPEN1_EL1), REG_ICV_IGRPEN1_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ICC_SEIEN_EL1), REG_ICC_SEIEN_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_CONTEXTIDR_EL1), REG_CONTEXTIDR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_TPIDR_EL1), REG_TPIDR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_SCXTNUM_EL1), REG_SCXTNUM_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTHCTL_EL21), REG_CNTHCTL_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_HID0), REG_HID0);
		builder.AddMemberWithValue(get_system_register_name(REG_HID25), REG_HID25);
		builder.AddMemberWithValue(get_system_register_name(REG_HID26), REG_HID26);
		builder.AddMemberWithValue(get_system_register_name(REG_HID27), REG_HID27);
		builder.AddMemberWithValue(get_system_register_name(REG_HID28), REG_HID28);
		builder.AddMemberWithValue(get_system_register_name(REG_HID29), REG_HID29);
		builder.AddMemberWithValue(get_system_register_name(REG_HID34), REG_HID34);
		builder.AddMemberWithValue(get_system_register_name(REG_HID1), REG_HID1);
		builder.AddMemberWithValue(get_system_register_name(REG_HID21), REG_HID21);
		builder.AddMemberWithValue(get_system_register_name(REG_BIUVCSCUPCMDCRD), REG_BIUVCSCUPCMDCRD);
		builder.AddMemberWithValue(get_system_register_name(REG_BIUVCSCUPDATCRD), REG_BIUVCSCUPDATCRD);
		builder.AddMemberWithValue(get_system_register_name(REG_HID2), REG_HID2);
		builder.AddMemberWithValue(get_system_register_name(REG_HID30), REG_HID30);
		builder.AddMemberWithValue(get_system_register_name(REG_HID31), REG_HID31);
		builder.AddMemberWithValue(get_system_register_name(REG_HID32), REG_HID32);
		builder.AddMemberWithValue(get_system_register_name(REG_HID33), REG_HID33);
		builder.AddMemberWithValue(get_system_register_name(REG_HID3), REG_HID3);
		builder.AddMemberWithValue(get_system_register_name(REG_BIUVCSCUPCMDCRDC2), REG_BIUVCSCUPCMDCRDC2);
		builder.AddMemberWithValue(get_system_register_name(REG_BIUVCSCUPDATCRDC2), REG_BIUVCSCUPDATCRDC2);
		builder.AddMemberWithValue(get_system_register_name(REG_HID4), REG_HID4);
		builder.AddMemberWithValue(get_system_register_name(REG_HID5), REG_HID5);
		builder.AddMemberWithValue(get_system_register_name(REG_HID6), REG_HID6);
		builder.AddMemberWithValue(get_system_register_name(REG_HID7), REG_HID7);
		builder.AddMemberWithValue(get_system_register_name(REG_HID8), REG_HID8);
		builder.AddMemberWithValue(get_system_register_name(REG_HID9), REG_HID9);
		builder.AddMemberWithValue(get_system_register_name(REG_HID10), REG_HID10);
		builder.AddMemberWithValue(get_system_register_name(REG_BLOCK_CMAINT_CFG), REG_BLOCK_CMAINT_CFG);
		builder.AddMemberWithValue(get_system_register_name(REG_HID11), REG_HID11);
		builder.AddMemberWithValue(get_system_register_name(REG_HID18), REG_HID18);
		builder.AddMemberWithValue(get_system_register_name(REG_HID36), REG_HID36);
		builder.AddMemberWithValue(get_system_register_name(REG_HID37), REG_HID37);
		builder.AddMemberWithValue(get_system_register_name(REG_HID12), REG_HID12);
		builder.AddMemberWithValue(get_system_register_name(REG_HID15), REG_HID15);
		builder.AddMemberWithValue(get_system_register_name(REG_HID19), REG_HID19);
		builder.AddMemberWithValue(get_system_register_name(REG_BIU_TLIMIT), REG_BIU_TLIMIT);
		builder.AddMemberWithValue(get_system_register_name(REG_HID13), REG_HID13);
		builder.AddMemberWithValue(get_system_register_name(REG_HID_RCTX_G0CTL), REG_HID_RCTX_G0CTL);
		builder.AddMemberWithValue(get_system_register_name(REG_HID_RCTX_G1CTL), REG_HID_RCTX_G1CTL);
		builder.AddMemberWithValue(get_system_register_name(REG_HID14), REG_HID14);
		builder.AddMemberWithValue(get_system_register_name(REG_HID16), REG_HID16);
		builder.AddMemberWithValue(get_system_register_name(REG_LLC_WRR2), REG_LLC_WRR2);
		builder.AddMemberWithValue(get_system_register_name(REG_BIU_AFI_CFG), REG_BIU_AFI_CFG);
		builder.AddMemberWithValue(get_system_register_name(REG_HID17), REG_HID17);
		builder.AddMemberWithValue(get_system_register_name(REG_HID24), REG_HID24);
		builder.AddMemberWithValue(get_system_register_name(REG_HID35), REG_HID35);
		builder.AddMemberWithValue(get_system_register_name(REG_CCSIDR_EL1), REG_CCSIDR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_CLIDR_EL1), REG_CLIDR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_SMIDR_EL1), REG_SMIDR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AIDR_EL1), REG_AIDR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PMCR0_EL1), REG_PMCR0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_APPL_CONTEXTPTR), REG_APPL_CONTEXTPTR);
		builder.AddMemberWithValue(get_system_register_name(REG_LD_LATPROF_CTL_EL1), REG_LD_LATPROF_CTL_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CPU_MSTALL_CTL01_EL1), REG_AON_CPU_MSTALL_CTL01_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PM_MEMFLT_CTL23_EL1), REG_PM_MEMFLT_CTL23_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTHV_CTL_EL21), REG_AGTCNTHV_CTL_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTVCTSS_NOREDIR_EL0), REG_AGTCNTVCTSS_NOREDIR_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMCR1_EL1), REG_PMCR1_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_LD_LATPROF_CTR_EL1), REG_LD_LATPROF_CTR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CPU_MSTALL_CTL23_EL1), REG_AON_CPU_MSTALL_CTL23_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PM_MEMFLT_CTL45_EL1), REG_PM_MEMFLT_CTL45_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTRDIR_EL1), REG_AGTCNTRDIR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTHCTL_NOREDIR_EL21), REG_AGTCNTHCTL_NOREDIR_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_PMCR2_EL1), REG_PMCR2_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_LD_LATPROF_STS_EL1), REG_LD_LATPROF_STS_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CPU_MSTALL_CTL45_EL1), REG_AON_CPU_MSTALL_CTL45_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTHP_CVAL_EL2), REG_AGTCNTHP_CVAL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTVCT_NOREDIR_EL0), REG_CNTVCT_NOREDIR_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTHP_CVAL_NOREDIR_EL21), REG_AGTCNTHP_CVAL_NOREDIR_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_PMCR3_EL1), REG_PMCR3_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_LD_LATPROF_INF_EL1), REG_LD_LATPROF_INF_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CPU_MSTALL_CTL67_EL1), REG_AON_CPU_MSTALL_CTL67_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTHP_TVAL_EL2), REG_AGTCNTHP_TVAL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTPCTSS_NOREDIR_EL0), REG_CNTPCTSS_NOREDIR_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTHP_TVAL_NOREDIR_EL21), REG_AGTCNTHP_TVAL_NOREDIR_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_PMCR4_EL1), REG_PMCR4_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_LD_LATPROF_CTL_EL2), REG_LD_LATPROF_CTL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CPU_MEMFLT_CTL01_EL1), REG_AON_CPU_MEMFLT_CTL01_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTHP_CTL_EL2), REG_AGTCNTHP_CTL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTVCTSS_NOREDIR_EL0), REG_CNTVCTSS_NOREDIR_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTHP_CTL_NOREDIR_EL21), REG_AGTCNTHP_CTL_NOREDIR_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_PMESR0_EL1), REG_PMESR0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_LD_LATPROF_CMD_EL1), REG_LD_LATPROF_CMD_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CPU_MEMFLT_CTL23_EL1), REG_AON_CPU_MEMFLT_CTL23_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTHV_CVAL_EL2), REG_AGTCNTHV_CVAL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTHV_CVAL_NOREDIR_EL21), REG_AGTCNTHV_CVAL_NOREDIR_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_PMESR1_EL1), REG_PMESR1_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PMCR1_EL2), REG_PMCR1_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CPU_MEMFLT_CTL45_EL1), REG_AON_CPU_MEMFLT_CTL45_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTHV_TVAL_EL2), REG_AGTCNTHV_TVAL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTHCTL_NOREDIR_EL21), REG_CNTHCTL_NOREDIR_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTHV_TVAL_NOREDIR_EL21), REG_AGTCNTHV_TVAL_NOREDIR_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_OPMAT0_EL1), REG_OPMAT0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PMCR1_EL12), REG_PMCR1_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CPU_MEMFLT_CTL67_EL1), REG_AON_CPU_MEMFLT_CTL67_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTHV_CTL_EL2), REG_AGTCNTHV_CTL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTHP_CVAL_NOREDIR_EL21), REG_CNTHP_CVAL_NOREDIR_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTHV_CTL_NOREDIR_EL21), REG_AGTCNTHV_CTL_NOREDIR_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_OPMAT1_EL1), REG_OPMAT1_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PMCR1_GL12), REG_PMCR1_GL12);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CPU_MSTALL_CTR0_EL1), REG_AON_CPU_MSTALL_CTR0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTFRQ_EL0), REG_AGTCNTFRQ_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTHP_TVAL_NOREDIR_EL21), REG_CNTHP_TVAL_NOREDIR_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTPCT_NOREDIR_EL0), REG_CNTPCT_NOREDIR_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_OPMSK0_EL1), REG_OPMSK0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_LD_LATPROF_CTL_EL12), REG_LD_LATPROF_CTL_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CPU_MSTALL_CTR1_EL1), REG_AON_CPU_MSTALL_CTR1_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTVOFF_EL2), REG_AGTCNTVOFF_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTHP_CTL_NOREDIR_EL21), REG_CNTHP_CTL_NOREDIR_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTHV_CTL_NOREDIR_EL21), REG_CNTHV_CTL_NOREDIR_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_OPMSK1_EL1), REG_OPMSK1_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_LD_LATPROF_INF_EL2), REG_LD_LATPROF_INF_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CPU_MSTALL_CTR2_EL1), REG_AON_CPU_MSTALL_CTR2_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTHP_CVAL_EL21), REG_AGTCNTHP_CVAL_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTHV_CVAL_NOREDIR_EL21), REG_CNTHV_CVAL_NOREDIR_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTPCT_NOREDIR_EL0), REG_AGTCNTPCT_NOREDIR_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CPU_MSTALL_CTR3_EL1), REG_AON_CPU_MSTALL_CTR3_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTHP_TVAL_EL21), REG_AGTCNTHP_TVAL_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTHV_TVAL_NOREDIR_EL21), REG_CNTHV_TVAL_NOREDIR_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_VMSA_HV_LOCK_EL2), REG_VMSA_HV_LOCK_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_PMSWCTRL_EL1), REG_PMSWCTRL_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PMCR5_EL0), REG_PMCR5_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CPU_MSTALL_CTR4_EL1), REG_AON_CPU_MSTALL_CTR4_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PMCOMPARE0_EL1), REG_PMCOMPARE0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PMCOMPARE1_EL1), REG_PMCOMPARE1_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_VMSA_NV_LOCK_EL2), REG_VMSA_NV_LOCK_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_PMSR_EL1), REG_PMSR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CPU_MSTALL_CTR5_EL1), REG_AON_CPU_MSTALL_CTR5_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTHP_CTL_EL21), REG_AGTCNTHP_CTL_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_PMCOMPARE5_EL1), REG_PMCOMPARE5_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PMCOMPARE6_EL1), REG_PMCOMPARE6_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PMCOMPARE7_EL1), REG_PMCOMPARE7_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PMCR_BVRNG4_EL1), REG_PMCR_BVRNG4_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PM_PMI_PC), REG_PM_PMI_PC);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CPU_MSTALL_CTR6_EL1), REG_AON_CPU_MSTALL_CTR6_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTHV_CVAL_EL21), REG_AGTCNTHV_CVAL_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTVCT_NOREDIR_EL0), REG_AGTCNTVCT_NOREDIR_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMCR_BVRNG5_EL1), REG_PMCR_BVRNG5_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CPU_MSTALL_CTR7_EL1), REG_AON_CPU_MSTALL_CTR7_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTHV_TVAL_EL21), REG_AGTCNTHV_TVAL_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTPCTSS_NOREDIR_EL0), REG_AGTCNTPCTSS_NOREDIR_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_CSSELR_EL1), REG_CSSELR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PMC0), REG_PMC0);
		builder.AddMemberWithValue(get_system_register_name(REG_UPMCFILTER0), REG_UPMCFILTER0);
		builder.AddMemberWithValue(get_system_register_name(REG_UPMCFILTER1), REG_UPMCFILTER1);
		builder.AddMemberWithValue(get_system_register_name(REG_UPMCFILTER2), REG_UPMCFILTER2);
		builder.AddMemberWithValue(get_system_register_name(REG_UPMCFILTER3), REG_UPMCFILTER3);
		builder.AddMemberWithValue(get_system_register_name(REG_UPMCFILTER4), REG_UPMCFILTER4);
		builder.AddMemberWithValue(get_system_register_name(REG_UPMCFILTER5), REG_UPMCFILTER5);
		builder.AddMemberWithValue(get_system_register_name(REG_UPMCFILTER6), REG_UPMCFILTER6);
		builder.AddMemberWithValue(get_system_register_name(REG_PMC1), REG_PMC1);
		builder.AddMemberWithValue(get_system_register_name(REG_UPMCFILTER7), REG_UPMCFILTER7);
		builder.AddMemberWithValue(get_system_register_name(REG_PMC2), REG_PMC2);
		builder.AddMemberWithValue(get_system_register_name(REG_PMC3), REG_PMC3);
		builder.AddMemberWithValue(get_system_register_name(REG_PMC4), REG_PMC4);
		builder.AddMemberWithValue(get_system_register_name(REG_PMC5), REG_PMC5);
		builder.AddMemberWithValue(get_system_register_name(REG_PMC6), REG_PMC6);
		builder.AddMemberWithValue(get_system_register_name(REG_PMC7), REG_PMC7);
		builder.AddMemberWithValue(get_system_register_name(REG_PMC8), REG_PMC8);
		builder.AddMemberWithValue(get_system_register_name(REG_PMC9), REG_PMC9);
		builder.AddMemberWithValue(get_system_register_name(REG_PMTRHLD6_EL1), REG_PMTRHLD6_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PMTRHLD4_EL1), REG_PMTRHLD4_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PMTRHLD2_EL1), REG_PMTRHLD2_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PMMMAP_EL1), REG_PMMMAP_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_CTR_EL0), REG_CTR_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_DCZID_EL0), REG_DCZID_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_NZCV), REG_NZCV);
		builder.AddMemberWithValue(get_system_register_name(REG_DAIF), REG_DAIF);
		builder.AddMemberWithValue(get_system_register_name(REG_SVCR), REG_SVCR);
		builder.AddMemberWithValue(get_system_register_name(REG_DIT), REG_DIT);
		builder.AddMemberWithValue(get_system_register_name(REG_SSBS), REG_SSBS);
		builder.AddMemberWithValue(get_system_register_name(REG_TCO), REG_TCO);
		builder.AddMemberWithValue(get_system_register_name(REG_FPCR), REG_FPCR);
		builder.AddMemberWithValue(get_system_register_name(REG_FPSR), REG_FPSR);
		builder.AddMemberWithValue(get_system_register_name(REG_DSPSR), REG_DSPSR);
		builder.AddMemberWithValue(get_system_register_name(REG_DLR), REG_DLR);
		builder.AddMemberWithValue(get_system_register_name(REG_PMCR_EL0), REG_PMCR_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMCNTENSET_EL0), REG_PMCNTENSET_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMCNTENCLR_EL0), REG_PMCNTENCLR_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMOVSCLR_EL0), REG_PMOVSCLR_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMSWINC_EL0), REG_PMSWINC_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMSELR_EL0), REG_PMSELR_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMCCNTR_EL0), REG_PMCCNTR_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMXEVTYPER_EL0), REG_PMXEVTYPER_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMXEVCNTR_EL0), REG_PMXEVCNTR_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_DAIFCLR), REG_DAIFCLR);
		builder.AddMemberWithValue(get_system_register_name(REG_PMUSERENR_EL0), REG_PMUSERENR_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMOVSSET_EL0), REG_PMOVSSET_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_TPIDR_EL0), REG_TPIDR_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_TPIDRRO_EL0), REG_TPIDRRO_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_TPIDR2_EL0), REG_TPIDR2_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_SCXTNUM_EL0), REG_SCXTNUM_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMCR_EL0), REG_AMCR_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMUSERENR_EL0), REG_AMUSERENR_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMCNTENCLR0_EL0), REG_AMCNTENCLR0_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMCNTENSET0_EL0), REG_AMCNTENSET0_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMCNTENCLR1_EL0), REG_AMCNTENCLR1_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMCNTENSET1_EL0), REG_AMCNTENSET1_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMEVCNTR00_EL0), REG_AMEVCNTR00_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMEVCNTR01_EL0), REG_AMEVCNTR01_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMEVCNTR02_EL0), REG_AMEVCNTR02_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMEVCNTR03_EL0), REG_AMEVCNTR03_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMEVCNTR10_EL0), REG_AMEVCNTR10_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMEVCNTR11_EL0), REG_AMEVCNTR11_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMEVCNTR12_EL0), REG_AMEVCNTR12_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMEVCNTR13_EL0), REG_AMEVCNTR13_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMEVCNTR14_EL0), REG_AMEVCNTR14_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMEVCNTR15_EL0), REG_AMEVCNTR15_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMEVCNTR16_EL0), REG_AMEVCNTR16_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMEVCNTR17_EL0), REG_AMEVCNTR17_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMEVCNTR18_EL0), REG_AMEVCNTR18_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMEVCNTR19_EL0), REG_AMEVCNTR19_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMEVCNTR110_EL0), REG_AMEVCNTR110_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMEVCNTR111_EL0), REG_AMEVCNTR111_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMEVCNTR112_EL0), REG_AMEVCNTR112_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMEVCNTR113_EL0), REG_AMEVCNTR113_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMEVCNTR114_EL0), REG_AMEVCNTR114_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMEVCNTR115_EL0), REG_AMEVCNTR115_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMEVTYPER10_EL0), REG_AMEVTYPER10_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMEVTYPER11_EL0), REG_AMEVTYPER11_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMEVTYPER12_EL0), REG_AMEVTYPER12_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMEVTYPER13_EL0), REG_AMEVTYPER13_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMEVTYPER14_EL0), REG_AMEVTYPER14_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMEVTYPER15_EL0), REG_AMEVTYPER15_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMEVTYPER16_EL0), REG_AMEVTYPER16_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMEVTYPER17_EL0), REG_AMEVTYPER17_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMEVTYPER18_EL0), REG_AMEVTYPER18_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMEVTYPER19_EL0), REG_AMEVTYPER19_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMEVTYPER110_EL0), REG_AMEVTYPER110_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMEVTYPER111_EL0), REG_AMEVTYPER111_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMEVTYPER112_EL0), REG_AMEVTYPER112_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMEVTYPER113_EL0), REG_AMEVTYPER113_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMEVTYPER114_EL0), REG_AMEVTYPER114_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMEVTYPER115_EL0), REG_AMEVTYPER115_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTFRQ_EL0), REG_CNTFRQ_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTPCT_EL0), REG_CNTPCT_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTVCT_EL0), REG_CNTVCT_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTPCTSS_EL0), REG_CNTPCTSS_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTVCTSS_EL0), REG_CNTVCTSS_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTHP_TVAL_EL21), REG_CNTHP_TVAL_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTHP_CTL_EL21), REG_CNTHP_CTL_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTHP_CVAL_EL21), REG_CNTHP_CVAL_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTHV_TVAL_EL21), REG_CNTHV_TVAL_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTHV_CTL_EL21), REG_CNTHV_CTL_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTHV_CVAL_EL21), REG_CNTHV_CVAL_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVCNTR0_EL0), REG_PMEVCNTR0_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVCNTR1_EL0), REG_PMEVCNTR1_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVCNTR2_EL0), REG_PMEVCNTR2_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVCNTR3_EL0), REG_PMEVCNTR3_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVCNTR4_EL0), REG_PMEVCNTR4_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVCNTR5_EL0), REG_PMEVCNTR5_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVCNTR6_EL0), REG_PMEVCNTR6_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVCNTR7_EL0), REG_PMEVCNTR7_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVCNTR8_EL0), REG_PMEVCNTR8_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVCNTR9_EL0), REG_PMEVCNTR9_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVCNTR10_EL0), REG_PMEVCNTR10_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVCNTR11_EL0), REG_PMEVCNTR11_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVCNTR12_EL0), REG_PMEVCNTR12_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVCNTR13_EL0), REG_PMEVCNTR13_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVCNTR14_EL0), REG_PMEVCNTR14_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVCNTR15_EL0), REG_PMEVCNTR15_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVCNTR16_EL0), REG_PMEVCNTR16_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVCNTR17_EL0), REG_PMEVCNTR17_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVCNTR18_EL0), REG_PMEVCNTR18_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVCNTR19_EL0), REG_PMEVCNTR19_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVCNTR20_EL0), REG_PMEVCNTR20_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVCNTR21_EL0), REG_PMEVCNTR21_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVCNTR22_EL0), REG_PMEVCNTR22_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVCNTR23_EL0), REG_PMEVCNTR23_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVCNTR24_EL0), REG_PMEVCNTR24_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVCNTR25_EL0), REG_PMEVCNTR25_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVCNTR26_EL0), REG_PMEVCNTR26_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVCNTR27_EL0), REG_PMEVCNTR27_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVCNTR28_EL0), REG_PMEVCNTR28_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVCNTR29_EL0), REG_PMEVCNTR29_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVCNTR30_EL0), REG_PMEVCNTR30_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVTYPER0_EL0), REG_PMEVTYPER0_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVTYPER1_EL0), REG_PMEVTYPER1_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVTYPER2_EL0), REG_PMEVTYPER2_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVTYPER3_EL0), REG_PMEVTYPER3_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVTYPER4_EL0), REG_PMEVTYPER4_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVTYPER5_EL0), REG_PMEVTYPER5_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVTYPER6_EL0), REG_PMEVTYPER6_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVTYPER7_EL0), REG_PMEVTYPER7_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVTYPER8_EL0), REG_PMEVTYPER8_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVTYPER9_EL0), REG_PMEVTYPER9_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVTYPER10_EL0), REG_PMEVTYPER10_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVTYPER11_EL0), REG_PMEVTYPER11_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVTYPER12_EL0), REG_PMEVTYPER12_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVTYPER13_EL0), REG_PMEVTYPER13_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVTYPER14_EL0), REG_PMEVTYPER14_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVTYPER15_EL0), REG_PMEVTYPER15_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVTYPER16_EL0), REG_PMEVTYPER16_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVTYPER17_EL0), REG_PMEVTYPER17_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVTYPER18_EL0), REG_PMEVTYPER18_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVTYPER19_EL0), REG_PMEVTYPER19_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVTYPER20_EL0), REG_PMEVTYPER20_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVTYPER21_EL0), REG_PMEVTYPER21_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVTYPER22_EL0), REG_PMEVTYPER22_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVTYPER23_EL0), REG_PMEVTYPER23_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVTYPER24_EL0), REG_PMEVTYPER24_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVTYPER25_EL0), REG_PMEVTYPER25_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVTYPER26_EL0), REG_PMEVTYPER26_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVTYPER27_EL0), REG_PMEVTYPER27_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVTYPER28_EL0), REG_PMEVTYPER28_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVTYPER29_EL0), REG_PMEVTYPER29_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMEVTYPER30_EL0), REG_PMEVTYPER30_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMCCFILTR_EL0), REG_PMCCFILTR_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_LSU_ERR_STS), REG_LSU_ERR_STS);
		builder.AddMemberWithValue(get_system_register_name(REG_AFLATCTL1_EL1), REG_AFLATCTL1_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AFLATVALBIN0_EL1), REG_AFLATVALBIN0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AFLATINFLO_EL1), REG_AFLATINFLO_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_LSU_ERR_CTL), REG_LSU_ERR_CTL);
		builder.AddMemberWithValue(get_system_register_name(REG_AFLATCTL2_EL1), REG_AFLATCTL2_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AFLATVALBIN1_EL1), REG_AFLATVALBIN1_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AFLATINFHI_EL1), REG_AFLATINFHI_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AFLATCTL3_EL1), REG_AFLATCTL3_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AFLATVALBIN2_EL1), REG_AFLATVALBIN2_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AFLATCTL4_EL1), REG_AFLATCTL4_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AFLATVALBIN3_EL1), REG_AFLATVALBIN3_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_LLC_FILL_CTL), REG_LLC_FILL_CTL);
		builder.AddMemberWithValue(get_system_register_name(REG_AFLATCTL5_LO_EL1), REG_AFLATCTL5_LO_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AFLATVALBIN4_EL1), REG_AFLATVALBIN4_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AFLATCTL5_HI_EL1), REG_AFLATCTL5_HI_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_LLC_FILL_DAT), REG_LLC_FILL_DAT);
		builder.AddMemberWithValue(get_system_register_name(REG_AFLATVALBIN5_EL1), REG_AFLATVALBIN5_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AFLATVALBIN6_EL1), REG_AFLATVALBIN6_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_LLC_RAM_CONFIG), REG_LLC_RAM_CONFIG);
		builder.AddMemberWithValue(get_system_register_name(REG_AFLATVALBIN7_EL1), REG_AFLATVALBIN7_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_LLC_ERR_STS), REG_LLC_ERR_STS);
		builder.AddMemberWithValue(get_system_register_name(REG_CMAINT_BCAST_LIST_0), REG_CMAINT_BCAST_LIST_0);
		builder.AddMemberWithValue(get_system_register_name(REG_CMAINT_BCAST_LIST_1), REG_CMAINT_BCAST_LIST_1);
		builder.AddMemberWithValue(get_system_register_name(REG_CMAINT_BCAST_CTL), REG_CMAINT_BCAST_CTL);
		builder.AddMemberWithValue(get_system_register_name(REG_LLC_ERR_ADR), REG_LLC_ERR_ADR);
		builder.AddMemberWithValue(get_system_register_name(REG_LLC_ERR_CTL), REG_LLC_ERR_CTL);
		builder.AddMemberWithValue(get_system_register_name(REG_LLC_ERR_INJ), REG_LLC_ERR_INJ);
		builder.AddMemberWithValue(get_system_register_name(REG_LLC_ERR_INF), REG_LLC_ERR_INF);
		builder.AddMemberWithValue(get_system_register_name(REG_USERTAGSEL_EL1), REG_USERTAGSEL_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_UUSERTAG_EL0), REG_UUSERTAG_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_KUSERTAG_EL1), REG_KUSERTAG_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_HUSERTAG_EL2), REG_HUSERTAG_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_LLC_TRACE_CTL0), REG_LLC_TRACE_CTL0);
		builder.AddMemberWithValue(get_system_register_name(REG_LLC_TRACE_CTL1), REG_LLC_TRACE_CTL1);
		builder.AddMemberWithValue(get_system_register_name(REG_LLC_UP_REQ_VC), REG_LLC_UP_REQ_VC);
		builder.AddMemberWithValue(get_system_register_name(REG_LLC_UP_REQ_VC_THRESH), REG_LLC_UP_REQ_VC_THRESH);
		builder.AddMemberWithValue(get_system_register_name(REG_LLC_UP_REQ_VC_2), REG_LLC_UP_REQ_VC_2);
		builder.AddMemberWithValue(get_system_register_name(REG_LLC_UP_REQ_VC_THRESH_2), REG_LLC_UP_REQ_VC_THRESH_2);
		builder.AddMemberWithValue(get_system_register_name(REG_LLC_DRAM_HASH0), REG_LLC_DRAM_HASH0);
		builder.AddMemberWithValue(get_system_register_name(REG_LLC_DRAM_HASH1), REG_LLC_DRAM_HASH1);
		builder.AddMemberWithValue(get_system_register_name(REG_LLC_DRAM_HASH2), REG_LLC_DRAM_HASH2);
		builder.AddMemberWithValue(get_system_register_name(REG_LLC_DRAM_HASH3), REG_LLC_DRAM_HASH3);
		builder.AddMemberWithValue(get_system_register_name(REG_LLC_TRACE_CTL2), REG_LLC_TRACE_CTL2);
		builder.AddMemberWithValue(get_system_register_name(REG_LLC_DRAM_HASH4), REG_LLC_DRAM_HASH4);
		builder.AddMemberWithValue(get_system_register_name(REG_LLC_UP_REQ_VC_3), REG_LLC_UP_REQ_VC_3);
		builder.AddMemberWithValue(get_system_register_name(REG_LLC_UP_REQ_VC_THRESH_3), REG_LLC_UP_REQ_VC_THRESH_3);
		builder.AddMemberWithValue(get_system_register_name(REG_LLC_UP_REQ_VC_4), REG_LLC_UP_REQ_VC_4);
		builder.AddMemberWithValue(get_system_register_name(REG_LLC_UP_REQ_VC_THRESH_4), REG_LLC_UP_REQ_VC_THRESH_4);
		builder.AddMemberWithValue(get_system_register_name(REG_LLC_HASH0), REG_LLC_HASH0);
		builder.AddMemberWithValue(get_system_register_name(REG_LLC_HASH1), REG_LLC_HASH1);
		builder.AddMemberWithValue(get_system_register_name(REG_LLC_HASH2), REG_LLC_HASH2);
		builder.AddMemberWithValue(get_system_register_name(REG_LLC_HASH3), REG_LLC_HASH3);
		builder.AddMemberWithValue(get_system_register_name(REG_LLC_WRR), REG_LLC_WRR);
		builder.AddMemberWithValue(get_system_register_name(REG_LLC_DRAM_HASH5), REG_LLC_DRAM_HASH5);
		builder.AddMemberWithValue(get_system_register_name(REG_LLC_DRAM_HASH6), REG_LLC_DRAM_HASH6);
		builder.AddMemberWithValue(get_system_register_name(REG_VPIDR_EL2), REG_VPIDR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_VMPIDR_EL2), REG_VMPIDR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_SCTLR_EL2), REG_SCTLR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ACTLR_EL2), REG_ACTLR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_HCR_EL2), REG_HCR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_MDCR_EL2), REG_MDCR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CPTR_EL2), REG_CPTR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_HSTR_EL2), REG_HSTR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_HFGRTR_EL2), REG_HFGRTR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_HFGWTR_EL2), REG_HFGWTR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_HFGITR_EL2), REG_HFGITR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_HACR_EL2), REG_HACR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_TRFCR_EL2), REG_TRFCR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_HCRX_EL2), REG_HCRX_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_SMPRIMAP_EL2), REG_SMPRIMAP_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_SMCR_EL2), REG_SMCR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_SDER32_EL2), REG_SDER32_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_TTBR0_EL2), REG_TTBR0_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_TTBR1_EL2), REG_TTBR1_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_TCR_EL2), REG_TCR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_VTTBR_EL2), REG_VTTBR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_VTCR_EL2), REG_VTCR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_VNCR_EL2), REG_VNCR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_VSTTBR_EL2), REG_VSTTBR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_VSTCR_EL2), REG_VSTCR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_DACR32_EL2), REG_DACR32_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_HDFGRTR_EL2), REG_HDFGRTR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_HDFGWTR_EL2), REG_HDFGWTR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_SPSR_EL2), REG_SPSR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ELR_EL2), REG_ELR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_SP_EL1), REG_SP_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_SPSR_IRQ), REG_SPSR_IRQ);
		builder.AddMemberWithValue(get_system_register_name(REG_SPSR_ABT), REG_SPSR_ABT);
		builder.AddMemberWithValue(get_system_register_name(REG_SPSR_UND), REG_SPSR_UND);
		builder.AddMemberWithValue(get_system_register_name(REG_SPSR_FIQ), REG_SPSR_FIQ);
		builder.AddMemberWithValue(get_system_register_name(REG_IFSR32_EL2), REG_IFSR32_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_AFSR0_EL2), REG_AFSR0_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_AFSR1_EL2), REG_AFSR1_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ESR_EL2), REG_ESR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_VSESR_EL2), REG_VSESR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_FPEXC32_EL2), REG_FPEXC32_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_TFSR_EL2), REG_TFSR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_FAR_EL2), REG_FAR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_HPFAR_EL2), REG_HPFAR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_PMSCR_EL2), REG_PMSCR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_MAIR_EL2), REG_MAIR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_AMAIR_EL2), REG_AMAIR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_MPAMHCR_EL2), REG_MPAMHCR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_MPAMVPMV_EL2), REG_MPAMVPMV_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_MPAM2_EL2), REG_MPAM2_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_MPAMVPM0_EL2), REG_MPAMVPM0_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_MPAMVPM1_EL2), REG_MPAMVPM1_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_MPAMVPM2_EL2), REG_MPAMVPM2_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_MPAMVPM3_EL2), REG_MPAMVPM3_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_MPAMVPM4_EL2), REG_MPAMVPM4_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_MPAMVPM5_EL2), REG_MPAMVPM5_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_MPAMVPM6_EL2), REG_MPAMVPM6_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_MPAMVPM7_EL2), REG_MPAMVPM7_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_VBAR_EL2), REG_VBAR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_RVBAR_EL2), REG_RVBAR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_RMR_EL2), REG_RMR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_VDISR_EL2), REG_VDISR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ICH_AP0R0_EL2), REG_ICH_AP0R0_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ICH_AP0R1_EL2), REG_ICH_AP0R1_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ICH_AP0R2_EL2), REG_ICH_AP0R2_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ICH_AP0R3_EL2), REG_ICH_AP0R3_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ICH_AP1R0_EL2), REG_ICH_AP1R0_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ICH_AP1R1_EL2), REG_ICH_AP1R1_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ICH_AP1R2_EL2), REG_ICH_AP1R2_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ICH_AP1R3_EL2), REG_ICH_AP1R3_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ICH_VSEIR_EL2), REG_ICH_VSEIR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ICC_SRE_EL2), REG_ICC_SRE_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ICH_HCR_EL2), REG_ICH_HCR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ICH_VTR_EL2), REG_ICH_VTR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ICH_MISR_EL2), REG_ICH_MISR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ICH_EISR_EL2), REG_ICH_EISR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ICH_ELRSR_EL2), REG_ICH_ELRSR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ICH_VMCR_EL2), REG_ICH_VMCR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ICH_LR0_EL2), REG_ICH_LR0_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ICH_LR1_EL2), REG_ICH_LR1_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ICH_LR2_EL2), REG_ICH_LR2_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ICH_LR3_EL2), REG_ICH_LR3_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ICH_LR4_EL2), REG_ICH_LR4_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ICH_LR5_EL2), REG_ICH_LR5_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ICH_LR6_EL2), REG_ICH_LR6_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ICH_LR7_EL2), REG_ICH_LR7_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ICH_LR8_EL2), REG_ICH_LR8_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ICH_LR9_EL2), REG_ICH_LR9_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ICH_LR10_EL2), REG_ICH_LR10_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ICH_LR11_EL2), REG_ICH_LR11_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ICH_LR12_EL2), REG_ICH_LR12_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ICH_LR13_EL2), REG_ICH_LR13_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ICH_LR14_EL2), REG_ICH_LR14_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ICH_LR15_EL2), REG_ICH_LR15_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CONTEXTIDR_EL2), REG_CONTEXTIDR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_TPIDR_EL2), REG_TPIDR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_SCXTNUM_EL2), REG_SCXTNUM_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTVOFF_EL2), REG_CNTVOFF_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTHCTL_EL2), REG_CNTHCTL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTHP_TVAL_EL2), REG_CNTHP_TVAL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTHP_CTL_EL2), REG_CNTHP_CTL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTHP_CVAL_EL2), REG_CNTHP_CVAL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTHV_TVAL_EL2), REG_CNTHV_TVAL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTHV_CTL_EL2), REG_CNTHV_CTL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTHV_CVAL_EL2), REG_CNTHV_CVAL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTHVS_TVAL_EL2), REG_CNTHVS_TVAL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTHVS_CTL_EL2), REG_CNTHVS_CTL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTHVS_CVAL_EL2), REG_CNTHVS_CVAL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTHPS_TVAL_EL2), REG_CNTHPS_TVAL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTHPS_CTL_EL2), REG_CNTHPS_CTL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTHPS_CVAL_EL2), REG_CNTHPS_CVAL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_FED_ERR_STS), REG_FED_ERR_STS);
		builder.AddMemberWithValue(get_system_register_name(REG_FED_ERR_CTL), REG_FED_ERR_CTL);
		builder.AddMemberWithValue(get_system_register_name(REG_APCTL_EL1), REG_APCTL_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_KERNKEYLO_EL1), REG_KERNKEYLO_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_KERNKEYHI_EL1), REG_KERNKEYHI_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_VMSALOCK_EL21), REG_VMSALOCK_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_AMX_STATE_T_EL1), REG_AMX_STATE_T_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AMX_CONFIG_EL1), REG_AMX_CONFIG_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_VMSA_LOCK_EL2), REG_VMSA_LOCK_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CTRR_B_UPR_EL1), REG_CTRR_B_UPR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_CTRR_B_LWR_EL1), REG_CTRR_B_LWR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_SP_SETUP_GL1), REG_SP_SETUP_GL1);
		builder.AddMemberWithValue(get_system_register_name(REG_SP_SETUP_GL2), REG_SP_SETUP_GL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CTRR_B_CTL_EL1), REG_CTRR_B_CTL_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_CTRR_A_LWR_EL1), REG_CTRR_A_LWR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_CTRR_A_UPR_EL1), REG_CTRR_A_UPR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_CTRR_A_CTL_EL1), REG_CTRR_A_CTL_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_VMSA_LOCK_EL12), REG_VMSA_LOCK_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTV_CTL_EL02), REG_AGTCNTV_CTL_EL02);
		builder.AddMemberWithValue(get_system_register_name(REG_AMX_STATE_EL1), REG_AMX_STATE_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AMX_STATUS_EL1), REG_AMX_STATUS_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTP_CVAL_EL02), REG_AGTCNTP_CVAL_EL02);
		builder.AddMemberWithValue(get_system_register_name(REG_REDIR_ACNTP_TVAL_EL02), REG_REDIR_ACNTP_TVAL_EL02);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTP_CTL_EL02), REG_AGTCNTP_CTL_EL02);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTV_CVAL_EL02), REG_AGTCNTV_CVAL_EL02);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTV_TVAL_EL02), REG_AGTCNTV_TVAL_EL02);
		builder.AddMemberWithValue(get_system_register_name(REG_AMX_CONFIG_EL12), REG_AMX_CONFIG_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_AMX_CONFIG_EL2), REG_AMX_CONFIG_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_HUPERM_EL0), REG_SPRR_HUPERM_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_VUPERM_EL0), REG_SPRR_VUPERM_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_CTRR_A_CTL_EL2), REG_CTRR_A_CTL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CTRR_B_CTL_EL2), REG_CTRR_B_CTL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CTRR_A_LWR_EL2), REG_CTRR_A_LWR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CTRR_A_UPR_EL2), REG_CTRR_A_UPR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CTRR_B_LWR_EL2), REG_CTRR_B_LWR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CTRR_B_UPR_EL2), REG_CTRR_B_UPR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_HUMPRR_EL2), REG_SPRR_HUMPRR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_HUPERM_SH01_EL2), REG_SPRR_HUPERM_SH01_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_HUPERM_SH02_EL2), REG_SPRR_HUPERM_SH02_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_HUPERM_SH03_EL2), REG_SPRR_HUPERM_SH03_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_HUPERM_SH04_EL2), REG_SPRR_HUPERM_SH04_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_HUPERM_SH05_EL2), REG_SPRR_HUPERM_SH05_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_HUPERM_SH06_EL2), REG_SPRR_HUPERM_SH06_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_HUPERM_SH07_EL2), REG_SPRR_HUPERM_SH07_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_VUMPRR_EL1), REG_SPRR_VUMPRR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_VUPERM_SH01_EL1), REG_SPRR_VUPERM_SH01_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_VUPERM_SH02_EL1), REG_SPRR_VUPERM_SH02_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_VUPERM_SH03_EL1), REG_SPRR_VUPERM_SH03_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_VUPERM_SH04_EL1), REG_SPRR_VUPERM_SH04_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_VUPERM_SH05_EL1), REG_SPRR_VUPERM_SH05_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_VUPERM_SH06_EL1), REG_SPRR_VUPERM_SH06_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_VUPERM_SH07_EL1), REG_SPRR_VUPERM_SH07_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_CTRR_A_LWR_EL12), REG_CTRR_A_LWR_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_CTRR_A_UPR_EL12), REG_CTRR_A_UPR_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_CTRR_B_LWR_EL12), REG_CTRR_B_LWR_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_CTRR_B_UPR_EL12), REG_CTRR_B_UPR_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_CTRR_A_CTL_EL12), REG_CTRR_A_CTL_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_CTRR_B_CTL_EL12), REG_CTRR_B_CTL_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTHCTL_EL21), REG_AGTCNTHCTL_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTKCTL_EL12), REG_AGTCNTKCTL_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_PREDAKEYLO_EL1), REG_PREDAKEYLO_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PREDAKEYHI_EL1), REG_PREDAKEYHI_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PREDBKEYLO_EL1), REG_PREDBKEYLO_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PREDBKEYHI_EL1), REG_PREDBKEYHI_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_SIQ_CFG_EL1), REG_SIQ_CFG_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTPCTSS_EL0), REG_AGTCNTPCTSS_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTVCTSS_EL0), REG_AGTCNTVCTSS_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AVNCR_EL2), REG_AVNCR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ACC_CTRR_A_LWR_EL2), REG_ACC_CTRR_A_LWR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ACC_CTRR_A_UPR_EL2), REG_ACC_CTRR_A_UPR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ACC_CTRR_B_LWR_EL2), REG_ACC_CTRR_B_LWR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ACC_CTRR_B_UPR_EL2), REG_ACC_CTRR_B_UPR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ACC_CTRR_A_CTL_EL2), REG_ACC_CTRR_A_CTL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ACC_CTRR_B_CTL_EL2), REG_ACC_CTRR_B_CTL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTPCT_EL0), REG_AGTCNTPCT_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTVCT_EL0), REG_AGTCNTVCT_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_ACFG_EL1), REG_ACFG_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AHCR_EL2), REG_AHCR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_APL_INTSTATUS_EL1), REG_APL_INTSTATUS_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_APL_INTSTATUS_EL2), REG_APL_INTSTATUS_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTHCTL_EL2), REG_AGTCNTHCTL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_JAPIAKEYLO_EL2), REG_JAPIAKEYLO_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_JAPIAKEYHI_EL2), REG_JAPIAKEYHI_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_JAPIBKEYLO_EL2), REG_JAPIBKEYLO_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_JAPIBKEYHI_EL2), REG_JAPIBKEYHI_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_JAPIAKEYLO_EL1), REG_JAPIAKEYLO_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_JAPIAKEYHI_EL1), REG_JAPIAKEYHI_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_JAPIBKEYLO_EL1), REG_JAPIBKEYLO_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_JAPIBKEYHI_EL1), REG_JAPIBKEYHI_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_JAPIAKEYLO_EL12), REG_JAPIAKEYLO_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_JAPIAKEYHI_EL12), REG_JAPIAKEYHI_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_JAPIBKEYLO_EL12), REG_JAPIBKEYLO_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_JAPIBKEYHI_EL12), REG_JAPIBKEYHI_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTRDIR_EL2), REG_AGTCNTRDIR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_AGTCNTRDIR_EL12), REG_AGTCNTRDIR_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_JRANGE_EL2), REG_JRANGE_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_JRANGE_EL1), REG_JRANGE_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_JRANGE_EL12), REG_JRANGE_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_JCTL_EL2), REG_JCTL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_JCTL_EL1), REG_JCTL_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_JCTL_EL12), REG_JCTL_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_JCTL_EL0), REG_JCTL_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_AMDSCR_EL1), REG_AMDSCR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_SCTLR_EL12), REG_SCTLR_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_ACTLR_EL12), REG_ACTLR_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_CPACR_EL12), REG_CPACR_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_TRFCR_EL12), REG_TRFCR_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_SMCR_EL12), REG_SMCR_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_TTBR0_EL12), REG_TTBR0_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_TTBR1_EL12), REG_TTBR1_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_TCR_EL12), REG_TCR_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_SPSR_EL12), REG_SPSR_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_ELR_EL12), REG_ELR_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_AFSR0_EL12), REG_AFSR0_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_AFSR1_EL12), REG_AFSR1_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_ESR_EL12), REG_ESR_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_TFSR_EL12), REG_TFSR_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_FAR_EL12), REG_FAR_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_PMSCR_EL12), REG_PMSCR_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_MAIR_EL12), REG_MAIR_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_AMAIR_EL12), REG_AMAIR_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_MPAM1_EL12), REG_MPAM1_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_VBAR_EL12), REG_VBAR_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_CONTEXTIDR_EL12), REG_CONTEXTIDR_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_SCXTNUM_EL12), REG_SCXTNUM_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTKCTL_EL12), REG_CNTKCTL_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTP_TVAL_EL02), REG_CNTP_TVAL_EL02);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTP_CTL_EL02), REG_CNTP_CTL_EL02);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTP_CVAL_EL02), REG_CNTP_CVAL_EL02);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTV_TVAL_EL02), REG_CNTV_TVAL_EL02);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTV_CTL_EL02), REG_CNTV_CTL_EL02);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTV_CVAL_EL02), REG_CNTV_CVAL_EL02);
		builder.AddMemberWithValue(get_system_register_name(REG_IPI_RR_LOCAL_EL1), REG_IPI_RR_LOCAL_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_IPI_RR_GLOBAL_EL1), REG_IPI_RR_GLOBAL_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AF_ERR_CFG0), REG_AF_ERR_CFG0);
		builder.AddMemberWithValue(get_system_register_name(REG_AP_ERR_CFG0), REG_AP_ERR_CFG0);
		builder.AddMemberWithValue(get_system_register_name(REG_AF_ERR_SRC_IDS), REG_AF_ERR_SRC_IDS);
		builder.AddMemberWithValue(get_system_register_name(REG_DPC_ERR_STS), REG_DPC_ERR_STS);
		builder.AddMemberWithValue(get_system_register_name(REG_DPC_ERR_CTL), REG_DPC_ERR_CTL);
		builder.AddMemberWithValue(get_system_register_name(REG_PROD_TRC_CORE_CFG_EL1), REG_PROD_TRC_CORE_CFG_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_TRACE_CORE_CFG), REG_TRACE_CORE_CFG);
		builder.AddMemberWithValue(get_system_register_name(REG_IPI_SR), REG_IPI_SR);
		builder.AddMemberWithValue(get_system_register_name(REG_APL_LRTMR_EL2), REG_APL_LRTMR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_APL_INTENABLE_EL2), REG_APL_INTENABLE_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_KTRACE_MESSAGE), REG_KTRACE_MESSAGE);
		builder.AddMemberWithValue(get_system_register_name(REG_TRACE_CORE_CFG_EXT), REG_TRACE_CORE_CFG_EXT);
		builder.AddMemberWithValue(get_system_register_name(REG_PROD_TRC_CORE_CFG_EL2), REG_PROD_TRC_CORE_CFG_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_HID_PROD_TRC_CORE_CFG_EL1), REG_HID_PROD_TRC_CORE_CFG_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_DBG_WRAP_GLB), REG_DBG_WRAP_GLB);
		builder.AddMemberWithValue(get_system_register_name(REG_TRACE_STREAM_BASE), REG_TRACE_STREAM_BASE);
		builder.AddMemberWithValue(get_system_register_name(REG_TRACE_STREAM_FILL), REG_TRACE_STREAM_FILL);
		builder.AddMemberWithValue(get_system_register_name(REG_TRACE_STREAM_BASE1), REG_TRACE_STREAM_BASE1);
		builder.AddMemberWithValue(get_system_register_name(REG_TRACE_STREAM_FILL1), REG_TRACE_STREAM_FILL1);
		builder.AddMemberWithValue(get_system_register_name(REG_TRACE_STREAM_IRQ), REG_TRACE_STREAM_IRQ);
		builder.AddMemberWithValue(get_system_register_name(REG_WATCHDOGDIAG0), REG_WATCHDOGDIAG0);
		builder.AddMemberWithValue(get_system_register_name(REG_WATCHDOGDIAG1), REG_WATCHDOGDIAG1);
		builder.AddMemberWithValue(get_system_register_name(REG_TRACE_AUX_CTL), REG_TRACE_AUX_CTL);
		builder.AddMemberWithValue(get_system_register_name(REG_IPI_CR), REG_IPI_CR);
		builder.AddMemberWithValue(get_system_register_name(REG_UTRIG_EVENT), REG_UTRIG_EVENT);
		builder.AddMemberWithValue(get_system_register_name(REG_HID_PROD_TRC_MASK_EL1), REG_HID_PROD_TRC_MASK_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_TRACE_CTL), REG_TRACE_CTL);
		builder.AddMemberWithValue(get_system_register_name(REG_TRACE_DAT), REG_TRACE_DAT);
		builder.AddMemberWithValue(get_system_register_name(REG_PROD_TRC_STRM_BASE0_GL2), REG_PROD_TRC_STRM_BASE0_GL2);
		builder.AddMemberWithValue(get_system_register_name(REG_PROD_TRC_STRM_BASE1_GL2), REG_PROD_TRC_STRM_BASE1_GL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CPU_CFG), REG_CPU_CFG);
		builder.AddMemberWithValue(get_system_register_name(REG_PBLK_STS), REG_PBLK_STS);
		builder.AddMemberWithValue(get_system_register_name(REG_PROD_TRC_CTL_EL1), REG_PROD_TRC_CTL_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PROD_TRC_STRM_BASE0_GL1), REG_PROD_TRC_STRM_BASE0_GL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PROD_TRC_STRM_BASE1_GL1), REG_PROD_TRC_STRM_BASE1_GL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PROD_TRC_STRM_FIQ_EL1), REG_PROD_TRC_STRM_FIQ_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_CPU_OVRD), REG_CPU_OVRD);
		builder.AddMemberWithValue(get_system_register_name(REG_PBLK_EXE_ST), REG_PBLK_EXE_ST);
		builder.AddMemberWithValue(get_system_register_name(REG_PROD_TRC_CORE_GL_CTL_GL1), REG_PROD_TRC_CORE_GL_CTL_GL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PROD_TRC_CORE_GL_CTL_GL2), REG_PROD_TRC_CORE_GL_CTL_GL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ACC_OVRD), REG_ACC_OVRD);
		builder.AddMemberWithValue(get_system_register_name(REG_ACC_OVRD1), REG_ACC_OVRD1);
		builder.AddMemberWithValue(get_system_register_name(REG_CPM_PWRDN_CTL), REG_CPM_PWRDN_CTL);
		builder.AddMemberWithValue(get_system_register_name(REG_PROD_TRC_BUF_RESTORE0_GL1), REG_PROD_TRC_BUF_RESTORE0_GL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PROD_TRC_BUF_RESTORE1_GL1), REG_PROD_TRC_BUF_RESTORE1_GL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PROD_TRC_EN_GL1), REG_PROD_TRC_EN_GL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PRE_LLCFLUSH_TMR), REG_PRE_LLCFLUSH_TMR);
		builder.AddMemberWithValue(get_system_register_name(REG_BIUINTFCTL_CFG), REG_BIUINTFCTL_CFG);
		builder.AddMemberWithValue(get_system_register_name(REG_BIUINTFWRR_CFG), REG_BIUINTFWRR_CFG);
		builder.AddMemberWithValue(get_system_register_name(REG_PRE_TD_TMR), REG_PRE_TD_TMR);
		builder.AddMemberWithValue(get_system_register_name(REG_ACC_SLP_WAKE_UP_TMR), REG_ACC_SLP_WAKE_UP_TMR);
		builder.AddMemberWithValue(get_system_register_name(REG_PBLK_PSW_DLY), REG_PBLK_PSW_DLY);
		builder.AddMemberWithValue(get_system_register_name(REG_CPU_STS), REG_CPU_STS);
		builder.AddMemberWithValue(get_system_register_name(REG_HIST_TRIG), REG_HIST_TRIG);
		builder.AddMemberWithValue(get_system_register_name(REG_PROD_TRC_BUF_RESTORE0_GL2), REG_PROD_TRC_BUF_RESTORE0_GL2);
		builder.AddMemberWithValue(get_system_register_name(REG_PROD_TRC_BUF_RESTORE1_GL2), REG_PROD_TRC_BUF_RESTORE1_GL2);
		builder.AddMemberWithValue(get_system_register_name(REG_PROD_TRC_STRM_FILL0_EL1), REG_PROD_TRC_STRM_FILL0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PROD_TRC_STRM_FILL1_EL1), REG_PROD_TRC_STRM_FILL1_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ARRAY_INDEX), REG_ARRAY_INDEX);
		builder.AddMemberWithValue(get_system_register_name(REG_PROD_TRC_CTL_EL2), REG_PROD_TRC_CTL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_PROD_TRC_EN_GL2), REG_PROD_TRC_EN_GL2);
		builder.AddMemberWithValue(get_system_register_name(REG_PROD_TRC_STRM_FIQ_EL2), REG_PROD_TRC_STRM_FIQ_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_PROD_TRC_CPMU_DUMP_TRIG_EL1), REG_PROD_TRC_CPMU_DUMP_TRIG_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PROD_LOSS_COUNT_EL1), REG_PROD_LOSS_COUNT_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_SW_TRACE_DATA_EL0), REG_SW_TRACE_DATA_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_IL1_DATA0), REG_IL1_DATA0);
		builder.AddMemberWithValue(get_system_register_name(REG_IL1_DATA1), REG_IL1_DATA1);
		builder.AddMemberWithValue(get_system_register_name(REG_DL1_DATA0), REG_DL1_DATA0);
		builder.AddMemberWithValue(get_system_register_name(REG_DL1_DATA1), REG_DL1_DATA1);
		builder.AddMemberWithValue(get_system_register_name(REG_MMUDATA0), REG_MMUDATA0);
		builder.AddMemberWithValue(get_system_register_name(REG_MMUDATA1), REG_MMUDATA1);
		builder.AddMemberWithValue(get_system_register_name(REG_DL1_DATA2), REG_DL1_DATA2);
		builder.AddMemberWithValue(get_system_register_name(REG_IL1_DATA2), REG_IL1_DATA2);
		builder.AddMemberWithValue(get_system_register_name(REG_LLC_DATA0), REG_LLC_DATA0);
		builder.AddMemberWithValue(get_system_register_name(REG_LLC_DATA1), REG_LLC_DATA1);
		builder.AddMemberWithValue(get_system_register_name(REG_SCTLR_EL3), REG_SCTLR_EL3);
		builder.AddMemberWithValue(get_system_register_name(REG_ACTLR_EL3), REG_ACTLR_EL3);
		builder.AddMemberWithValue(get_system_register_name(REG_SCR_EL3), REG_SCR_EL3);
		builder.AddMemberWithValue(get_system_register_name(REG_SDER32_EL3), REG_SDER32_EL3);
		builder.AddMemberWithValue(get_system_register_name(REG_CPTR_EL3), REG_CPTR_EL3);
		builder.AddMemberWithValue(get_system_register_name(REG_MDCR_EL3), REG_MDCR_EL3);
		builder.AddMemberWithValue(get_system_register_name(REG_TTBR0_EL3), REG_TTBR0_EL3);
		builder.AddMemberWithValue(get_system_register_name(REG_TCR_EL3), REG_TCR_EL3);
		builder.AddMemberWithValue(get_system_register_name(REG_SPSR_EL3), REG_SPSR_EL3);
		builder.AddMemberWithValue(get_system_register_name(REG_ELR_EL3), REG_ELR_EL3);
		builder.AddMemberWithValue(get_system_register_name(REG_SP_EL2), REG_SP_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_AFSR0_EL3), REG_AFSR0_EL3);
		builder.AddMemberWithValue(get_system_register_name(REG_AFSR1_EL3), REG_AFSR1_EL3);
		builder.AddMemberWithValue(get_system_register_name(REG_ESR_EL3), REG_ESR_EL3);
		builder.AddMemberWithValue(get_system_register_name(REG_TFSR_EL3), REG_TFSR_EL3);
		builder.AddMemberWithValue(get_system_register_name(REG_FAR_EL3), REG_FAR_EL3);
		builder.AddMemberWithValue(get_system_register_name(REG_MAIR_EL3), REG_MAIR_EL3);
		builder.AddMemberWithValue(get_system_register_name(REG_AMAIR_EL3), REG_AMAIR_EL3);
		builder.AddMemberWithValue(get_system_register_name(REG_MPAM3_EL3), REG_MPAM3_EL3);
		builder.AddMemberWithValue(get_system_register_name(REG_VBAR_EL3), REG_VBAR_EL3);
		builder.AddMemberWithValue(get_system_register_name(REG_RVBAR_EL3), REG_RVBAR_EL3);
		builder.AddMemberWithValue(get_system_register_name(REG_RMR_EL3), REG_RMR_EL3);
		builder.AddMemberWithValue(get_system_register_name(REG_ICC_CTLR_EL3), REG_ICC_CTLR_EL3);
		builder.AddMemberWithValue(get_system_register_name(REG_ICC_SRE_EL3), REG_ICC_SRE_EL3);
		builder.AddMemberWithValue(get_system_register_name(REG_ICC_IGRPEN1_EL3), REG_ICC_IGRPEN1_EL3);
		builder.AddMemberWithValue(get_system_register_name(REG_TPIDR_EL3), REG_TPIDR_EL3);
		builder.AddMemberWithValue(get_system_register_name(REG_SCXTNUM_EL3), REG_SCXTNUM_EL3);
		builder.AddMemberWithValue(get_system_register_name(REG_MMU_ERR_STS), REG_MMU_ERR_STS);
		builder.AddMemberWithValue(get_system_register_name(REG_AFSR1_GL1), REG_AFSR1_GL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AFSR1_GL2), REG_AFSR1_GL2);
		builder.AddMemberWithValue(get_system_register_name(REG_AFSR1_GL12), REG_AFSR1_GL12);
		builder.AddMemberWithValue(get_system_register_name(REG_BP_OBJC_ADR_EL1), REG_BP_OBJC_ADR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_BP_OBJC_CTL_EL1), REG_BP_OBJC_CTL_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_SP_GL11), REG_SP_GL11);
		builder.AddMemberWithValue(get_system_register_name(REG_MMU_SESR_EL2), REG_MMU_SESR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_CONFIG_EL1), REG_SPRR_CONFIG_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_HPFAR_GL2), REG_HPFAR_GL2);
		builder.AddMemberWithValue(get_system_register_name(REG_GXF_CONFIG_EL1), REG_GXF_CONFIG_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AMRANGE_EL21), REG_AMRANGE_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_GXF_CONFIG_EL2), REG_GXF_CONFIG_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_UPERM_EL0), REG_SPRR_UPERM_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_PPERM_EL1), REG_SPRR_PPERM_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_PPERM_EL2), REG_SPRR_PPERM_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_APGAKEYLO_EL12), REG_APGAKEYLO_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_APGAKEYHI_EL12), REG_APGAKEYHI_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_KERNKEYLO_EL12), REG_KERNKEYLO_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_KERNKEYHI_EL12), REG_KERNKEYHI_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_AFPCR_EL0), REG_AFPCR_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_SP_GL22), REG_SP_GL22);
		builder.AddMemberWithValue(get_system_register_name(REG_AMXIDR_EL1), REG_AMXIDR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_HUMPRR_EL21), REG_SPRR_HUMPRR_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_PMPRR_EL1), REG_SPRR_PMPRR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_PMPRR_EL2), REG_SPRR_PMPRR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_HUPERM_SH01_EL21), REG_SPRR_HUPERM_SH01_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_HUPERM_SH02_EL21), REG_SPRR_HUPERM_SH02_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_HUPERM_SH03_EL21), REG_SPRR_HUPERM_SH03_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_HUPERM_SH04_EL21), REG_SPRR_HUPERM_SH04_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_HUPERM_SH05_EL21), REG_SPRR_HUPERM_SH05_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_HUPERM_SH06_EL21), REG_SPRR_HUPERM_SH06_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_HUPERM_SH07_EL21), REG_SPRR_HUPERM_SH07_EL21);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_PPERM_SH01_EL1), REG_SPRR_PPERM_SH01_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_PPERM_SH02_EL1), REG_SPRR_PPERM_SH02_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_PPERM_SH03_EL1), REG_SPRR_PPERM_SH03_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_PPERM_SH04_EL1), REG_SPRR_PPERM_SH04_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_PPERM_SH05_EL1), REG_SPRR_PPERM_SH05_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_PPERM_SH06_EL1), REG_SPRR_PPERM_SH06_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_PPERM_SH07_EL1), REG_SPRR_PPERM_SH07_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_PPERM_SH01_EL2), REG_SPRR_PPERM_SH01_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_PPERM_SH02_EL2), REG_SPRR_PPERM_SH02_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_PPERM_SH03_EL2), REG_SPRR_PPERM_SH03_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_PPERM_SH04_EL2), REG_SPRR_PPERM_SH04_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_PPERM_SH05_EL2), REG_SPRR_PPERM_SH05_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_PPERM_SH06_EL2), REG_SPRR_PPERM_SH06_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_PPERM_SH07_EL2), REG_SPRR_PPERM_SH07_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_PMPRR_EL12), REG_SPRR_PMPRR_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_PPERM_SH01_EL12), REG_SPRR_PPERM_SH01_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_PPERM_SH02_EL12), REG_SPRR_PPERM_SH02_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_PPERM_SH03_EL12), REG_SPRR_PPERM_SH03_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_PPERM_SH04_EL12), REG_SPRR_PPERM_SH04_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_PPERM_SH05_EL12), REG_SPRR_PPERM_SH05_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_PPERM_SH06_EL12), REG_SPRR_PPERM_SH06_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_PPERM_SH07_EL12), REG_SPRR_PPERM_SH07_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_APIAKEYLO_EL12), REG_APIAKEYLO_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_APIAKEYHI_EL12), REG_APIAKEYHI_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_APIBKEYLO_EL12), REG_APIBKEYLO_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_APIBKEYHI_EL12), REG_APIBKEYHI_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_APDAKEYLO_EL12), REG_APDAKEYLO_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_APDAKEYHI_EL12), REG_APDAKEYHI_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_APDBKEYLO_EL12), REG_APDBKEYLO_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_APDBKEYHI_EL12), REG_APDBKEYHI_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_CURRENTG), REG_CURRENTG);
		builder.AddMemberWithValue(get_system_register_name(REG_GXF_ENTRY_EL1), REG_GXF_ENTRY_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_GXF_PABENTRY_EL1), REG_GXF_PABENTRY_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ASPSR_EL1), REG_ASPSR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ADSPSR_EL0), REG_ADSPSR_EL0);
		builder.AddMemberWithValue(get_system_register_name(REG_PMCR1_GL2), REG_PMCR1_GL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ASPSR_EL2), REG_ASPSR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_PMCR1_GL1), REG_PMCR1_GL1);
		builder.AddMemberWithValue(get_system_register_name(REG_VBAR_GL12), REG_VBAR_GL12);
		builder.AddMemberWithValue(get_system_register_name(REG_SPSR_GL12), REG_SPSR_GL12);
		builder.AddMemberWithValue(get_system_register_name(REG_ASPSR_GL12), REG_ASPSR_GL12);
		builder.AddMemberWithValue(get_system_register_name(REG_ESR_GL12), REG_ESR_GL12);
		builder.AddMemberWithValue(get_system_register_name(REG_ELR_GL12), REG_ELR_GL12);
		builder.AddMemberWithValue(get_system_register_name(REG_FAR_GL12), REG_FAR_GL12);
		builder.AddMemberWithValue(get_system_register_name(REG_SP_GL1), REG_SP_GL1);
		builder.AddMemberWithValue(get_system_register_name(REG_TPIDR_GL1), REG_TPIDR_GL1);
		builder.AddMemberWithValue(get_system_register_name(REG_VBAR_GL1), REG_VBAR_GL1);
		builder.AddMemberWithValue(get_system_register_name(REG_SPSR_GL1), REG_SPSR_GL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ASPSR_GL1), REG_ASPSR_GL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ESR_GL1), REG_ESR_GL1);
		builder.AddMemberWithValue(get_system_register_name(REG_ELR_GL1), REG_ELR_GL1);
		builder.AddMemberWithValue(get_system_register_name(REG_FAR_GL1), REG_FAR_GL1);
		builder.AddMemberWithValue(get_system_register_name(REG_SP_GL2), REG_SP_GL2);
		builder.AddMemberWithValue(get_system_register_name(REG_TPIDR_GL2), REG_TPIDR_GL2);
		builder.AddMemberWithValue(get_system_register_name(REG_VBAR_GL2), REG_VBAR_GL2);
		builder.AddMemberWithValue(get_system_register_name(REG_SPSR_GL2), REG_SPSR_GL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ASPSR_GL2), REG_ASPSR_GL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ESR_GL2), REG_ESR_GL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ELR_GL2), REG_ELR_GL2);
		builder.AddMemberWithValue(get_system_register_name(REG_FAR_GL2), REG_FAR_GL2);
		builder.AddMemberWithValue(get_system_register_name(REG_GXF_ENTRY_EL2), REG_GXF_ENTRY_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_GXF_PABENTRY_EL2), REG_GXF_PABENTRY_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_APCTL_EL2), REG_APCTL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_APSTS_EL2), REG_APSTS_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_APSTS_EL1), REG_APSTS_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_KERNKEYLO_EL2), REG_KERNKEYLO_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_KERNKEYHI_EL2), REG_KERNKEYHI_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_ASPSR_EL12), REG_ASPSR_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_APIAKEYLO_EL2), REG_APIAKEYLO_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_APIAKEYHI_EL2), REG_APIAKEYHI_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_APIBKEYLO_EL2), REG_APIBKEYLO_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_APIBKEYHI_EL2), REG_APIBKEYHI_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_APDAKEYLO_EL2), REG_APDAKEYLO_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_APDAKEYHI_EL2), REG_APDAKEYHI_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_APDBKEYLO_EL2), REG_APDBKEYLO_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_APDBKEYHI_EL2), REG_APDBKEYHI_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_APGAKEYLO_EL2), REG_APGAKEYLO_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_APGAKEYHI_EL2), REG_APGAKEYHI_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_CONFIG_EL2), REG_SPRR_CONFIG_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_AMRANGE_EL2), REG_SPRR_AMRANGE_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_VMKEYLO_EL2), REG_VMKEYLO_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_VMKEYHI_EL2), REG_VMKEYHI_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_MMU_SFAR_EL2), REG_MMU_SFAR_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_APSTS_EL12), REG_APSTS_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_APCTL_EL12), REG_APCTL_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_GXF_CONFIG_EL12), REG_GXF_CONFIG_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_GXF_ENTRY_EL12), REG_GXF_ENTRY_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_GXF_PABENTRY_EL12), REG_GXF_PABENTRY_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_CONFIG_EL12), REG_SPRR_CONFIG_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_AMRANGE_EL12), REG_SPRR_AMRANGE_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_MMU_SESR_CTL_EL2), REG_MMU_SESR_CTL_EL2);
		builder.AddMemberWithValue(get_system_register_name(REG_SPRR_PPERM_EL12), REG_SPRR_PPERM_EL12);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTPS_TVAL_EL1), REG_CNTPS_TVAL_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTPS_CTL_EL1), REG_CNTPS_CTL_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_CNTPS_CVAL_EL1), REG_CNTPS_CVAL_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_PSTATE_SPSEL), REG_PSTATE_SPSEL);
		builder.AddMemberWithValue(get_system_register_name(REG_PWRDNSAVE0), REG_PWRDNSAVE0);
		builder.AddMemberWithValue(get_system_register_name(REG_NRG_ACC_CTL), REG_NRG_ACC_CTL);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CNT0), REG_AON_CNT0);
		builder.AddMemberWithValue(get_system_register_name(REG_CPU_CNT0), REG_CPU_CNT0);
		builder.AddMemberWithValue(get_system_register_name(REG_UPMCR0_EL1), REG_UPMCR0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_UPMC8), REG_UPMC8);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CNT8), REG_AON_CNT8);
		builder.AddMemberWithValue(get_system_register_name(REG_PWRDNSAVE1), REG_PWRDNSAVE1);
		builder.AddMemberWithValue(get_system_register_name(REG_CORE_NRG_ACC_DAT), REG_CORE_NRG_ACC_DAT);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CNT_CTL0), REG_AON_CNT_CTL0);
		builder.AddMemberWithValue(get_system_register_name(REG_CPU_CNT_CTL0), REG_CPU_CNT_CTL0);
		builder.AddMemberWithValue(get_system_register_name(REG_UPMESR0_EL1), REG_UPMESR0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_UPMC9), REG_UPMC9);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CNT_CTL8), REG_AON_CNT_CTL8);
		builder.AddMemberWithValue(get_system_register_name(REG_ACC_PWR_DN_SAVE), REG_ACC_PWR_DN_SAVE);
		builder.AddMemberWithValue(get_system_register_name(REG_CPM_NRG_ACC_DAT), REG_CPM_NRG_ACC_DAT);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CNT1), REG_AON_CNT1);
		builder.AddMemberWithValue(get_system_register_name(REG_CPU_CNT1), REG_CPU_CNT1);
		builder.AddMemberWithValue(get_system_register_name(REG_UPMSWCTRL_EL1), REG_UPMSWCTRL_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_UPMC10), REG_UPMC10);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CNT9), REG_AON_CNT9);
		builder.AddMemberWithValue(get_system_register_name(REG_CORE_SRM_NRG_ACC_DAT), REG_CORE_SRM_NRG_ACC_DAT);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CNT_CTL1), REG_AON_CNT_CTL1);
		builder.AddMemberWithValue(get_system_register_name(REG_CPU_CNT_CTL1), REG_CPU_CNT_CTL1);
		builder.AddMemberWithValue(get_system_register_name(REG_UPMECM0_EL1), REG_UPMECM0_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_UPMC11), REG_UPMC11);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CNT_CTL9), REG_AON_CNT_CTL9);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CNT_CTL), REG_AON_CNT_CTL);
		builder.AddMemberWithValue(get_system_register_name(REG_CPM_SRM_NRG_ACC_DAT), REG_CPM_SRM_NRG_ACC_DAT);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CNT2), REG_AON_CNT2);
		builder.AddMemberWithValue(get_system_register_name(REG_CPU_CNT2), REG_CPU_CNT2);
		builder.AddMemberWithValue(get_system_register_name(REG_UPMECM1_EL1), REG_UPMECM1_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_UPMC12), REG_UPMC12);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CNT10), REG_AON_CNT10);
		builder.AddMemberWithValue(get_system_register_name(REG_CPU_CNT_CTL), REG_CPU_CNT_CTL);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CNT_CTL2), REG_AON_CNT_CTL2);
		builder.AddMemberWithValue(get_system_register_name(REG_CPU_CNT_CTL2), REG_CPU_CNT_CTL2);
		builder.AddMemberWithValue(get_system_register_name(REG_UPMPCM_EL1), REG_UPMPCM_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_UPMC13), REG_UPMC13);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CNT_CTL10), REG_AON_CNT_CTL10);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CNT3), REG_AON_CNT3);
		builder.AddMemberWithValue(get_system_register_name(REG_CPU_CNT3), REG_CPU_CNT3);
		builder.AddMemberWithValue(get_system_register_name(REG_UPMSR_EL1), REG_UPMSR_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_UPMC14), REG_UPMC14);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CNT11), REG_AON_CNT11);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CNT_CTL3), REG_AON_CNT_CTL3);
		builder.AddMemberWithValue(get_system_register_name(REG_CPU_CNT_CTL3), REG_CPU_CNT_CTL3);
		builder.AddMemberWithValue(get_system_register_name(REG_UPMC0), REG_UPMC0);
		builder.AddMemberWithValue(get_system_register_name(REG_UPMC15), REG_UPMC15);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CNT_CTL11), REG_AON_CNT_CTL11);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CNT4), REG_AON_CNT4);
		builder.AddMemberWithValue(get_system_register_name(REG_CPU_CNT4), REG_CPU_CNT4);
		builder.AddMemberWithValue(get_system_register_name(REG_UPMC1), REG_UPMC1);
		builder.AddMemberWithValue(get_system_register_name(REG_UPMECM2_EL1), REG_UPMECM2_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CNT_CTL4), REG_AON_CNT_CTL4);
		builder.AddMemberWithValue(get_system_register_name(REG_CPU_CNT_CTL4), REG_CPU_CNT_CTL4);
		builder.AddMemberWithValue(get_system_register_name(REG_UPMC2), REG_UPMC2);
		builder.AddMemberWithValue(get_system_register_name(REG_UPMECM3_EL1), REG_UPMECM3_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CNT5), REG_AON_CNT5);
		builder.AddMemberWithValue(get_system_register_name(REG_CPU_CNT5), REG_CPU_CNT5);
		builder.AddMemberWithValue(get_system_register_name(REG_UPMC3), REG_UPMC3);
		builder.AddMemberWithValue(get_system_register_name(REG_UPMCR1_EL1), REG_UPMCR1_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CNT_CTL5), REG_AON_CNT_CTL5);
		builder.AddMemberWithValue(get_system_register_name(REG_CPU_CNT_CTL5), REG_CPU_CNT_CTL5);
		builder.AddMemberWithValue(get_system_register_name(REG_UPMC4), REG_UPMC4);
		builder.AddMemberWithValue(get_system_register_name(REG_UPMESR1_EL1), REG_UPMESR1_EL1);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CNT6), REG_AON_CNT6);
		builder.AddMemberWithValue(get_system_register_name(REG_CPU_CNT6), REG_CPU_CNT6);
		builder.AddMemberWithValue(get_system_register_name(REG_UPMC5), REG_UPMC5);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CNT_CTL6), REG_AON_CNT_CTL6);
		builder.AddMemberWithValue(get_system_register_name(REG_CPU_CNT_CTL6), REG_CPU_CNT_CTL6);
		builder.AddMemberWithValue(get_system_register_name(REG_UPMC6), REG_UPMC6);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CNT7), REG_AON_CNT7);
		builder.AddMemberWithValue(get_system_register_name(REG_CPU_CNT7), REG_CPU_CNT7);
		builder.AddMemberWithValue(get_system_register_name(REG_UPMC7), REG_UPMC7);
		builder.AddMemberWithValue(get_system_register_name(REG_AON_CNT_CTL7), REG_AON_CNT_CTL7);
		builder.AddMemberWithValue(get_system_register_name(REG_CPU_CNT_CTL7), REG_CPU_CNT_CTL7);
	});
	Ref<Enumeration> _enum = builder.Finalize();
	return _enum;
}

Ref<Type> get_system_register_enum_type(Ref<BinaryView> view)
{
	Ref<Enumeration> _enum = get_system_register_enum();
	Ref<Type> enumType = Type::EnumerationType(view->GetDefaultArchitecture(), _enum, 4, false);
	return enumType;
}

QualifiedName get_system_register_enum_type_name(Ref<BinaryView> view)
{
	Ref<Type> enumType = get_system_register_enum_type(view);
	QualifiedName systemRegName = QualifiedName("SystemReg");
	string enumId = Type::GenerateAutoTypeId(view->GetDefaultArchitecture()->GetName(), systemRegName);
	QualifiedName enumTypeName = view->DefineType(enumId, systemRegName, enumType);
	return enumTypeName;
}

const vector<uint32_t>& get_system_registers()
{
	static vector<uint32_t> system_regs {
		REG_EDSCR,
		REG_EDPRCR,
		REG_UAOIMM,
		REG_PANIMM,
		REG_SPSELIMM,
		REG_DITIMM,
		REG_SVCRIMM,
		REG_ICIALLUIS,
		REG_ICIALLU,
		REG_DCIVAC,
		REG_DCISW,
		REG_ATS1E1R,
		REG_ATS1E1W,
		REG_ATS1E0R,
		REG_ATS1E0W,
		REG_DCCSW,
		REG_DCCISW,
		REG_TLBIVMALLE1IS,
		REG_TLBIVAE1IS,
		REG_TLBIASIDE1IS,
		REG_TLBIVAAE1IS,
		REG_TLBIVALE1IS,
		REG_TLBIVAALE1IS,
		REG_TLBIVMALLE1,
		REG_TLBIVAE1,
		REG_TLBIASIDE1,
		REG_TLBIVAAE1,
		REG_TLBIVALE1,
		REG_TLBIVAALE1,
		REG_DCZVA,
		REG_ICIVAU,
		REG_DCCVAC,
		REG_DCCVAU,
		REG_DCCIVAC,
		REG_ATS1E2R,
		REG_ATS1E2W,
		REG_ATS12E1R,
		REG_ATS12E1W,
		REG_ATS12E0R,
		REG_ATS12E0W,
		REG_TLBIIPAS2E1IS,
		REG_TLBIIPAS2LE1IS,
		REG_TLBIALLE2IS,
		REG_TLBIVAE2IS,
		REG_TLBIALLE1IS,
		REG_TLBIVALE2IS,
		REG_TLBIVMALLS12E1IS,
		REG_TLBIIPAS2E1,
		REG_TLBIIPAS2LE1,
		REG_TLBIALLE2,
		REG_TLBIVAE2,
		REG_TLBIALLE1,
		REG_TLBIVALE2,
		REG_TLBIVMALLS12E1,
		REG_ATS1E3R,
		REG_ATS1E3W,
		REG_TLBIALLE3IS,
		REG_TLBIVAE3IS,
		REG_TLBIVALE3IS,
		REG_TLBIALLE3,
		REG_TLBIVAE3,
		REG_TLBIVALE3,
		REG_OSDTRRX_EL1,
		REG_DBGBVR0_EL1,
		REG_DBGBCR0_EL1,
		REG_DBGWVR0_EL1,
		REG_DBGWCR0_EL1,
		REG_DBGBVR1_EL1,
		REG_DBGBCR1_EL1,
		REG_DBGWVR1_EL1,
		REG_DBGWCR1_EL1,
		REG_MDCCINT_EL1,
		REG_MDSCR_EL1,
		REG_DBGBVR2_EL1,
		REG_DBGBCR2_EL1,
		REG_DBGWVR2_EL1,
		REG_DBGWCR2_EL1,
		REG_OSDTRTX_EL1,
		REG_DBGBVR3_EL1,
		REG_DBGBCR3_EL1,
		REG_DBGWVR3_EL1,
		REG_DBGWCR3_EL1,
		REG_DBGBVR4_EL1,
		REG_DBGBCR4_EL1,
		REG_DBGWVR4_EL1,
		REG_DBGWCR4_EL1,
		REG_DBGBVR5_EL1,
		REG_DBGBCR5_EL1,
		REG_DBGWVR5_EL1,
		REG_DBGWCR5_EL1,
		REG_DBGWFAR,
		REG_OSECCR_EL1,
		REG_DBGBVR6_EL1,
		REG_DBGBCR6_EL1,
		REG_DBGWVR6_EL1,
		REG_DBGWCR6_EL1,
		REG_DBGBVR7_EL1,
		REG_DBGBCR7_EL1,
		REG_DBGWVR7_EL1,
		REG_DBGWCR7_EL1,
		REG_DBGBVR8_EL1,
		REG_DBGBCR8_EL1,
		REG_DBGWVR8_EL1,
		REG_DBGWCR8_EL1,
		REG_DBGBVR9_EL1,
		REG_DBGBCR9_EL1,
		REG_DBGWVR9_EL1,
		REG_DBGWCR9_EL1,
		REG_DBGBVR10_EL1,
		REG_DBGBCR10_EL1,
		REG_DBGWVR10_EL1,
		REG_DBGWCR10_EL1,
		REG_DBGBVR11_EL1,
		REG_DBGBCR11_EL1,
		REG_DBGWVR11_EL1,
		REG_DBGWCR11_EL1,
		REG_DBGBVR12_EL1,
		REG_DBGBCR12_EL1,
		REG_DBGWVR12_EL1,
		REG_DBGWCR12_EL1,
		REG_DBGBVR13_EL1,
		REG_DBGBCR13_EL1,
		REG_DBGWVR13_EL1,
		REG_DBGWCR13_EL1,
		REG_DBGBVR14_EL1,
		REG_DBGBCR14_EL1,
		REG_DBGWVR14_EL1,
		REG_DBGWCR14_EL1,
		REG_DBGBVR15_EL1,
		REG_DBGBCR15_EL1,
		REG_DBGWVR15_EL1,
		REG_DBGWCR15_EL1,
		REG_MDRAR_EL1,
		REG_OSLAR_EL1,
		REG_OSLSR_EL1,
		REG_OSDLR_EL1,
		REG_DBGPRCR_EL1,
		REG_DBGCLAIMSET_EL1,
		REG_DBGCLAIMCLR_EL1,
		REG_DBGAUTHSTAT_EL1,
		REG_TRCTRACEIDR,
		REG_TRCVICTLR,
		REG_TRCSEQEVR0,
		REG_TRCCNTRLDVR0,
		REG_TRCIMSPEC0,
		REG_TRCPRGCTLR,
		REG_TRCQCTLR,
		REG_TRCVIIECTLR,
		REG_TRCSEQEVR1,
		REG_TRCCNTRLDVR1,
		REG_TRCIMSPEC1,
		REG_TRCPROCSELR,
		REG_TRCVISSCTLR,
		REG_TRCSEQEVR2,
		REG_TRCCNTRLDVR2,
		REG_TRCIMSPEC2,
		REG_TRCVIPCSSCTLR,
		REG_TRCCNTRLDVR3,
		REG_TRCIMSPEC3,
		REG_TRCCONFIGR,
		REG_TRCCNTCTLR0,
		REG_TRCIMSPEC4,
		REG_TRCCNTCTLR1,
		REG_TRCIMSPEC5,
		REG_TRCAUXCTLR,
		REG_TRCSEQRSTEVR,
		REG_TRCCNTCTLR2,
		REG_TRCIMSPEC6,
		REG_TRCSEQSTR,
		REG_TRCCNTCTLR3,
		REG_TRCIMSPEC7,
		REG_TRCEVENTCTL0R,
		REG_TRCVDCTLR,
		REG_TRCEXTINSELR,
		REG_TRCCNTVR0,
		REG_TRCEVENTCTL1R,
		REG_TRCVDSACCTLR,
		REG_TRCEXTINSELR1,
		REG_TRCCNTVR1,
		REG_TRCRSR,
		REG_TRCVDARCCTLR,
		REG_TRCEXTINSELR2,
		REG_TRCCNTVR2,
		REG_TRCSTALLCTLR,
		REG_TRCEXTINSELR3,
		REG_TRCCNTVR3,
		REG_TRCTSCTLR,
		REG_TRCSYNCPR,
		REG_TRCCCCTLR,
		REG_TRCBBCTLR,
		REG_TRCRSCTLR16,
		REG_TRCSSCCR0,
		REG_TRCSSPCICR0,
		REG_TRCOSLAR,
		REG_TRCRSCTLR17,
		REG_TRCSSCCR1,
		REG_TRCSSPCICR1,
		REG_TRCRSCTLR2,
		REG_TRCRSCTLR18,
		REG_TRCSSCCR2,
		REG_TRCSSPCICR2,
		REG_TRCRSCTLR3,
		REG_TRCRSCTLR19,
		REG_TRCSSCCR3,
		REG_TRCSSPCICR3,
		REG_TRCRSCTLR4,
		REG_TRCRSCTLR20,
		REG_TRCSSCCR4,
		REG_TRCSSPCICR4,
		REG_TRCPDCR,
		REG_TRCRSCTLR5,
		REG_TRCRSCTLR21,
		REG_TRCSSCCR5,
		REG_TRCSSPCICR5,
		REG_TRCRSCTLR6,
		REG_TRCRSCTLR22,
		REG_TRCSSCCR6,
		REG_TRCSSPCICR6,
		REG_TRCRSCTLR7,
		REG_TRCRSCTLR23,
		REG_TRCSSCCR7,
		REG_TRCSSPCICR7,
		REG_TRCRSCTLR8,
		REG_TRCRSCTLR24,
		REG_TRCSSCSR0,
		REG_TRCRSCTLR9,
		REG_TRCRSCTLR25,
		REG_TRCSSCSR1,
		REG_TRCRSCTLR10,
		REG_TRCRSCTLR26,
		REG_TRCSSCSR2,
		REG_TRCRSCTLR11,
		REG_TRCRSCTLR27,
		REG_TRCSSCSR3,
		REG_TRCRSCTLR12,
		REG_TRCRSCTLR28,
		REG_TRCSSCSR4,
		REG_TRCRSCTLR13,
		REG_TRCRSCTLR29,
		REG_TRCSSCSR5,
		REG_TRCRSCTLR14,
		REG_TRCRSCTLR30,
		REG_TRCSSCSR6,
		REG_TRCRSCTLR15,
		REG_TRCRSCTLR31,
		REG_TRCSSCSR7,
		REG_TRCACVR0,
		REG_TRCACVR8,
		REG_TRCACATR0,
		REG_TRCACATR8,
		REG_TRCDVCVR0,
		REG_TRCDVCVR4,
		REG_TRCDVCMR0,
		REG_TRCDVCMR4,
		REG_TRCACVR1,
		REG_TRCACVR9,
		REG_TRCACATR1,
		REG_TRCACATR9,
		REG_TRCACVR2,
		REG_TRCACVR10,
		REG_TRCACATR2,
		REG_TRCACATR10,
		REG_TRCDVCVR1,
		REG_TRCDVCVR5,
		REG_TRCDVCMR1,
		REG_TRCDVCMR5,
		REG_TRCACVR3,
		REG_TRCACVR11,
		REG_TRCACATR3,
		REG_TRCACATR11,
		REG_TRCACVR4,
		REG_TRCACVR12,
		REG_TRCACATR4,
		REG_TRCACATR12,
		REG_TRCDVCVR2,
		REG_TRCDVCVR6,
		REG_TRCDVCMR2,
		REG_TRCDVCMR6,
		REG_TRCACVR5,
		REG_TRCACVR13,
		REG_TRCACATR5,
		REG_TRCACATR13,
		REG_TRCACVR6,
		REG_TRCACVR14,
		REG_TRCACATR6,
		REG_TRCACATR14,
		REG_TRCDVCVR3,
		REG_TRCDVCVR7,
		REG_TRCDVCMR3,
		REG_TRCDVCMR7,
		REG_TRCACVR7,
		REG_TRCACVR15,
		REG_TRCACATR7,
		REG_TRCACATR15,
		REG_TRCCIDCVR0,
		REG_TRCVMIDCVR0,
		REG_TRCCIDCCTLR0,
		REG_TRCCIDCCTLR1,
		REG_TRCCIDCVR1,
		REG_TRCVMIDCVR1,
		REG_TRCVMIDCCTLR0,
		REG_TRCVMIDCCTLR1,
		REG_TRCCIDCVR2,
		REG_TRCVMIDCVR2,
		REG_TRCCIDCVR3,
		REG_TRCVMIDCVR3,
		REG_TRCCIDCVR4,
		REG_TRCVMIDCVR4,
		REG_TRCCIDCVR5,
		REG_TRCVMIDCVR5,
		REG_TRCCIDCVR6,
		REG_TRCVMIDCVR6,
		REG_TRCCIDCVR7,
		REG_TRCVMIDCVR7,
		REG_TRCITCTRL,
		REG_TRCCLAIMSET,
		REG_TRCCLAIMCLR,
		REG_TRCLAR,
		REG_TEECR32_EL1,
		REG_TEEHBR32_EL1,
		REG_MDCCSR_EL0,
		REG_DBGDTR_EL0,
		REG_DBGDTRRX_EL0,
		REG_DBGVCR32_EL2,
		REG_MIDR_EL1,
		REG_MPIDR_EL1,
		REG_REVIDR_EL1,
		REG_ID_PFR0_EL1,
		REG_ID_PFR1_EL1,
		REG_ID_DFR0_EL1,
		REG_ID_AFR0_EL1,
		REG_ID_MMFR0_EL1,
		REG_ID_MMFR1_EL1,
		REG_ID_MMFR2_EL1,
		REG_ID_MMFR3_EL1,
		REG_ID_ISAR0_EL1,
		REG_ID_ISAR1_EL1,
		REG_ID_ISAR2_EL1,
		REG_ID_ISAR3_EL1,
		REG_ID_ISAR4_EL1,
		REG_ID_ISAR5_EL1,
		REG_ID_MMFR4_EL1,
		REG_ID_ISAR6_EL1,
		REG_MVFR0_EL1,
		REG_MVFR1_EL1,
		REG_MVFR2_EL1,
		REG_ID_AA32RES3_EL1,
		REG_ID_PFR2_EL1,
		REG_ID_AA32RES5_EL1,
		REG_ID_AA32RES6_EL1,
		REG_ID_AA32RES7_EL1,
		REG_ID_AA64PFR0_EL1,
		REG_ID_AA64PFR1_EL1,
		REG_ID_AA64PFR2_EL1,
		REG_ID_AA64PFR3_EL1,
		REG_ID_AA64ZFR0_EL1,
		REG_ID_AA64SMFR0_EL1,
		REG_ID_AA64ZFR2_EL1,
		REG_ID_AA64ZFR3_EL1,
		REG_ID_AA64DFR0_EL1,
		REG_ID_AA64DFR1_EL1,
		REG_ID_AA64DFR2_EL1,
		REG_ID_AA64DFR3_EL1,
		REG_ID_AA64AFR0_EL1,
		REG_ID_AA64AFR1_EL1,
		REG_ID_AA64AFR2_EL1,
		REG_ID_AA64AFR3_EL1,
		REG_ID_AA64ISAR0_EL1,
		REG_ID_AA64ISAR1_EL1,
		REG_ID_AA64ISAR2_EL1,
		REG_ID_AA64ISAR3_EL1,
		REG_ID_AA64ISAR4_EL1,
		REG_ID_AA64ISAR5_EL1,
		REG_ID_AA64ISAR6_EL1,
		REG_ID_AA64ISAR7_EL1,
		REG_ID_AA64MMFR0_EL1,
		REG_ID_AA64MMFR1_EL1,
		REG_ID_AA64MMFR2_EL1,
		REG_ID_AA64MMFR3_EL1,
		REG_ID_AA64MMFR4_EL1,
		REG_ID_AA64MMFR5_EL1,
		REG_ID_AA64MMFR6_EL1,
		REG_ID_AA64MMFR7_EL1,
		REG_SCTLR_EL1,
		REG_ACTLR_EL1,
		REG_CPACR_EL1,
		REG_RGSR_EL1,
		REG_GCR_EL1,
		REG_TRFCR_EL1,
		REG_SMPRI_EL1,
		REG_SMCR_EL1,
		REG_TTBR0_EL1,
		REG_TTBR1_EL1,
		REG_TCR_EL1,
		REG_APIAKEYLO_EL1,
		REG_APIAKEYHI_EL1,
		REG_APIBKEYLO_EL1,
		REG_APIBKEYHI_EL1,
		REG_APDAKEYLO_EL1,
		REG_APDAKEYHI_EL1,
		REG_APDBKEYLO_EL1,
		REG_APDBKEYHI_EL1,
		REG_APGAKEYLO_EL1,
		REG_APGAKEYHI_EL1,
		REG_SPSR_EL1,
		REG_ELR_EL1,
		REG_SP_EL0,
		REG_SPSEL,
		REG_CURRENTEL,
		REG_PAN,
		REG_UAO,
		REG_ICV_PMR_EL1,
		REG_AFSR0_EL1,
		REG_AFSR1_EL1,
		REG_ESR_EL1,
		REG_ERRIDR_EL1,
		REG_ERRSELR_EL1,
		REG_ERXCTLR_EL1,
		REG_ERXSTATUS_EL1,
		REG_ERXADDR_EL1,
		REG_ERXPFGCTL_EL1,
		REG_ERXPFGCDN_EL1,
		REG_ERXMISC0_EL1,
		REG_ERXMISC1_EL1,
		REG_ERXMISC2_EL1,
		REG_ERXMISC3_EL1,
		REG_ERXTS_EL1,
		REG_TFSR_EL1,
		REG_TFSRE0_EL1,
		REG_FAR_EL1,
		REG_PAR_EL1,
		REG_PMSCR_EL1,
		REG_PMSICR_EL1,
		REG_PMSIRR_EL1,
		REG_PMSFCR_EL1,
		REG_PMSEVFR_EL1,
		REG_PMSLATFR_EL1,
		REG_PMSIDR_EL1,
		REG_PMBLIMITR_EL1,
		REG_PMBPTR_EL1,
		REG_PMBSR_EL1,
		REG_PMBIDR_EL1,
		REG_TRBLIMITR_EL1,
		REG_TRBPTR_EL1,
		REG_TRBBASER_EL1,
		REG_TRBSR_EL1,
		REG_TRBMAR_EL1,
		REG_TRBTRG_EL1,
		REG_PMINTENSET_EL1,
		REG_PMINTENCLR_EL1,
		REG_PMMIR_EL1,
		REG_MAIR_EL1,
		REG_AMAIR_EL1,
		REG_LORSA_EL1,
		REG_LOREA_EL1,
		REG_LORN_EL1,
		REG_LORC_EL1,
		REG_LORID_EL1,
		REG_MPAM1_EL1,
		REG_MPAM0_EL1,
		REG_CTRR_C_LWR_EL1,
		REG_CTRR_C_UPR_EL1,
		REG_CTRR_D_LWR_EL1,
		REG_CTRR_D_UPR_EL1,
		REG_CTRR_C_LWR_EL12,
		REG_CTRR_C_UPR_EL12,
		REG_CTRR_D_LWR_EL12,
		REG_CTRR_D_UPR_EL12,
		REG_CTRR_C_LWR_EL2,
		REG_CTRR_C_UPR_EL2,
		REG_CTRR_D_LWR_EL2,
		REG_CTRR_D_UPR_EL2,
		REG_CTRR_C_CTL_EL1,
		REG_CTRR_D_CTL_EL1,
		REG_CTRR_C_CTL_EL12,
		REG_CTRR_D_CTL_EL12,
		REG_CTRR_C_CTL_EL2,
		REG_CTRR_D_CTL_EL2,
		REG_CTXR_A_LWR_EL1,
		REG_CTXR_A_UPR_EL1,
		REG_CTXR_B_LWR_EL1,
		REG_CTXR_B_UPR_EL1,
		REG_CTXR_C_LWR_EL1,
		REG_CTXR_C_UPR_EL1,
		REG_CTXR_D_LWR_EL1,
		REG_CTXR_D_UPR_EL1,
		REG_CTXR_A_LWR_EL12,
		REG_CTXR_A_UPR_EL12,
		REG_CTXR_B_LWR_EL12,
		REG_CTXR_B_UPR_EL12,
		REG_CTXR_C_LWR_EL12,
		REG_CTXR_C_UPR_EL12,
		REG_CTXR_D_LWR_EL12,
		REG_CTXR_D_UPR_EL12,
		REG_CTXR_A_LWR_EL2,
		REG_CTXR_A_UPR_EL2,
		REG_CTXR_B_LWR_EL2,
		REG_CTXR_B_UPR_EL2,
		REG_CTXR_C_LWR_EL2,
		REG_CTXR_C_UPR_EL2,
		REG_CTXR_D_LWR_EL2,
		REG_CTXR_D_UPR_EL2,
		REG_CTXR_A_CTL_EL1,
		REG_CTXR_B_CTL_EL1,
		REG_CTXR_C_CTL_EL1,
		REG_CTXR_D_CTL_EL1,
		REG_CTXR_A_CTL_EL12,
		REG_CTXR_B_CTL_EL12,
		REG_CTXR_C_CTL_EL12,
		REG_CTXR_D_CTL_EL12,
		REG_CTXR_A_CTL_EL2,
		REG_CTXR_B_CTL_EL2,
		REG_CTXR_C_CTL_EL2,
		REG_CTXR_D_CTL_EL2,
		REG_ACC_CTRR_C_LWR_EL2,
		REG_ACC_CTRR_C_UPR_EL2,
		REG_ACC_CTRR_D_LWR_EL2,
		REG_ACC_CTRR_D_UPR_EL2,
		REG_ACC_CTXR_A_LWR_EL2,
		REG_ACC_CTXR_A_UPR_EL2,
		REG_ACC_CTXR_B_LWR_EL2,
		REG_ACC_CTXR_B_UPR_EL2,
		REG_ACC_CTXR_C_LWR_EL2,
		REG_ACC_CTXR_C_UPR_EL2,
		REG_ACC_CTXR_D_LWR_EL2,
		REG_ACC_CTXR_D_UPR_EL2,
		REG_ACC_CTRR_C_CTL_EL2,
		REG_ACC_CTRR_D_CTL_EL2,
		REG_ACC_CTXR_A_CTL_EL2,
		REG_ACC_CTXR_B_CTL_EL2,
		REG_ACC_CTXR_C_CTL_EL2,
		REG_ACC_CTXR_D_CTL_EL2,
		REG_VBAR_EL1,
		REG_RVBAR_EL1,
		REG_RMR_EL1,
		REG_ISR_EL1,
		REG_DISR_EL1,
		REG_ICV_IAR0_EL1,
		REG_ICV_EOIR0_EL1,
		REG_ICV_HPPIR0_EL1,
		REG_ICV_BPR0_EL1,
		REG_ICC_AP0R0_EL1,
		REG_ICC_AP0R1_EL1,
		REG_ICC_AP0R2_EL1,
		REG_ICC_AP0R3_EL1,
		REG_ICC_AP1R0_EL1,
		REG_ICC_AP1R1_EL1,
		REG_ICC_AP1R2_EL1,
		REG_ICC_AP1R3_EL1,
		REG_ICV_DIR_EL1,
		REG_ICV_RPR_EL1,
		REG_ICC_SGI1R_EL1,
		REG_ICC_ASGI1R_EL1,
		REG_ICC_SGI0R_EL1,
		REG_ICV_IAR1_EL1,
		REG_ICV_EOIR1_EL1,
		REG_ICV_HPPIR1_EL1,
		REG_ICV_BPR1CBPR_EL1,
		REG_ICV_CTLR_EL1,
		REG_ICC_SRE_EL1,
		REG_ICV_IGRPEN0_EL1,
		REG_ICV_IGRPEN1_EL1,
		REG_ICC_SEIEN_EL1,
		REG_CONTEXTIDR_EL1,
		REG_TPIDR_EL1,
		REG_SCXTNUM_EL1,
		REG_CNTHCTL_EL21,
		REG_HID0,
		REG_HID25,
		REG_HID26,
		REG_HID27,
		REG_HID28,
		REG_HID29,
		REG_HID34,
		REG_HID1,
		REG_HID21,
		REG_BIUVCSCUPCMDCRD,
		REG_BIUVCSCUPDATCRD,
		REG_HID2,
		REG_HID30,
		REG_HID31,
		REG_HID32,
		REG_HID33,
		REG_HID3,
		REG_BIUVCSCUPCMDCRDC2,
		REG_BIUVCSCUPDATCRDC2,
		REG_HID4,
		REG_HID5,
		REG_HID6,
		REG_HID7,
		REG_HID8,
		REG_HID9,
		REG_HID10,
		REG_BLOCK_CMAINT_CFG,
		REG_HID11,
		REG_HID18,
		REG_HID36,
		REG_HID37,
		REG_HID12,
		REG_HID15,
		REG_HID19,
		REG_BIU_TLIMIT,
		REG_HID13,
		REG_HID_RCTX_G0CTL,
		REG_HID_RCTX_G1CTL,
		REG_HID14,
		REG_HID16,
		REG_LLC_WRR2,
		REG_BIU_AFI_CFG,
		REG_HID17,
		REG_HID24,
		REG_HID35,
		REG_CCSIDR_EL1,
		REG_CLIDR_EL1,
		REG_SMIDR_EL1,
		REG_AIDR_EL1,
		REG_PMCR0_EL1,
		REG_APPL_CONTEXTPTR,
		REG_LD_LATPROF_CTL_EL1,
		REG_AON_CPU_MSTALL_CTL01_EL1,
		REG_PM_MEMFLT_CTL23_EL1,
		REG_AGTCNTHV_CTL_EL21,
		REG_AGTCNTVCTSS_NOREDIR_EL0,
		REG_PMCR1_EL1,
		REG_LD_LATPROF_CTR_EL1,
		REG_AON_CPU_MSTALL_CTL23_EL1,
		REG_PM_MEMFLT_CTL45_EL1,
		REG_AGTCNTRDIR_EL1,
		REG_AGTCNTHCTL_NOREDIR_EL21,
		REG_PMCR2_EL1,
		REG_LD_LATPROF_STS_EL1,
		REG_AON_CPU_MSTALL_CTL45_EL1,
		REG_AGTCNTHP_CVAL_EL2,
		REG_CNTVCT_NOREDIR_EL0,
		REG_AGTCNTHP_CVAL_NOREDIR_EL21,
		REG_PMCR3_EL1,
		REG_LD_LATPROF_INF_EL1,
		REG_AON_CPU_MSTALL_CTL67_EL1,
		REG_AGTCNTHP_TVAL_EL2,
		REG_CNTPCTSS_NOREDIR_EL0,
		REG_AGTCNTHP_TVAL_NOREDIR_EL21,
		REG_PMCR4_EL1,
		REG_LD_LATPROF_CTL_EL2,
		REG_AON_CPU_MEMFLT_CTL01_EL1,
		REG_AGTCNTHP_CTL_EL2,
		REG_CNTVCTSS_NOREDIR_EL0,
		REG_AGTCNTHP_CTL_NOREDIR_EL21,
		REG_PMESR0_EL1,
		REG_LD_LATPROF_CMD_EL1,
		REG_AON_CPU_MEMFLT_CTL23_EL1,
		REG_AGTCNTHV_CVAL_EL2,
		REG_AGTCNTHV_CVAL_NOREDIR_EL21,
		REG_PMESR1_EL1,
		REG_PMCR1_EL2,
		REG_AON_CPU_MEMFLT_CTL45_EL1,
		REG_AGTCNTHV_TVAL_EL2,
		REG_CNTHCTL_NOREDIR_EL21,
		REG_AGTCNTHV_TVAL_NOREDIR_EL21,
		REG_OPMAT0_EL1,
		REG_PMCR1_EL12,
		REG_AON_CPU_MEMFLT_CTL67_EL1,
		REG_AGTCNTHV_CTL_EL2,
		REG_CNTHP_CVAL_NOREDIR_EL21,
		REG_AGTCNTHV_CTL_NOREDIR_EL21,
		REG_OPMAT1_EL1,
		REG_PMCR1_GL12,
		REG_AON_CPU_MSTALL_CTR0_EL1,
		REG_AGTCNTFRQ_EL0,
		REG_CNTHP_TVAL_NOREDIR_EL21,
		REG_CNTPCT_NOREDIR_EL0,
		REG_OPMSK0_EL1,
		REG_LD_LATPROF_CTL_EL12,
		REG_AON_CPU_MSTALL_CTR1_EL1,
		REG_AGTCNTVOFF_EL2,
		REG_CNTHP_CTL_NOREDIR_EL21,
		REG_CNTHV_CTL_NOREDIR_EL21,
		REG_OPMSK1_EL1,
		REG_LD_LATPROF_INF_EL2,
		REG_AON_CPU_MSTALL_CTR2_EL1,
		REG_AGTCNTHP_CVAL_EL21,
		REG_CNTHV_CVAL_NOREDIR_EL21,
		REG_AGTCNTPCT_NOREDIR_EL0,
		REG_AON_CPU_MSTALL_CTR3_EL1,
		REG_AGTCNTHP_TVAL_EL21,
		REG_CNTHV_TVAL_NOREDIR_EL21,
		REG_VMSA_HV_LOCK_EL2,
		REG_PMSWCTRL_EL1,
		REG_PMCR5_EL0,
		REG_AON_CPU_MSTALL_CTR4_EL1,
		REG_PMCOMPARE0_EL1,
		REG_PMCOMPARE1_EL1,
		REG_VMSA_NV_LOCK_EL2,
		REG_PMSR_EL1,
		REG_AON_CPU_MSTALL_CTR5_EL1,
		REG_AGTCNTHP_CTL_EL21,
		REG_PMCOMPARE5_EL1,
		REG_PMCOMPARE6_EL1,
		REG_PMCOMPARE7_EL1,
		REG_PMCR_BVRNG4_EL1,
		REG_PM_PMI_PC,
		REG_AON_CPU_MSTALL_CTR6_EL1,
		REG_AGTCNTHV_CVAL_EL21,
		REG_AGTCNTVCT_NOREDIR_EL0,
		REG_PMCR_BVRNG5_EL1,
		REG_AON_CPU_MSTALL_CTR7_EL1,
		REG_AGTCNTHV_TVAL_EL21,
		REG_AGTCNTPCTSS_NOREDIR_EL0,
		REG_CSSELR_EL1,
		REG_PMC0,
		REG_UPMCFILTER0,
		REG_UPMCFILTER1,
		REG_UPMCFILTER2,
		REG_UPMCFILTER3,
		REG_UPMCFILTER4,
		REG_UPMCFILTER5,
		REG_UPMCFILTER6,
		REG_PMC1,
		REG_UPMCFILTER7,
		REG_PMC2,
		REG_PMC3,
		REG_PMC4,
		REG_PMC5,
		REG_PMC6,
		REG_PMC7,
		REG_PMC8,
		REG_PMC9,
		REG_PMTRHLD6_EL1,
		REG_PMTRHLD4_EL1,
		REG_PMTRHLD2_EL1,
		REG_PMMMAP_EL1,
		REG_CTR_EL0,
		REG_DCZID_EL0,
		REG_NZCV,
		REG_DAIF,
		REG_SVCR,
		REG_DIT,
		REG_SSBS,
		REG_TCO,
		REG_FPCR,
		REG_FPSR,
		REG_DSPSR,
		REG_DLR,
		REG_PMCR_EL0,
		REG_PMCNTENSET_EL0,
		REG_PMCNTENCLR_EL0,
		REG_PMOVSCLR_EL0,
		REG_PMSWINC_EL0,
		REG_PMSELR_EL0,
		REG_PMCCNTR_EL0,
		REG_PMXEVTYPER_EL0,
		REG_PMXEVCNTR_EL0,
		REG_DAIFCLR,
		REG_PMUSERENR_EL0,
		REG_PMOVSSET_EL0,
		REG_TPIDR_EL0,
		REG_TPIDRRO_EL0,
		REG_TPIDR2_EL0,
		REG_SCXTNUM_EL0,
		REG_AMCR_EL0,
		REG_AMUSERENR_EL0,
		REG_AMCNTENCLR0_EL0,
		REG_AMCNTENSET0_EL0,
		REG_AMCNTENCLR1_EL0,
		REG_AMCNTENSET1_EL0,
		REG_AMEVCNTR00_EL0,
		REG_AMEVCNTR01_EL0,
		REG_AMEVCNTR02_EL0,
		REG_AMEVCNTR03_EL0,
		REG_AMEVCNTR10_EL0,
		REG_AMEVCNTR11_EL0,
		REG_AMEVCNTR12_EL0,
		REG_AMEVCNTR13_EL0,
		REG_AMEVCNTR14_EL0,
		REG_AMEVCNTR15_EL0,
		REG_AMEVCNTR16_EL0,
		REG_AMEVCNTR17_EL0,
		REG_AMEVCNTR18_EL0,
		REG_AMEVCNTR19_EL0,
		REG_AMEVCNTR110_EL0,
		REG_AMEVCNTR111_EL0,
		REG_AMEVCNTR112_EL0,
		REG_AMEVCNTR113_EL0,
		REG_AMEVCNTR114_EL0,
		REG_AMEVCNTR115_EL0,
		REG_AMEVTYPER10_EL0,
		REG_AMEVTYPER11_EL0,
		REG_AMEVTYPER12_EL0,
		REG_AMEVTYPER13_EL0,
		REG_AMEVTYPER14_EL0,
		REG_AMEVTYPER15_EL0,
		REG_AMEVTYPER16_EL0,
		REG_AMEVTYPER17_EL0,
		REG_AMEVTYPER18_EL0,
		REG_AMEVTYPER19_EL0,
		REG_AMEVTYPER110_EL0,
		REG_AMEVTYPER111_EL0,
		REG_AMEVTYPER112_EL0,
		REG_AMEVTYPER113_EL0,
		REG_AMEVTYPER114_EL0,
		REG_AMEVTYPER115_EL0,
		REG_CNTFRQ_EL0,
		REG_CNTPCT_EL0,
		REG_CNTVCT_EL0,
		REG_CNTPCTSS_EL0,
		REG_CNTVCTSS_EL0,
		REG_CNTHP_TVAL_EL21,
		REG_CNTHP_CTL_EL21,
		REG_CNTHP_CVAL_EL21,
		REG_CNTHV_TVAL_EL21,
		REG_CNTHV_CTL_EL21,
		REG_CNTHV_CVAL_EL21,
		REG_PMEVCNTR0_EL0,
		REG_PMEVCNTR1_EL0,
		REG_PMEVCNTR2_EL0,
		REG_PMEVCNTR3_EL0,
		REG_PMEVCNTR4_EL0,
		REG_PMEVCNTR5_EL0,
		REG_PMEVCNTR6_EL0,
		REG_PMEVCNTR7_EL0,
		REG_PMEVCNTR8_EL0,
		REG_PMEVCNTR9_EL0,
		REG_PMEVCNTR10_EL0,
		REG_PMEVCNTR11_EL0,
		REG_PMEVCNTR12_EL0,
		REG_PMEVCNTR13_EL0,
		REG_PMEVCNTR14_EL0,
		REG_PMEVCNTR15_EL0,
		REG_PMEVCNTR16_EL0,
		REG_PMEVCNTR17_EL0,
		REG_PMEVCNTR18_EL0,
		REG_PMEVCNTR19_EL0,
		REG_PMEVCNTR20_EL0,
		REG_PMEVCNTR21_EL0,
		REG_PMEVCNTR22_EL0,
		REG_PMEVCNTR23_EL0,
		REG_PMEVCNTR24_EL0,
		REG_PMEVCNTR25_EL0,
		REG_PMEVCNTR26_EL0,
		REG_PMEVCNTR27_EL0,
		REG_PMEVCNTR28_EL0,
		REG_PMEVCNTR29_EL0,
		REG_PMEVCNTR30_EL0,
		REG_PMEVTYPER0_EL0,
		REG_PMEVTYPER1_EL0,
		REG_PMEVTYPER2_EL0,
		REG_PMEVTYPER3_EL0,
		REG_PMEVTYPER4_EL0,
		REG_PMEVTYPER5_EL0,
		REG_PMEVTYPER6_EL0,
		REG_PMEVTYPER7_EL0,
		REG_PMEVTYPER8_EL0,
		REG_PMEVTYPER9_EL0,
		REG_PMEVTYPER10_EL0,
		REG_PMEVTYPER11_EL0,
		REG_PMEVTYPER12_EL0,
		REG_PMEVTYPER13_EL0,
		REG_PMEVTYPER14_EL0,
		REG_PMEVTYPER15_EL0,
		REG_PMEVTYPER16_EL0,
		REG_PMEVTYPER17_EL0,
		REG_PMEVTYPER18_EL0,
		REG_PMEVTYPER19_EL0,
		REG_PMEVTYPER20_EL0,
		REG_PMEVTYPER21_EL0,
		REG_PMEVTYPER22_EL0,
		REG_PMEVTYPER23_EL0,
		REG_PMEVTYPER24_EL0,
		REG_PMEVTYPER25_EL0,
		REG_PMEVTYPER26_EL0,
		REG_PMEVTYPER27_EL0,
		REG_PMEVTYPER28_EL0,
		REG_PMEVTYPER29_EL0,
		REG_PMEVTYPER30_EL0,
		REG_PMCCFILTR_EL0,
		REG_LSU_ERR_STS,
		REG_AFLATCTL1_EL1,
		REG_AFLATVALBIN0_EL1,
		REG_AFLATINFLO_EL1,
		REG_LSU_ERR_CTL,
		REG_AFLATCTL2_EL1,
		REG_AFLATVALBIN1_EL1,
		REG_AFLATINFHI_EL1,
		REG_AFLATCTL3_EL1,
		REG_AFLATVALBIN2_EL1,
		REG_AFLATCTL4_EL1,
		REG_AFLATVALBIN3_EL1,
		REG_LLC_FILL_CTL,
		REG_AFLATCTL5_LO_EL1,
		REG_AFLATVALBIN4_EL1,
		REG_AFLATCTL5_HI_EL1,
		REG_LLC_FILL_DAT,
		REG_AFLATVALBIN5_EL1,
		REG_AFLATVALBIN6_EL1,
		REG_LLC_RAM_CONFIG,
		REG_AFLATVALBIN7_EL1,
		REG_LLC_ERR_STS,
		REG_CMAINT_BCAST_LIST_0,
		REG_CMAINT_BCAST_LIST_1,
		REG_CMAINT_BCAST_CTL,
		REG_LLC_ERR_ADR,
		REG_LLC_ERR_CTL,
		REG_LLC_ERR_INJ,
		REG_LLC_ERR_INF,
		REG_USERTAGSEL_EL1,
		REG_UUSERTAG_EL0,
		REG_KUSERTAG_EL1,
		REG_HUSERTAG_EL2,
		REG_LLC_TRACE_CTL0,
		REG_LLC_TRACE_CTL1,
		REG_LLC_UP_REQ_VC,
		REG_LLC_UP_REQ_VC_THRESH,
		REG_LLC_UP_REQ_VC_2,
		REG_LLC_UP_REQ_VC_THRESH_2,
		REG_LLC_DRAM_HASH0,
		REG_LLC_DRAM_HASH1,
		REG_LLC_DRAM_HASH2,
		REG_LLC_DRAM_HASH3,
		REG_LLC_TRACE_CTL2,
		REG_LLC_DRAM_HASH4,
		REG_LLC_UP_REQ_VC_3,
		REG_LLC_UP_REQ_VC_THRESH_3,
		REG_LLC_UP_REQ_VC_4,
		REG_LLC_UP_REQ_VC_THRESH_4,
		REG_LLC_HASH0,
		REG_LLC_HASH1,
		REG_LLC_HASH2,
		REG_LLC_HASH3,
		REG_LLC_WRR,
		REG_LLC_DRAM_HASH5,
		REG_LLC_DRAM_HASH6,
		REG_VPIDR_EL2,
		REG_VMPIDR_EL2,
		REG_SCTLR_EL2,
		REG_ACTLR_EL2,
		REG_HCR_EL2,
		REG_MDCR_EL2,
		REG_CPTR_EL2,
		REG_HSTR_EL2,
		REG_HFGRTR_EL2,
		REG_HFGWTR_EL2,
		REG_HFGITR_EL2,
		REG_HACR_EL2,
		REG_TRFCR_EL2,
		REG_HCRX_EL2,
		REG_SMPRIMAP_EL2,
		REG_SMCR_EL2,
		REG_SDER32_EL2,
		REG_TTBR0_EL2,
		REG_TTBR1_EL2,
		REG_TCR_EL2,
		REG_VTTBR_EL2,
		REG_VTCR_EL2,
		REG_VNCR_EL2,
		REG_VSTTBR_EL2,
		REG_VSTCR_EL2,
		REG_DACR32_EL2,
		REG_HDFGRTR_EL2,
		REG_HDFGWTR_EL2,
		REG_SPSR_EL2,
		REG_ELR_EL2,
		REG_SP_EL1,
		REG_SPSR_IRQ,
		REG_SPSR_ABT,
		REG_SPSR_UND,
		REG_SPSR_FIQ,
		REG_IFSR32_EL2,
		REG_AFSR0_EL2,
		REG_AFSR1_EL2,
		REG_ESR_EL2,
		REG_VSESR_EL2,
		REG_FPEXC32_EL2,
		REG_TFSR_EL2,
		REG_FAR_EL2,
		REG_HPFAR_EL2,
		REG_PMSCR_EL2,
		REG_MAIR_EL2,
		REG_AMAIR_EL2,
		REG_MPAMHCR_EL2,
		REG_MPAMVPMV_EL2,
		REG_MPAM2_EL2,
		REG_MPAMVPM0_EL2,
		REG_MPAMVPM1_EL2,
		REG_MPAMVPM2_EL2,
		REG_MPAMVPM3_EL2,
		REG_MPAMVPM4_EL2,
		REG_MPAMVPM5_EL2,
		REG_MPAMVPM6_EL2,
		REG_MPAMVPM7_EL2,
		REG_VBAR_EL2,
		REG_RVBAR_EL2,
		REG_RMR_EL2,
		REG_VDISR_EL2,
		REG_ICH_AP0R0_EL2,
		REG_ICH_AP0R1_EL2,
		REG_ICH_AP0R2_EL2,
		REG_ICH_AP0R3_EL2,
		REG_ICH_AP1R0_EL2,
		REG_ICH_AP1R1_EL2,
		REG_ICH_AP1R2_EL2,
		REG_ICH_AP1R3_EL2,
		REG_ICH_VSEIR_EL2,
		REG_ICC_SRE_EL2,
		REG_ICH_HCR_EL2,
		REG_ICH_VTR_EL2,
		REG_ICH_MISR_EL2,
		REG_ICH_EISR_EL2,
		REG_ICH_ELRSR_EL2,
		REG_ICH_VMCR_EL2,
		REG_ICH_LR0_EL2,
		REG_ICH_LR1_EL2,
		REG_ICH_LR2_EL2,
		REG_ICH_LR3_EL2,
		REG_ICH_LR4_EL2,
		REG_ICH_LR5_EL2,
		REG_ICH_LR6_EL2,
		REG_ICH_LR7_EL2,
		REG_ICH_LR8_EL2,
		REG_ICH_LR9_EL2,
		REG_ICH_LR10_EL2,
		REG_ICH_LR11_EL2,
		REG_ICH_LR12_EL2,
		REG_ICH_LR13_EL2,
		REG_ICH_LR14_EL2,
		REG_ICH_LR15_EL2,
		REG_CONTEXTIDR_EL2,
		REG_TPIDR_EL2,
		REG_SCXTNUM_EL2,
		REG_CNTVOFF_EL2,
		REG_CNTHCTL_EL2,
		REG_CNTHP_TVAL_EL2,
		REG_CNTHP_CTL_EL2,
		REG_CNTHP_CVAL_EL2,
		REG_CNTHV_TVAL_EL2,
		REG_CNTHV_CTL_EL2,
		REG_CNTHV_CVAL_EL2,
		REG_CNTHVS_TVAL_EL2,
		REG_CNTHVS_CTL_EL2,
		REG_CNTHVS_CVAL_EL2,
		REG_CNTHPS_TVAL_EL2,
		REG_CNTHPS_CTL_EL2,
		REG_CNTHPS_CVAL_EL2,
		REG_FED_ERR_STS,
		REG_FED_ERR_CTL,
		REG_APCTL_EL1,
		REG_KERNKEYLO_EL1,
		REG_KERNKEYHI_EL1,
		REG_VMSALOCK_EL21,
		REG_AMX_STATE_T_EL1,
		REG_AMX_CONFIG_EL1,
		REG_VMSA_LOCK_EL2,
		REG_CTRR_B_UPR_EL1,
		REG_CTRR_B_LWR_EL1,
		REG_SP_SETUP_GL1,
		REG_SP_SETUP_GL2,
		REG_CTRR_B_CTL_EL1,
		REG_CTRR_A_LWR_EL1,
		REG_CTRR_A_UPR_EL1,
		REG_CTRR_A_CTL_EL1,
		REG_VMSA_LOCK_EL12,
		REG_AGTCNTV_CTL_EL02,
		REG_AMX_STATE_EL1,
		REG_AMX_STATUS_EL1,
		REG_AGTCNTP_CVAL_EL02,
		REG_REDIR_ACNTP_TVAL_EL02,
		REG_AGTCNTP_CTL_EL02,
		REG_AGTCNTV_CVAL_EL02,
		REG_AGTCNTV_TVAL_EL02,
		REG_AMX_CONFIG_EL12,
		REG_AMX_CONFIG_EL2,
		REG_SPRR_HUPERM_EL0,
		REG_SPRR_VUPERM_EL0,
		REG_CTRR_A_CTL_EL2,
		REG_CTRR_B_CTL_EL2,
		REG_CTRR_A_LWR_EL2,
		REG_CTRR_A_UPR_EL2,
		REG_CTRR_B_LWR_EL2,
		REG_CTRR_B_UPR_EL2,
		REG_SPRR_HUMPRR_EL2,
		REG_SPRR_HUPERM_SH01_EL2,
		REG_SPRR_HUPERM_SH02_EL2,
		REG_SPRR_HUPERM_SH03_EL2,
		REG_SPRR_HUPERM_SH04_EL2,
		REG_SPRR_HUPERM_SH05_EL2,
		REG_SPRR_HUPERM_SH06_EL2,
		REG_SPRR_HUPERM_SH07_EL2,
		REG_SPRR_VUMPRR_EL1,
		REG_SPRR_VUPERM_SH01_EL1,
		REG_SPRR_VUPERM_SH02_EL1,
		REG_SPRR_VUPERM_SH03_EL1,
		REG_SPRR_VUPERM_SH04_EL1,
		REG_SPRR_VUPERM_SH05_EL1,
		REG_SPRR_VUPERM_SH06_EL1,
		REG_SPRR_VUPERM_SH07_EL1,
		REG_CTRR_A_LWR_EL12,
		REG_CTRR_A_UPR_EL12,
		REG_CTRR_B_LWR_EL12,
		REG_CTRR_B_UPR_EL12,
		REG_CTRR_A_CTL_EL12,
		REG_CTRR_B_CTL_EL12,
		REG_AGTCNTHCTL_EL21,
		REG_AGTCNTKCTL_EL12,
		REG_PREDAKEYLO_EL1,
		REG_PREDAKEYHI_EL1,
		REG_PREDBKEYLO_EL1,
		REG_PREDBKEYHI_EL1,
		REG_SIQ_CFG_EL1,
		REG_AGTCNTPCTSS_EL0,
		REG_AGTCNTVCTSS_EL0,
		REG_AVNCR_EL2,
		REG_ACC_CTRR_A_LWR_EL2,
		REG_ACC_CTRR_A_UPR_EL2,
		REG_ACC_CTRR_B_LWR_EL2,
		REG_ACC_CTRR_B_UPR_EL2,
		REG_ACC_CTRR_A_CTL_EL2,
		REG_ACC_CTRR_B_CTL_EL2,
		REG_AGTCNTPCT_EL0,
		REG_AGTCNTVCT_EL0,
		REG_ACFG_EL1,
		REG_AHCR_EL2,
		REG_APL_INTSTATUS_EL1,
		REG_APL_INTSTATUS_EL2,
		REG_AGTCNTHCTL_EL2,
		REG_JAPIAKEYLO_EL2,
		REG_JAPIAKEYHI_EL2,
		REG_JAPIBKEYLO_EL2,
		REG_JAPIBKEYHI_EL2,
		REG_JAPIAKEYLO_EL1,
		REG_JAPIAKEYHI_EL1,
		REG_JAPIBKEYLO_EL1,
		REG_JAPIBKEYHI_EL1,
		REG_JAPIAKEYLO_EL12,
		REG_JAPIAKEYHI_EL12,
		REG_JAPIBKEYLO_EL12,
		REG_JAPIBKEYHI_EL12,
		REG_AGTCNTRDIR_EL2,
		REG_AGTCNTRDIR_EL12,
		REG_JRANGE_EL2,
		REG_JRANGE_EL1,
		REG_JRANGE_EL12,
		REG_JCTL_EL2,
		REG_JCTL_EL1,
		REG_JCTL_EL12,
		REG_JCTL_EL0,
		REG_AMDSCR_EL1,
		REG_SCTLR_EL12,
		REG_ACTLR_EL12,
		REG_CPACR_EL12,
		REG_TRFCR_EL12,
		REG_SMCR_EL12,
		REG_TTBR0_EL12,
		REG_TTBR1_EL12,
		REG_TCR_EL12,
		REG_SPSR_EL12,
		REG_ELR_EL12,
		REG_AFSR0_EL12,
		REG_AFSR1_EL12,
		REG_ESR_EL12,
		REG_TFSR_EL12,
		REG_FAR_EL12,
		REG_PMSCR_EL12,
		REG_MAIR_EL12,
		REG_AMAIR_EL12,
		REG_MPAM1_EL12,
		REG_VBAR_EL12,
		REG_CONTEXTIDR_EL12,
		REG_SCXTNUM_EL12,
		REG_CNTKCTL_EL12,
		REG_CNTP_TVAL_EL02,
		REG_CNTP_CTL_EL02,
		REG_CNTP_CVAL_EL02,
		REG_CNTV_TVAL_EL02,
		REG_CNTV_CTL_EL02,
		REG_CNTV_CVAL_EL02,
		REG_IPI_RR_LOCAL_EL1,
		REG_IPI_RR_GLOBAL_EL1,
		REG_AF_ERR_CFG0,
		REG_AP_ERR_CFG0,
		REG_AF_ERR_SRC_IDS,
		REG_DPC_ERR_STS,
		REG_DPC_ERR_CTL,
		REG_PROD_TRC_CORE_CFG_EL1,
		REG_TRACE_CORE_CFG,
		REG_IPI_SR,
		REG_APL_LRTMR_EL2,
		REG_APL_INTENABLE_EL2,
		REG_KTRACE_MESSAGE,
		REG_TRACE_CORE_CFG_EXT,
		REG_PROD_TRC_CORE_CFG_EL2,
		REG_HID_PROD_TRC_CORE_CFG_EL1,
		REG_DBG_WRAP_GLB,
		REG_TRACE_STREAM_BASE,
		REG_TRACE_STREAM_FILL,
		REG_TRACE_STREAM_BASE1,
		REG_TRACE_STREAM_FILL1,
		REG_TRACE_STREAM_IRQ,
		REG_WATCHDOGDIAG0,
		REG_WATCHDOGDIAG1,
		REG_TRACE_AUX_CTL,
		REG_IPI_CR,
		REG_UTRIG_EVENT,
		REG_HID_PROD_TRC_MASK_EL1,
		REG_TRACE_CTL,
		REG_TRACE_DAT,
		REG_PROD_TRC_STRM_BASE0_GL2,
		REG_PROD_TRC_STRM_BASE1_GL2,
		REG_CPU_CFG,
		REG_PBLK_STS,
		REG_PROD_TRC_CTL_EL1,
		REG_PROD_TRC_STRM_BASE0_GL1,
		REG_PROD_TRC_STRM_BASE1_GL1,
		REG_PROD_TRC_STRM_FIQ_EL1,
		REG_CPU_OVRD,
		REG_PBLK_EXE_ST,
		REG_PROD_TRC_CORE_GL_CTL_GL1,
		REG_PROD_TRC_CORE_GL_CTL_GL2,
		REG_ACC_OVRD,
		REG_ACC_OVRD1,
		REG_CPM_PWRDN_CTL,
		REG_PROD_TRC_BUF_RESTORE0_GL1,
		REG_PROD_TRC_BUF_RESTORE1_GL1,
		REG_PROD_TRC_EN_GL1,
		REG_PRE_LLCFLUSH_TMR,
		REG_BIUINTFCTL_CFG,
		REG_BIUINTFWRR_CFG,
		REG_PRE_TD_TMR,
		REG_ACC_SLP_WAKE_UP_TMR,
		REG_PBLK_PSW_DLY,
		REG_CPU_STS,
		REG_HIST_TRIG,
		REG_PROD_TRC_BUF_RESTORE0_GL2,
		REG_PROD_TRC_BUF_RESTORE1_GL2,
		REG_PROD_TRC_STRM_FILL0_EL1,
		REG_PROD_TRC_STRM_FILL1_EL1,
		REG_ARRAY_INDEX,
		REG_PROD_TRC_CTL_EL2,
		REG_PROD_TRC_EN_GL2,
		REG_PROD_TRC_STRM_FIQ_EL2,
		REG_PROD_TRC_CPMU_DUMP_TRIG_EL1,
		REG_PROD_LOSS_COUNT_EL1,
		REG_SW_TRACE_DATA_EL0,
		REG_IL1_DATA0,
		REG_IL1_DATA1,
		REG_DL1_DATA0,
		REG_DL1_DATA1,
		REG_MMUDATA0,
		REG_MMUDATA1,
		REG_DL1_DATA2,
		REG_IL1_DATA2,
		REG_LLC_DATA0,
		REG_LLC_DATA1,
		REG_SCTLR_EL3,
		REG_ACTLR_EL3,
		REG_SCR_EL3,
		REG_SDER32_EL3,
		REG_CPTR_EL3,
		REG_MDCR_EL3,
		REG_TTBR0_EL3,
		REG_TCR_EL3,
		REG_SPSR_EL3,
		REG_ELR_EL3,
		REG_SP_EL2,
		REG_AFSR0_EL3,
		REG_AFSR1_EL3,
		REG_ESR_EL3,
		REG_TFSR_EL3,
		REG_FAR_EL3,
		REG_MAIR_EL3,
		REG_AMAIR_EL3,
		REG_MPAM3_EL3,
		REG_VBAR_EL3,
		REG_RVBAR_EL3,
		REG_RMR_EL3,
		REG_ICC_CTLR_EL3,
		REG_ICC_SRE_EL3,
		REG_ICC_IGRPEN1_EL3,
		REG_TPIDR_EL3,
		REG_SCXTNUM_EL3,
		REG_MMU_ERR_STS,
		REG_AFSR1_GL1,
		REG_AFSR1_GL2,
		REG_AFSR1_GL12,
		REG_BP_OBJC_ADR_EL1,
		REG_BP_OBJC_CTL_EL1,
		REG_SP_GL11,
		REG_MMU_SESR_EL2,
		REG_SPRR_CONFIG_EL1,
		REG_HPFAR_GL2,
		REG_GXF_CONFIG_EL1,
		REG_AMRANGE_EL21,
		REG_GXF_CONFIG_EL2,
		REG_SPRR_UPERM_EL0,
		REG_SPRR_PPERM_EL1,
		REG_SPRR_PPERM_EL2,
		REG_APGAKEYLO_EL12,
		REG_APGAKEYHI_EL12,
		REG_KERNKEYLO_EL12,
		REG_KERNKEYHI_EL12,
		REG_AFPCR_EL0,
		REG_SP_GL22,
		REG_AMXIDR_EL1,
		REG_SPRR_HUMPRR_EL21,
		REG_SPRR_PMPRR_EL1,
		REG_SPRR_PMPRR_EL2,
		REG_SPRR_HUPERM_SH01_EL21,
		REG_SPRR_HUPERM_SH02_EL21,
		REG_SPRR_HUPERM_SH03_EL21,
		REG_SPRR_HUPERM_SH04_EL21,
		REG_SPRR_HUPERM_SH05_EL21,
		REG_SPRR_HUPERM_SH06_EL21,
		REG_SPRR_HUPERM_SH07_EL21,
		REG_SPRR_PPERM_SH01_EL1,
		REG_SPRR_PPERM_SH02_EL1,
		REG_SPRR_PPERM_SH03_EL1,
		REG_SPRR_PPERM_SH04_EL1,
		REG_SPRR_PPERM_SH05_EL1,
		REG_SPRR_PPERM_SH06_EL1,
		REG_SPRR_PPERM_SH07_EL1,
		REG_SPRR_PPERM_SH01_EL2,
		REG_SPRR_PPERM_SH02_EL2,
		REG_SPRR_PPERM_SH03_EL2,
		REG_SPRR_PPERM_SH04_EL2,
		REG_SPRR_PPERM_SH05_EL2,
		REG_SPRR_PPERM_SH06_EL2,
		REG_SPRR_PPERM_SH07_EL2,
		REG_SPRR_PMPRR_EL12,
		REG_SPRR_PPERM_SH01_EL12,
		REG_SPRR_PPERM_SH02_EL12,
		REG_SPRR_PPERM_SH03_EL12,
		REG_SPRR_PPERM_SH04_EL12,
		REG_SPRR_PPERM_SH05_EL12,
		REG_SPRR_PPERM_SH06_EL12,
		REG_SPRR_PPERM_SH07_EL12,
		REG_APIAKEYLO_EL12,
		REG_APIAKEYHI_EL12,
		REG_APIBKEYLO_EL12,
		REG_APIBKEYHI_EL12,
		REG_APDAKEYLO_EL12,
		REG_APDAKEYHI_EL12,
		REG_APDBKEYLO_EL12,
		REG_APDBKEYHI_EL12,
		REG_CURRENTG,
		REG_GXF_ENTRY_EL1,
		REG_GXF_PABENTRY_EL1,
		REG_ASPSR_EL1,
		REG_ADSPSR_EL0,
		REG_PMCR1_GL2,
		REG_ASPSR_EL2,
		REG_PMCR1_GL1,
		REG_VBAR_GL12,
		REG_SPSR_GL12,
		REG_ASPSR_GL12,
		REG_ESR_GL12,
		REG_ELR_GL12,
		REG_FAR_GL12,
		REG_SP_GL1,
		REG_TPIDR_GL1,
		REG_VBAR_GL1,
		REG_SPSR_GL1,
		REG_ASPSR_GL1,
		REG_ESR_GL1,
		REG_ELR_GL1,
		REG_FAR_GL1,
		REG_SP_GL2,
		REG_TPIDR_GL2,
		REG_VBAR_GL2,
		REG_SPSR_GL2,
		REG_ASPSR_GL2,
		REG_ESR_GL2,
		REG_ELR_GL2,
		REG_FAR_GL2,
		REG_GXF_ENTRY_EL2,
		REG_GXF_PABENTRY_EL2,
		REG_APCTL_EL2,
		REG_APSTS_EL2,
		REG_APSTS_EL1,
		REG_KERNKEYLO_EL2,
		REG_KERNKEYHI_EL2,
		REG_ASPSR_EL12,
		REG_APIAKEYLO_EL2,
		REG_APIAKEYHI_EL2,
		REG_APIBKEYLO_EL2,
		REG_APIBKEYHI_EL2,
		REG_APDAKEYLO_EL2,
		REG_APDAKEYHI_EL2,
		REG_APDBKEYLO_EL2,
		REG_APDBKEYHI_EL2,
		REG_APGAKEYLO_EL2,
		REG_APGAKEYHI_EL2,
		REG_SPRR_CONFIG_EL2,
		REG_SPRR_AMRANGE_EL2,
		REG_VMKEYLO_EL2,
		REG_VMKEYHI_EL2,
		REG_MMU_SFAR_EL2,
		REG_APSTS_EL12,
		REG_APCTL_EL12,
		REG_GXF_CONFIG_EL12,
		REG_GXF_ENTRY_EL12,
		REG_GXF_PABENTRY_EL12,
		REG_SPRR_CONFIG_EL12,
		REG_SPRR_AMRANGE_EL12,
		REG_MMU_SESR_CTL_EL2,
		REG_SPRR_PPERM_EL12,
		REG_CNTPS_TVAL_EL1,
		REG_CNTPS_CTL_EL1,
		REG_CNTPS_CVAL_EL1,
		REG_PSTATE_SPSEL,
		REG_PWRDNSAVE0,
		REG_NRG_ACC_CTL,
		REG_AON_CNT0,
		REG_CPU_CNT0,
		REG_UPMCR0_EL1,
		REG_UPMC8,
		REG_AON_CNT8,
		REG_PWRDNSAVE1,
		REG_CORE_NRG_ACC_DAT,
		REG_AON_CNT_CTL0,
		REG_CPU_CNT_CTL0,
		REG_UPMESR0_EL1,
		REG_UPMC9,
		REG_AON_CNT_CTL8,
		REG_ACC_PWR_DN_SAVE,
		REG_CPM_NRG_ACC_DAT,
		REG_AON_CNT1,
		REG_CPU_CNT1,
		REG_UPMSWCTRL_EL1,
		REG_UPMC10,
		REG_AON_CNT9,
		REG_CORE_SRM_NRG_ACC_DAT,
		REG_AON_CNT_CTL1,
		REG_CPU_CNT_CTL1,
		REG_UPMECM0_EL1,
		REG_UPMC11,
		REG_AON_CNT_CTL9,
		REG_AON_CNT_CTL,
		REG_CPM_SRM_NRG_ACC_DAT,
		REG_AON_CNT2,
		REG_CPU_CNT2,
		REG_UPMECM1_EL1,
		REG_UPMC12,
		REG_AON_CNT10,
		REG_CPU_CNT_CTL,
		REG_AON_CNT_CTL2,
		REG_CPU_CNT_CTL2,
		REG_UPMPCM_EL1,
		REG_UPMC13,
		REG_AON_CNT_CTL10,
		REG_AON_CNT3,
		REG_CPU_CNT3,
		REG_UPMSR_EL1,
		REG_UPMC14,
		REG_AON_CNT11,
		REG_AON_CNT_CTL3,
		REG_CPU_CNT_CTL3,
		REG_UPMC0,
		REG_UPMC15,
		REG_AON_CNT_CTL11,
		REG_AON_CNT4,
		REG_CPU_CNT4,
		REG_UPMC1,
		REG_UPMECM2_EL1,
		REG_AON_CNT_CTL4,
		REG_CPU_CNT_CTL4,
		REG_UPMC2,
		REG_UPMECM3_EL1,
		REG_AON_CNT5,
		REG_CPU_CNT5,
		REG_UPMC3,
		REG_UPMCR1_EL1,
		REG_AON_CNT_CTL5,
		REG_CPU_CNT_CTL5,
		REG_UPMC4,
		REG_UPMESR1_EL1,
		REG_AON_CNT6,
		REG_CPU_CNT6,
		REG_UPMC5,
		REG_AON_CNT_CTL6,
		REG_CPU_CNT_CTL6,
		REG_UPMC6,
		REG_AON_CNT7,
		REG_CPU_CNT7,
		REG_UPMC7,
		REG_AON_CNT_CTL7,
		REG_CPU_CNT_CTL7,
	};
	return system_regs;
}

