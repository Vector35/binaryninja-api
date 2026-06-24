// Copyright (c) 2025. Battelle Energy Alliance, LLC
// ALL RIGHTS RESERVED

#include "util.h"

#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "conditions.h"
#include "instructions.h"
#include "registers.h"

namespace BN = BinaryNinja;

#define ITEXT(m)                            \
  result.emplace_back(InstructionToken, m); \
  result.emplace_back(TextToken, " ");

namespace C166 {
namespace {
struct SfrRegister {
  uint32_t addr;
  uint32_t reg;
  const char* name;
};

constexpr SfrRegister kSfrRegisters[] = {
    {0xF000, 0xF000, "qx0"}, {0xF002, 0xF002, "qx1"},
    {0xF004, 0xF004, "qr0"}, {0xF006, 0xF006, "qr1"},
    {0xF00C, 0xF00C, "cpuid"}, {0xF050, 0xF050, "cc2_t7"},
    {0xF052, 0xF052, "cc2_t8"}, {0xF054, 0xF054, "cc2_t7rel"},
    {0xF056, 0xF056, "cc2_t8rel"}, {0xF05A, 0xF05A, "ssc1_tb"},
    {0xF05C, 0xF05C, "ssc1_rb"}, {0xF05E, 0xF05E, "ssc1_br"},
    {0xF060, 0xF060, "cc1_pisel"}, {0xF062, 0xF062, "cc1_ioc"},
    {0xF064, 0xF064, "cc2_pisel"}, {0xF066, 0xF066, "cc2_ioc"},
    {0xF068, 0xF068, "comdata"}, {0xF06A, 0xF06A, "rwdata"},
    {0xF06C, 0xF06C, "iosr"}, {0xF070, 0xF070, "idrt"},
    {0xF076, 0xF076, "idmem2"}, {0xF078, 0xF078, "idprog"},
    {0xF07A, 0xF07A, "idmem"}, {0xF07C, 0xF07C, "idchip"},
    {0xF07E, 0xF07E, "idmanuf"}, {0xF080, 0xF080, "pocon0l"},
    {0xF082, 0xF082, "pocon0h"}, {0xF084, 0xF084, "pocon1l"},
    {0xF086, 0xF086, "pocon1h"}, {0xF088, 0xF088, "pocon2"},
    {0xF08A, 0xF08A, "pocon3"}, {0xF08C, 0xF08C, "pocon4"},
    {0xF08E, 0xF08E, "pocon6"}, {0xF090, 0xF090, "pocon7"},
    {0xF094, 0xF094, "pocon9"}, {0xF09C, 0xF09C, "adc_ctr2"},
    {0xF09E, 0xF09E, "adc_ctr2in"}, {0xF0A0, 0xF0A0, "adc_dat2"},
    {0xF0A4, 0xF0A4, "asc1_txfcon"}, {0xF0A6, 0xF0A6, "asc1_rxfcon"},
    {0xF0AA, 0xF0AA, "pocon20"}, {0xF0B0, 0xF0B0, "ssc0_tb"},
    {0xF0B2, 0xF0B2, "ssc0_rb"}, {0xF0B4, 0xF0B4, "ssc0_br"},
    {0xF0B8, 0xF0B8, "asc0_abstat"}, {0xF0BA, 0xF0BA, "asc0_fstat"},
    {0xF0BC, 0xF0BC, "asc1_abstat"}, {0xF0BE, 0xF0BE, "asc1_fstat"},
    {0xF0C0, 0xF0C0, "scuslc"}, {0xF0C2, 0xF0C2, "scusls"},
    {0xF0C4, 0xF0C4, "asc0_txfcon"}, {0xF0C6, 0xF0C6, "asc0_rxfcon"},
    {0xF0CC, 0xF0CC, "rtc_rell"}, {0xF0CE, 0xF0CE, "rtc_relh"},
    {0xF0D0, 0xF0D0, "rtc_t14rel"}, {0xF0D2, 0xF0D2, "rtc_t14"},
    {0xF0D4, 0xF0D4, "rtc_rtcl"}, {0xF0D6, 0xF0D6, "rtc_rtch"},
    {0xF0D8, 0xF0D8, "dtidr"}, {0xF0EC, 0xF0EC, "dcmpsp"},
    {0xF0EE, 0xF0EE, "dcmpdp"}, {0xF0F0, 0xF0F0, "dtrevt"},
    {0xF0F2, 0xF0F2, "dexevt"}, {0xF0F4, 0xF0F4, "dswevt"},
    {0xF0F8, 0xF0F8, "cmadr"}, {0xF0FA, 0xF0FA, "cmctr"},
    {0xF0FC, 0xF0FC, "dbgsr"}, {0xF0FE, 0xF0FE, "imbctr"},
    {0xF100, 0xF100, "dp0l"}, {0xF102, 0xF102, "dp0h"},
    {0xF104, 0xF104, "dp1l"}, {0xF106, 0xF106, "dp1h"},
    {0xF108, 0xF108, "rstcfg"}, {0xF10C, 0xF10C, "rtc_isnc"},
    {0xF10E, 0xF10E, "rtc_isnch"}, {0xF110, 0xF110, "rtc_con"},
    {0xF112, 0xF112, "rtc_conh"}, {0xF120, 0xF120, "altsel0p1h"},
    {0xF122, 0xF122, "altsel0p2"}, {0xF126, 0xF126, "altsel0p3"},
    {0xF128, 0xF128, "altsel1p3"}, {0xF12A, 0xF12A, "altsel0p4"},
    {0xF12C, 0xF12C, "altsel0p6"}, {0xF130, 0xF130, "altsel0p1l"},
    {0xF136, 0xF136, "altsel1p4"}, {0xF138, 0xF138, "altsel0p9"},
    {0xF13A, 0xF13A, "altsel1p9"}, {0xF13C, 0xF13C, "altsel0p7"},
    {0xF13E, 0xF13E, "altsel1p7"}, {0xF140, 0xF140, "ccu6_ic"},
    {0xF142, 0xF142, "can_1ic"}, {0xF144, 0xF144, "can_2ic"},
    {0xF146, 0xF146, "can_3ic"}, {0xF148, 0xF148, "can_4ic"},
    {0xF14A, 0xF14A, "can_5ic"}, {0xF14C, 0xF14C, "can_6ic"},
    {0xF14E, 0xF14E, "can_7ic"}, {0xF150, 0xF150, "asc1_tbic"},
    {0xF15C, 0xF15C, "asc0_abic"}, {0xF160, 0xF160, "cc2_cc16ic"},
    {0xF162, 0xF162, "cc2_cc17ic"}, {0xF164, 0xF164, "cc2_cc18ic"},
    {0xF166, 0xF166, "cc2_cc19ic"}, {0xF168, 0xF168, "cc2_cc20ic"},
    {0xF16A, 0xF16A, "cc2_cc21ic"}, {0xF16C, 0xF16C, "cc2_cc22ic"},
    {0xF16E, 0xF16E, "cc2_cc23ic"}, {0xF170, 0xF170, "cc2_cc24ic"},
    {0xF172, 0xF172, "cc2_cc25ic"}, {0xF174, 0xF174, "cc2_cc26ic"},
    {0xF176, 0xF176, "cc2_cc27ic"}, {0xF178, 0xF178, "cc2_cc28ic"},
    {0xF17A, 0xF17A, "cc2_t7ic"}, {0xF17C, 0xF17C, "cc2_t8ic"},
    {0xF180, 0xF180, "eopic"}, {0xF182, 0xF182, "asc1_tic"},
    {0xF184, 0xF184, "cc2_cc29ic"}, {0xF186, 0xF186, "iic_dic"},
    {0xF188, 0xF188, "ccu6_eic"}, {0xF18A, 0xF18A, "asc1_ric"},
    {0xF18C, 0xF18C, "cc2_cc30ic"}, {0xF18E, 0xF18E, "iic_peic"},
    {0xF190, 0xF190, "ccu6_t12ic"}, {0xF192, 0xF192, "asc1_eic"},
    {0xF194, 0xF194, "cc2_cc31ic"}, {0xF196, 0xF196, "can_0ic"},
    {0xF198, 0xF198, "ccu6_t13ic"}, {0xF19A, 0xF19A, "sdlm_ic"},
    {0xF19C, 0xF19C, "asc0_tbic"}, {0xF19E, 0xF19E, "pllic"},
    {0xF1A0, 0xF1A0, "rtc_ic"}, {0xF1AA, 0xF1AA, "ssc1_tic"},
    {0xF1AC, 0xF1AC, "ssc1_ric"}, {0xF1AE, 0xF1AE, "ssc1_eic"},
    {0xF1B8, 0xF1B8, "asc0_abcon"}, {0xF1BA, 0xF1BA, "asc1_abic"},
    {0xF1BC, 0xF1BC, "asc1_abcon"}, {0xF1BE, 0xF1BE, "syscon0"},
    {0xF1C0, 0xF1C0, "exicon"}, {0xF1C2, 0xF1C2, "odp2"},
    {0xF1C4, 0xF1C4, "picon"}, {0xF1C6, 0xF1C6, "odp3"},
    {0xF1CA, 0xF1CA, "odp4"}, {0xF1CE, 0xF1CE, "odp6"},
    {0xF1D0, 0xF1D0, "pllcon"}, {0xF1D2, 0xF1D2, "odp7"},
    {0xF1D4, 0xF1D4, "syscon3"}, {0xF1D8, 0xF1D8, "exisel1"},
    {0xF1DA, 0xF1DA, "exisel0"}, {0xF1DC, 0xF1DC, "syscon1"},
    {0xFE00, Registers::DPP0, "dpp0"}, {0xFE02, Registers::DPP1, "dpp1"},
    {0xFE04, Registers::DPP2, "dpp2"}, {0xFE06, Registers::DPP3, "dpp3"},
    {0xFE08, Registers::CSP, "csp"}, {0xFE0A, 0xFE0A, "emucon"},
    {0xFE0C, 0xFE0C, "mdh"}, {0xFE0E, 0xFE0E, "mdl"},
    {0xFE10, Registers::CP, "cp"}, {0xFE12, 0xFE12, "sp"},
    {0xFE14, 0xFE14, "stkov"}, {0xFE16, 0xFE16, "stkun"},
    {0xFE18, Registers::CPUCON1, "cpucon1"}, {0xFE1A, Registers::CPUCON2, "cpucon2"},
    {0xFE28, 0xFE28, "cc2_sem"}, {0xFE2A, 0xFE2A, "cc2_see"},
    {0xFE2C, 0xFE2C, "cc1_sem"}, {0xFE2E, 0xFE2E, "cc1_see"},
    {0xFE40, 0xFE40, "gpt12e_t2"}, {0xFE42, 0xFE42, "gpt12e_t3"},
    {0xFE44, 0xFE44, "gpt12e_t4"}, {0xFE46, 0xFE46, "gpt12e_t5"},
    {0xFE48, 0xFE48, "gpt12e_t6"}, {0xFE4A, 0xFE4A, "gpt12e_caprel"},
    {0xFE4C, 0xFE4C, "gpt12e_pisel"}, {0xFE50, 0xFE50, "cc1_t0"},
    {0xFE52, 0xFE52, "cc1_t1"}, {0xFE54, 0xFE54, "cc1_t0rel"},
    {0xFE56, 0xFE56, "cc1_t1rel"}, {0xFE58, 0xFE58, "opsen"},
    {0xFE5A, 0xFE5A, "tstmod"}, {0xFE5C, 0xFE5C, "mal"},
    {0xFE5E, 0xFE5E, "mah"}, {0xFE60, 0xFE60, "cc2_cc16"},
    {0xFE62, 0xFE62, "cc2_cc17"}, {0xFE64, 0xFE64, "cc2_cc18"},
    {0xFE66, 0xFE66, "cc2_cc19"}, {0xFE68, 0xFE68, "cc2_cc20"},
    {0xFE6A, 0xFE6A, "cc2_cc21"}, {0xFE6C, 0xFE6C, "cc2_cc22"},
    {0xFE6E, 0xFE6E, "cc2_cc23"}, {0xFE70, 0xFE70, "cc2_cc24"},
    {0xFE72, 0xFE72, "cc2_cc25"}, {0xFE74, 0xFE74, "cc2_cc26"},
    {0xFE76, 0xFE76, "cc2_cc27"}, {0xFE78, 0xFE78, "cc2_cc28"},
    {0xFE7A, 0xFE7A, "cc2_cc29"}, {0xFE7C, 0xFE7C, "cc2_cc30"},
    {0xFE7E, 0xFE7E, "cc2_cc31"}, {0xFE80, 0xFE80, "cc1_cc0"},
    {0xFE82, 0xFE82, "cc1_cc1"}, {0xFE84, 0xFE84, "cc1_cc2"},
    {0xFE86, 0xFE86, "cc1_cc3"}, {0xFE88, 0xFE88, "cc1_cc4"},
    {0xFE8A, 0xFE8A, "cc1_cc5"}, {0xFE8C, 0xFE8C, "cc1_cc6"},
    {0xFE8E, 0xFE8E, "cc1_cc7"}, {0xFE90, 0xFE90, "cc1_cc8"},
    {0xFE92, 0xFE92, "cc1_cc9"}, {0xFE94, 0xFE94, "cc1_cc10"},
    {0xFE96, 0xFE96, "cc1_cc11"}, {0xFE98, 0xFE98, "cc1_cc12"},
    {0xFE9A, 0xFE9A, "cc1_cc13"}, {0xFE9C, 0xFE9C, "cc1_cc14"},
    {0xFE9E, 0xFE9E, "cc1_cc15"}, {0xFEA0, 0xFEA0, "adc_dat"},
    {0xFEA8, 0xFEA8, "adc_id"}, {0xFEAA, 0xFEAA, "asc0_pmw"},
    {0xFEAC, 0xFEAC, "asc1_pmw"}, {0xFEAE, 0xFEAE, "wdt"},
    {0xFEB0, 0xFEB0, "asc0_tbuf"}, {0xFEB2, 0xFEB2, "asc0_rbuf"},
    {0xFEB4, 0xFEB4, "asc0_bg"}, {0xFEB6, 0xFEB6, "asc0_fdv"},
    {0xFEB8, 0xFEB8, "asc1_tbuf"}, {0xFEBA, 0xFEBA, "asc1_rbuf"},
    {0xFEBC, 0xFEBC, "asc1_bg"}, {0xFEBE, 0xFEBE, "asc1_fdv"},
    {0xFEC0, 0xFEC0, "pecc0"}, {0xFEC2, 0xFEC2, "pecc1"},
    {0xFEC4, 0xFEC4, "pecc2"}, {0xFEC6, 0xFEC6, "pecc3"},
    {0xFEC8, 0xFEC8, "pecc4"}, {0xFECA, 0xFECA, "pecc5"},
    {0xFECC, 0xFECC, "pecc6"}, {0xFECE, 0xFECE, "pecc7"},
    {0xFF00, 0xFF00, "p0l"}, {0xFF02, 0xFF02, "p0h"},
    {0xFF04, 0xFF04, "p1l"}, {0xFF06, 0xFF06, "p1h"},
    {0xFF08, 0xFF08, "idx0"}, {0xFF0A, 0xFF0A, "idx1"},
    {0xFF0C, 0xFF0C, "spseg"}, {0xFF0E, 0xFF0E, "mdc"},
    {0xFF10, Registers::PSW, "psw"}, {0xFF12, 0xFF12, "vecseg"},
    {0xFF16, 0xFF16, "p9"}, {0xFF18, 0xFF18, "dp9"},
    {0xFF1A, 0xFF1A, "odp9"}, {0xFF1C, 0xFF1C, "zeros"},
    {0xFF1E, 0xFF1E, "ones"}, {0xFF20, 0xFF20, "cc2_t78con"},
    {0xFF22, 0xFF22, "cc2_m4"}, {0xFF24, 0xFF24, "cc2_m5"},
    {0xFF26, 0xFF26, "cc2_m6"}, {0xFF28, 0xFF28, "cc2_m7"},
    {0xFF2A, 0xFF2A, "cc2_drm"}, {0xFF2C, 0xFF2C, "cc2_out"},
    {0xFF40, 0xFF40, "gpt12e_t2con"}, {0xFF42, 0xFF42, "gpt12e_t3con"},
    {0xFF44, 0xFF44, "gpt12e_t4con"}, {0xFF46, 0xFF46, "gpt12e_t5con"},
    {0xFF48, 0xFF48, "gpt12e_t6con"}, {0xFF50, 0xFF50, "cc1_t01con"},
    {0xFF52, 0xFF52, "cc1_m0"}, {0xFF54, 0xFF54, "cc1_m1"},
    {0xFF56, 0xFF56, "cc1_m2"}, {0xFF58, 0xFF58, "cc1_m3"},
    {0xFF5A, 0xFF5A, "cc1_drm"}, {0xFF5C, 0xFF5C, "cc1_out"},
    {0xFF5E, 0xFF5E, "ssc1_con"}, {0xFF60, 0xFF60, "gpt12e_t2ic"},
    {0xFF62, 0xFF62, "gpt12e_t3ic"}, {0xFF64, 0xFF64, "gpt12e_t4ic"},
    {0xFF66, 0xFF66, "gpt12e_t5ic"}, {0xFF68, 0xFF68, "gpt12e_t6ic"},
    {0xFF6A, 0xFF6A, "gpt12e_cric"}, {0xFF6C, 0xFF6C, "asc0_tic"},
    {0xFF6E, 0xFF6E, "asc0_ric"}, {0xFF70, 0xFF70, "asc0_eic"},
    {0xFF72, 0xFF72, "ssc0_tic"}, {0xFF74, 0xFF74, "ssc0_ric"},
    {0xFF76, 0xFF76, "ssc0_eic"}, {0xFF78, 0xFF78, "cc1_cc0ic"},
    {0xFF7A, 0xFF7A, "cc1_cc1ic"}, {0xFF7C, 0xFF7C, "cc1_cc2ic"},
    {0xFF7E, 0xFF7E, "cc1_cc3ic"}, {0xFF80, 0xFF80, "cc1_cc4ic"},
    {0xFF82, 0xFF82, "cc1_cc5ic"}, {0xFF84, 0xFF84, "cc1_cc6ic"},
    {0xFF86, 0xFF86, "cc1_cc7ic"}, {0xFF88, 0xFF88, "cc1_cc8ic"},
    {0xFF8A, 0xFF8A, "cc1_cc9ic"}, {0xFF8C, 0xFF8C, "cc1_cc10ic"},
    {0xFF8E, 0xFF8E, "cc1_cc11ic"}, {0xFF90, 0xFF90, "cc1_cc12ic"},
    {0xFF92, 0xFF92, "cc1_cc13ic"}, {0xFF94, 0xFF94, "cc1_cc14ic"},
    {0xFF96, 0xFF96, "cc1_cc15ic"}, {0xFF98, 0xFF98, "adc_cic"},
    {0xFF9A, 0xFF9A, "adc_eic"}, {0xFF9C, 0xFF9C, "cc1_t0ic"},
    {0xFF9E, 0xFF9E, "cc1_t1ic"}, {0xFFA0, 0xFFA0, "adc_con"},
    {0xFFA2, 0xFFA2, "p5"}, {0xFFA4, 0xFFA4, "p5didis"},
    {0xFFA6, 0xFFA6, "adc_con1"}, {0xFFA8, 0xFFA8, "pecisnc"},
    {0xFFAA, 0xFFAA, "focon"}, {0xFFAC, 0xFFAC, "tfr"},
    {0xFFAE, 0xFFAE, "wdtcon"}, {0xFFB0, 0xFFB0, "asc0_con"},
    {0xFFB2, 0xFFB2, "ssc0_con"}, {0xFFB4, 0xFFB4, "p20"},
    {0xFFB6, 0xFFB6, "dp20"}, {0xFFB8, 0xFFB8, "asc1_con"},
    {0xFFBE, 0xFFBE, "adc_ctr0"}, {0xFFC0, 0xFFC0, "p2"},
    {0xFFC2, 0xFFC2, "dp2"}, {0xFFC4, 0xFFC4, "p3"},
    {0xFFC6, 0xFFC6, "dp3"}, {0xFFC8, 0xFFC8, "p4"},
    {0xFFCA, 0xFFCA, "dp4"}, {0xFFCC, 0xFFCC, "p6"},
    {0xFFCE, 0xFFCE, "dp6"}, {0xFFD0, 0xFFD0, "p7"},
    {0xFFD2, 0xFFD2, "dp7"}, {0xFFDA, 0xFFDA, "mrw"},
    {0xFFDC, 0xFFDC, "mcw"}, {0xFFDE, 0xFFDE, "msw"},
};
}  // namespace

// Maintain a "global" (map/hashtable) of {address: state} pairings.
// State will be an object that can be extended to include any relevant
// per-instruction (at a given address)
//     data that can have an effect on the instruction operation (lifting) or
//     disassembly (text).
std::unordered_map<uint64_t, InstructionState> StateMap;
std::mutex StateMapMutex;

// Default Constructor
InstructionState::InstructionState() {
  ext_state = ExtNone;
  pag10 = 0x0;
  seg8 = 0x0;
  num_insns = 0;
}

void Instruction::SetExtpPag10(uint64_t addr, uint16_t pag10,
                               uint8_t num_insns) {
  // BN::LogInfo("util.cpp: SetExtpPagSeg: addr=0x%" PRIx64 ", pag10=0x%hx", addr,
  // pag10);
  std::lock_guard<std::mutex> guard(StateMapMutex);

  auto it = StateMap.find(addr);
  if (it != StateMap.end()) {
    StateMap[addr].ext_state |= ExtPage;
    StateMap[addr].pag10 = pag10;
    StateMap[addr].num_insns = num_insns;
  } else {
    // Insert new element
    InstructionState new_insn_state;
    new_insn_state.ext_state = ExtPage;
    new_insn_state.pag10 = pag10;
    new_insn_state.num_insns = num_insns;
    StateMap[addr] = new_insn_state;
  }
}

void Instruction::SetExtsSeg8(uint64_t addr, uint16_t seg8, uint8_t num_insns) {
  // BN::LogInfo("util.cpp: SetExtsSeg8: addr=0x%" PRIx64 ", seg8=0x%hx", addr, seg8);
  std::lock_guard<std::mutex> guard(StateMapMutex);

  auto it = StateMap.find(addr);
  if (it != StateMap.end()) {
    StateMap[addr].ext_state |= ExtSegment;
    StateMap[addr].seg8 = seg8;
    StateMap[addr].num_insns = num_insns;
  } else {
    // Insert new element
    InstructionState new_insn_state;
    new_insn_state.ext_state = ExtSegment;
    new_insn_state.seg8 = seg8;
    new_insn_state.num_insns = num_insns;
    StateMap[addr] = new_insn_state;
  }
}

void Instruction::SetExtr(uint64_t addr, uint8_t num_insns) {
  // BN::LogInfo("util.cpp: SetExtr: addr=0x%" PRIx64, addr);
  std::lock_guard<std::mutex> guard(StateMapMutex);

  if (const auto it = StateMap.find(addr); it != StateMap.end()) {
    StateMap[addr].ext_state |= ExtRegister;
    StateMap[addr].num_insns = num_insns;
  } else {
    // Insert new element
    InstructionState new_insn_state;
    new_insn_state.ext_state = ExtRegister;
    new_insn_state.num_insns = num_insns;

    StateMap[addr] = new_insn_state;
  }
}

bool Instruction::ShouldUseExtr(const uint64_t addr) {
  std::lock_guard<std::mutex> guard(StateMapMutex);
  bool use_extr = false;

  // If there's an entry containing extra state information for this address,
  // use it.
  auto it = StateMap.find(addr);
  if (it != StateMap.end()) {
    if (StateMap[addr].ext_state & ExtRegister) {
      use_extr = true;
    }
  }

  return use_extr;
}

bool Instruction::ShouldUseExts(const uint64_t addr, uint32_t* seg8) {
  std::lock_guard<std::mutex> guard(StateMapMutex);
  bool use_exts = false;

  // If there's an entry containing extra state information for this address,
  // use it.
  if (const auto it = StateMap.find(addr); it != StateMap.end()) {
    if (StateMap[addr].ext_state & ExtSegment) {
      use_exts = true;
      *seg8 = StateMap[addr].seg8;
    }
  }

  return use_exts;
}

bool Instruction::ShouldUseExtp(const uint64_t addr, uint32_t* pag10) {
  std::lock_guard<std::mutex> guard(StateMapMutex);
  bool use_extp = false;

  // If there's an entry containing extra state information for this address,
  // use it.
  if (const auto it = StateMap.find(addr); it != StateMap.end()) {
    if (StateMap[addr].ext_state & ExtPage) {
      use_extp = true;
      *pag10 = StateMap[addr].pag10;
    }
  }

  return use_extp;
}

InstructionState Instruction::GetInstructionState(const uint64_t addr) {
  std::lock_guard<std::mutex> guard(StateMapMutex);

  if (StateMap.find(addr) == StateMap.end()) {
    InstructionState empty = {};
    return empty;
  } else {
    return StateMap[addr];
  }
}

size_t Instruction::SerializeStateMap(uint8_t* buf, size_t size) {
  std::lock_guard<std::mutex> guard(StateMapMutex);

  uint64_t elem_count = StateMap.size();
  uint64_t elem_size = (sizeof(uint64_t) + sizeof(InstructionState));

  if (size < elem_count * elem_size) {
    return 0;
  }

  uint8_t* head = buf;
  for (auto elem : StateMap) {
    std::memcpy(head, &elem.first, sizeof(elem.first));
    head += sizeof(elem.first);
    std::memcpy(head, &elem.second, sizeof(elem.second));
    head += sizeof(elem.second);
  }

  return head - buf;
}

bool Instruction::DeserializeStateMap(const uint8_t* buf, size_t size) {
  std::lock_guard<std::mutex> guard(StateMapMutex);

  if (size % (sizeof(uint64_t) + sizeof(InstructionState)) != 0) {
    return false;
  }

  StateMap.clear();

  for (const uint8_t* head = buf; head < buf + size;
       head += sizeof(uint64_t) + sizeof(InstructionState)) {
    uint64_t addr;
    memcpy(&addr, head, sizeof(addr));

    InstructionState state;
    memcpy(&state, head + sizeof(addr), sizeof(state));

    StateMap[addr] = state;
  }

  return true;
}

size_t Instruction::SizeOfStateMap() {
  uint64_t elem_count = StateMap.size();
  uint64_t elem_size = (sizeof(uint64_t) + sizeof(InstructionState));
  return elem_count * elem_size;
}

/*
 * Indirect Addressing (EXTS) Expressions
 */

// exts; [Rw]
BN::ExprId Instruction::GetIndAddrExpr_Exts_Rw(BN::LowLevelILFunction& il,
                                               uint32_t seg8, uint32_t Rw) {
  const BN::ExprId IndAddrSeg8 =
      il.ShiftLeft(3, il.Const(3, seg8), il.Const(2, 16));
  const BN::ExprId IndAddr = il.Or(3, IndAddrSeg8, il.Register(2, Rw));
  return IndAddr;
}
// exts; [Rw + #data16]
BN::ExprId Instruction::GetIndAddrExpr_Exts_Rw_data16(
    BN::LowLevelILFunction& il, uint32_t seg8, uint32_t Rw, uint16_t data16) {
  const BN::ExprId IndAddrSeg8 =
      il.ShiftLeft(3, il.Const(3, seg8), il.Const(2, 16));
  const BN::ExprId IndAddrOff =
      il.And(2, il.Add(2, il.Register(2, Rw), il.Const(2, data16)),
             il.Const(2, 0xFFFF));
  BN::ExprId IndAddr = il.Or(3, IndAddrSeg8, IndAddrOff);
  return IndAddr;
}

/*
 * Indirect Addressing (EXTP) Expressions
 */

// extp; [Rw]
BN::ExprId Instruction::GetIndAddrExpr_Extp_Rw(BN::LowLevelILFunction& il,
                                               uint32_t pag10, uint32_t Rw) {
  const BN::ExprId IndAddrPag10 =
      il.ShiftLeft(3, il.Const(3, pag10), il.Const(2, 14));
  const BN::ExprId IndAddr = il.Or(
      3, IndAddrPag10, il.And(2, il.Register(2, Rw), il.Const(2, 0x3FFF)));
  return IndAddr;
}

// extp; [Rw + #data16]
BN::ExprId Instruction::GetIndAddrExpr_Extp_Rw_data16(
    BN::LowLevelILFunction& il, uint32_t pag10, uint32_t Rw, uint16_t data16) {
  const BN::ExprId IndAddrPag10 =
      il.ShiftLeft(3, il.Const(3, pag10), il.Const(2, 14));
  const BN::ExprId IndAddrOff =
      il.And(2, il.Add(2, il.Register(2, Rw), il.Const(2, data16)),
             il.Const(2, 0xFFFF));
  const BN::ExprId IndAddr = il.Or(3, IndAddrPag10, IndAddrOff);
  return IndAddr;
}

/*
 * Indirect Addressing (DPP) Expressions
 */

static uint32_t GetNextTempRegister(BN::LowLevelILFunction& il,
                                    uint32_t offset = 0) {
  return LLIL_TEMP(il.GetTemporaryRegisterCount() + offset);
}

static void SelectDppRegister(BN::LowLevelILFunction& il, BN::ExprId dppIndex,
                              uint32_t selectedDppReg) {
  BN::LowLevelILLabel useDpp0, checkDpp1, useDpp1, checkDpp2, useDpp2, useDpp3,
      done;

  il.AddInstruction(
      il.If(il.CompareEqual(2, dppIndex, il.Const(2, 0)), useDpp0, checkDpp1));

  il.MarkLabel(useDpp0);
  il.AddInstruction(
      il.SetRegister(2, selectedDppReg, il.Register(2, Registers::DPP0)));
  il.AddInstruction(il.Goto(done));

  il.MarkLabel(checkDpp1);
  il.AddInstruction(
      il.If(il.CompareEqual(2, dppIndex, il.Const(2, 1)), useDpp1, checkDpp2));

  il.MarkLabel(useDpp1);
  il.AddInstruction(
      il.SetRegister(2, selectedDppReg, il.Register(2, Registers::DPP1)));
  il.AddInstruction(il.Goto(done));

  il.MarkLabel(checkDpp2);
  il.AddInstruction(
      il.If(il.CompareEqual(2, dppIndex, il.Const(2, 2)), useDpp2, useDpp3));

  il.MarkLabel(useDpp2);
  il.AddInstruction(
      il.SetRegister(2, selectedDppReg, il.Register(2, Registers::DPP2)));
  il.AddInstruction(il.Goto(done));

  il.MarkLabel(useDpp3);
  il.AddInstruction(
      il.SetRegister(2, selectedDppReg, il.Register(2, Registers::DPP3)));

  il.MarkLabel(done);
}

static BN::ExprId BuildDppAddress(BN::LowLevelILFunction& il,
                                  BN::ExprId ind) {
  const uint32_t dppIndexReg = GetNextTempRegister(il);
  const uint32_t selectedDppReg = GetNextTempRegister(il, 1);
  const uint32_t addrReg = GetNextTempRegister(il, 2);

  il.AddInstruction(il.SetRegister(
      2, dppIndexReg, il.LogicalShiftRight(2, ind, il.Const(2, 14))));

  const BN::ExprId DppIndex = il.Register(2, dppIndexReg);
  SelectDppRegister(il, DppIndex, selectedDppReg);

  const BN::ExprId IndAddrUpper =
      il.ShiftLeft(3, il.Register(2, selectedDppReg), il.Const(2, 14));
  const BN::ExprId IndAddrLower = il.And(2, ind, il.Const(2, 0x3FFF));

  il.AddInstruction(
      il.SetRegister(3, addrReg, il.Or(3, IndAddrUpper, IndAddrLower)));
  return il.Register(3, addrReg);
}

// [Rw]
BN::ExprId Instruction::GetIndAddrExpr_Rw(BN::LowLevelILFunction& il,
                                          uint32_t Rw) {
  return BuildDppAddress(il, il.Register(2, Rw));
}

BN::ExprId Instruction::GetIndAddrExpr_Rw_data16(BN::LowLevelILFunction& il,
                                                 uint32_t Rw, uint16_t data16) {
  const uint32_t indReg = GetNextTempRegister(il);
  il.AddInstruction(il.SetRegister(
      2, indReg,
      il.And(2, il.Add(2, il.Const(2, data16), il.Register(2, Rw)),
             il.Const(2, 0xFFFF))));
  return BuildDppAddress(il, il.Register(2, indReg));
}

const char* Instruction::ConditionCodeToString(const uint8_t code) {
  switch (code) {
    case Conditions::CC_UC:
      return "cc_uc";
    case Conditions::CC_Z:
      return "cc_z";
    case Conditions::CC_NZ:
      return "cc_nz";
    case Conditions::CC_V:
      return "cc_v";
    case Conditions::CC_NV:
      return "cc_nv";
    case Conditions::CC_N:
      return "cc_n";
    case Conditions::CC_NN:
      return "cc_nn";
    case Conditions::CC_ULT:
      return "cc_ult";
    case Conditions::CC_ULE:
      return "cc_ule";
    case Conditions::CC_UGE:
      return "cc_uge";
    case Conditions::CC_UGT:
      return "cc_ugt";
    case Conditions::CC_SLT:
      return "cc_slt";
    case Conditions::CC_SLE:
      return "cc_sle";
    case Conditions::CC_SGE:
      return "cc_sge";
    case Conditions::CC_SGT:
      return "cc_sgt";
    case Conditions::CC_NET:
      return "cc_net";
    default:
      BN::LogDebug("Invalid condition code");
      return "?!?";
  }
}

uint8_t Instruction::GetBitPosition(const uint8_t* data, size_t len) {
  return (*data & (0xFu << 4u)) >> 4u;
}

uint32_t Instruction::GetBitoffRamAddress(const uint8_t value) {
  return 0xFD00 + 2 * value;
}

uint32_t Instruction::GetBitoffSfrAddress(const uint8_t value, bool extr) {
  uint32_t base = (extr) ? 0xF100 : 0xFF00;
  return base + 2 * (value & 0x7Fu);
}

uint16_t Instruction::GetData16(const uint8_t* data, const size_t len) {
  const auto wdata = (const uint16_t*)data;
  return *(wdata + 1);
}

uint8_t Instruction::GetData3(const uint8_t* data, const size_t len) {
  return *(data + 1) & 0b111u;
}

uint8_t Instruction::GetData4High(const uint8_t* data, const size_t len) {
  const auto wdata = (const uint16_t*)data;
  switch (len) {
    case 2:
      return (*wdata & (0b1111u << ((4 * len) + 4))) >> ((4 * len) + 4);
    case 4:
      return (*(wdata + 1) & (0b1111u << ((4 * len) + 4))) >> ((4 * len) + 4);
    default:
      BN::LogError("GetData4High -- Invalid len parameter: %zu", len);
      return 0;
  }
}

uint8_t Instruction::GetData4Low(const uint8_t* data, const size_t len) {
  const auto wdata = (const uint16_t*)data;
  switch (len) {
    case 2:
      return (*wdata & (0b1111u << (4 * len))) >> (4 * len);
    case 4:
      return (*(wdata + 1) & (0b1111u << (4 * len))) >> (4 * len);
    default:
      BN::LogError("GetData4Low -- Invalid len parameter: %zu", len);
      return 0;
  }
}

uint8_t Instruction::GetData8High(const uint8_t* data, const size_t len) {
  const auto wdata = (const uint16_t*)data;
  return (*(wdata + 1) & (0xFFu << 8u)) >> 8u;
}

uint8_t Instruction::GetData8Low(const uint8_t* data, const size_t len) {
  const auto wdata = (const uint16_t*)data;
  return *(wdata + 1) & 0xFFu;
}

BNLowLevelILFlagCondition Instruction::GetFlagCondition(const uint8_t code) {
  switch (code) {
    case Conditions::CC_Z:
      return LLFC_E;
    case Conditions::CC_NZ:
      return LLFC_NE;
    case Conditions::CC_V:
      return LLFC_O;
    case Conditions::CC_NV:
      return LLFC_NO;
    case Conditions::CC_N:
      return LLFC_NEG;
    case Conditions::CC_NN:
      return LLFC_POS;
    case Conditions::CC_ULT:
      return LLFC_ULT;
    case Conditions::CC_ULE:
      return LLFC_ULE;
    case Conditions::CC_UGE:
      return LLFC_UGE;
    case Conditions::CC_UGT:
      return LLFC_UGT;
    case Conditions::CC_SLT:
      return LLFC_SLT;
    case Conditions::CC_SLE:
      return LLFC_SLE;
    case Conditions::CC_SGE:
      return LLFC_SGE;
    case Conditions::CC_SGT:
      return LLFC_SGT;
    case Conditions::CC_NET:  // TODO: Special flag? Not end of table?!?
    case Conditions::CC_UC:
    default:
      BN::LogDebug("Invalid flag condition code");
      return LLFC_E;  // TODO: Better return value?
  }
}

uint8_t Instruction::GetIndirectIndex(const uint8_t* data, size_t len) {
  return *(data + 1) & 0b11u;
}

uint32_t Instruction::GetMem(const uint64_t addr, const uint8_t* data,
                             const size_t len) {
  std::lock_guard<std::mutex> guard(StateMapMutex);

  const auto wdata = (const uint16_t*)data;
  uint32_t mem = (*(wdata + 1) & (0xFFFFu));
  uint32_t offset;

  // If there's an entry containing extra state information for this address,
  // use it.
  auto it = StateMap.find(addr);
  if (it != StateMap.end()) {
    if (StateMap[addr].ext_state & ExtPage) {  // EXTP Overrides DPP
      offset = mem & 0x3FFF;
      return (StateMap[addr].pag10 << 14) | offset;
    } else if (StateMap[addr].ext_state & ExtSegment) {  // EXTS Overrides DPP
      return (StateMap[addr].seg8 << 16) | mem;
    }
  }

  return mem;
}

uint16_t Instruction::GetOpCaddr(const uint8_t* data, const size_t len) {
  const auto wdata = (const uint16_t*)data;
  return *(wdata + 1);
}

uint8_t Instruction::GetOpSeg(const uint8_t* data, const size_t len) {
  const auto wdata = (const uint16_t*)data;
  return (*wdata & (0xFFu << 8u)) >> 8u;
}

uint32_t Instruction::GetRegSfrAddress(const uint8_t value, bool extr) {
  uint32_t base = (extr) ? 0xF000 : 0xFE00;
  return base + 2 * value;
}

uint32_t Instruction::TranslateSfrRegister(uint32_t reg) {
  for (const auto& sfr : kSfrRegisters) {
    if (sfr.addr == reg) return sfr.reg;
  }
  return reg;
}

const char* Instruction::GetSfrRegisterName(uint32_t reg) {
  for (const auto& sfr : kSfrRegisters) {
    if (sfr.reg == reg) return sfr.name;
  }
  return nullptr;
}

uint8_t Instruction::GetRegShortAddr(const uint8_t* data, const size_t len) {
  return *(data + 1);
}

bool Instruction::JumpDirect(BN::Architecture* arch, BN::LowLevelILFunction& il,
                             uint32_t target) {
  BNLowLevelILLabel* label = il.GetLabelForAddress(arch, target);

  if (label)
    il.AddInstruction(il.Goto(*label));
  else
    il.AddInstruction(il.Jump(il.ConstPointer(3, target)));

  return true;
}

bool Instruction::JumpIndirect(BN::Architecture* arch,
                               BN::LowLevelILFunction& il, uint32_t rid,
                               uint32_t addr) {
  BN::ExprId csp = il.And(3, il.Const(3, addr), il.Const(3, 0xFF0000));
  BN::ExprId target = il.Or(3, csp, il.ZeroExtend(3, il.Register(2, rid)));
  il.AddInstruction(il.Jump(target));
  return true;
}

BN::ExprId Instruction::ReadRegisterOrMemory(BN::LowLevelILFunction& il,
                                             const uint32_t operand,
                                             const size_t width) {
  if (Instruction::IsRegister(operand, width))
    return il.Register(width, operand);
  return il.Load(width, il.ConstPointer(3, operand));
}

BN::ExprId Instruction::WriteRegisterOrMemory(BN::LowLevelILFunction& il,
                                              const uint32_t operand,
                                              const size_t width,
                                              BN::ExprId value,
                                              const uint32_t flags) {
  if (Instruction::IsRegister(operand, width))
    return il.SetRegister(width, operand, value, flags);
  return il.Store(width, il.ConstPointer(3, operand), value, flags);
}

void Instruction::AddRegisterOrAddressToken(
    std::vector<BN::InstructionTextToken>& result, const uint32_t operand,
    const size_t width) {
  char buf[32];
  if (Instruction::IsRegister(operand, width)) {
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(operand));
    result.emplace_back(RegisterToken, buf, operand);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", operand);
    result.emplace_back(PossibleAddressToken, buf, operand);
  }
}

bool Instruction::LiftOpMemReg(
    const uint64_t addr, const uint8_t* data, size_t len, size_t width,
    uint32_t flags, bool store, BN::LowLevelILFunction& il,
    const std::function<
        BN::ExprId(size_t size, BN::ExprId a, BN::ExprId b, uint32_t flags,
                   const BN::ILSourceLocation& loc)>& operation) {
  uint32_t mem = Instruction::TranslateMem(Instruction::GetMem(addr, data, 4));
  uint32_t reg =
      Instruction::TranslateReg(addr, Instruction::GetRegShortAddr(data, 4));

  BN::ExprId op2;
  if (Instruction::IsRegister(reg, width)) {
    if (width == 1 && reg <= Registers::R15) reg += 16;
    op2 = il.Register(width, reg);
  } else {
    op2 = Instruction::ElideReg(il, reg, width);
  }

  const BN::ExprId op1 = Instruction::ReadRegisterOrMemory(il, mem, width);
  if (store)
    il.AddInstruction(Instruction::WriteRegisterOrMemory(
        il, mem, width,
        operation(width, op1, op2, flags, BN::ILSourceLocation()), flags));
  else
    il.AddInstruction(
        operation(width, op1, op2, flags, BN::ILSourceLocation()));

  return true;
}

bool Instruction::LiftOpRegData(
    const uint64_t addr, const uint8_t* data, size_t len, size_t width,
    uint32_t flags, bool store, BN::LowLevelILFunction& il,
    const std::function<
        BN::ExprId(size_t size, BN::ExprId a, BN::ExprId b, uint32_t flags,
                   const BN::ILSourceLocation& loc)>& operation) {
  uint32_t reg =
      Instruction::TranslateReg(addr, Instruction::GetRegShortAddr(data, len));

  unsigned int ndata;
  switch (width) {
    case 1:
      ndata = Instruction::GetData8Low(data, len);  // TODO: Verify
      break;
    case 2:
      ndata = Instruction::GetData16(data, len);
      break;
    default:
      BN::LogError("Instruction::%s received invalid width: %zu", __func__,
                   width);
      return false;
  }

  if (Instruction::IsRegister(reg, width)) {
    if (width == 1 && reg <= Registers::R15) reg += 16;
    if (store)
      il.AddInstruction(il.SetRegister(
          width, reg,
          operation(width, il.Register(width, reg), il.Const(width, ndata),
                    flags, BN::ILSourceLocation())));
    else
      il.AddInstruction(operation(width, il.Register(width, reg),
                                  il.Const(width, ndata), flags,
                                  BN::ILSourceLocation()));
  } else {
    if (store)
      il.AddInstruction(il.Store(
          width, il.ConstPointer(3, reg),
          operation(width, il.Load(width, il.ConstPointer(3, reg)),
                    il.Const(width, ndata), flags, BN::ILSourceLocation())));
    else
      il.AddInstruction(
          operation(width, il.Load(width, il.ConstPointer(3, reg)),
                    il.Const(width, ndata), flags, BN::ILSourceLocation()));
  }

  return true;
}

bool Instruction::LiftOpRegMem(
    const uint64_t addr, const uint8_t* data, size_t len, size_t width,
    uint32_t flags, bool store, BN::LowLevelILFunction& il,
    const std::function<
        BN::ExprId(size_t size, BN::ExprId a, BN::ExprId b, uint32_t flags,
                   const BN::ILSourceLocation& loc)>& operation) {
  uint32_t reg =
      Instruction::TranslateReg(addr, Instruction::GetRegShortAddr(data, 4));
  uint32_t mem = Instruction::TranslateMem(Instruction::GetMem(addr, data, 4));

  const BN::ExprId memValue =
      Instruction::ReadRegisterOrMemory(il, mem, width);
  if (Instruction::IsRegister(reg, width)) {
    if (width == 1 && reg <= Registers::R15) reg += 16;
    if (store)
      il.AddInstruction(
          il.SetRegister(width, reg,
                         operation(width, il.Register(width, reg),
                                   memValue, flags, BN::ILSourceLocation())));
    else
      il.AddInstruction(operation(width, il.Register(width, reg),
                                  memValue, flags, BN::ILSourceLocation()));
  } else {
    if (store)
      il.AddInstruction(
          il.Store(width, il.ConstPointer(3, reg),
                   operation(width, il.Load(width, il.ConstPointer(3, reg)),
                             memValue, flags, BN::ILSourceLocation())));
    else
      il.AddInstruction(operation(width,
                                  il.Load(width, il.ConstPointer(3, reg)),
                                  memValue, flags, BN::ILSourceLocation()));
  }

  return true;
}

bool Instruction::LiftOpRnRm(
    const uint8_t* data, const size_t len, const size_t width,
    const uint32_t flags, bool store, BN::LowLevelILFunction& il,
    const std::function<
        BN::ExprId(size_t size, BN::ExprId a, BN::ExprId b, uint32_t flags,
                   const BN::ILSourceLocation& loc)>& operation) {
  uint32_t rn = Instruction::GetData4High(data, 2);
  uint32_t rm = Instruction::GetData4Low(data, 2);

  if (width == 1) {
    rn += 16;
    rm += 16;
  }

  if (store)
    il.AddInstruction(il.SetRegister(
        width, rn,
        operation(width, il.Register(width, rn), il.Register(width, rm), flags,
                  BN::ILSourceLocation())));
  else
    il.AddInstruction(operation(width, il.Register(width, rn),
                                il.Register(width, rm), flags,
                                BN::ILSourceLocation()));

  return true;
}

bool Instruction::LiftOpRnRwiData3(
    const uint64_t addr, const uint8_t* data, const size_t len,
    const size_t width, const uint32_t flags, bool store,
    BN::LowLevelILFunction& il,
    const std::function<
        BN::ExprId(size_t size, BN::ExprId a, BN::ExprId b, uint32_t flags,
                   const BN::ILSourceLocation& loc)>& operation) {
  uint32_t rn = Instruction::GetData4High(data, 2);
  uint8_t scode = ((*(data + 1) & 0xCu) >> 2u);
  uint32_t rwi = Instruction::GetIndirectIndex(data, 2);
  uint8_t data3 = Instruction::GetData3(data, 2);

  if (width == 1) rn += 16;

  BN::ExprId src = 0, post = 0;  // TODO: Is 0 the best initial value?
  switch (scode) {
    case 0b11:  // Rw_n, [Rw_i+]
      post = il.SetRegister(2, rwi,
                            il.Add(2, il.Register(2, rwi), il.Const(2, 2)));
    case 0b10:  // Rw_n, [Rw_i]
    {
      BN::ExprId SrcIndAddr;
      uint32_t seg8, pag10;
      if (Instruction::ShouldUseExts(addr, &seg8)) {
        SrcIndAddr = Instruction::GetIndAddrExpr_Exts_Rw(il, seg8, rwi);
      } else if (Instruction::ShouldUseExtp(addr, &pag10)) {
        SrcIndAddr = Instruction::GetIndAddrExpr_Extp_Rw(il, pag10, rwi);
      } else {
        SrcIndAddr = Instruction::GetIndAddrExpr_Rw(il, rwi);
      }
      src = il.Load(width, SrcIndAddr);
    } break;
    case 0b00:
    case 0b01:  // Rw_n, #data3
      src = il.Const(1, data3);
      break;
    default:
      BN::LogError("%s: Invalid sub-opcode: 0x%x", __func__, scode);
      return false;
  }

  if (store)
    il.AddInstruction(
        il.SetRegister(width, rn,
                       operation(width, il.Register(width, rn), src, flags,
                                 BN::ILSourceLocation())));
  else
    il.AddInstruction(operation(width, il.Register(width, rn), src, flags,
                                BN::ILSourceLocation()));

  if (post) il.AddInstruction(post);

  return true;
}

int8_t Instruction::SignExtend(uint8_t data) {
  if ((data >> 7u) & 1u) data |= 0x80u;
  return (int8_t)data;
}

bool Instruction::TextOpMemReg(const uint64_t addr, const uint8_t* data,
                               size_t len, size_t width,
                               std::vector<BN::InstructionTextToken>& result,
                               const std::string& instr) {
  char buf[32];
  uint32_t mem = Instruction::TranslateMem(Instruction::GetMem(addr, data, 4));
  uint32_t reg =
      Instruction::TranslateReg(addr, Instruction::GetRegShortAddr(data, 4));

  ITEXT(instr)

  Instruction::AddRegisterOrAddressToken(result, mem, width);

  result.emplace_back(OperandSeparatorToken, ", ");

  if (Instruction::IsRegister(reg, width)) {
    if (width == 1 && reg <= Registers::R15) reg += 16;
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(reg));
    result.emplace_back(RegisterToken, buf, reg);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", reg);
    result.emplace_back(PossibleAddressToken, buf, reg);
  }

  return true;
}

bool Instruction::TextOpRegData(const uint64_t addr, const uint8_t* data,
                                size_t len, size_t width,
                                std::vector<BN::InstructionTextToken>& result,
                                const std::string& instr) {
  char buf[32];
  uint32_t reg =
      Instruction::TranslateReg(addr, Instruction::GetRegShortAddr(data, 4));

  unsigned int ndata;
  switch (width) {
    case 1:
      ndata = Instruction::GetData8Low(data, len);  // TODO: Verify
      break;
    case 2:
      ndata = Instruction::GetData16(data, len);
      break;
    default:
      BN::LogError("Instruction::%s received invalid width: %zu", __func__,
                   width);
      return false;
  }

  ITEXT(instr)

  if (Instruction::IsRegister(reg, width)) {
    if (width == 1 && reg <= Registers::R15) reg += 16;
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(reg));
    result.emplace_back(RegisterToken, buf, reg);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", reg);
    result.emplace_back(PossibleAddressToken, buf, reg);
  }
  result.emplace_back(OperandSeparatorToken, ", ");
  result.emplace_back(TextToken, "#");
  std::snprintf(buf, sizeof(buf), "0x%x", ndata);
  result.emplace_back(IntegerToken, buf, ndata, width);

  return true;
}

bool Instruction::TextOpRegMem(const uint64_t addr, const uint8_t* data,
                               size_t len, size_t width,
                               std::vector<BN::InstructionTextToken>& result,
                               const std::string& instr) {
  char buf[32];
  uint32_t reg =
      Instruction::TranslateReg(addr, Instruction::GetRegShortAddr(data, 4));
  uint32_t mem = Instruction::TranslateMem(Instruction::GetMem(addr, data, 4));

  ITEXT(instr)

  if (Instruction::IsRegister(reg, width)) {
    if (width == 1 && reg <= Registers::R15) reg += 16;
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(reg));
    result.emplace_back(RegisterToken, buf, reg);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", reg);
    result.emplace_back(PossibleAddressToken, buf, reg);
  }
  result.emplace_back(OperandSeparatorToken, ", ");

  Instruction::AddRegisterOrAddressToken(result, mem, width);

  return true;
}

bool Instruction::TextOpRnRm(const uint8_t* data, const size_t len,
                             const size_t width,
                             std::vector<BN::InstructionTextToken>& result,
                             const std::string& instr) {
  char buf[32];
  uint32_t rn = Instruction::GetData4High(data, 2);
  uint32_t rm = Instruction::GetData4Low(data, 2);

  if (width == 1) {
    rn += 16;
    rm += 16;
  }

  ITEXT(instr)

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rn));
  result.emplace_back(RegisterToken, buf, rn);
  result.emplace_back(OperandSeparatorToken, ", ");
  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rm));
  result.emplace_back(RegisterToken, buf, rm);

  return true;
}

bool Instruction::TextOpRnRwiData3(
    const uint8_t* data, size_t len, size_t width,
    std::vector<BN::InstructionTextToken>& result, const std::string& instr) {
  char buf[32];
  uint32_t rn = Instruction::GetData4High(data, 2);
  uint8_t scode = ((*(data + 1) & 0xCu) >> 2u);
  uint32_t rwi = Instruction::GetIndirectIndex(data, 2);
  uint8_t data3 = Instruction::GetData3(data, 2);

  ITEXT(instr)

  if (width == 1) rn += 16;

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rn));
  result.emplace_back(RegisterToken, buf, rn);

  switch (scode) {
    case 0b10:
      result.emplace_back(OperandSeparatorToken, ", [");
      std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwi));
      result.emplace_back(RegisterToken, buf, rwi);
      result.emplace_back(TextToken, "]");
      return true;
    case 0b11:
      result.emplace_back(OperandSeparatorToken, ", [");
      std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwi));
      result.emplace_back(RegisterToken, buf, rwi);
      result.emplace_back(TextToken, "+]");
      return true;
    case 0b00:
    case 0b01:
      result.emplace_back(OperandSeparatorToken, ", ");
      result.emplace_back(TextToken, "#");
      std::snprintf(buf, sizeof(buf), "0x%x", data3);
      result.emplace_back(IntegerToken, buf, data3, 1);
      return true;
    default:
      BN::LogError("%s: Invalid sub-opcode.", __func__);
      return false;
  }
}

uint32_t Instruction::TranslateBitOff(const uint64_t addr,
                                      const uint32_t bitoff) {
  if (bitoff <= 0x7F) {
    return GetBitoffRamAddress(bitoff);
  } else if (bitoff <= 0xEF)
    return GetBitoffSfrAddress(bitoff, ShouldUseExtr(addr));
  else {
    return bitoff & 0xFu;
  }
}

uint32_t Instruction::TranslateMem(const uint32_t mem) {
  return TranslateSfrRegister(mem);
}

uint32_t Instruction::TranslateReg(const uint64_t addr, const uint32_t reg) {
  if (reg <= 0xEF) {
    return TranslateSfrRegister(GetRegSfrAddress(reg, ShouldUseExtr(addr)));
  } else {
    return reg & 0xFu;
  }
}

bool Instruction::IsRegister(const uint32_t reg, const size_t width) {
  if (reg <= Registers::R15) return true;
  if (width == 2) {
    return GetSfrRegisterName(reg) != nullptr;
  }
  return false;
}

std::vector<uint32_t> Instruction::GetSfrRegisters() {
  std::vector<uint32_t> result;
  for (const auto& sfr : kSfrRegisters) {
    bool found = false;
    for (const auto reg : result) {
      if (reg == sfr.reg) {
        found = true;
        break;
      }
    }
    if (!found) result.push_back(sfr.reg);
  }
  return result;
}

const char* Instruction::RegToStr(const uint32_t rid) {
  if (const auto* sfrName = GetSfrRegisterName(rid); sfrName != nullptr)
    return sfrName;

  switch (rid) {
    /* Full-Width GPRs + Stack Pointer */
    case Registers::R0:
      return "r0";
    case Registers::R1:
      return "r1";
    case Registers::R2:
      return "r2";
    case Registers::R3:
      return "r3";
    case Registers::R4:
      return "r4";
    case Registers::R5:
      return "r5";
    case Registers::R6:
      return "r6";
    case Registers::R7:
      return "r7";
    case Registers::R8:
      return "r8";
    case Registers::R9:
      return "r9";
    case Registers::R10:
      return "r10";
    case Registers::R11:
      return "r11";
    case Registers::R12:
      return "r12";
    case Registers::R13:
      return "r13";
    case Registers::R14:
      return "r14";
    case Registers::R15:  // Stack Pointer
      return "r15";
    case Registers::RL0:
      return "rl0";
    case Registers::RH0:
      return "rh0";
    case Registers::RL1:
      return "rl1";
    case Registers::RH1:
      return "rh1";
    case Registers::RL2:
      return "rl2";
    case Registers::RH2:
      return "rh2";
    case Registers::RL3:
      return "rl3";
    case Registers::RH3:
      return "rh3";
    case Registers::RL4:
      return "rl4";
    case Registers::RH4:
      return "rh4";
    case Registers::RL5:
      return "rl5";
    case Registers::RH5:
      return "rh5";
    case Registers::RL6:
      return "rl6";
    case Registers::RH6:
      return "rh6";
    case Registers::RL7:
      return "rl7";
    case Registers::RH7:
      return "rh7";
    case Registers::CSP:
      return "csp";
    case Registers::CPUCON1:
      return "cpucon1";
    case Registers::CPUCON2:
      return "cpucon2";
    case Registers::PSW:
      return "psw";
    case Registers::CP:
      return "cp";
    case Registers::VIRTUAL_LR:
      return "virtual_lr";
    case Registers::DPP0:
      return "dpp0";
    case Registers::DPP1:
      return "dpp1";
    case Registers::DPP2:
      return "dpp2";
    case Registers::DPP3:
      return "dpp3";
    default:
      return nullptr;
  }
}

bool Instruction::GetConstantRegister(uint32_t reg, uint16_t& value) {
  switch (reg) {
    case 0xFF1C:  // ZEROS
      value = 0x0;
      return true;
    case 0xFF1E:  // ONES
      value = 0xFFFF;
      return true;
    default:
      return false;
  }
}

BN::ExprId Instruction::ElideReg(BN::LowLevelILFunction& il, const uint32_t reg,
                                 const int width) {
  if (uint16_t constant = 0; GetConstantRegister(reg, constant)) {
    return il.Const(width, constant);
  } else if (IsRegister(reg, width)) {
    return il.Register(width, reg);
  } else {
    return il.Load(width, il.ConstPointer(3, reg));
  }
}

uint32_t Calla::GetConditionCode(const uint8_t* data, const size_t len) {
  return (*(data + 1) & 0xF0u) >> 4u;
}

uint32_t Calli::GetConditionCode(const uint8_t* data, const size_t len) {
  return (*(data + 1) & 0xF0u) >> 4u;
}

uint8_t Callr::GetRelativeOffset(const uint8_t* data, const size_t len) {
  return *(data + 1) & 0xFFu;
}

uint32_t Callr::GetTarget(const uint8_t* data, const uint64_t addr,
                          const size_t len) {
  return addr +
         Instruction::SignExtend(Callr::GetRelativeOffset(data, len)) * 2 + 2;
}

uint32_t Calla::GetTarget(const uint8_t* data, const uint64_t addr,
                          const size_t len) {
  const auto wdata = (const uint16_t*)data;
  return (addr & (0xFFu << 16u)) + *(wdata + 1);
}

uint32_t Calls::GetTarget(const uint8_t* data, const size_t len) {
  const uint8_t seg = Instruction::GetOpSeg(data, len);
  const uint16_t caddr = Instruction::GetOpCaddr(data, len);
  return (static_cast<uint32_t>(seg) << 16u) | caddr;
}

const char* Extprs::GetInstruction(const uint8_t* data, uint64_t addr,
                                   const size_t len) {
  const uint16_t instr = *(const uint16_t*)data;
  const auto scode = (instr & (0b11u << 14u)) >> 14u;
  switch (scode) {
    case 0b00:
      return "exts";
    case 0b01:
      return "extp";
    default:
      BN::LogDebug("0x%" PRIx64 ": Encountered unimplemented extended instruction",
                   addr);
      return "UNIMPLEMENTED_EXT";
  }
}

uint8_t Jb::GetRelativeOffset(const uint8_t* data, const size_t len) {
  const auto wdata = (const uint16_t*)data;
  return *(wdata + 1) & 0xFFu;
}

uint32_t Jb::GetTarget(const uint8_t* data, const uint64_t addr,
                       const size_t len) {
  return addr + Instruction::SignExtend(Jb::GetRelativeOffset(data, len)) * 2 +
         length;
}

uint8_t Jbc::GetRelativeOffset(const uint8_t* data, const size_t len) {
  const auto wdata = (const uint16_t*)data;
  return *(wdata + 1) & 0xFFu;
}

uint32_t Jbc::GetTarget(const uint8_t* data, const uint64_t addr,
                        const size_t len) {
  return addr + Instruction::SignExtend(Jbc::GetRelativeOffset(data, len)) * 2 +
         length;
}

uint32_t Jmpa::GetConditionCode(const uint8_t* data, const size_t len) {
  return (*(data + 1) & 0xF0u) >> 4u;
}

uint32_t Jmpa::GetTarget(const uint8_t* data, const uint64_t addr,
                         const size_t len) {
  const auto wdata = (const uint16_t*)data;
  return (addr & (0xFFu << 16u)) + *(wdata + 1);
}

uint32_t Jmpr::GetConditionCode(const uint8_t* data, const size_t len) {
  return (*data & 0xF0u) >> 4u;
}

uint8_t Jmpr::GetRelativeOffset(const uint8_t* data, const size_t len) {
  return *(data + 1) & 0xFFu;
}

uint32_t Jmpr::GetTarget(const uint8_t* data, const uint64_t addr,
                         const size_t len) {
  return addr +
         Instruction::SignExtend(Jmpr::GetRelativeOffset(data, len)) * 2 + 2;
}

uint32_t Jmps::GetTarget(const uint8_t* data, const size_t len) {
  const uint8_t seg = Instruction::GetOpSeg(data, len);
  const uint16_t caddr = Instruction::GetOpCaddr(data, len);
  return ((uint32_t)seg << 16u) | caddr;
}

uint8_t Jnb::GetRelativeOffset(const uint8_t* data, const size_t len) {
  const auto wdata = (const uint16_t*)data;
  return *(wdata + 1) & 0xFFu;
}

uint32_t Jnb::GetTarget(const uint8_t* data, const uint64_t addr,
                        const size_t len) {
  return addr + Instruction::SignExtend(Jnb::GetRelativeOffset(data, len)) * 2 +
         length;
}

uint8_t Jnbs::GetRelativeOffset(const uint8_t* data, const size_t len) {
  const auto wdata = (const uint16_t*)data;
  return *(wdata + 1) & 0xFFu;
}

uint32_t Jnbs::GetTarget(const uint8_t* data, const uint64_t addr,
                         const size_t len) {
  return addr +
         Instruction::SignExtend(Jnbs::GetRelativeOffset(data, len)) * 2 +
         length;
}

uint32_t Trap::GetTarget(const uint8_t* data, const uint64_t addr) {
  const uint8_t trap7 = Trap::GetTrap7(data);
  return (addr & (0xFFu << 16u)) + (trap7 * 4);
}

uint8_t Trap::GetTrap7(const uint8_t* data) {
  return (*(data + 1) & (0b1111111u << 1u)) >> 1u;
}
}  // namespace C166
