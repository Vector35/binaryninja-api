/* ppc adaptive assembler

	Do not include any BINJA stuff in here (includes like binaryninjaapi.h,
	calls like LogDebug(), etc.) so that this can be easily compiled and
	linked against test_asm.cpp for timing and stressing.
*/

/* */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

/* c++ stuff */
#include <map>
#include <string>
#include <vector>
using namespace std;

/* capstone stuff */
#include "capstone/capstone.h"

//#define MYLOG printf
#define MYLOG(...) while(0);

#include "assembler.h"

/*****************************************************************************/
/* precomputed stuff */
/*****************************************************************************/

struct info {
	uint32_t seed; /* start parent */
	uint32_t mask; /* which bits to mutate */
};

map<string, info> lookup = {
{               "tdi NUM , GPR , NUM",{0x0800000A,0x03FFFFFF}}, // 000010xxxxxxxxxxxxxxxxxxxxxxxxxx  tdi 0, r0, 0xa
{                  "tdlgti GPR , NUM",{0x08200000,0x001FFFFF}}, // 00001000001xxxxxxxxxxxxxxxxxxxxx  tdlgti r0, 0
{                  "tdllti GPR , NUM",{0x08400000,0x001FFFFF}}, // 00001000010xxxxxxxxxxxxxxxxxxxxx  tdllti r0, 0
{                   "tdeqi GPR , NUM",{0x08800000,0x001FFFFF}}, // 00001000100xxxxxxxxxxxxxxxxxxxxx  tdeqi r0, 0
{                   "tdgti GPR , NUM",{0x09000000,0x001FFFFF}}, // 00001001000xxxxxxxxxxxxxxxxxxxxx  tdgti r0, 0
{                   "tdlti GPR , NUM",{0x0A000000,0x001FFFFF}}, // 00001010000xxxxxxxxxxxxxxxxxxxxx  tdlti r0, 0
{                   "tdnei GPR , NUM",{0x0B000000,0x001FFFFF}}, // 00001011000xxxxxxxxxxxxxxxxxxxxx  tdnei r0, 0
{                    "tdui GPR , NUM",{0x0BE00000,0x001FFFFF}}, // 00001011111xxxxxxxxxxxxxxxxxxxxx  tdui r0, 0
{               "twi NUM , GPR , NUM",{0x0C000000,0x03FFFFFF}}, // 000011xxxxxxxxxxxxxxxxxxxxxxxxxx  twi 0, r0, 0
{                  "twlgti GPR , NUM",{0x0C200000,0x001FFFFF}}, // 00001100001xxxxxxxxxxxxxxxxxxxxx  twlgti r0, 0
{                  "twllti GPR , NUM",{0x0C400000,0x001FFFFF}}, // 00001100010xxxxxxxxxxxxxxxxxxxxx  twllti r0, 0
{                   "tweqi GPR , NUM",{0x0C800000,0x001FFFFF}}, // 00001100100xxxxxxxxxxxxxxxxxxxxx  tweqi r0, 0
{                   "twgti GPR , NUM",{0x0D000000,0x001FFFFF}}, // 00001101000xxxxxxxxxxxxxxxxxxxxx  twgti r0, 0
{                   "twlti GPR , NUM",{0x0E000000,0x001FFFFF}}, // 00001110000xxxxxxxxxxxxxxxxxxxxx  twlti r0, 0
{                   "twnei GPR , NUM",{0x0F000000,0x001FFFFF}}, // 00001111000xxxxxxxxxxxxxxxxxxxxx  twnei r0, 0
{                    "twui GPR , NUM",{0x0FE00000,0x001FFFFF}}, // 00001111111xxxxxxxxxxxxxxxxxxxxx  twui r0, 0
{        "vaddubm VREG , VREG , VREG",{0x10000000,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00000000000  vaddubm v0, v0, v0
{         "vmaxub VREG , VREG , VREG",{0x10000002,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00000000010  vmaxub v0, v0, v0
{           "vrlb VREG , VREG , VREG",{0x10000004,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00000000100  vrlb v0, v0, v0
{       "vcmpequb VREG , VREG , VREG",{0x10000006,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00000000110  vcmpequb v0, v0, v0
{        "vmuloub VREG , VREG , VREG",{0x10000008,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00000001000  vmuloub v0, v0, v0
{         "vaddfp VREG , VREG , VREG",{0x1000000A,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00000001010  vaddfp v0, v0, v0
{         "vmrghb VREG , VREG , VREG",{0x1000000C,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00000001100  vmrghb v0, v0, v0
{        "vpkuhum VREG , VREG , VREG",{0x1000000E,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00000001110  vpkuhum v0, v0, v0
{"vmhaddshs VREG , VREG , VREG , VREG",{0x10000020,0x03FFFFC0}}, // 000100xxxxxxxxxxxxxxxxxxxx100000  vmhaddshs v0, v0, v0, v0
{"vmhraddshs VREG , VREG , VREG , VREG",{0x10000021,0x03FFFFC0}}, // 000100xxxxxxxxxxxxxxxxxxxx100001  vmhraddshs v0, v0, v0, v0
{"vmladduhm VREG , VREG , VREG , VREG",{0x10000022,0x03FFFFC0}}, // 000100xxxxxxxxxxxxxxxxxxxx100010  vmladduhm v0, v0, v0, v0
{"vmsumubm VREG , VREG , VREG , VREG",{0x10000024,0x03FFFFC0}}, // 000100xxxxxxxxxxxxxxxxxxxx100100  vmsumubm v0, v0, v0, v0
{"vmsummbm VREG , VREG , VREG , VREG",{0x10000025,0x03FFFFC0}}, // 000100xxxxxxxxxxxxxxxxxxxx100101  vmsummbm v0, v0, v0, v0
{"vmsumuhm VREG , VREG , VREG , VREG",{0x10000026,0x03FFFFC0}}, // 000100xxxxxxxxxxxxxxxxxxxx100110  vmsumuhm v0, v0, v0, v0
{"vmsumuhs VREG , VREG , VREG , VREG",{0x10000027,0x03FFFFC0}}, // 000100xxxxxxxxxxxxxxxxxxxx100111  vmsumuhs v0, v0, v0, v0
{"vmsumshm VREG , VREG , VREG , VREG",{0x10000028,0x03FFFFC0}}, // 000100xxxxxxxxxxxxxxxxxxxx101000  vmsumshm v0, v0, v0, v0
{"vmsumshs VREG , VREG , VREG , VREG",{0x10000029,0x03FFFFC0}}, // 000100xxxxxxxxxxxxxxxxxxxx101001  vmsumshs v0, v0, v0, v0
{    "vsel VREG , VREG , VREG , VREG",{0x1000002A,0x03FFFFC0}}, // 000100xxxxxxxxxxxxxxxxxxxx101010  vsel v0, v0, v0, v0
{   "vperm VREG , VREG , VREG , VREG",{0x1000002B,0x03FFFFC0}}, // 000100xxxxxxxxxxxxxxxxxxxx101011  vperm v0, v0, v0, v0
{   "vsldoi VREG , VREG , VREG , NUM",{0x1000002C,0x03FFFBC0}}, // 000100xxxxxxxxxxxxxxx0xxxx101100  vsldoi v0, v0, v0, 0
{ "vmaddfp VREG , VREG , VREG , VREG",{0x1000002E,0x03FFFFC0}}, // 000100xxxxxxxxxxxxxxxxxxxx101110  vmaddfp v0, v0, v0, v0
{"vnmsubfp VREG , VREG , VREG , VREG",{0x1000002F,0x03FFFFC0}}, // 000100xxxxxxxxxxxxxxxxxxxx101111  vnmsubfp v0, v0, v0, v0
{        "vadduhm VREG , VREG , VREG",{0x10000040,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00001000000  vadduhm v0, v0, v0
{         "vmaxuh VREG , VREG , VREG",{0x10000042,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00001000010  vmaxuh v0, v0, v0
{           "vrlh VREG , VREG , VREG",{0x10000044,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00001000100  vrlh v0, v0, v0
{       "vcmpequh VREG , VREG , VREG",{0x10000046,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00001000110  vcmpequh v0, v0, v0
{        "vmulouh VREG , VREG , VREG",{0x10000048,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00001001000  vmulouh v0, v0, v0
{         "vsubfp VREG , VREG , VREG",{0x1000004A,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00001001010  vsubfp v0, v0, v0
{         "vmrghh VREG , VREG , VREG",{0x1000004C,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00001001100  vmrghh v0, v0, v0
{        "vpkuwum VREG , VREG , VREG",{0x1000004E,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00001001110  vpkuwum v0, v0, v0
{        "vadduwm VREG , VREG , VREG",{0x10000080,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00010000000  vadduwm v0, v0, v0
{         "vmaxuw VREG , VREG , VREG",{0x10000082,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00010000010  vmaxuw v0, v0, v0
{           "vrlw VREG , VREG , VREG",{0x10000084,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00010000100  vrlw v0, v0, v0
{       "vcmpequw VREG , VREG , VREG",{0x10000086,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00010000110  vcmpequw v0, v0, v0
{         "vmrghw VREG , VREG , VREG",{0x1000008C,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00010001100  vmrghw v0, v0, v0
{        "vpkuhus VREG , VREG , VREG",{0x1000008E,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00010001110  vpkuhus v0, v0, v0
{       "vcmpeqfp VREG , VREG , VREG",{0x100000C6,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00011000110  vcmpeqfp v0, v0, v0
{        "vpkuwus VREG , VREG , VREG",{0x100000CE,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00011001110  vpkuwus v0, v0, v0
{         "vmaxsb VREG , VREG , VREG",{0x10000102,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00100000010  vmaxsb v0, v0, v0
{           "vslb VREG , VREG , VREG",{0x10000104,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00100000100  vslb v0, v0, v0
{        "vmulosb VREG , VREG , VREG",{0x10000108,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00100001000  vmulosb v0, v0, v0
{                 "vrefp VREG , VREG",{0x1000010A,0x03E0F800}}, // 000100xxxxx00000xxxxx00100001010  vrefp v0, v0
{         "vmrglb VREG , VREG , VREG",{0x1000010C,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00100001100  vmrglb v0, v0, v0
{        "vpkshus VREG , VREG , VREG",{0x1000010E,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00100001110  vpkshus v0, v0, v0
{         "vmaxsh VREG , VREG , VREG",{0x10000142,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00101000010  vmaxsh v0, v0, v0
{           "vslh VREG , VREG , VREG",{0x10000144,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00101000100  vslh v0, v0, v0
{        "vmulosh VREG , VREG , VREG",{0x10000148,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00101001000  vmulosh v0, v0, v0
{             "vrsqrtefp VREG , VREG",{0x1000014A,0x03E0F800}}, // 000100xxxxx00000xxxxx00101001010  vrsqrtefp v0, v0
{         "vmrglh VREG , VREG , VREG",{0x1000014C,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00101001100  vmrglh v0, v0, v0
{        "vpkswus VREG , VREG , VREG",{0x1000014E,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00101001110  vpkswus v0, v0, v0
{        "vaddcuw VREG , VREG , VREG",{0x10000180,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00110000000  vaddcuw v0, v0, v0
{         "vmaxsw VREG , VREG , VREG",{0x10000182,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00110000010  vmaxsw v0, v0, v0
{           "vslw VREG , VREG , VREG",{0x10000184,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00110000100  vslw v0, v0, v0
{              "vexptefp VREG , VREG",{0x1000018A,0x03E0F800}}, // 000100xxxxx00000xxxxx00110001010  vexptefp v0, v0
{         "vmrglw VREG , VREG , VREG",{0x1000018C,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00110001100  vmrglw v0, v0, v0
{        "vpkshss VREG , VREG , VREG",{0x1000018E,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00110001110  vpkshss v0, v0, v0
{            "vsl VREG , VREG , VREG",{0x100001C4,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00111000100  vsl v0, v0, v0
{       "vcmpgefp VREG , VREG , VREG",{0x100001C6,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00111000110  vcmpgefp v0, v0, v0
{               "vlogefp VREG , VREG",{0x100001CA,0x03E0F800}}, // 000100xxxxx00000xxxxx00111001010  vlogefp v0, v0
{        "vpkswss VREG , VREG , VREG",{0x100001CE,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx00111001110  vpkswss v0, v0, v0
{        "vaddubs VREG , VREG , VREG",{0x10000200,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01000000000  vaddubs v0, v0, v0
{         "vminub VREG , VREG , VREG",{0x10000202,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01000000010  vminub v0, v0, v0
{           "vsrb VREG , VREG , VREG",{0x10000204,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01000000100  vsrb v0, v0, v0
{       "vcmpgtub VREG , VREG , VREG",{0x10000206,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01000000110  vcmpgtub v0, v0, v0
{        "vmuleub VREG , VREG , VREG",{0x10000208,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01000001000  vmuleub v0, v0, v0
{                 "vrfin VREG , VREG",{0x1000020A,0x03E0F800}}, // 000100xxxxx00000xxxxx01000001010  vrfin v0, v0
{          "vspltb VREG , VREG , NUM",{0x1000020C,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01000001100  vspltb v0, v0, 0
{               "vupkhsb VREG , VREG",{0x1000020E,0x03E0F800}}, // 000100xxxxx00000xxxxx01000001110  vupkhsb v0, v0
{        "vadduhs VREG , VREG , VREG",{0x10000240,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01001000000  vadduhs v0, v0, v0
{         "vminuh VREG , VREG , VREG",{0x10000242,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01001000010  vminuh v0, v0, v0
{           "vsrh VREG , VREG , VREG",{0x10000244,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01001000100  vsrh v0, v0, v0
{       "vcmpgtuh VREG , VREG , VREG",{0x10000246,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01001000110  vcmpgtuh v0, v0, v0
{        "vmuleuh VREG , VREG , VREG",{0x10000248,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01001001000  vmuleuh v0, v0, v0
{                 "vrfiz VREG , VREG",{0x1000024A,0x03E0F800}}, // 000100xxxxx00000xxxxx01001001010  vrfiz v0, v0
{          "vsplth VREG , VREG , NUM",{0x1000024C,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01001001100  vsplth v0, v0, 0
{               "vupkhsh VREG , VREG",{0x1000024E,0x03E0F800}}, // 000100xxxxx00000xxxxx01001001110  vupkhsh v0, v0
{        "vadduws VREG , VREG , VREG",{0x10000280,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01010000000  vadduws v0, v0, v0
{         "vminuw VREG , VREG , VREG",{0x10000282,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01010000010  vminuw v0, v0, v0
{           "vsrw VREG , VREG , VREG",{0x10000284,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01010000100  vsrw v0, v0, v0
{       "vcmpgtuw VREG , VREG , VREG",{0x10000286,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01010000110  vcmpgtuw v0, v0, v0
{                 "vrfip VREG , VREG",{0x1000028A,0x03E0F800}}, // 000100xxxxx00000xxxxx01010001010  vrfip v0, v0
{          "vspltw VREG , VREG , NUM",{0x1000028C,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01010001100  vspltw v0, v0, 0
{               "vupklsb VREG , VREG",{0x1000028E,0x03E0F800}}, // 000100xxxxx00000xxxxx01010001110  vupklsb v0, v0
{            "vsr VREG , VREG , VREG",{0x100002C4,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01011000100  vsr v0, v0, v0
{       "vcmpgtfp VREG , VREG , VREG",{0x100002C6,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01011000110  vcmpgtfp v0, v0, v0
{                 "vrfim VREG , VREG",{0x100002CA,0x03E0F800}}, // 000100xxxxx00000xxxxx01011001010  vrfim v0, v0
{               "vupklsh VREG , VREG",{0x100002CE,0x03E0F800}}, // 000100xxxxx00000xxxxx01011001110  vupklsh v0, v0
{        "vaddsbs VREG , VREG , VREG",{0x10000300,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01100000000  vaddsbs v0, v0, v0
{         "vminsb VREG , VREG , VREG",{0x10000302,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01100000010  vminsb v0, v0, v0
{          "vsrab VREG , VREG , VREG",{0x10000304,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01100000100  vsrab v0, v0, v0
{       "vcmpgtsb VREG , VREG , VREG",{0x10000306,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01100000110  vcmpgtsb v0, v0, v0
{        "vmulesb VREG , VREG , VREG",{0x10000308,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01100001000  vmulesb v0, v0, v0
{           "vcfux VREG , VREG , NUM",{0x1000030A,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01100001010  vcfux v0, v0, 0
{               "vspltisb VREG , NUM",{0x1000030C,0x03FF0000}}, // 000100xxxxxxxxxx0000001100001100  vspltisb v0, 0
{          "vpkpx VREG , VREG , VREG",{0x1000030E,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01100001110  vpkpx v0, v0, v0
{        "vaddshs VREG , VREG , VREG",{0x10000340,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01101000000  vaddshs v0, v0, v0
{         "vminsh VREG , VREG , VREG",{0x10000342,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01101000010  vminsh v0, v0, v0
{          "vsrah VREG , VREG , VREG",{0x10000344,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01101000100  vsrah v0, v0, v0
{       "vcmpgtsh VREG , VREG , VREG",{0x10000346,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01101000110  vcmpgtsh v0, v0, v0
{        "vmulesh VREG , VREG , VREG",{0x10000348,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01101001000  vmulesh v0, v0, v0
{           "vcfsx VREG , VREG , NUM",{0x1000034A,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01101001010  vcfsx v0, v0, 0
{               "vspltish VREG , NUM",{0x1000034C,0x03FF0000}}, // 000100xxxxxxxxxx0000001101001100  vspltish v0, 0
{               "vupkhpx VREG , VREG",{0x1000034E,0x03E0F800}}, // 000100xxxxx00000xxxxx01101001110  vupkhpx v0, v0
{        "vaddsws VREG , VREG , VREG",{0x10000380,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01110000000  vaddsws v0, v0, v0
{         "vminsw VREG , VREG , VREG",{0x10000382,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01110000010  vminsw v0, v0, v0
{          "vsraw VREG , VREG , VREG",{0x10000384,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01110000100  vsraw v0, v0, v0
{       "vcmpgtsw VREG , VREG , VREG",{0x10000386,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01110000110  vcmpgtsw v0, v0, v0
{          "vctuxs VREG , VREG , NUM",{0x1000038A,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01110001010  vctuxs v0, v0, 0
{               "vspltisw VREG , NUM",{0x1000038C,0x03FF0000}}, // 000100xxxxxxxxxx0000001110001100  vspltisw v0, 0
{        "vcmpbfp VREG , VREG , VREG",{0x100003C6,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01111000110  vcmpbfp v0, v0, v0
{          "vctsxs VREG , VREG , NUM",{0x100003CA,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx01111001010  vctsxs v0, v0, 0
{               "vupklpx VREG , VREG",{0x100003CE,0x03E0F800}}, // 000100xxxxx00000xxxxx01111001110  vupklpx v0, v0
{        "vsububm VREG , VREG , VREG",{0x10000400,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx10000000000  vsububm v0, v0, v0
{         "vavgub VREG , VREG , VREG",{0x10000402,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx10000000010  vavgub v0, v0, v0
{           "vand VREG , VREG , VREG",{0x10000404,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx10000000100  vand v0, v0, v0
{     "vcmpequb . VREG , VREG , VREG",{0x10000406,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx10000000110  vcmpequb. v0, v0, v0
{         "vmaxfp VREG , VREG , VREG",{0x1000040A,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx10000001010  vmaxfp v0, v0, v0
{           "vslo VREG , VREG , VREG",{0x1000040C,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx10000001100  vslo v0, v0, v0
{        "vsubuhm VREG , VREG , VREG",{0x10000440,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx10001000000  vsubuhm v0, v0, v0
{         "vavguh VREG , VREG , VREG",{0x10000442,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx10001000010  vavguh v0, v0, v0
{          "vandc VREG , VREG , VREG",{0x10000444,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx10001000100  vandc v0, v0, v0
{     "vcmpequh . VREG , VREG , VREG",{0x10000446,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx10001000110  vcmpequh. v0, v0, v0
{         "vminfp VREG , VREG , VREG",{0x1000044A,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx10001001010  vminfp v0, v0, v0
{           "vsro VREG , VREG , VREG",{0x1000044C,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx10001001100  vsro v0, v0, v0
{        "vsubuwm VREG , VREG , VREG",{0x10000480,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx10010000000  vsubuwm v0, v0, v0
{         "vavguw VREG , VREG , VREG",{0x10000482,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx10010000010  vavguw v0, v0, v0
{            "vor VREG , VREG , VREG",{0x10000484,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx10010000100  vor v0, v0, v0
{     "vcmpequw . VREG , VREG , VREG",{0x10000486,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx10010000110  vcmpequw. v0, v0, v0
{           "vxor VREG , VREG , VREG",{0x100004C4,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx10011000100  vxor v0, v0, v0
{     "vcmpeqfp . VREG , VREG , VREG",{0x100004C6,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx10011000110  vcmpeqfp. v0, v0, v0
{         "vavgsb VREG , VREG , VREG",{0x10000502,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx10100000010  vavgsb v0, v0, v0
{           "vnor VREG , VREG , VREG",{0x10000504,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx10100000100  vnor v0, v0, v0
{         "vavgsh VREG , VREG , VREG",{0x10000542,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx10101000010  vavgsh v0, v0, v0
{        "vsubcuw VREG , VREG , VREG",{0x10000580,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx10110000000  vsubcuw v0, v0, v0
{         "vavgsw VREG , VREG , VREG",{0x10000582,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx10110000010  vavgsw v0, v0, v0
{     "vcmpgefp . VREG , VREG , VREG",{0x100005C6,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx10111000110  vcmpgefp. v0, v0, v0
{        "vsububs VREG , VREG , VREG",{0x10000600,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx11000000000  vsububs v0, v0, v0
{                       "mfvscr VREG",{0x10000604,0x03E00000}}, // 000100xxxxx000000000011000000100  mfvscr v0
{     "vcmpgtub . VREG , VREG , VREG",{0x10000606,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx11000000110  vcmpgtub. v0, v0, v0
{       "vsum4ubs VREG , VREG , VREG",{0x10000608,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx11000001000  vsum4ubs v0, v0, v0
{        "vsubuhs VREG , VREG , VREG",{0x10000640,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx11001000000  vsubuhs v0, v0, v0
{                       "mtvscr VREG",{0x10000644,0x0000F800}}, // 0001000000000000xxxxx11001000100  mtvscr v0
{     "vcmpgtuh . VREG , VREG , VREG",{0x10000646,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx11001000110  vcmpgtuh. v0, v0, v0
{       "vsum4shs VREG , VREG , VREG",{0x10000648,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx11001001000  vsum4shs v0, v0, v0
{        "vsubuws VREG , VREG , VREG",{0x10000680,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx11010000000  vsubuws v0, v0, v0
{     "vcmpgtuw . VREG , VREG , VREG",{0x10000686,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx11010000110  vcmpgtuw. v0, v0, v0
{       "vsum2sws VREG , VREG , VREG",{0x10000688,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx11010001000  vsum2sws v0, v0, v0
{     "vcmpgtfp . VREG , VREG , VREG",{0x100006C6,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx11011000110  vcmpgtfp. v0, v0, v0
{        "vsubsbs VREG , VREG , VREG",{0x10000700,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx11100000000  vsubsbs v0, v0, v0
{     "vcmpgtsb . VREG , VREG , VREG",{0x10000706,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx11100000110  vcmpgtsb. v0, v0, v0
{       "vsum4sbs VREG , VREG , VREG",{0x10000708,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx11100001000  vsum4sbs v0, v0, v0
{        "vsubshs VREG , VREG , VREG",{0x10000740,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx11101000000  vsubshs v0, v0, v0
{     "vcmpgtsh . VREG , VREG , VREG",{0x10000746,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx11101000110  vcmpgtsh. v0, v0, v0
{        "vsubsws VREG , VREG , VREG",{0x10000780,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx11110000000  vsubsws v0, v0, v0
{     "vcmpgtsw . VREG , VREG , VREG",{0x10000786,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx11110000110  vcmpgtsw. v0, v0, v0
{        "vsumsws VREG , VREG , VREG",{0x10000788,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx11110001000  vsumsws v0, v0, v0
{      "vcmpbfp . VREG , VREG , VREG",{0x100007C6,0x03FFF800}}, // 000100xxxxxxxxxxxxxxx11111000110  vcmpbfp. v0, v0, v0
{             "mulli GPR , GPR , NUM",{0x1C000000,0x03FFFFFF}}, // 000111xxxxxxxxxxxxxxxxxxxxxxxxxx  mulli r0, r0, 0
{            "subfic GPR , GPR , NUM",{0x20000000,0x03FFFFFF}}, // 001000xxxxxxxxxxxxxxxxxxxxxxxxxx  subfic r0, r0, 0
{                  "cmplwi GPR , NUM",{0x28000000,0x001FFFFF}}, // 00101000000xxxxxxxxxxxxxxxxxxxxx  cmplwi r0, 0
{                  "cmpldi GPR , NUM",{0x28200000,0x001FFFFF}}, // 00101000001xxxxxxxxxxxxxxxxxxxxx  cmpldi r0, 0
{           "cmplwi CREG , GPR , NUM",{0x28800000,0x039FFFFF}}, // 001010xxx00xxxxxxxxxxxxxxxxxxxxx  cmplwi cr1, r0, 0
{           "cmpldi CREG , GPR , NUM",{0x28A00000,0x039FFFFF}}, // 001010xxx01xxxxxxxxxxxxxxxxxxxxx  cmpldi cr1, r0, 0
{                   "cmpwi GPR , NUM",{0x2C000000,0x001FFFFF}}, // 00101100000xxxxxxxxxxxxxxxxxxxxx  cmpwi r0, 0
{                   "cmpdi GPR , NUM",{0x2C200000,0x001FFFFF}}, // 00101100001xxxxxxxxxxxxxxxxxxxxx  cmpdi r0, 0
{            "cmpwi CREG , GPR , NUM",{0x2C800000,0x039FFFFF}}, // 001011xxx00xxxxxxxxxxxxxxxxxxxxx  cmpwi cr1, r0, 0
{            "cmpdi CREG , GPR , NUM",{0x2CA00000,0x039FFFFF}}, // 001011xxx01xxxxxxxxxxxxxxxxxxxxx  cmpdi cr1, r0, 0
{             "addic GPR , GPR , NUM",{0x30000000,0x03FFFFFF}}, // 001100xxxxxxxxxxxxxxxxxxxxxxxxxx  addic r0, r0, 0
{           "addic . GPR , GPR , NUM",{0x34000000,0x03FFFFFF}}, // 001101xxxxxxxxxxxxxxxxxxxxxxxxxx  addic. r0, r0, 0
{                      "li GPR , NUM",{0x38000000,0x03E0FFFF}}, // 001110xxxxx00000xxxxxxxxxxxxxxxx  li r0, 0
{              "addi GPR , GPR , NUM",{0x38010000,0x03FFFFFF}}, // 001110xxxxxxxxxxxxxxxxxxxxxxxxxx  addi r0, r1, 0
{                     "lis GPR , NUM",{0x3C000000,0x03E0FFFF}}, // 001111xxxxx00000xxxxxxxxxxxxxxxx  lis r0, 0
{             "addis GPR , GPR , NUM",{0x3C010000,0x03FFFFFF}}, // 001111xxxxxxxxxxxxxxxxxxxxxxxxxx  addis r0, r1, 0
{                        "bdnzf FLAG",{0x40000000,0x00230000}}, // 0100000000x000xx0000000000000000  bdnzf lt
{                       "bdnzfl FLAG",{0x40000001,0x00230000}}, // 0100000000x000xx0000000000000001  bdnzfl lt
{                       "bdnzfa FLAG",{0x40000002,0x00230000}}, // 0100000000x000xx0000000000000010  bdnzfa lt
{                      "bdnzfla FLAG",{0x40000003,0x00230000}}, // 0100000000x000xx0000000000000011  bdnzfla lt
{                  "bdnzf FLAG , NUM",{0x40000004,0x0023FFFC}}, // 0100000000x000xxxxxxxxxxxxxxxx00  bdnzf lt, 0x4
{                 "bdnzfl FLAG , NUM",{0x40000005,0x0023FFFC}}, // 0100000000x000xxxxxxxxxxxxxxxx01  bdnzfl lt, 0x4
{                 "bdnzfa FLAG , NUM",{0x40000006,0x0023FFFC}}, // 0100000000x000xxxxxxxxxxxxxxxx10  bdnzfa lt, 0x4
{                "bdnzfla FLAG , NUM",{0x40000007,0x0023FFFC}}, // 0100000000x000xxxxxxxxxxxxxxxx11  bdnzfla lt, 0x4
{           "bdnzf NUM * CREG + FLAG",{0x40040000,0x003F0000}}, // 0100000000xxxxxx0000000000000000  bdnzf 4*cr1+lt
{          "bdnzfl NUM * CREG + FLAG",{0x40040001,0x003F0000}}, // 0100000000xxxxxx0000000000000001  bdnzfl 4*cr1+lt
{          "bdnzfa NUM * CREG + FLAG",{0x40040002,0x003F0000}}, // 0100000000xxxxxx0000000000000010  bdnzfa 4*cr1+lt
{         "bdnzfla NUM * CREG + FLAG",{0x40040003,0x003F0000}}, // 0100000000xxxxxx0000000000000011  bdnzfla 4*cr1+lt
{     "bdnzf NUM * CREG + FLAG , NUM",{0x40040004,0x003FFFFC}}, // 0100000000xxxxxxxxxxxxxxxxxxxx00  bdnzf 4*cr1+lt, 0x4
{    "bdnzfl NUM * CREG + FLAG , NUM",{0x40040005,0x003FFFFC}}, // 0100000000xxxxxxxxxxxxxxxxxxxx01  bdnzfl 4*cr1+lt, 0x4
{    "bdnzfa NUM * CREG + FLAG , NUM",{0x40040006,0x003FFFFC}}, // 0100000000xxxxxxxxxxxxxxxxxxxx10  bdnzfa 4*cr1+lt, 0x4
{   "bdnzfla NUM * CREG + FLAG , NUM",{0x40040007,0x003FFFFC}}, // 0100000000xxxxxxxxxxxxxxxxxxxx11  bdnzfla 4*cr1+lt, 0x4
{                         "bdzf FLAG",{0x40400000,0x00230000}}, // 0100000001x000xx0000000000000000  bdzf lt
{                        "bdzfl FLAG",{0x40400001,0x00230000}}, // 0100000001x000xx0000000000000001  bdzfl lt
{                        "bdzfa FLAG",{0x40400002,0x00230000}}, // 0100000001x000xx0000000000000010  bdzfa lt
{                       "bdzfla FLAG",{0x40400003,0x00230000}}, // 0100000001x000xx0000000000000011  bdzfla lt
{                   "bdzf FLAG , NUM",{0x40400004,0x0023FFFC}}, // 0100000001x000xxxxxxxxxxxxxxxx00  bdzf lt, 0x4
{                  "bdzfl FLAG , NUM",{0x40400005,0x0023FFFC}}, // 0100000001x000xxxxxxxxxxxxxxxx01  bdzfl lt, 0x4
{                  "bdzfa FLAG , NUM",{0x40400006,0x0023FFFC}}, // 0100000001x000xxxxxxxxxxxxxxxx10  bdzfa lt, 0x4
{                 "bdzfla FLAG , NUM",{0x40400007,0x0023FFFC}}, // 0100000001x000xxxxxxxxxxxxxxxx11  bdzfla lt, 0x4
{            "bdzf NUM * CREG + FLAG",{0x40440000,0x003F0000}}, // 0100000001xxxxxx0000000000000000  bdzf 4*cr1+lt
{           "bdzfl NUM * CREG + FLAG",{0x40440001,0x003F0000}}, // 0100000001xxxxxx0000000000000001  bdzfl 4*cr1+lt
{           "bdzfa NUM * CREG + FLAG",{0x40440002,0x003F0000}}, // 0100000001xxxxxx0000000000000010  bdzfa 4*cr1+lt
{          "bdzfla NUM * CREG + FLAG",{0x40440003,0x003F0000}}, // 0100000001xxxxxx0000000000000011  bdzfla 4*cr1+lt
{      "bdzf NUM * CREG + FLAG , NUM",{0x40440004,0x003FFFFC}}, // 0100000001xxxxxxxxxxxxxxxxxxxx00  bdzf 4*cr1+lt, 0x4
{     "bdzfl NUM * CREG + FLAG , NUM",{0x40440005,0x003FFFFC}}, // 0100000001xxxxxxxxxxxxxxxxxxxx01  bdzfl 4*cr1+lt, 0x4
{     "bdzfa NUM * CREG + FLAG , NUM",{0x40440006,0x003FFFFC}}, // 0100000001xxxxxxxxxxxxxxxxxxxx10  bdzfa 4*cr1+lt, 0x4
{    "bdzfla NUM * CREG + FLAG , NUM",{0x40440007,0x003FFFFC}}, // 0100000001xxxxxxxxxxxxxxxxxxxx11  bdzfla 4*cr1+lt, 0x4
{                               "bge",{0x40800000,0x00200000}}, // 0100000010x000000000000000000000  bge
{                              "bgel",{0x40800001,0x00200000}}, // 0100000010x000000000000000000001  bgel
{                              "bgea",{0x40800002,0x00200000}}, // 0100000010x000000000000000000010  bgea
{                             "bgela",{0x40800003,0x00200000}}, // 0100000010x000000000000000000011  bgela
{                           "bge NUM",{0x40800004,0x0020FFFC}}, // 0100000010x00000xxxxxxxxxxxxxx00  bge 0x4
{                          "bgel NUM",{0x40800005,0x0020FFFC}}, // 0100000010x00000xxxxxxxxxxxxxx01  bgel 0x4
{                          "bgea NUM",{0x40800006,0x0020FFFC}}, // 0100000010x00000xxxxxxxxxxxxxx10  bgea 0x4
{                         "bgela NUM",{0x40800007,0x0020FFFC}}, // 0100000010x00000xxxxxxxxxxxxxx11  bgela 0x4
{                               "ble",{0x40810000,0x00200000}}, // 0100000010x000010000000000000000  ble
{                              "blel",{0x40810001,0x00200000}}, // 0100000010x000010000000000000001  blel
{                              "blea",{0x40810002,0x00200000}}, // 0100000010x000010000000000000010  blea
{                             "blela",{0x40810003,0x00200000}}, // 0100000010x000010000000000000011  blela
{                           "ble NUM",{0x40810004,0x0020FFFC}}, // 0100000010x00001xxxxxxxxxxxxxx00  ble 0x4
{                          "blel NUM",{0x40810005,0x0020FFFC}}, // 0100000010x00001xxxxxxxxxxxxxx01  blel 0x4
{                          "blea NUM",{0x40810006,0x0020FFFC}}, // 0100000010x00001xxxxxxxxxxxxxx10  blea 0x4
{                         "blela NUM",{0x40810007,0x0020FFFC}}, // 0100000010x00001xxxxxxxxxxxxxx11  blela 0x4
{                               "bne",{0x40820000,0x00200000}}, // 0100000010x000100000000000000000  bne
{                              "bnel",{0x40820001,0x00200000}}, // 0100000010x000100000000000000001  bnel
{                              "bnea",{0x40820002,0x00200000}}, // 0100000010x000100000000000000010  bnea
{                             "bnela",{0x40820003,0x00200000}}, // 0100000010x000100000000000000011  bnela
{                           "bne NUM",{0x40820004,0x0020FFFC}}, // 0100000010x00010xxxxxxxxxxxxxx00  bne 0x4
{                          "bnel NUM",{0x40820005,0x0020FFFC}}, // 0100000010x00010xxxxxxxxxxxxxx01  bnel 0x4
{                          "bnea NUM",{0x40820006,0x0020FFFC}}, // 0100000010x00010xxxxxxxxxxxxxx10  bnea 0x4
{                         "bnela NUM",{0x40820007,0x0020FFFC}}, // 0100000010x00010xxxxxxxxxxxxxx11  bnela 0x4
{                               "bns",{0x40830000,0x00200000}}, // 0100000010x000110000000000000000  bns
{                              "bnsl",{0x40830001,0x00200000}}, // 0100000010x000110000000000000001  bnsl
{                              "bnsa",{0x40830002,0x00200000}}, // 0100000010x000110000000000000010  bnsa
{                             "bnsla",{0x40830003,0x00200000}}, // 0100000010x000110000000000000011  bnsla
{                           "bns NUM",{0x40830004,0x0020FFFC}}, // 0100000010x00011xxxxxxxxxxxxxx00  bns 0x4
{                          "bnsl NUM",{0x40830005,0x0020FFFC}}, // 0100000010x00011xxxxxxxxxxxxxx01  bnsl 0x4
{                          "bnsa NUM",{0x40830006,0x0020FFFC}}, // 0100000010x00011xxxxxxxxxxxxxx10  bnsa 0x4
{                         "bnsla NUM",{0x40830007,0x0020FFFC}}, // 0100000010x00011xxxxxxxxxxxxxx11  bnsla 0x4
{                          "bge CREG",{0x40840000,0x003C0000}}, // 0100000010xxxx000000000000000000  bge cr1
{                         "bgel CREG",{0x40840001,0x003C0000}}, // 0100000010xxxx000000000000000001  bgel cr1
{                         "bgea CREG",{0x40840002,0x003C0000}}, // 0100000010xxxx000000000000000010  bgea cr1
{                        "bgela CREG",{0x40840003,0x003C0000}}, // 0100000010xxxx000000000000000011  bgela cr1
{                    "bge CREG , NUM",{0x40840004,0x003CFFFC}}, // 0100000010xxxx00xxxxxxxxxxxxxx00  bge cr1, 0x4
{                   "bgel CREG , NUM",{0x40840005,0x003CFFFC}}, // 0100000010xxxx00xxxxxxxxxxxxxx01  bgel cr1, 0x4
{                   "bgea CREG , NUM",{0x40840006,0x003CFFFC}}, // 0100000010xxxx00xxxxxxxxxxxxxx10  bgea cr1, 0x4
{                  "bgela CREG , NUM",{0x40840007,0x003CFFFC}}, // 0100000010xxxx00xxxxxxxxxxxxxx11  bgela cr1, 0x4
{                          "ble CREG",{0x40850000,0x003C0000}}, // 0100000010xxxx010000000000000000  ble cr1
{                         "blel CREG",{0x40850001,0x003C0000}}, // 0100000010xxxx010000000000000001  blel cr1
{                         "blea CREG",{0x40850002,0x003C0000}}, // 0100000010xxxx010000000000000010  blea cr1
{                        "blela CREG",{0x40850003,0x003C0000}}, // 0100000010xxxx010000000000000011  blela cr1
{                    "ble CREG , NUM",{0x40850004,0x003CFFFC}}, // 0100000010xxxx01xxxxxxxxxxxxxx00  ble cr1, 0x4
{                   "blel CREG , NUM",{0x40850005,0x003CFFFC}}, // 0100000010xxxx01xxxxxxxxxxxxxx01  blel cr1, 0x4
{                   "blea CREG , NUM",{0x40850006,0x003CFFFC}}, // 0100000010xxxx01xxxxxxxxxxxxxx10  blea cr1, 0x4
{                  "blela CREG , NUM",{0x40850007,0x003CFFFC}}, // 0100000010xxxx01xxxxxxxxxxxxxx11  blela cr1, 0x4
{                          "bne CREG",{0x40860000,0x003C0000}}, // 0100000010xxxx100000000000000000  bne cr1
{                         "bnel CREG",{0x40860001,0x003C0000}}, // 0100000010xxxx100000000000000001  bnel cr1
{                         "bnea CREG",{0x40860002,0x003C0000}}, // 0100000010xxxx100000000000000010  bnea cr1
{                        "bnela CREG",{0x40860003,0x003C0000}}, // 0100000010xxxx100000000000000011  bnela cr1
{                    "bne CREG , NUM",{0x40860004,0x003CFFFC}}, // 0100000010xxxx10xxxxxxxxxxxxxx00  bne cr1, 0x4
{                   "bnel CREG , NUM",{0x40860005,0x003CFFFC}}, // 0100000010xxxx10xxxxxxxxxxxxxx01  bnel cr1, 0x4
{                   "bnea CREG , NUM",{0x40860006,0x003CFFFC}}, // 0100000010xxxx10xxxxxxxxxxxxxx10  bnea cr1, 0x4
{                  "bnela CREG , NUM",{0x40860007,0x003CFFFC}}, // 0100000010xxxx10xxxxxxxxxxxxxx11  bnela cr1, 0x4
{                          "bns CREG",{0x40870000,0x003C0000}}, // 0100000010xxxx110000000000000000  bns cr1
{                         "bnsl CREG",{0x40870001,0x003C0000}}, // 0100000010xxxx110000000000000001  bnsl cr1
{                         "bnsa CREG",{0x40870002,0x003C0000}}, // 0100000010xxxx110000000000000010  bnsa cr1
{                        "bnsla CREG",{0x40870003,0x003C0000}}, // 0100000010xxxx110000000000000011  bnsla cr1
{                    "bns CREG , NUM",{0x40870004,0x003CFFFC}}, // 0100000010xxxx11xxxxxxxxxxxxxx00  bns cr1, 0x4
{                   "bnsl CREG , NUM",{0x40870005,0x003CFFFC}}, // 0100000010xxxx11xxxxxxxxxxxxxx01  bnsl cr1, 0x4
{                   "bnsa CREG , NUM",{0x40870006,0x003CFFFC}}, // 0100000010xxxx11xxxxxxxxxxxxxx10  bnsa cr1, 0x4
{                  "bnsla CREG , NUM",{0x40870007,0x003CFFFC}}, // 0100000010xxxx11xxxxxxxxxxxxxx11  bnsla cr1, 0x4
{                             "bge -",{0x40C00000,0x00000000}}, // 01000000110000000000000000000000  bge-
{                            "bgel -",{0x40C00001,0x00000000}}, // 01000000110000000000000000000001  bgel-
{                            "bgea -",{0x40C00002,0x00000000}}, // 01000000110000000000000000000010  bgea-
{                           "bgela -",{0x40C00003,0x00000000}}, // 01000000110000000000000000000011  bgela-
{                         "bge - NUM",{0x40C00004,0x0000FFFC}}, // 0100000011000000xxxxxxxxxxxxxx00  bge- 0x4
{                        "bgel - NUM",{0x40C00005,0x0000FFFC}}, // 0100000011000000xxxxxxxxxxxxxx01  bgel- 0x4
{                        "bgea - NUM",{0x40C00006,0x0000FFFC}}, // 0100000011000000xxxxxxxxxxxxxx10  bgea- 0x4
{                       "bgela - NUM",{0x40C00007,0x0000FFFC}}, // 0100000011000000xxxxxxxxxxxxxx11  bgela- 0x4
{                             "ble -",{0x40C10000,0x00000000}}, // 01000000110000010000000000000000  ble-
{                            "blel -",{0x40C10001,0x00000000}}, // 01000000110000010000000000000001  blel-
{                            "blea -",{0x40C10002,0x00000000}}, // 01000000110000010000000000000010  blea-
{                           "blela -",{0x40C10003,0x00000000}}, // 01000000110000010000000000000011  blela-
{                         "ble - NUM",{0x40C10004,0x0000FFFC}}, // 0100000011000001xxxxxxxxxxxxxx00  ble- 0x4
{                        "blel - NUM",{0x40C10005,0x0000FFFC}}, // 0100000011000001xxxxxxxxxxxxxx01  blel- 0x4
{                        "blea - NUM",{0x40C10006,0x0000FFFC}}, // 0100000011000001xxxxxxxxxxxxxx10  blea- 0x4
{                       "blela - NUM",{0x40C10007,0x0000FFFC}}, // 0100000011000001xxxxxxxxxxxxxx11  blela- 0x4
{                             "bne -",{0x40C20000,0x00000000}}, // 01000000110000100000000000000000  bne-
{                            "bnel -",{0x40C20001,0x00000000}}, // 01000000110000100000000000000001  bnel-
{                            "bnea -",{0x40C20002,0x00000000}}, // 01000000110000100000000000000010  bnea-
{                           "bnela -",{0x40C20003,0x00000000}}, // 01000000110000100000000000000011  bnela-
{                         "bne - NUM",{0x40C20004,0x0000FFFC}}, // 0100000011000010xxxxxxxxxxxxxx00  bne- 0x4
{                        "bnel - NUM",{0x40C20005,0x0000FFFC}}, // 0100000011000010xxxxxxxxxxxxxx01  bnel- 0x4
{                        "bnea - NUM",{0x40C20006,0x0000FFFC}}, // 0100000011000010xxxxxxxxxxxxxx10  bnea- 0x4
{                       "bnela - NUM",{0x40C20007,0x0000FFFC}}, // 0100000011000010xxxxxxxxxxxxxx11  bnela- 0x4
{                             "bns -",{0x40C30000,0x00000000}}, // 01000000110000110000000000000000  bns-
{                            "bnsl -",{0x40C30001,0x00000000}}, // 01000000110000110000000000000001  bnsl-
{                            "bnsa -",{0x40C30002,0x00000000}}, // 01000000110000110000000000000010  bnsa-
{                           "bnsla -",{0x40C30003,0x00000000}}, // 01000000110000110000000000000011  bnsla-
{                         "bns - NUM",{0x40C30004,0x0000FFFC}}, // 0100000011000011xxxxxxxxxxxxxx00  bns- 0x4
{                        "bnsl - NUM",{0x40C30005,0x0000FFFC}}, // 0100000011000011xxxxxxxxxxxxxx01  bnsl- 0x4
{                        "bnsa - NUM",{0x40C30006,0x0000FFFC}}, // 0100000011000011xxxxxxxxxxxxxx10  bnsa- 0x4
{                       "bnsla - NUM",{0x40C30007,0x0000FFFC}}, // 0100000011000011xxxxxxxxxxxxxx11  bnsla- 0x4
{                        "bge - CREG",{0x40C40000,0x001C0000}}, // 01000000110xxx000000000000000000  bge- cr1
{                       "bgel - CREG",{0x40C40001,0x001C0000}}, // 01000000110xxx000000000000000001  bgel- cr1
{                       "bgea - CREG",{0x40C40002,0x001C0000}}, // 01000000110xxx000000000000000010  bgea- cr1
{                      "bgela - CREG",{0x40C40003,0x001C0000}}, // 01000000110xxx000000000000000011  bgela- cr1
{                  "bge - CREG , NUM",{0x40C40004,0x001CFFFC}}, // 01000000110xxx00xxxxxxxxxxxxxx00  bge- cr1, 0x4
{                 "bgel - CREG , NUM",{0x40C40005,0x001CFFFC}}, // 01000000110xxx00xxxxxxxxxxxxxx01  bgel- cr1, 0x4
{                 "bgea - CREG , NUM",{0x40C40006,0x001CFFFC}}, // 01000000110xxx00xxxxxxxxxxxxxx10  bgea- cr1, 0x4
{                "bgela - CREG , NUM",{0x40C40007,0x001CFFFC}}, // 01000000110xxx00xxxxxxxxxxxxxx11  bgela- cr1, 0x4
{                        "ble - CREG",{0x40C50000,0x001C0000}}, // 01000000110xxx010000000000000000  ble- cr1
{                       "blel - CREG",{0x40C50001,0x001C0000}}, // 01000000110xxx010000000000000001  blel- cr1
{                       "blea - CREG",{0x40C50002,0x001C0000}}, // 01000000110xxx010000000000000010  blea- cr1
{                      "blela - CREG",{0x40C50003,0x001C0000}}, // 01000000110xxx010000000000000011  blela- cr1
{                  "ble - CREG , NUM",{0x40C50004,0x001CFFFC}}, // 01000000110xxx01xxxxxxxxxxxxxx00  ble- cr1, 0x4
{                 "blel - CREG , NUM",{0x40C50005,0x001CFFFC}}, // 01000000110xxx01xxxxxxxxxxxxxx01  blel- cr1, 0x4
{                 "blea - CREG , NUM",{0x40C50006,0x001CFFFC}}, // 01000000110xxx01xxxxxxxxxxxxxx10  blea- cr1, 0x4
{                "blela - CREG , NUM",{0x40C50007,0x001CFFFC}}, // 01000000110xxx01xxxxxxxxxxxxxx11  blela- cr1, 0x4
{                        "bne - CREG",{0x40C60000,0x001C0000}}, // 01000000110xxx100000000000000000  bne- cr1
{                       "bnel - CREG",{0x40C60001,0x001C0000}}, // 01000000110xxx100000000000000001  bnel- cr1
{                       "bnea - CREG",{0x40C60002,0x001C0000}}, // 01000000110xxx100000000000000010  bnea- cr1
{                      "bnela - CREG",{0x40C60003,0x001C0000}}, // 01000000110xxx100000000000000011  bnela- cr1
{                  "bne - CREG , NUM",{0x40C60004,0x001CFFFC}}, // 01000000110xxx10xxxxxxxxxxxxxx00  bne- cr1, 0x4
{                 "bnel - CREG , NUM",{0x40C60005,0x001CFFFC}}, // 01000000110xxx10xxxxxxxxxxxxxx01  bnel- cr1, 0x4
{                 "bnea - CREG , NUM",{0x40C60006,0x001CFFFC}}, // 01000000110xxx10xxxxxxxxxxxxxx10  bnea- cr1, 0x4
{                "bnela - CREG , NUM",{0x40C60007,0x001CFFFC}}, // 01000000110xxx10xxxxxxxxxxxxxx11  bnela- cr1, 0x4
{                        "bns - CREG",{0x40C70000,0x001C0000}}, // 01000000110xxx110000000000000000  bns- cr1
{                       "bnsl - CREG",{0x40C70001,0x001C0000}}, // 01000000110xxx110000000000000001  bnsl- cr1
{                       "bnsa - CREG",{0x40C70002,0x001C0000}}, // 01000000110xxx110000000000000010  bnsa- cr1
{                      "bnsla - CREG",{0x40C70003,0x001C0000}}, // 01000000110xxx110000000000000011  bnsla- cr1
{                  "bns - CREG , NUM",{0x40C70004,0x001CFFFC}}, // 01000000110xxx11xxxxxxxxxxxxxx00  bns- cr1, 0x4
{                 "bnsl - CREG , NUM",{0x40C70005,0x001CFFFC}}, // 01000000110xxx11xxxxxxxxxxxxxx01  bnsl- cr1, 0x4
{                 "bnsa - CREG , NUM",{0x40C70006,0x001CFFFC}}, // 01000000110xxx11xxxxxxxxxxxxxx10  bnsa- cr1, 0x4
{                "bnsla - CREG , NUM",{0x40C70007,0x001CFFFC}}, // 01000000110xxx11xxxxxxxxxxxxxx11  bnsla- cr1, 0x4
{                             "bge +",{0x40E00000,0x00000000}}, // 01000000111000000000000000000000  bge+
{                            "bgel +",{0x40E00001,0x00000000}}, // 01000000111000000000000000000001  bgel+
{                            "bgea +",{0x40E00002,0x00000000}}, // 01000000111000000000000000000010  bgea+
{                           "bgela +",{0x40E00003,0x00000000}}, // 01000000111000000000000000000011  bgela+
{                         "bge + NUM",{0x40E00004,0x0000FFFC}}, // 0100000011100000xxxxxxxxxxxxxx00  bge+ 0x4
{                        "bgel + NUM",{0x40E00005,0x0000FFFC}}, // 0100000011100000xxxxxxxxxxxxxx01  bgel+ 0x4
{                        "bgea + NUM",{0x40E00006,0x0000FFFC}}, // 0100000011100000xxxxxxxxxxxxxx10  bgea+ 0x4
{                       "bgela + NUM",{0x40E00007,0x0000FFFC}}, // 0100000011100000xxxxxxxxxxxxxx11  bgela+ 0x4
{                             "ble +",{0x40E10000,0x00000000}}, // 01000000111000010000000000000000  ble+
{                            "blel +",{0x40E10001,0x00000000}}, // 01000000111000010000000000000001  blel+
{                            "blea +",{0x40E10002,0x00000000}}, // 01000000111000010000000000000010  blea+
{                           "blela +",{0x40E10003,0x00000000}}, // 01000000111000010000000000000011  blela+
{                         "ble + NUM",{0x40E10004,0x0000FFFC}}, // 0100000011100001xxxxxxxxxxxxxx00  ble+ 0x4
{                        "blel + NUM",{0x40E10005,0x0000FFFC}}, // 0100000011100001xxxxxxxxxxxxxx01  blel+ 0x4
{                        "blea + NUM",{0x40E10006,0x0000FFFC}}, // 0100000011100001xxxxxxxxxxxxxx10  blea+ 0x4
{                       "blela + NUM",{0x40E10007,0x0000FFFC}}, // 0100000011100001xxxxxxxxxxxxxx11  blela+ 0x4
{                             "bne +",{0x40E20000,0x00000000}}, // 01000000111000100000000000000000  bne+
{                            "bnel +",{0x40E20001,0x00000000}}, // 01000000111000100000000000000001  bnel+
{                            "bnea +",{0x40E20002,0x00000000}}, // 01000000111000100000000000000010  bnea+
{                           "bnela +",{0x40E20003,0x00000000}}, // 01000000111000100000000000000011  bnela+
{                         "bne + NUM",{0x40E20004,0x0000FFFC}}, // 0100000011100010xxxxxxxxxxxxxx00  bne+ 0x4
{                        "bnel + NUM",{0x40E20005,0x0000FFFC}}, // 0100000011100010xxxxxxxxxxxxxx01  bnel+ 0x4
{                        "bnea + NUM",{0x40E20006,0x0000FFFC}}, // 0100000011100010xxxxxxxxxxxxxx10  bnea+ 0x4
{                       "bnela + NUM",{0x40E20007,0x0000FFFC}}, // 0100000011100010xxxxxxxxxxxxxx11  bnela+ 0x4
{                             "bns +",{0x40E30000,0x00000000}}, // 01000000111000110000000000000000  bns+
{                            "bnsl +",{0x40E30001,0x00000000}}, // 01000000111000110000000000000001  bnsl+
{                            "bnsa +",{0x40E30002,0x00000000}}, // 01000000111000110000000000000010  bnsa+
{                           "bnsla +",{0x40E30003,0x00000000}}, // 01000000111000110000000000000011  bnsla+
{                         "bns + NUM",{0x40E30004,0x0000FFFC}}, // 0100000011100011xxxxxxxxxxxxxx00  bns+ 0x4
{                        "bnsl + NUM",{0x40E30005,0x0000FFFC}}, // 0100000011100011xxxxxxxxxxxxxx01  bnsl+ 0x4
{                        "bnsa + NUM",{0x40E30006,0x0000FFFC}}, // 0100000011100011xxxxxxxxxxxxxx10  bnsa+ 0x4
{                       "bnsla + NUM",{0x40E30007,0x0000FFFC}}, // 0100000011100011xxxxxxxxxxxxxx11  bnsla+ 0x4
{                        "bge + CREG",{0x40E40000,0x001C0000}}, // 01000000111xxx000000000000000000  bge+ cr1
{                       "bgel + CREG",{0x40E40001,0x001C0000}}, // 01000000111xxx000000000000000001  bgel+ cr1
{                       "bgea + CREG",{0x40E40002,0x001C0000}}, // 01000000111xxx000000000000000010  bgea+ cr1
{                      "bgela + CREG",{0x40E40003,0x001C0000}}, // 01000000111xxx000000000000000011  bgela+ cr1
{                  "bge + CREG , NUM",{0x40E40004,0x001CFFFC}}, // 01000000111xxx00xxxxxxxxxxxxxx00  bge+ cr1, 0x4
{                 "bgel + CREG , NUM",{0x40E40005,0x001CFFFC}}, // 01000000111xxx00xxxxxxxxxxxxxx01  bgel+ cr1, 0x4
{                 "bgea + CREG , NUM",{0x40E40006,0x001CFFFC}}, // 01000000111xxx00xxxxxxxxxxxxxx10  bgea+ cr1, 0x4
{                "bgela + CREG , NUM",{0x40E40007,0x001CFFFC}}, // 01000000111xxx00xxxxxxxxxxxxxx11  bgela+ cr1, 0x4
{                        "ble + CREG",{0x40E50000,0x001C0000}}, // 01000000111xxx010000000000000000  ble+ cr1
{                       "blel + CREG",{0x40E50001,0x001C0000}}, // 01000000111xxx010000000000000001  blel+ cr1
{                       "blea + CREG",{0x40E50002,0x001C0000}}, // 01000000111xxx010000000000000010  blea+ cr1
{                      "blela + CREG",{0x40E50003,0x001C0000}}, // 01000000111xxx010000000000000011  blela+ cr1
{                  "ble + CREG , NUM",{0x40E50004,0x001CFFFC}}, // 01000000111xxx01xxxxxxxxxxxxxx00  ble+ cr1, 0x4
{                 "blel + CREG , NUM",{0x40E50005,0x001CFFFC}}, // 01000000111xxx01xxxxxxxxxxxxxx01  blel+ cr1, 0x4
{                 "blea + CREG , NUM",{0x40E50006,0x001CFFFC}}, // 01000000111xxx01xxxxxxxxxxxxxx10  blea+ cr1, 0x4
{                "blela + CREG , NUM",{0x40E50007,0x001CFFFC}}, // 01000000111xxx01xxxxxxxxxxxxxx11  blela+ cr1, 0x4
{                        "bne + CREG",{0x40E60000,0x001C0000}}, // 01000000111xxx100000000000000000  bne+ cr1
{                       "bnel + CREG",{0x40E60001,0x001C0000}}, // 01000000111xxx100000000000000001  bnel+ cr1
{                       "bnea + CREG",{0x40E60002,0x001C0000}}, // 01000000111xxx100000000000000010  bnea+ cr1
{                      "bnela + CREG",{0x40E60003,0x001C0000}}, // 01000000111xxx100000000000000011  bnela+ cr1
{                  "bne + CREG , NUM",{0x40E60004,0x001CFFFC}}, // 01000000111xxx10xxxxxxxxxxxxxx00  bne+ cr1, 0x4
{                 "bnel + CREG , NUM",{0x40E60005,0x001CFFFC}}, // 01000000111xxx10xxxxxxxxxxxxxx01  bnel+ cr1, 0x4
{                 "bnea + CREG , NUM",{0x40E60006,0x001CFFFC}}, // 01000000111xxx10xxxxxxxxxxxxxx10  bnea+ cr1, 0x4
{                "bnela + CREG , NUM",{0x40E60007,0x001CFFFC}}, // 01000000111xxx10xxxxxxxxxxxxxx11  bnela+ cr1, 0x4
{                        "bns + CREG",{0x40E70000,0x001C0000}}, // 01000000111xxx110000000000000000  bns+ cr1
{                       "bnsl + CREG",{0x40E70001,0x001C0000}}, // 01000000111xxx110000000000000001  bnsl+ cr1
{                       "bnsa + CREG",{0x40E70002,0x001C0000}}, // 01000000111xxx110000000000000010  bnsa+ cr1
{                      "bnsla + CREG",{0x40E70003,0x001C0000}}, // 01000000111xxx110000000000000011  bnsla+ cr1
{                  "bns + CREG , NUM",{0x40E70004,0x001CFFFC}}, // 01000000111xxx11xxxxxxxxxxxxxx00  bns+ cr1, 0x4
{                 "bnsl + CREG , NUM",{0x40E70005,0x001CFFFC}}, // 01000000111xxx11xxxxxxxxxxxxxx01  bnsl+ cr1, 0x4
{                 "bnsa + CREG , NUM",{0x40E70006,0x001CFFFC}}, // 01000000111xxx11xxxxxxxxxxxxxx10  bnsa+ cr1, 0x4
{                "bnsla + CREG , NUM",{0x40E70007,0x001CFFFC}}, // 01000000111xxx11xxxxxxxxxxxxxx11  bnsla+ cr1, 0x4
{                        "bdnzt FLAG",{0x41000000,0x00230000}}, // 0100000100x000xx0000000000000000  bdnzt lt
{                       "bdnztl FLAG",{0x41000001,0x00230000}}, // 0100000100x000xx0000000000000001  bdnztl lt
{                       "bdnzta FLAG",{0x41000002,0x00230000}}, // 0100000100x000xx0000000000000010  bdnzta lt
{                      "bdnztla FLAG",{0x41000003,0x00230000}}, // 0100000100x000xx0000000000000011  bdnztla lt
{                  "bdnzt FLAG , NUM",{0x41000004,0x0023FFFC}}, // 0100000100x000xxxxxxxxxxxxxxxx00  bdnzt lt, 0x4
{                 "bdnztl FLAG , NUM",{0x41000005,0x0023FFFC}}, // 0100000100x000xxxxxxxxxxxxxxxx01  bdnztl lt, 0x4
{                 "bdnzta FLAG , NUM",{0x41000006,0x0023FFFC}}, // 0100000100x000xxxxxxxxxxxxxxxx10  bdnzta lt, 0x4
{                "bdnztla FLAG , NUM",{0x41000007,0x0023FFFC}}, // 0100000100x000xxxxxxxxxxxxxxxx11  bdnztla lt, 0x4
{           "bdnzt NUM * CREG + FLAG",{0x41040000,0x003F0000}}, // 0100000100xxxxxx0000000000000000  bdnzt 4*cr1+lt
{          "bdnztl NUM * CREG + FLAG",{0x41040001,0x003F0000}}, // 0100000100xxxxxx0000000000000001  bdnztl 4*cr1+lt
{          "bdnzta NUM * CREG + FLAG",{0x41040002,0x003F0000}}, // 0100000100xxxxxx0000000000000010  bdnzta 4*cr1+lt
{         "bdnztla NUM * CREG + FLAG",{0x41040003,0x003F0000}}, // 0100000100xxxxxx0000000000000011  bdnztla 4*cr1+lt
{     "bdnzt NUM * CREG + FLAG , NUM",{0x41040004,0x003FFFFC}}, // 0100000100xxxxxxxxxxxxxxxxxxxx00  bdnzt 4*cr1+lt, 0x4
{    "bdnztl NUM * CREG + FLAG , NUM",{0x41040005,0x003FFFFC}}, // 0100000100xxxxxxxxxxxxxxxxxxxx01  bdnztl 4*cr1+lt, 0x4
{    "bdnzta NUM * CREG + FLAG , NUM",{0x41040006,0x003FFFFC}}, // 0100000100xxxxxxxxxxxxxxxxxxxx10  bdnzta 4*cr1+lt, 0x4
{   "bdnztla NUM * CREG + FLAG , NUM",{0x41040007,0x003FFFFC}}, // 0100000100xxxxxxxxxxxxxxxxxxxx11  bdnztla 4*cr1+lt, 0x4
{                         "bdzt FLAG",{0x41400000,0x00230000}}, // 0100000101x000xx0000000000000000  bdzt lt
{                        "bdztl FLAG",{0x41400001,0x00230000}}, // 0100000101x000xx0000000000000001  bdztl lt
{                        "bdzta FLAG",{0x41400002,0x00230000}}, // 0100000101x000xx0000000000000010  bdzta lt
{                       "bdztla FLAG",{0x41400003,0x00230000}}, // 0100000101x000xx0000000000000011  bdztla lt
{                   "bdzt FLAG , NUM",{0x41400004,0x0023FFFC}}, // 0100000101x000xxxxxxxxxxxxxxxx00  bdzt lt, 0x4
{                  "bdztl FLAG , NUM",{0x41400005,0x0023FFFC}}, // 0100000101x000xxxxxxxxxxxxxxxx01  bdztl lt, 0x4
{                  "bdzta FLAG , NUM",{0x41400006,0x0023FFFC}}, // 0100000101x000xxxxxxxxxxxxxxxx10  bdzta lt, 0x4
{                 "bdztla FLAG , NUM",{0x41400007,0x0023FFFC}}, // 0100000101x000xxxxxxxxxxxxxxxx11  bdztla lt, 0x4
{            "bdzt NUM * CREG + FLAG",{0x41440000,0x003F0000}}, // 0100000101xxxxxx0000000000000000  bdzt 4*cr1+lt
{           "bdztl NUM * CREG + FLAG",{0x41440001,0x003F0000}}, // 0100000101xxxxxx0000000000000001  bdztl 4*cr1+lt
{           "bdzta NUM * CREG + FLAG",{0x41440002,0x003F0000}}, // 0100000101xxxxxx0000000000000010  bdzta 4*cr1+lt
{          "bdztla NUM * CREG + FLAG",{0x41440003,0x003F0000}}, // 0100000101xxxxxx0000000000000011  bdztla 4*cr1+lt
{      "bdzt NUM * CREG + FLAG , NUM",{0x41440004,0x003FFFFC}}, // 0100000101xxxxxxxxxxxxxxxxxxxx00  bdzt 4*cr1+lt, 0x4
{     "bdztl NUM * CREG + FLAG , NUM",{0x41440005,0x003FFFFC}}, // 0100000101xxxxxxxxxxxxxxxxxxxx01  bdztl 4*cr1+lt, 0x4
{     "bdzta NUM * CREG + FLAG , NUM",{0x41440006,0x003FFFFC}}, // 0100000101xxxxxxxxxxxxxxxxxxxx10  bdzta 4*cr1+lt, 0x4
{    "bdztla NUM * CREG + FLAG , NUM",{0x41440007,0x003FFFFC}}, // 0100000101xxxxxxxxxxxxxxxxxxxx11  bdztla 4*cr1+lt, 0x4
{                               "blt",{0x41800000,0x00200000}}, // 0100000110x000000000000000000000  blt
{                              "bltl",{0x41800001,0x00200000}}, // 0100000110x000000000000000000001  bltl
{                              "blta",{0x41800002,0x00200000}}, // 0100000110x000000000000000000010  blta
{                             "bltla",{0x41800003,0x00200000}}, // 0100000110x000000000000000000011  bltla
{                           "blt NUM",{0x41800004,0x0020FFFC}}, // 0100000110x00000xxxxxxxxxxxxxx00  blt 0x4
{                          "bltl NUM",{0x41800005,0x0020FFFC}}, // 0100000110x00000xxxxxxxxxxxxxx01  bltl 0x4
{                          "blta NUM",{0x41800006,0x0020FFFC}}, // 0100000110x00000xxxxxxxxxxxxxx10  blta 0x4
{                         "bltla NUM",{0x41800007,0x0020FFFC}}, // 0100000110x00000xxxxxxxxxxxxxx11  bltla 0x4
{                               "bgt",{0x41810000,0x00200000}}, // 0100000110x000010000000000000000  bgt
{                              "bgtl",{0x41810001,0x00200000}}, // 0100000110x000010000000000000001  bgtl
{                              "bgta",{0x41810002,0x00200000}}, // 0100000110x000010000000000000010  bgta
{                             "bgtla",{0x41810003,0x00200000}}, // 0100000110x000010000000000000011  bgtla
{                           "bgt NUM",{0x41810004,0x0020FFFC}}, // 0100000110x00001xxxxxxxxxxxxxx00  bgt 0x4
{                          "bgtl NUM",{0x41810005,0x0020FFFC}}, // 0100000110x00001xxxxxxxxxxxxxx01  bgtl 0x4
{                          "bgta NUM",{0x41810006,0x0020FFFC}}, // 0100000110x00001xxxxxxxxxxxxxx10  bgta 0x4
{                         "bgtla NUM",{0x41810007,0x0020FFFC}}, // 0100000110x00001xxxxxxxxxxxxxx11  bgtla 0x4
{                               "beq",{0x41820000,0x00200000}}, // 0100000110x000100000000000000000  beq
{                              "beql",{0x41820001,0x00200000}}, // 0100000110x000100000000000000001  beql
{                              "beqa",{0x41820002,0x00200000}}, // 0100000110x000100000000000000010  beqa
{                             "beqla",{0x41820003,0x00200000}}, // 0100000110x000100000000000000011  beqla
{                           "beq NUM",{0x41820004,0x0020FFFC}}, // 0100000110x00010xxxxxxxxxxxxxx00  beq 0x4
{                          "beql NUM",{0x41820005,0x0020FFFC}}, // 0100000110x00010xxxxxxxxxxxxxx01  beql 0x4
{                          "beqa NUM",{0x41820006,0x0020FFFC}}, // 0100000110x00010xxxxxxxxxxxxxx10  beqa 0x4
{                         "beqla NUM",{0x41820007,0x0020FFFC}}, // 0100000110x00010xxxxxxxxxxxxxx11  beqla 0x4
{                               "bso",{0x41830000,0x00200000}}, // 0100000110x000110000000000000000  bso
{                              "bsol",{0x41830001,0x00200000}}, // 0100000110x000110000000000000001  bsol
{                              "bsoa",{0x41830002,0x00200000}}, // 0100000110x000110000000000000010  bsoa
{                             "bsola",{0x41830003,0x00200000}}, // 0100000110x000110000000000000011  bsola
{                           "bso NUM",{0x41830004,0x0020FFFC}}, // 0100000110x00011xxxxxxxxxxxxxx00  bso 0x4
{                          "bsol NUM",{0x41830005,0x0020FFFC}}, // 0100000110x00011xxxxxxxxxxxxxx01  bsol 0x4
{                          "bsoa NUM",{0x41830006,0x0020FFFC}}, // 0100000110x00011xxxxxxxxxxxxxx10  bsoa 0x4
{                         "bsola NUM",{0x41830007,0x0020FFFC}}, // 0100000110x00011xxxxxxxxxxxxxx11  bsola 0x4
{                          "blt CREG",{0x41840000,0x003C0000}}, // 0100000110xxxx000000000000000000  blt cr1
{                         "bltl CREG",{0x41840001,0x003C0000}}, // 0100000110xxxx000000000000000001  bltl cr1
{                         "blta CREG",{0x41840002,0x003C0000}}, // 0100000110xxxx000000000000000010  blta cr1
{                        "bltla CREG",{0x41840003,0x003C0000}}, // 0100000110xxxx000000000000000011  bltla cr1
{                    "blt CREG , NUM",{0x41840004,0x003CFFFC}}, // 0100000110xxxx00xxxxxxxxxxxxxx00  blt cr1, 0x4
{                   "bltl CREG , NUM",{0x41840005,0x003CFFFC}}, // 0100000110xxxx00xxxxxxxxxxxxxx01  bltl cr1, 0x4
{                   "blta CREG , NUM",{0x41840006,0x003CFFFC}}, // 0100000110xxxx00xxxxxxxxxxxxxx10  blta cr1, 0x4
{                  "bltla CREG , NUM",{0x41840007,0x003CFFFC}}, // 0100000110xxxx00xxxxxxxxxxxxxx11  bltla cr1, 0x4
{                          "bgt CREG",{0x41850000,0x003C0000}}, // 0100000110xxxx010000000000000000  bgt cr1
{                         "bgtl CREG",{0x41850001,0x003C0000}}, // 0100000110xxxx010000000000000001  bgtl cr1
{                         "bgta CREG",{0x41850002,0x003C0000}}, // 0100000110xxxx010000000000000010  bgta cr1
{                        "bgtla CREG",{0x41850003,0x003C0000}}, // 0100000110xxxx010000000000000011  bgtla cr1
{                    "bgt CREG , NUM",{0x41850004,0x003CFFFC}}, // 0100000110xxxx01xxxxxxxxxxxxxx00  bgt cr1, 0x4
{                   "bgtl CREG , NUM",{0x41850005,0x003CFFFC}}, // 0100000110xxxx01xxxxxxxxxxxxxx01  bgtl cr1, 0x4
{                   "bgta CREG , NUM",{0x41850006,0x003CFFFC}}, // 0100000110xxxx01xxxxxxxxxxxxxx10  bgta cr1, 0x4
{                  "bgtla CREG , NUM",{0x41850007,0x003CFFFC}}, // 0100000110xxxx01xxxxxxxxxxxxxx11  bgtla cr1, 0x4
{                          "beq CREG",{0x41860000,0x003C0000}}, // 0100000110xxxx100000000000000000  beq cr1
{                         "beql CREG",{0x41860001,0x003C0000}}, // 0100000110xxxx100000000000000001  beql cr1
{                         "beqa CREG",{0x41860002,0x003C0000}}, // 0100000110xxxx100000000000000010  beqa cr1
{                        "beqla CREG",{0x41860003,0x003C0000}}, // 0100000110xxxx100000000000000011  beqla cr1
{                    "beq CREG , NUM",{0x41860004,0x003CFFFC}}, // 0100000110xxxx10xxxxxxxxxxxxxx00  beq cr1, 0x4
{                   "beql CREG , NUM",{0x41860005,0x003CFFFC}}, // 0100000110xxxx10xxxxxxxxxxxxxx01  beql cr1, 0x4
{                   "beqa CREG , NUM",{0x41860006,0x003CFFFC}}, // 0100000110xxxx10xxxxxxxxxxxxxx10  beqa cr1, 0x4
{                  "beqla CREG , NUM",{0x41860007,0x003CFFFC}}, // 0100000110xxxx10xxxxxxxxxxxxxx11  beqla cr1, 0x4
{                          "bso CREG",{0x41870000,0x003C0000}}, // 0100000110xxxx110000000000000000  bso cr1
{                         "bsol CREG",{0x41870001,0x003C0000}}, // 0100000110xxxx110000000000000001  bsol cr1
{                         "bsoa CREG",{0x41870002,0x003C0000}}, // 0100000110xxxx110000000000000010  bsoa cr1
{                        "bsola CREG",{0x41870003,0x003C0000}}, // 0100000110xxxx110000000000000011  bsola cr1
{                    "bso CREG , NUM",{0x41870004,0x003CFFFC}}, // 0100000110xxxx11xxxxxxxxxxxxxx00  bso cr1, 0x4
{                   "bsol CREG , NUM",{0x41870005,0x003CFFFC}}, // 0100000110xxxx11xxxxxxxxxxxxxx01  bsol cr1, 0x4
{                   "bsoa CREG , NUM",{0x41870006,0x003CFFFC}}, // 0100000110xxxx11xxxxxxxxxxxxxx10  bsoa cr1, 0x4
{                  "bsola CREG , NUM",{0x41870007,0x003CFFFC}}, // 0100000110xxxx11xxxxxxxxxxxxxx11  bsola cr1, 0x4
{                             "blt -",{0x41C00000,0x00000000}}, // 01000001110000000000000000000000  blt-
{                            "bltl -",{0x41C00001,0x00000000}}, // 01000001110000000000000000000001  bltl-
{                            "blta -",{0x41C00002,0x00000000}}, // 01000001110000000000000000000010  blta-
{                           "bltla -",{0x41C00003,0x00000000}}, // 01000001110000000000000000000011  bltla-
{                         "blt - NUM",{0x41C00004,0x0000FFFC}}, // 0100000111000000xxxxxxxxxxxxxx00  blt- 0x4
{                        "bltl - NUM",{0x41C00005,0x0000FFFC}}, // 0100000111000000xxxxxxxxxxxxxx01  bltl- 0x4
{                        "blta - NUM",{0x41C00006,0x0000FFFC}}, // 0100000111000000xxxxxxxxxxxxxx10  blta- 0x4
{                       "bltla - NUM",{0x41C00007,0x0000FFFC}}, // 0100000111000000xxxxxxxxxxxxxx11  bltla- 0x4
{                             "bgt -",{0x41C10000,0x00000000}}, // 01000001110000010000000000000000  bgt-
{                            "bgtl -",{0x41C10001,0x00000000}}, // 01000001110000010000000000000001  bgtl-
{                            "bgta -",{0x41C10002,0x00000000}}, // 01000001110000010000000000000010  bgta-
{                           "bgtla -",{0x41C10003,0x00000000}}, // 01000001110000010000000000000011  bgtla-
{                         "bgt - NUM",{0x41C10004,0x0000FFFC}}, // 0100000111000001xxxxxxxxxxxxxx00  bgt- 0x4
{                        "bgtl - NUM",{0x41C10005,0x0000FFFC}}, // 0100000111000001xxxxxxxxxxxxxx01  bgtl- 0x4
{                        "bgta - NUM",{0x41C10006,0x0000FFFC}}, // 0100000111000001xxxxxxxxxxxxxx10  bgta- 0x4
{                       "bgtla - NUM",{0x41C10007,0x0000FFFC}}, // 0100000111000001xxxxxxxxxxxxxx11  bgtla- 0x4
{                             "beq -",{0x41C20000,0x00000000}}, // 01000001110000100000000000000000  beq-
{                            "beql -",{0x41C20001,0x00000000}}, // 01000001110000100000000000000001  beql-
{                            "beqa -",{0x41C20002,0x00000000}}, // 01000001110000100000000000000010  beqa-
{                           "beqla -",{0x41C20003,0x00000000}}, // 01000001110000100000000000000011  beqla-
{                         "beq - NUM",{0x41C20004,0x0000FFFC}}, // 0100000111000010xxxxxxxxxxxxxx00  beq- 0x4
{                        "beql - NUM",{0x41C20005,0x0000FFFC}}, // 0100000111000010xxxxxxxxxxxxxx01  beql- 0x4
{                        "beqa - NUM",{0x41C20006,0x0000FFFC}}, // 0100000111000010xxxxxxxxxxxxxx10  beqa- 0x4
{                       "beqla - NUM",{0x41C20007,0x0000FFFC}}, // 0100000111000010xxxxxxxxxxxxxx11  beqla- 0x4
{                             "bso -",{0x41C30000,0x00000000}}, // 01000001110000110000000000000000  bso-
{                            "bsol -",{0x41C30001,0x00000000}}, // 01000001110000110000000000000001  bsol-
{                            "bsoa -",{0x41C30002,0x00000000}}, // 01000001110000110000000000000010  bsoa-
{                           "bsola -",{0x41C30003,0x00000000}}, // 01000001110000110000000000000011  bsola-
{                         "bso - NUM",{0x41C30004,0x0000FFFC}}, // 0100000111000011xxxxxxxxxxxxxx00  bso- 0x4
{                        "bsol - NUM",{0x41C30005,0x0000FFFC}}, // 0100000111000011xxxxxxxxxxxxxx01  bsol- 0x4
{                        "bsoa - NUM",{0x41C30006,0x0000FFFC}}, // 0100000111000011xxxxxxxxxxxxxx10  bsoa- 0x4
{                       "bsola - NUM",{0x41C30007,0x0000FFFC}}, // 0100000111000011xxxxxxxxxxxxxx11  bsola- 0x4
{                        "blt - CREG",{0x41C40000,0x001C0000}}, // 01000001110xxx000000000000000000  blt- cr1
{                       "bltl - CREG",{0x41C40001,0x001C0000}}, // 01000001110xxx000000000000000001  bltl- cr1
{                       "blta - CREG",{0x41C40002,0x001C0000}}, // 01000001110xxx000000000000000010  blta- cr1
{                      "bltla - CREG",{0x41C40003,0x001C0000}}, // 01000001110xxx000000000000000011  bltla- cr1
{                  "blt - CREG , NUM",{0x41C40004,0x001CFFFC}}, // 01000001110xxx00xxxxxxxxxxxxxx00  blt- cr1, 0x4
{                 "bltl - CREG , NUM",{0x41C40005,0x001CFFFC}}, // 01000001110xxx00xxxxxxxxxxxxxx01  bltl- cr1, 0x4
{                 "blta - CREG , NUM",{0x41C40006,0x001CFFFC}}, // 01000001110xxx00xxxxxxxxxxxxxx10  blta- cr1, 0x4
{                "bltla - CREG , NUM",{0x41C40007,0x001CFFFC}}, // 01000001110xxx00xxxxxxxxxxxxxx11  bltla- cr1, 0x4
{                        "bgt - CREG",{0x41C50000,0x001C0000}}, // 01000001110xxx010000000000000000  bgt- cr1
{                       "bgtl - CREG",{0x41C50001,0x001C0000}}, // 01000001110xxx010000000000000001  bgtl- cr1
{                       "bgta - CREG",{0x41C50002,0x001C0000}}, // 01000001110xxx010000000000000010  bgta- cr1
{                      "bgtla - CREG",{0x41C50003,0x001C0000}}, // 01000001110xxx010000000000000011  bgtla- cr1
{                  "bgt - CREG , NUM",{0x41C50004,0x001CFFFC}}, // 01000001110xxx01xxxxxxxxxxxxxx00  bgt- cr1, 0x4
{                 "bgtl - CREG , NUM",{0x41C50005,0x001CFFFC}}, // 01000001110xxx01xxxxxxxxxxxxxx01  bgtl- cr1, 0x4
{                 "bgta - CREG , NUM",{0x41C50006,0x001CFFFC}}, // 01000001110xxx01xxxxxxxxxxxxxx10  bgta- cr1, 0x4
{                "bgtla - CREG , NUM",{0x41C50007,0x001CFFFC}}, // 01000001110xxx01xxxxxxxxxxxxxx11  bgtla- cr1, 0x4
{                        "beq - CREG",{0x41C60000,0x001C0000}}, // 01000001110xxx100000000000000000  beq- cr1
{                       "beql - CREG",{0x41C60001,0x001C0000}}, // 01000001110xxx100000000000000001  beql- cr1
{                       "beqa - CREG",{0x41C60002,0x001C0000}}, // 01000001110xxx100000000000000010  beqa- cr1
{                      "beqla - CREG",{0x41C60003,0x001C0000}}, // 01000001110xxx100000000000000011  beqla- cr1
{                  "beq - CREG , NUM",{0x41C60004,0x001CFFFC}}, // 01000001110xxx10xxxxxxxxxxxxxx00  beq- cr1, 0x4
{                 "beql - CREG , NUM",{0x41C60005,0x001CFFFC}}, // 01000001110xxx10xxxxxxxxxxxxxx01  beql- cr1, 0x4
{                 "beqa - CREG , NUM",{0x41C60006,0x001CFFFC}}, // 01000001110xxx10xxxxxxxxxxxxxx10  beqa- cr1, 0x4
{                "beqla - CREG , NUM",{0x41C60007,0x001CFFFC}}, // 01000001110xxx10xxxxxxxxxxxxxx11  beqla- cr1, 0x4
{                        "bso - CREG",{0x41C70000,0x001C0000}}, // 01000001110xxx110000000000000000  bso- cr1
{                       "bsol - CREG",{0x41C70001,0x001C0000}}, // 01000001110xxx110000000000000001  bsol- cr1
{                       "bsoa - CREG",{0x41C70002,0x001C0000}}, // 01000001110xxx110000000000000010  bsoa- cr1
{                      "bsola - CREG",{0x41C70003,0x001C0000}}, // 01000001110xxx110000000000000011  bsola- cr1
{                  "bso - CREG , NUM",{0x41C70004,0x001CFFFC}}, // 01000001110xxx11xxxxxxxxxxxxxx00  bso- cr1, 0x4
{                 "bsol - CREG , NUM",{0x41C70005,0x001CFFFC}}, // 01000001110xxx11xxxxxxxxxxxxxx01  bsol- cr1, 0x4
{                 "bsoa - CREG , NUM",{0x41C70006,0x001CFFFC}}, // 01000001110xxx11xxxxxxxxxxxxxx10  bsoa- cr1, 0x4
{                "bsola - CREG , NUM",{0x41C70007,0x001CFFFC}}, // 01000001110xxx11xxxxxxxxxxxxxx11  bsola- cr1, 0x4
{                             "blt +",{0x41E00000,0x00000000}}, // 01000001111000000000000000000000  blt+
{                            "bltl +",{0x41E00001,0x00000000}}, // 01000001111000000000000000000001  bltl+
{                            "blta +",{0x41E00002,0x00000000}}, // 01000001111000000000000000000010  blta+
{                           "bltla +",{0x41E00003,0x00000000}}, // 01000001111000000000000000000011  bltla+
{                         "blt + NUM",{0x41E00004,0x0000FFFC}}, // 0100000111100000xxxxxxxxxxxxxx00  blt+ 0x4
{                        "bltl + NUM",{0x41E00005,0x0000FFFC}}, // 0100000111100000xxxxxxxxxxxxxx01  bltl+ 0x4
{                        "blta + NUM",{0x41E00006,0x0000FFFC}}, // 0100000111100000xxxxxxxxxxxxxx10  blta+ 0x4
{                       "bltla + NUM",{0x41E00007,0x0000FFFC}}, // 0100000111100000xxxxxxxxxxxxxx11  bltla+ 0x4
{                             "bgt +",{0x41E10000,0x00000000}}, // 01000001111000010000000000000000  bgt+
{                            "bgtl +",{0x41E10001,0x00000000}}, // 01000001111000010000000000000001  bgtl+
{                            "bgta +",{0x41E10002,0x00000000}}, // 01000001111000010000000000000010  bgta+
{                           "bgtla +",{0x41E10003,0x00000000}}, // 01000001111000010000000000000011  bgtla+
{                         "bgt + NUM",{0x41E10004,0x0000FFFC}}, // 0100000111100001xxxxxxxxxxxxxx00  bgt+ 0x4
{                        "bgtl + NUM",{0x41E10005,0x0000FFFC}}, // 0100000111100001xxxxxxxxxxxxxx01  bgtl+ 0x4
{                        "bgta + NUM",{0x41E10006,0x0000FFFC}}, // 0100000111100001xxxxxxxxxxxxxx10  bgta+ 0x4
{                       "bgtla + NUM",{0x41E10007,0x0000FFFC}}, // 0100000111100001xxxxxxxxxxxxxx11  bgtla+ 0x4
{                             "beq +",{0x41E20000,0x00000000}}, // 01000001111000100000000000000000  beq+
{                            "beql +",{0x41E20001,0x00000000}}, // 01000001111000100000000000000001  beql+
{                            "beqa +",{0x41E20002,0x00000000}}, // 01000001111000100000000000000010  beqa+
{                           "beqla +",{0x41E20003,0x00000000}}, // 01000001111000100000000000000011  beqla+
{                         "beq + NUM",{0x41E20004,0x0000FFFC}}, // 0100000111100010xxxxxxxxxxxxxx00  beq+ 0x4
{                        "beql + NUM",{0x41E20005,0x0000FFFC}}, // 0100000111100010xxxxxxxxxxxxxx01  beql+ 0x4
{                        "beqa + NUM",{0x41E20006,0x0000FFFC}}, // 0100000111100010xxxxxxxxxxxxxx10  beqa+ 0x4
{                       "beqla + NUM",{0x41E20007,0x0000FFFC}}, // 0100000111100010xxxxxxxxxxxxxx11  beqla+ 0x4
{                             "bso +",{0x41E30000,0x00000000}}, // 01000001111000110000000000000000  bso+
{                            "bsol +",{0x41E30001,0x00000000}}, // 01000001111000110000000000000001  bsol+
{                            "bsoa +",{0x41E30002,0x00000000}}, // 01000001111000110000000000000010  bsoa+
{                           "bsola +",{0x41E30003,0x00000000}}, // 01000001111000110000000000000011  bsola+
{                         "bso + NUM",{0x41E30004,0x0000FFFC}}, // 0100000111100011xxxxxxxxxxxxxx00  bso+ 0x4
{                        "bsol + NUM",{0x41E30005,0x0000FFFC}}, // 0100000111100011xxxxxxxxxxxxxx01  bsol+ 0x4
{                        "bsoa + NUM",{0x41E30006,0x0000FFFC}}, // 0100000111100011xxxxxxxxxxxxxx10  bsoa+ 0x4
{                       "bsola + NUM",{0x41E30007,0x0000FFFC}}, // 0100000111100011xxxxxxxxxxxxxx11  bsola+ 0x4
{                        "blt + CREG",{0x41E40000,0x001C0000}}, // 01000001111xxx000000000000000000  blt+ cr1
{                       "bltl + CREG",{0x41E40001,0x001C0000}}, // 01000001111xxx000000000000000001  bltl+ cr1
{                       "blta + CREG",{0x41E40002,0x001C0000}}, // 01000001111xxx000000000000000010  blta+ cr1
{                      "bltla + CREG",{0x41E40003,0x001C0000}}, // 01000001111xxx000000000000000011  bltla+ cr1
{                  "blt + CREG , NUM",{0x41E40004,0x001CFFFC}}, // 01000001111xxx00xxxxxxxxxxxxxx00  blt+ cr1, 0x4
{                 "bltl + CREG , NUM",{0x41E40005,0x001CFFFC}}, // 01000001111xxx00xxxxxxxxxxxxxx01  bltl+ cr1, 0x4
{                 "blta + CREG , NUM",{0x41E40006,0x001CFFFC}}, // 01000001111xxx00xxxxxxxxxxxxxx10  blta+ cr1, 0x4
{                "bltla + CREG , NUM",{0x41E40007,0x001CFFFC}}, // 01000001111xxx00xxxxxxxxxxxxxx11  bltla+ cr1, 0x4
{                        "bgt + CREG",{0x41E50000,0x001C0000}}, // 01000001111xxx010000000000000000  bgt+ cr1
{                       "bgtl + CREG",{0x41E50001,0x001C0000}}, // 01000001111xxx010000000000000001  bgtl+ cr1
{                       "bgta + CREG",{0x41E50002,0x001C0000}}, // 01000001111xxx010000000000000010  bgta+ cr1
{                      "bgtla + CREG",{0x41E50003,0x001C0000}}, // 01000001111xxx010000000000000011  bgtla+ cr1
{                  "bgt + CREG , NUM",{0x41E50004,0x001CFFFC}}, // 01000001111xxx01xxxxxxxxxxxxxx00  bgt+ cr1, 0x4
{                 "bgtl + CREG , NUM",{0x41E50005,0x001CFFFC}}, // 01000001111xxx01xxxxxxxxxxxxxx01  bgtl+ cr1, 0x4
{                 "bgta + CREG , NUM",{0x41E50006,0x001CFFFC}}, // 01000001111xxx01xxxxxxxxxxxxxx10  bgta+ cr1, 0x4
{                "bgtla + CREG , NUM",{0x41E50007,0x001CFFFC}}, // 01000001111xxx01xxxxxxxxxxxxxx11  bgtla+ cr1, 0x4
{                        "beq + CREG",{0x41E60000,0x001C0000}}, // 01000001111xxx100000000000000000  beq+ cr1
{                       "beql + CREG",{0x41E60001,0x001C0000}}, // 01000001111xxx100000000000000001  beql+ cr1
{                       "beqa + CREG",{0x41E60002,0x001C0000}}, // 01000001111xxx100000000000000010  beqa+ cr1
{                      "beqla + CREG",{0x41E60003,0x001C0000}}, // 01000001111xxx100000000000000011  beqla+ cr1
{                  "beq + CREG , NUM",{0x41E60004,0x001CFFFC}}, // 01000001111xxx10xxxxxxxxxxxxxx00  beq+ cr1, 0x4
{                 "beql + CREG , NUM",{0x41E60005,0x001CFFFC}}, // 01000001111xxx10xxxxxxxxxxxxxx01  beql+ cr1, 0x4
{                 "beqa + CREG , NUM",{0x41E60006,0x001CFFFC}}, // 01000001111xxx10xxxxxxxxxxxxxx10  beqa+ cr1, 0x4
{                "beqla + CREG , NUM",{0x41E60007,0x001CFFFC}}, // 01000001111xxx10xxxxxxxxxxxxxx11  beqla+ cr1, 0x4
{                        "bso + CREG",{0x41E70000,0x001C0000}}, // 01000001111xxx110000000000000000  bso+ cr1
{                       "bsol + CREG",{0x41E70001,0x001C0000}}, // 01000001111xxx110000000000000001  bsol+ cr1
{                       "bsoa + CREG",{0x41E70002,0x001C0000}}, // 01000001111xxx110000000000000010  bsoa+ cr1
{                      "bsola + CREG",{0x41E70003,0x001C0000}}, // 01000001111xxx110000000000000011  bsola+ cr1
{                  "bso + CREG , NUM",{0x41E70004,0x001CFFFC}}, // 01000001111xxx11xxxxxxxxxxxxxx00  bso+ cr1, 0x4
{                 "bsol + CREG , NUM",{0x41E70005,0x001CFFFC}}, // 01000001111xxx11xxxxxxxxxxxxxx01  bsol+ cr1, 0x4
{                 "bsoa + CREG , NUM",{0x41E70006,0x001CFFFC}}, // 01000001111xxx11xxxxxxxxxxxxxx10  bsoa+ cr1, 0x4
{                "bsola + CREG , NUM",{0x41E70007,0x001CFFFC}}, // 01000001111xxx11xxxxxxxxxxxxxx11  bsola+ cr1, 0x4
{                          "bdnz NUM",{0x42000000,0x01BFFFFC}}, // 0100001xx0xxxxxxxxxxxxxxxxxxxx00  bdnz 0x0
{                         "bdnzl NUM",{0x42000001,0x01BFFFFC}}, // 0100001xx0xxxxxxxxxxxxxxxxxxxx01  bdnzl 0x0
{                         "bdnza NUM",{0x42000002,0x01BFFFFC}}, // 0100001xx0xxxxxxxxxxxxxxxxxxxx10  bdnza 0x0
{                        "bdnzla NUM",{0x42000003,0x01BFFFFC}}, // 0100001xx0xxxxxxxxxxxxxxxxxxxx11  bdnzla 0x0
{                              "bdnz",{0x42010000,0x01BF0000}}, // 0100001xx0xxxxxx0000000000000000  bdnz
{                             "bdnzl",{0x42010001,0x01BF0000}}, // 0100001xx0xxxxxx0000000000000001  bdnzl
{                             "bdnza",{0x42010002,0x01BF0000}}, // 0100001xx0xxxxxx0000000000000010  bdnza
{                            "bdnzla",{0x42010003,0x01BF0000}}, // 0100001xx0xxxxxx0000000000000011  bdnzla
{                           "bdz NUM",{0x42400000,0x01BFFFFC}}, // 0100001xx1xxxxxxxxxxxxxxxxxxxx00  bdz 0x0
{                          "bdzl NUM",{0x42400001,0x01BFFFFC}}, // 0100001xx1xxxxxxxxxxxxxxxxxxxx01  bdzl 0x0
{                          "bdza NUM",{0x42400002,0x01BFFFFC}}, // 0100001xx1xxxxxxxxxxxxxxxxxxxx10  bdza 0x0
{                         "bdzla NUM",{0x42400003,0x01BFFFFC}}, // 0100001xx1xxxxxxxxxxxxxxxxxxxx11  bdzla 0x0
{                               "bdz",{0x42410000,0x01BF0000}}, // 0100001xx1xxxxxx0000000000000000  bdz
{                              "bdzl",{0x42410001,0x01BF0000}}, // 0100001xx1xxxxxx0000000000000001  bdzl
{                              "bdza",{0x42410002,0x01BF0000}}, // 0100001xx1xxxxxx0000000000000010  bdza
{                             "bdzla",{0x42410003,0x01BF0000}}, // 0100001xx1xxxxxx0000000000000011  bdzla
{                        "bdnz - NUM",{0x43000000,0x001FFFFC}}, // 01000011000xxxxxxxxxxxxxxxxxxx00  bdnz- 0x0
{                       "bdnzl - NUM",{0x43000001,0x001FFFFC}}, // 01000011000xxxxxxxxxxxxxxxxxxx01  bdnzl- 0x0
{                       "bdnza - NUM",{0x43000002,0x001FFFFC}}, // 01000011000xxxxxxxxxxxxxxxxxxx10  bdnza- 0x0
{                      "bdnzla - NUM",{0x43000003,0x001FFFFC}}, // 01000011000xxxxxxxxxxxxxxxxxxx11  bdnzla- 0x0
{                            "bdnz -",{0x43010000,0x001F0000}}, // 01000011000xxxxx0000000000000000  bdnz-
{                           "bdnzl -",{0x43010001,0x001F0000}}, // 01000011000xxxxx0000000000000001  bdnzl-
{                           "bdnza -",{0x43010002,0x001F0000}}, // 01000011000xxxxx0000000000000010  bdnza-
{                          "bdnzla -",{0x43010003,0x001F0000}}, // 01000011000xxxxx0000000000000011  bdnzla-
{                        "bdnz + NUM",{0x43200000,0x001FFFFC}}, // 01000011001xxxxxxxxxxxxxxxxxxx00  bdnz+ 0x0
{                       "bdnzl + NUM",{0x43200001,0x001FFFFC}}, // 01000011001xxxxxxxxxxxxxxxxxxx01  bdnzl+ 0x0
{                       "bdnza + NUM",{0x43200002,0x001FFFFC}}, // 01000011001xxxxxxxxxxxxxxxxxxx10  bdnza+ 0x0
{                      "bdnzla + NUM",{0x43200003,0x001FFFFC}}, // 01000011001xxxxxxxxxxxxxxxxxxx11  bdnzla+ 0x0
{                            "bdnz +",{0x43210000,0x001F0000}}, // 01000011001xxxxx0000000000000000  bdnz+
{                           "bdnzl +",{0x43210001,0x001F0000}}, // 01000011001xxxxx0000000000000001  bdnzl+
{                           "bdnza +",{0x43210002,0x001F0000}}, // 01000011001xxxxx0000000000000010  bdnza+
{                          "bdnzla +",{0x43210003,0x001F0000}}, // 01000011001xxxxx0000000000000011  bdnzla+
{                         "bdz - NUM",{0x43400000,0x001FFFFC}}, // 01000011010xxxxxxxxxxxxxxxxxxx00  bdz- 0x0
{                        "bdzl - NUM",{0x43400001,0x001FFFFC}}, // 01000011010xxxxxxxxxxxxxxxxxxx01  bdzl- 0x0
{                        "bdza - NUM",{0x43400002,0x001FFFFC}}, // 01000011010xxxxxxxxxxxxxxxxxxx10  bdza- 0x0
{                       "bdzla - NUM",{0x43400003,0x001FFFFC}}, // 01000011010xxxxxxxxxxxxxxxxxxx11  bdzla- 0x0
{                             "bdz -",{0x43410000,0x001F0000}}, // 01000011010xxxxx0000000000000000  bdz-
{                            "bdzl -",{0x43410001,0x001F0000}}, // 01000011010xxxxx0000000000000001  bdzl-
{                            "bdza -",{0x43410002,0x001F0000}}, // 01000011010xxxxx0000000000000010  bdza-
{                           "bdzla -",{0x43410003,0x001F0000}}, // 01000011010xxxxx0000000000000011  bdzla-
{                         "bdz + NUM",{0x43600000,0x001FFFFC}}, // 01000011011xxxxxxxxxxxxxxxxxxx00  bdz+ 0x0
{                        "bdzl + NUM",{0x43600001,0x001FFFFC}}, // 01000011011xxxxxxxxxxxxxxxxxxx01  bdzl+ 0x0
{                        "bdza + NUM",{0x43600002,0x001FFFFC}}, // 01000011011xxxxxxxxxxxxxxxxxxx10  bdza+ 0x0
{                       "bdzla + NUM",{0x43600003,0x001FFFFC}}, // 01000011011xxxxxxxxxxxxxxxxxxx11  bdzla+ 0x0
{                             "bdz +",{0x43610000,0x001F0000}}, // 01000011011xxxxx0000000000000000  bdz+
{                            "bdzl +",{0x43610001,0x001F0000}}, // 01000011011xxxxx0000000000000001  bdzl+
{                            "bdza +",{0x43610002,0x001F0000}}, // 01000011011xxxxx0000000000000010  bdza+
{                           "bdzla +",{0x43610003,0x001F0000}}, // 01000011011xxxxx0000000000000011  bdzla+
{                                "sc",{0x44000002,0x03FFF01D}}, // 010001xxxxxxxxxxxxxx0000000xxx1x  sc
{                            "sc NUM",{0x44000022,0x03FFFFFD}}, // 010001xxxxxxxxxxxxxxxxxxxxxxxx1x  sc 1
{                             "b NUM",{0x48000000,0x03FFFFFC}}, // 010010xxxxxxxxxxxxxxxxxxxxxxxx00  b 0x0
{                            "bl NUM",{0x48000001,0x03FFFFFC}}, // 010010xxxxxxxxxxxxxxxxxxxxxxxx01  bl 0x0
{                            "ba NUM",{0x48000002,0x03FFFFFC}}, // 010010xxxxxxxxxxxxxxxxxxxxxxxx10  ba 0x0
{                           "bla NUM",{0x48000003,0x03FFFFFC}}, // 010010xxxxxxxxxxxxxxxxxxxxxxxx11  bla 0x0
{                  "mcrf CREG , CREG",{0x4C000000,0x039C0000}}, // 010011xxx00xxx000000000000000000  mcrf cr0, cr0
{                      "bdnzflr FLAG",{0x4C000020,0x00230000}}, // 0100110000x000xx0000000000100000  bdnzflr lt
{                     "bdnzflrl FLAG",{0x4C000021,0x00230000}}, // 0100110000x000xx0000000000100001  bdnzflrl lt
{                              "rfid",{0x4C000024,0x00000000}}, // 01001100000000000000000000100100  rfid
{                   "crnot NUM , NUM",{0x4C000042,0x03FFF800}}, // 010011xxxxxxxxxxxxxxx00001000010  crnot 0, 0
{                             "rfmci",{0x4C00004C,0x00000000}}, // 01001100000000000000000001001100  rfmci
{                              "rfdi",{0x4C00004E,0x00000000}}, // 01001100000000000000000001001110  rfdi
{                               "rfi",{0x4C000064,0x00000000}}, // 01001100000000000000000001100100  rfi
{                              "rfci",{0x4C000066,0x00000000}}, // 01001100000000000000000001100110  rfci
{            "crandc NUM , NUM , NUM",{0x4C000102,0x03FFF800}}, // 010011xxxxxxxxxxxxxxx00100000010  crandc 0, 0, 0
{                             "isync",{0x4C00012C,0x00000000}}, // 01001100000000000000000100101100  isync
{                         "crclr NUM",{0x4C000182,0x03FFF800}}, // 010011xxxxxxxxxxxxxxx00110000010  crclr 0
{            "crnand NUM , NUM , NUM",{0x4C0001C2,0x03FFF800}}, // 010011xxxxxxxxxxxxxxx00111000010  crnand 0, 0, 0
{             "crand NUM , NUM , NUM",{0x4C000202,0x03FFF800}}, // 010011xxxxxxxxxxxxxxx01000000010  crand 0, 0, 0
{                         "crset NUM",{0x4C000242,0x03FFF800}}, // 010011xxxxxxxxxxxxxxx01001000010  crset 0
{             "crorc NUM , NUM , NUM",{0x4C000342,0x03FFF800}}, // 010011xxxxxxxxxxxxxxx01101000010  crorc 0, 0, 0
{                  "crmove NUM , NUM",{0x4C000382,0x03FFF800}}, // 010011xxxxxxxxxxxxxxx01110000010  crmove 0, 0
{                     "bdnzfctr FLAG",{0x4C000420,0x00230000}}, // 0100110000x000xx0000010000100000  bdnzfctr lt
{                    "bdnzfctrl FLAG",{0x4C000421,0x00230000}}, // 0100110000x000xx0000010000100001  bdnzfctrl lt
{                "bdnzflr FLAG , NUM",{0x4C000820,0x00231800}}, // 0100110000x000xx000xx00000100000  bdnzflr lt, 0x4
{               "bdnzflrl FLAG , NUM",{0x4C000821,0x00231800}}, // 0100110000x000xx000xx00000100001  bdnzflrl lt, 0x4
{             "crnor NUM , NUM , NUM",{0x4C000842,0x03FFF800}}, // 010011xxxxxxxxxxxxxxx00001000010  crnor 0, 0, 1
{             "crxor NUM , NUM , NUM",{0x4C000982,0x03FFF800}}, // 010011xxxxxxxxxxxxxxx00110000010  crxor 0, 0, 1
{             "creqv NUM , NUM , NUM",{0x4C000A42,0x03FFF800}}, // 010011xxxxxxxxxxxxxxx01001000010  creqv 0, 0, 1
{              "cror NUM , NUM , NUM",{0x4C000B82,0x03FFF800}}, // 010011xxxxxxxxxxxxxxx01110000010  cror 0, 0, 1
{               "bdnzfctr FLAG , NUM",{0x4C000C20,0x00231800}}, // 0100110000x000xx000xx10000100000  bdnzfctr lt, 0x4
{              "bdnzfctrl FLAG , NUM",{0x4C000C21,0x00231800}}, // 0100110000x000xx000xx10000100001  bdnzfctrl lt, 0x4
{         "bdnzflr NUM * CREG + FLAG",{0x4C040020,0x003F0000}}, // 0100110000xxxxxx0000000000100000  bdnzflr 4*cr1+lt
{        "bdnzflrl NUM * CREG + FLAG",{0x4C040021,0x003F0000}}, // 0100110000xxxxxx0000000000100001  bdnzflrl 4*cr1+lt
{        "bdnzfctr NUM * CREG + FLAG",{0x4C040420,0x003F0000}}, // 0100110000xxxxxx0000010000100000  bdnzfctr 4*cr1+lt
{       "bdnzfctrl NUM * CREG + FLAG",{0x4C040421,0x003F0000}}, // 0100110000xxxxxx0000010000100001  bdnzfctrl 4*cr1+lt
{   "bdnzflr NUM * CREG + FLAG , NUM",{0x4C040820,0x003F1800}}, // 0100110000xxxxxx000xx00000100000  bdnzflr 4*cr1+lt, 0x4
{  "bdnzflrl NUM * CREG + FLAG , NUM",{0x4C040821,0x003F1800}}, // 0100110000xxxxxx000xx00000100001  bdnzflrl 4*cr1+lt, 0x4
{  "bdnzfctr NUM * CREG + FLAG , NUM",{0x4C040C20,0x003F1800}}, // 0100110000xxxxxx000xx10000100000  bdnzfctr 4*cr1+lt, 0x4
{ "bdnzfctrl NUM * CREG + FLAG , NUM",{0x4C040C21,0x003F1800}}, // 0100110000xxxxxx000xx10000100001  bdnzfctrl 4*cr1+lt, 0x4
{                       "bdzflr FLAG",{0x4C400020,0x00230000}}, // 0100110001x000xx0000000000100000  bdzflr lt
{                      "bdzflrl FLAG",{0x4C400021,0x00230000}}, // 0100110001x000xx0000000000100001  bdzflrl lt
{                      "bdzfctr FLAG",{0x4C400420,0x00230000}}, // 0100110001x000xx0000010000100000  bdzfctr lt
{                     "bdzfctrl FLAG",{0x4C400421,0x00230000}}, // 0100110001x000xx0000010000100001  bdzfctrl lt
{                 "bdzflr FLAG , NUM",{0x4C400820,0x00231800}}, // 0100110001x000xx000xx00000100000  bdzflr lt, 0x4
{                "bdzflrl FLAG , NUM",{0x4C400821,0x00231800}}, // 0100110001x000xx000xx00000100001  bdzflrl lt, 0x4
{                "bdzfctr FLAG , NUM",{0x4C400C20,0x00231800}}, // 0100110001x000xx000xx10000100000  bdzfctr lt, 0x4
{               "bdzfctrl FLAG , NUM",{0x4C400C21,0x00231800}}, // 0100110001x000xx000xx10000100001  bdzfctrl lt, 0x4
{          "bdzflr NUM * CREG + FLAG",{0x4C440020,0x003F0000}}, // 0100110001xxxxxx0000000000100000  bdzflr 4*cr1+lt
{         "bdzflrl NUM * CREG + FLAG",{0x4C440021,0x003F0000}}, // 0100110001xxxxxx0000000000100001  bdzflrl 4*cr1+lt
{         "bdzfctr NUM * CREG + FLAG",{0x4C440420,0x003F0000}}, // 0100110001xxxxxx0000010000100000  bdzfctr 4*cr1+lt
{        "bdzfctrl NUM * CREG + FLAG",{0x4C440421,0x003F0000}}, // 0100110001xxxxxx0000010000100001  bdzfctrl 4*cr1+lt
{    "bdzflr NUM * CREG + FLAG , NUM",{0x4C440820,0x003F1800}}, // 0100110001xxxxxx000xx00000100000  bdzflr 4*cr1+lt, 0x4
{   "bdzflrl NUM * CREG + FLAG , NUM",{0x4C440821,0x003F1800}}, // 0100110001xxxxxx000xx00000100001  bdzflrl 4*cr1+lt, 0x4
{   "bdzfctr NUM * CREG + FLAG , NUM",{0x4C440C20,0x003F1800}}, // 0100110001xxxxxx000xx10000100000  bdzfctr 4*cr1+lt, 0x4
{  "bdzfctrl NUM * CREG + FLAG , NUM",{0x4C440C21,0x003F1800}}, // 0100110001xxxxxx000xx10000100001  bdzfctrl 4*cr1+lt, 0x4
{                             "bgelr",{0x4C800020,0x00200000}}, // 0100110010x000000000000000100000  bgelr
{                            "bgelrl",{0x4C800021,0x00200000}}, // 0100110010x000000000000000100001  bgelrl
{                            "bgectr",{0x4C800420,0x00200000}}, // 0100110010x000000000010000100000  bgectr
{                           "bgectrl",{0x4C800421,0x00200000}}, // 0100110010x000000000010000100001  bgectrl
{                         "bgelr NUM",{0x4C800820,0x00201800}}, // 0100110010x00000000xx00000100000  bgelr 0x4
{                        "bgelrl NUM",{0x4C800821,0x00201800}}, // 0100110010x00000000xx00000100001  bgelrl 0x4
{                        "bgectr NUM",{0x4C800C20,0x00201800}}, // 0100110010x00000000xx10000100000  bgectr 0x4
{                       "bgectrl NUM",{0x4C800C21,0x00201800}}, // 0100110010x00000000xx10000100001  bgectrl 0x4
{                             "blelr",{0x4C810020,0x00200000}}, // 0100110010x000010000000000100000  blelr
{                            "blelrl",{0x4C810021,0x00200000}}, // 0100110010x000010000000000100001  blelrl
{                            "blectr",{0x4C810420,0x00200000}}, // 0100110010x000010000010000100000  blectr
{                           "blectrl",{0x4C810421,0x00200000}}, // 0100110010x000010000010000100001  blectrl
{                         "blelr NUM",{0x4C810820,0x00201800}}, // 0100110010x00001000xx00000100000  blelr 0x4
{                        "blelrl NUM",{0x4C810821,0x00201800}}, // 0100110010x00001000xx00000100001  blelrl 0x4
{                        "blectr NUM",{0x4C810C20,0x00201800}}, // 0100110010x00001000xx10000100000  blectr 0x4
{                       "blectrl NUM",{0x4C810C21,0x00201800}}, // 0100110010x00001000xx10000100001  blectrl 0x4
{                             "bnelr",{0x4C820020,0x00200000}}, // 0100110010x000100000000000100000  bnelr
{                            "bnelrl",{0x4C820021,0x00200000}}, // 0100110010x000100000000000100001  bnelrl
{                            "bnectr",{0x4C820420,0x00200000}}, // 0100110010x000100000010000100000  bnectr
{                           "bnectrl",{0x4C820421,0x00200000}}, // 0100110010x000100000010000100001  bnectrl
{                         "bnelr NUM",{0x4C820820,0x00201800}}, // 0100110010x00010000xx00000100000  bnelr 0x4
{                        "bnelrl NUM",{0x4C820821,0x00201800}}, // 0100110010x00010000xx00000100001  bnelrl 0x4
{                        "bnectr NUM",{0x4C820C20,0x00201800}}, // 0100110010x00010000xx10000100000  bnectr 0x4
{                       "bnectrl NUM",{0x4C820C21,0x00201800}}, // 0100110010x00010000xx10000100001  bnectrl 0x4
{                             "bnslr",{0x4C830020,0x00200000}}, // 0100110010x000110000000000100000  bnslr
{                            "bnslrl",{0x4C830021,0x00200000}}, // 0100110010x000110000000000100001  bnslrl
{                            "bnsctr",{0x4C830420,0x00200000}}, // 0100110010x000110000010000100000  bnsctr
{                           "bnsctrl",{0x4C830421,0x00200000}}, // 0100110010x000110000010000100001  bnsctrl
{                         "bnslr NUM",{0x4C830820,0x00201800}}, // 0100110010x00011000xx00000100000  bnslr 0x4
{                        "bnslrl NUM",{0x4C830821,0x00201800}}, // 0100110010x00011000xx00000100001  bnslrl 0x4
{                        "bnsctr NUM",{0x4C830C20,0x00201800}}, // 0100110010x00011000xx10000100000  bnsctr 0x4
{                       "bnsctrl NUM",{0x4C830C21,0x00201800}}, // 0100110010x00011000xx10000100001  bnsctrl 0x4
{                        "bgelr CREG",{0x4C840020,0x003C0000}}, // 0100110010xxxx000000000000100000  bgelr cr1
{                       "bgelrl CREG",{0x4C840021,0x003C0000}}, // 0100110010xxxx000000000000100001  bgelrl cr1
{                       "bgectr CREG",{0x4C840420,0x003C0000}}, // 0100110010xxxx000000010000100000  bgectr cr1
{                      "bgectrl CREG",{0x4C840421,0x003C0000}}, // 0100110010xxxx000000010000100001  bgectrl cr1
{                  "bgelr CREG , NUM",{0x4C840820,0x003C1800}}, // 0100110010xxxx00000xx00000100000  bgelr cr1, 0x4
{                 "bgelrl CREG , NUM",{0x4C840821,0x003C1800}}, // 0100110010xxxx00000xx00000100001  bgelrl cr1, 0x4
{                 "bgectr CREG , NUM",{0x4C840C20,0x003C1800}}, // 0100110010xxxx00000xx10000100000  bgectr cr1, 0x4
{                "bgectrl CREG , NUM",{0x4C840C21,0x003C1800}}, // 0100110010xxxx00000xx10000100001  bgectrl cr1, 0x4
{                        "blelr CREG",{0x4C850020,0x003C0000}}, // 0100110010xxxx010000000000100000  blelr cr1
{                       "blelrl CREG",{0x4C850021,0x003C0000}}, // 0100110010xxxx010000000000100001  blelrl cr1
{                       "blectr CREG",{0x4C850420,0x003C0000}}, // 0100110010xxxx010000010000100000  blectr cr1
{                      "blectrl CREG",{0x4C850421,0x003C0000}}, // 0100110010xxxx010000010000100001  blectrl cr1
{                  "blelr CREG , NUM",{0x4C850820,0x003C1800}}, // 0100110010xxxx01000xx00000100000  blelr cr1, 0x4
{                 "blelrl CREG , NUM",{0x4C850821,0x003C1800}}, // 0100110010xxxx01000xx00000100001  blelrl cr1, 0x4
{                 "blectr CREG , NUM",{0x4C850C20,0x003C1800}}, // 0100110010xxxx01000xx10000100000  blectr cr1, 0x4
{                "blectrl CREG , NUM",{0x4C850C21,0x003C1800}}, // 0100110010xxxx01000xx10000100001  blectrl cr1, 0x4
{                        "bnelr CREG",{0x4C860020,0x003C0000}}, // 0100110010xxxx100000000000100000  bnelr cr1
{                       "bnelrl CREG",{0x4C860021,0x003C0000}}, // 0100110010xxxx100000000000100001  bnelrl cr1
{                       "bnectr CREG",{0x4C860420,0x003C0000}}, // 0100110010xxxx100000010000100000  bnectr cr1
{                      "bnectrl CREG",{0x4C860421,0x003C0000}}, // 0100110010xxxx100000010000100001  bnectrl cr1
{                  "bnelr CREG , NUM",{0x4C860820,0x003C1800}}, // 0100110010xxxx10000xx00000100000  bnelr cr1, 0x4
{                 "bnelrl CREG , NUM",{0x4C860821,0x003C1800}}, // 0100110010xxxx10000xx00000100001  bnelrl cr1, 0x4
{                 "bnectr CREG , NUM",{0x4C860C20,0x003C1800}}, // 0100110010xxxx10000xx10000100000  bnectr cr1, 0x4
{                "bnectrl CREG , NUM",{0x4C860C21,0x003C1800}}, // 0100110010xxxx10000xx10000100001  bnectrl cr1, 0x4
{                        "bnslr CREG",{0x4C870020,0x003C0000}}, // 0100110010xxxx110000000000100000  bnslr cr1
{                       "bnslrl CREG",{0x4C870021,0x003C0000}}, // 0100110010xxxx110000000000100001  bnslrl cr1
{                       "bnsctr CREG",{0x4C870420,0x003C0000}}, // 0100110010xxxx110000010000100000  bnsctr cr1
{                      "bnsctrl CREG",{0x4C870421,0x003C0000}}, // 0100110010xxxx110000010000100001  bnsctrl cr1
{                  "bnslr CREG , NUM",{0x4C870820,0x003C1800}}, // 0100110010xxxx11000xx00000100000  bnslr cr1, 0x4
{                 "bnslrl CREG , NUM",{0x4C870821,0x003C1800}}, // 0100110010xxxx11000xx00000100001  bnslrl cr1, 0x4
{                 "bnsctr CREG , NUM",{0x4C870C20,0x003C1800}}, // 0100110010xxxx11000xx10000100000  bnsctr cr1, 0x4
{                "bnsctrl CREG , NUM",{0x4C870C21,0x003C1800}}, // 0100110010xxxx11000xx10000100001  bnsctrl cr1, 0x4
{                           "bgelr -",{0x4CC00020,0x00000000}}, // 01001100110000000000000000100000  bgelr-
{                          "bgelrl -",{0x4CC00021,0x00000000}}, // 01001100110000000000000000100001  bgelrl-
{                          "bgectr -",{0x4CC00420,0x00000000}}, // 01001100110000000000010000100000  bgectr-
{                         "bgectrl -",{0x4CC00421,0x00000000}}, // 01001100110000000000010000100001  bgectrl-
{                       "bgelr - NUM",{0x4CC00820,0x00001800}}, // 0100110011000000000xx00000100000  bgelr- 0x4
{                      "bgelrl - NUM",{0x4CC00821,0x00001800}}, // 0100110011000000000xx00000100001  bgelrl- 0x4
{                      "bgectr - NUM",{0x4CC00C20,0x00001800}}, // 0100110011000000000xx10000100000  bgectr- 0x4
{                     "bgectrl - NUM",{0x4CC00C21,0x00001800}}, // 0100110011000000000xx10000100001  bgectrl- 0x4
{                           "blelr -",{0x4CC10020,0x00000000}}, // 01001100110000010000000000100000  blelr-
{                          "blelrl -",{0x4CC10021,0x00000000}}, // 01001100110000010000000000100001  blelrl-
{                          "blectr -",{0x4CC10420,0x00000000}}, // 01001100110000010000010000100000  blectr-
{                         "blectrl -",{0x4CC10421,0x00000000}}, // 01001100110000010000010000100001  blectrl-
{                       "blelr - NUM",{0x4CC10820,0x00001800}}, // 0100110011000001000xx00000100000  blelr- 0x4
{                      "blelrl - NUM",{0x4CC10821,0x00001800}}, // 0100110011000001000xx00000100001  blelrl- 0x4
{                      "blectr - NUM",{0x4CC10C20,0x00001800}}, // 0100110011000001000xx10000100000  blectr- 0x4
{                     "blectrl - NUM",{0x4CC10C21,0x00001800}}, // 0100110011000001000xx10000100001  blectrl- 0x4
{                           "bnelr -",{0x4CC20020,0x00000000}}, // 01001100110000100000000000100000  bnelr-
{                          "bnelrl -",{0x4CC20021,0x00000000}}, // 01001100110000100000000000100001  bnelrl-
{                          "bnectr -",{0x4CC20420,0x00000000}}, // 01001100110000100000010000100000  bnectr-
{                         "bnectrl -",{0x4CC20421,0x00000000}}, // 01001100110000100000010000100001  bnectrl-
{                       "bnelr - NUM",{0x4CC20820,0x00001800}}, // 0100110011000010000xx00000100000  bnelr- 0x4
{                      "bnelrl - NUM",{0x4CC20821,0x00001800}}, // 0100110011000010000xx00000100001  bnelrl- 0x4
{                      "bnectr - NUM",{0x4CC20C20,0x00001800}}, // 0100110011000010000xx10000100000  bnectr- 0x4
{                     "bnectrl - NUM",{0x4CC20C21,0x00001800}}, // 0100110011000010000xx10000100001  bnectrl- 0x4
{                           "bnslr -",{0x4CC30020,0x00000000}}, // 01001100110000110000000000100000  bnslr-
{                          "bnslrl -",{0x4CC30021,0x00000000}}, // 01001100110000110000000000100001  bnslrl-
{                          "bnsctr -",{0x4CC30420,0x00000000}}, // 01001100110000110000010000100000  bnsctr-
{                         "bnsctrl -",{0x4CC30421,0x00000000}}, // 01001100110000110000010000100001  bnsctrl-
{                       "bnslr - NUM",{0x4CC30820,0x00001800}}, // 0100110011000011000xx00000100000  bnslr- 0x4
{                      "bnslrl - NUM",{0x4CC30821,0x00001800}}, // 0100110011000011000xx00000100001  bnslrl- 0x4
{                      "bnsctr - NUM",{0x4CC30C20,0x00001800}}, // 0100110011000011000xx10000100000  bnsctr- 0x4
{                     "bnsctrl - NUM",{0x4CC30C21,0x00001800}}, // 0100110011000011000xx10000100001  bnsctrl- 0x4
{                      "bgelr - CREG",{0x4CC40020,0x001C0000}}, // 01001100110xxx000000000000100000  bgelr- cr1
{                     "bgelrl - CREG",{0x4CC40021,0x001C0000}}, // 01001100110xxx000000000000100001  bgelrl- cr1
{                     "bgectr - CREG",{0x4CC40420,0x001C0000}}, // 01001100110xxx000000010000100000  bgectr- cr1
{                    "bgectrl - CREG",{0x4CC40421,0x001C0000}}, // 01001100110xxx000000010000100001  bgectrl- cr1
{                "bgelr - CREG , NUM",{0x4CC40820,0x001C1800}}, // 01001100110xxx00000xx00000100000  bgelr- cr1, 0x4
{               "bgelrl - CREG , NUM",{0x4CC40821,0x001C1800}}, // 01001100110xxx00000xx00000100001  bgelrl- cr1, 0x4
{               "bgectr - CREG , NUM",{0x4CC40C20,0x001C1800}}, // 01001100110xxx00000xx10000100000  bgectr- cr1, 0x4
{              "bgectrl - CREG , NUM",{0x4CC40C21,0x001C1800}}, // 01001100110xxx00000xx10000100001  bgectrl- cr1, 0x4
{                      "blelr - CREG",{0x4CC50020,0x001C0000}}, // 01001100110xxx010000000000100000  blelr- cr1
{                     "blelrl - CREG",{0x4CC50021,0x001C0000}}, // 01001100110xxx010000000000100001  blelrl- cr1
{                     "blectr - CREG",{0x4CC50420,0x001C0000}}, // 01001100110xxx010000010000100000  blectr- cr1
{                    "blectrl - CREG",{0x4CC50421,0x001C0000}}, // 01001100110xxx010000010000100001  blectrl- cr1
{                "blelr - CREG , NUM",{0x4CC50820,0x001C1800}}, // 01001100110xxx01000xx00000100000  blelr- cr1, 0x4
{               "blelrl - CREG , NUM",{0x4CC50821,0x001C1800}}, // 01001100110xxx01000xx00000100001  blelrl- cr1, 0x4
{               "blectr - CREG , NUM",{0x4CC50C20,0x001C1800}}, // 01001100110xxx01000xx10000100000  blectr- cr1, 0x4
{              "blectrl - CREG , NUM",{0x4CC50C21,0x001C1800}}, // 01001100110xxx01000xx10000100001  blectrl- cr1, 0x4
{                      "bnelr - CREG",{0x4CC60020,0x001C0000}}, // 01001100110xxx100000000000100000  bnelr- cr1
{                     "bnelrl - CREG",{0x4CC60021,0x001C0000}}, // 01001100110xxx100000000000100001  bnelrl- cr1
{                     "bnectr - CREG",{0x4CC60420,0x001C0000}}, // 01001100110xxx100000010000100000  bnectr- cr1
{                    "bnectrl - CREG",{0x4CC60421,0x001C0000}}, // 01001100110xxx100000010000100001  bnectrl- cr1
{                "bnelr - CREG , NUM",{0x4CC60820,0x001C1800}}, // 01001100110xxx10000xx00000100000  bnelr- cr1, 0x4
{               "bnelrl - CREG , NUM",{0x4CC60821,0x001C1800}}, // 01001100110xxx10000xx00000100001  bnelrl- cr1, 0x4
{               "bnectr - CREG , NUM",{0x4CC60C20,0x001C1800}}, // 01001100110xxx10000xx10000100000  bnectr- cr1, 0x4
{              "bnectrl - CREG , NUM",{0x4CC60C21,0x001C1800}}, // 01001100110xxx10000xx10000100001  bnectrl- cr1, 0x4
{                      "bnslr - CREG",{0x4CC70020,0x001C0000}}, // 01001100110xxx110000000000100000  bnslr- cr1
{                     "bnslrl - CREG",{0x4CC70021,0x001C0000}}, // 01001100110xxx110000000000100001  bnslrl- cr1
{                     "bnsctr - CREG",{0x4CC70420,0x001C0000}}, // 01001100110xxx110000010000100000  bnsctr- cr1
{                    "bnsctrl - CREG",{0x4CC70421,0x001C0000}}, // 01001100110xxx110000010000100001  bnsctrl- cr1
{                "bnslr - CREG , NUM",{0x4CC70820,0x001C1800}}, // 01001100110xxx11000xx00000100000  bnslr- cr1, 0x4
{               "bnslrl - CREG , NUM",{0x4CC70821,0x001C1800}}, // 01001100110xxx11000xx00000100001  bnslrl- cr1, 0x4
{               "bnsctr - CREG , NUM",{0x4CC70C20,0x001C1800}}, // 01001100110xxx11000xx10000100000  bnsctr- cr1, 0x4
{              "bnsctrl - CREG , NUM",{0x4CC70C21,0x001C1800}}, // 01001100110xxx11000xx10000100001  bnsctrl- cr1, 0x4
{                           "bgelr +",{0x4CE00020,0x00000000}}, // 01001100111000000000000000100000  bgelr+
{                          "bgelrl +",{0x4CE00021,0x00000000}}, // 01001100111000000000000000100001  bgelrl+
{                          "bgectr +",{0x4CE00420,0x00000000}}, // 01001100111000000000010000100000  bgectr+
{                         "bgectrl +",{0x4CE00421,0x00000000}}, // 01001100111000000000010000100001  bgectrl+
{                       "bgelr + NUM",{0x4CE00820,0x00001800}}, // 0100110011100000000xx00000100000  bgelr+ 0x4
{                      "bgelrl + NUM",{0x4CE00821,0x00001800}}, // 0100110011100000000xx00000100001  bgelrl+ 0x4
{                      "bgectr + NUM",{0x4CE00C20,0x00001800}}, // 0100110011100000000xx10000100000  bgectr+ 0x4
{                     "bgectrl + NUM",{0x4CE00C21,0x00001800}}, // 0100110011100000000xx10000100001  bgectrl+ 0x4
{                           "blelr +",{0x4CE10020,0x00000000}}, // 01001100111000010000000000100000  blelr+
{                          "blelrl +",{0x4CE10021,0x00000000}}, // 01001100111000010000000000100001  blelrl+
{                          "blectr +",{0x4CE10420,0x00000000}}, // 01001100111000010000010000100000  blectr+
{                         "blectrl +",{0x4CE10421,0x00000000}}, // 01001100111000010000010000100001  blectrl+
{                       "blelr + NUM",{0x4CE10820,0x00001800}}, // 0100110011100001000xx00000100000  blelr+ 0x4
{                      "blelrl + NUM",{0x4CE10821,0x00001800}}, // 0100110011100001000xx00000100001  blelrl+ 0x4
{                      "blectr + NUM",{0x4CE10C20,0x00001800}}, // 0100110011100001000xx10000100000  blectr+ 0x4
{                     "blectrl + NUM",{0x4CE10C21,0x00001800}}, // 0100110011100001000xx10000100001  blectrl+ 0x4
{                           "bnelr +",{0x4CE20020,0x00000000}}, // 01001100111000100000000000100000  bnelr+
{                          "bnelrl +",{0x4CE20021,0x00000000}}, // 01001100111000100000000000100001  bnelrl+
{                          "bnectr +",{0x4CE20420,0x00000000}}, // 01001100111000100000010000100000  bnectr+
{                         "bnectrl +",{0x4CE20421,0x00000000}}, // 01001100111000100000010000100001  bnectrl+
{                       "bnelr + NUM",{0x4CE20820,0x00001800}}, // 0100110011100010000xx00000100000  bnelr+ 0x4
{                      "bnelrl + NUM",{0x4CE20821,0x00001800}}, // 0100110011100010000xx00000100001  bnelrl+ 0x4
{                      "bnectr + NUM",{0x4CE20C20,0x00001800}}, // 0100110011100010000xx10000100000  bnectr+ 0x4
{                     "bnectrl + NUM",{0x4CE20C21,0x00001800}}, // 0100110011100010000xx10000100001  bnectrl+ 0x4
{                           "bnslr +",{0x4CE30020,0x00000000}}, // 01001100111000110000000000100000  bnslr+
{                          "bnslrl +",{0x4CE30021,0x00000000}}, // 01001100111000110000000000100001  bnslrl+
{                          "bnsctr +",{0x4CE30420,0x00000000}}, // 01001100111000110000010000100000  bnsctr+
{                         "bnsctrl +",{0x4CE30421,0x00000000}}, // 01001100111000110000010000100001  bnsctrl+
{                       "bnslr + NUM",{0x4CE30820,0x00001800}}, // 0100110011100011000xx00000100000  bnslr+ 0x4
{                      "bnslrl + NUM",{0x4CE30821,0x00001800}}, // 0100110011100011000xx00000100001  bnslrl+ 0x4
{                      "bnsctr + NUM",{0x4CE30C20,0x00001800}}, // 0100110011100011000xx10000100000  bnsctr+ 0x4
{                     "bnsctrl + NUM",{0x4CE30C21,0x00001800}}, // 0100110011100011000xx10000100001  bnsctrl+ 0x4
{                      "bgelr + CREG",{0x4CE40020,0x001C0000}}, // 01001100111xxx000000000000100000  bgelr+ cr1
{                     "bgelrl + CREG",{0x4CE40021,0x001C0000}}, // 01001100111xxx000000000000100001  bgelrl+ cr1
{                     "bgectr + CREG",{0x4CE40420,0x001C0000}}, // 01001100111xxx000000010000100000  bgectr+ cr1
{                    "bgectrl + CREG",{0x4CE40421,0x001C0000}}, // 01001100111xxx000000010000100001  bgectrl+ cr1
{                "bgelr + CREG , NUM",{0x4CE40820,0x001C1800}}, // 01001100111xxx00000xx00000100000  bgelr+ cr1, 0x4
{               "bgelrl + CREG , NUM",{0x4CE40821,0x001C1800}}, // 01001100111xxx00000xx00000100001  bgelrl+ cr1, 0x4
{               "bgectr + CREG , NUM",{0x4CE40C20,0x001C1800}}, // 01001100111xxx00000xx10000100000  bgectr+ cr1, 0x4
{              "bgectrl + CREG , NUM",{0x4CE40C21,0x001C1800}}, // 01001100111xxx00000xx10000100001  bgectrl+ cr1, 0x4
{                      "blelr + CREG",{0x4CE50020,0x001C0000}}, // 01001100111xxx010000000000100000  blelr+ cr1
{                     "blelrl + CREG",{0x4CE50021,0x001C0000}}, // 01001100111xxx010000000000100001  blelrl+ cr1
{                     "blectr + CREG",{0x4CE50420,0x001C0000}}, // 01001100111xxx010000010000100000  blectr+ cr1
{                    "blectrl + CREG",{0x4CE50421,0x001C0000}}, // 01001100111xxx010000010000100001  blectrl+ cr1
{                "blelr + CREG , NUM",{0x4CE50820,0x001C1800}}, // 01001100111xxx01000xx00000100000  blelr+ cr1, 0x4
{               "blelrl + CREG , NUM",{0x4CE50821,0x001C1800}}, // 01001100111xxx01000xx00000100001  blelrl+ cr1, 0x4
{               "blectr + CREG , NUM",{0x4CE50C20,0x001C1800}}, // 01001100111xxx01000xx10000100000  blectr+ cr1, 0x4
{              "blectrl + CREG , NUM",{0x4CE50C21,0x001C1800}}, // 01001100111xxx01000xx10000100001  blectrl+ cr1, 0x4
{                      "bnelr + CREG",{0x4CE60020,0x001C0000}}, // 01001100111xxx100000000000100000  bnelr+ cr1
{                     "bnelrl + CREG",{0x4CE60021,0x001C0000}}, // 01001100111xxx100000000000100001  bnelrl+ cr1
{                     "bnectr + CREG",{0x4CE60420,0x001C0000}}, // 01001100111xxx100000010000100000  bnectr+ cr1
{                    "bnectrl + CREG",{0x4CE60421,0x001C0000}}, // 01001100111xxx100000010000100001  bnectrl+ cr1
{                "bnelr + CREG , NUM",{0x4CE60820,0x001C1800}}, // 01001100111xxx10000xx00000100000  bnelr+ cr1, 0x4
{               "bnelrl + CREG , NUM",{0x4CE60821,0x001C1800}}, // 01001100111xxx10000xx00000100001  bnelrl+ cr1, 0x4
{               "bnectr + CREG , NUM",{0x4CE60C20,0x001C1800}}, // 01001100111xxx10000xx10000100000  bnectr+ cr1, 0x4
{              "bnectrl + CREG , NUM",{0x4CE60C21,0x001C1800}}, // 01001100111xxx10000xx10000100001  bnectrl+ cr1, 0x4
{                      "bnslr + CREG",{0x4CE70020,0x001C0000}}, // 01001100111xxx110000000000100000  bnslr+ cr1
{                     "bnslrl + CREG",{0x4CE70021,0x001C0000}}, // 01001100111xxx110000000000100001  bnslrl+ cr1
{                     "bnsctr + CREG",{0x4CE70420,0x001C0000}}, // 01001100111xxx110000010000100000  bnsctr+ cr1
{                    "bnsctrl + CREG",{0x4CE70421,0x001C0000}}, // 01001100111xxx110000010000100001  bnsctrl+ cr1
{                "bnslr + CREG , NUM",{0x4CE70820,0x001C1800}}, // 01001100111xxx11000xx00000100000  bnslr+ cr1, 0x4
{               "bnslrl + CREG , NUM",{0x4CE70821,0x001C1800}}, // 01001100111xxx11000xx00000100001  bnslrl+ cr1, 0x4
{               "bnsctr + CREG , NUM",{0x4CE70C20,0x001C1800}}, // 01001100111xxx11000xx10000100000  bnsctr+ cr1, 0x4
{              "bnsctrl + CREG , NUM",{0x4CE70C21,0x001C1800}}, // 01001100111xxx11000xx10000100001  bnsctrl+ cr1, 0x4
{                      "bdnztlr FLAG",{0x4D000020,0x00230000}}, // 0100110100x000xx0000000000100000  bdnztlr lt
{                     "bdnztlrl FLAG",{0x4D000021,0x00230000}}, // 0100110100x000xx0000000000100001  bdnztlrl lt
{                     "bdnztctr FLAG",{0x4D000420,0x00230000}}, // 0100110100x000xx0000010000100000  bdnztctr lt
{                    "bdnztctrl FLAG",{0x4D000421,0x00230000}}, // 0100110100x000xx0000010000100001  bdnztctrl lt
{                "bdnztlr FLAG , NUM",{0x4D000820,0x00231800}}, // 0100110100x000xx000xx00000100000  bdnztlr lt, 0x4
{               "bdnztlrl FLAG , NUM",{0x4D000821,0x00231800}}, // 0100110100x000xx000xx00000100001  bdnztlrl lt, 0x4
{               "bdnztctr FLAG , NUM",{0x4D000C20,0x00231800}}, // 0100110100x000xx000xx10000100000  bdnztctr lt, 0x4
{              "bdnztctrl FLAG , NUM",{0x4D000C21,0x00231800}}, // 0100110100x000xx000xx10000100001  bdnztctrl lt, 0x4
{         "bdnztlr NUM * CREG + FLAG",{0x4D040020,0x003F0000}}, // 0100110100xxxxxx0000000000100000  bdnztlr 4*cr1+lt
{        "bdnztlrl NUM * CREG + FLAG",{0x4D040021,0x003F0000}}, // 0100110100xxxxxx0000000000100001  bdnztlrl 4*cr1+lt
{        "bdnztctr NUM * CREG + FLAG",{0x4D040420,0x003F0000}}, // 0100110100xxxxxx0000010000100000  bdnztctr 4*cr1+lt
{       "bdnztctrl NUM * CREG + FLAG",{0x4D040421,0x003F0000}}, // 0100110100xxxxxx0000010000100001  bdnztctrl 4*cr1+lt
{   "bdnztlr NUM * CREG + FLAG , NUM",{0x4D040820,0x003F1800}}, // 0100110100xxxxxx000xx00000100000  bdnztlr 4*cr1+lt, 0x4
{  "bdnztlrl NUM * CREG + FLAG , NUM",{0x4D040821,0x003F1800}}, // 0100110100xxxxxx000xx00000100001  bdnztlrl 4*cr1+lt, 0x4
{  "bdnztctr NUM * CREG + FLAG , NUM",{0x4D040C20,0x003F1800}}, // 0100110100xxxxxx000xx10000100000  bdnztctr 4*cr1+lt, 0x4
{ "bdnztctrl NUM * CREG + FLAG , NUM",{0x4D040C21,0x003F1800}}, // 0100110100xxxxxx000xx10000100001  bdnztctrl 4*cr1+lt, 0x4
{                       "bdztlr FLAG",{0x4D400020,0x00230000}}, // 0100110101x000xx0000000000100000  bdztlr lt
{                      "bdztlrl FLAG",{0x4D400021,0x00230000}}, // 0100110101x000xx0000000000100001  bdztlrl lt
{                      "bdztctr FLAG",{0x4D400420,0x00230000}}, // 0100110101x000xx0000010000100000  bdztctr lt
{                     "bdztctrl FLAG",{0x4D400421,0x00230000}}, // 0100110101x000xx0000010000100001  bdztctrl lt
{                 "bdztlr FLAG , NUM",{0x4D400820,0x00231800}}, // 0100110101x000xx000xx00000100000  bdztlr lt, 0x4
{                "bdztlrl FLAG , NUM",{0x4D400821,0x00231800}}, // 0100110101x000xx000xx00000100001  bdztlrl lt, 0x4
{                "bdztctr FLAG , NUM",{0x4D400C20,0x00231800}}, // 0100110101x000xx000xx10000100000  bdztctr lt, 0x4
{               "bdztctrl FLAG , NUM",{0x4D400C21,0x00231800}}, // 0100110101x000xx000xx10000100001  bdztctrl lt, 0x4
{          "bdztlr NUM * CREG + FLAG",{0x4D440020,0x003F0000}}, // 0100110101xxxxxx0000000000100000  bdztlr 4*cr1+lt
{         "bdztlrl NUM * CREG + FLAG",{0x4D440021,0x003F0000}}, // 0100110101xxxxxx0000000000100001  bdztlrl 4*cr1+lt
{         "bdztctr NUM * CREG + FLAG",{0x4D440420,0x003F0000}}, // 0100110101xxxxxx0000010000100000  bdztctr 4*cr1+lt
{        "bdztctrl NUM * CREG + FLAG",{0x4D440421,0x003F0000}}, // 0100110101xxxxxx0000010000100001  bdztctrl 4*cr1+lt
{    "bdztlr NUM * CREG + FLAG , NUM",{0x4D440820,0x003F1800}}, // 0100110101xxxxxx000xx00000100000  bdztlr 4*cr1+lt, 0x4
{   "bdztlrl NUM * CREG + FLAG , NUM",{0x4D440821,0x003F1800}}, // 0100110101xxxxxx000xx00000100001  bdztlrl 4*cr1+lt, 0x4
{   "bdztctr NUM * CREG + FLAG , NUM",{0x4D440C20,0x003F1800}}, // 0100110101xxxxxx000xx10000100000  bdztctr 4*cr1+lt, 0x4
{  "bdztctrl NUM * CREG + FLAG , NUM",{0x4D440C21,0x003F1800}}, // 0100110101xxxxxx000xx10000100001  bdztctrl 4*cr1+lt, 0x4
{                             "bltlr",{0x4D800020,0x00200000}}, // 0100110110x000000000000000100000  bltlr
{                            "bltlrl",{0x4D800021,0x00200000}}, // 0100110110x000000000000000100001  bltlrl
{                            "bltctr",{0x4D800420,0x00200000}}, // 0100110110x000000000010000100000  bltctr
{                           "bltctrl",{0x4D800421,0x00200000}}, // 0100110110x000000000010000100001  bltctrl
{                         "bltlr NUM",{0x4D800820,0x00201800}}, // 0100110110x00000000xx00000100000  bltlr 0x4
{                        "bltlrl NUM",{0x4D800821,0x00201800}}, // 0100110110x00000000xx00000100001  bltlrl 0x4
{                        "bltctr NUM",{0x4D800C20,0x00201800}}, // 0100110110x00000000xx10000100000  bltctr 0x4
{                       "bltctrl NUM",{0x4D800C21,0x00201800}}, // 0100110110x00000000xx10000100001  bltctrl 0x4
{                             "bgtlr",{0x4D810020,0x00200000}}, // 0100110110x000010000000000100000  bgtlr
{                            "bgtlrl",{0x4D810021,0x00200000}}, // 0100110110x000010000000000100001  bgtlrl
{                            "bgtctr",{0x4D810420,0x00200000}}, // 0100110110x000010000010000100000  bgtctr
{                           "bgtctrl",{0x4D810421,0x00200000}}, // 0100110110x000010000010000100001  bgtctrl
{                         "bgtlr NUM",{0x4D810820,0x00201800}}, // 0100110110x00001000xx00000100000  bgtlr 0x4
{                        "bgtlrl NUM",{0x4D810821,0x00201800}}, // 0100110110x00001000xx00000100001  bgtlrl 0x4
{                        "bgtctr NUM",{0x4D810C20,0x00201800}}, // 0100110110x00001000xx10000100000  bgtctr 0x4
{                       "bgtctrl NUM",{0x4D810C21,0x00201800}}, // 0100110110x00001000xx10000100001  bgtctrl 0x4
{                             "beqlr",{0x4D820020,0x00200000}}, // 0100110110x000100000000000100000  beqlr
{                            "beqlrl",{0x4D820021,0x00200000}}, // 0100110110x000100000000000100001  beqlrl
{                            "beqctr",{0x4D820420,0x00200000}}, // 0100110110x000100000010000100000  beqctr
{                           "beqctrl",{0x4D820421,0x00200000}}, // 0100110110x000100000010000100001  beqctrl
{                         "beqlr NUM",{0x4D820820,0x00201800}}, // 0100110110x00010000xx00000100000  beqlr 0x4
{                        "beqlrl NUM",{0x4D820821,0x00201800}}, // 0100110110x00010000xx00000100001  beqlrl 0x4
{                        "beqctr NUM",{0x4D820C20,0x00201800}}, // 0100110110x00010000xx10000100000  beqctr 0x4
{                       "beqctrl NUM",{0x4D820C21,0x00201800}}, // 0100110110x00010000xx10000100001  beqctrl 0x4
{                             "bsolr",{0x4D830020,0x00200000}}, // 0100110110x000110000000000100000  bsolr
{                            "bsolrl",{0x4D830021,0x00200000}}, // 0100110110x000110000000000100001  bsolrl
{                            "bsoctr",{0x4D830420,0x00200000}}, // 0100110110x000110000010000100000  bsoctr
{                           "bsoctrl",{0x4D830421,0x00200000}}, // 0100110110x000110000010000100001  bsoctrl
{                         "bsolr NUM",{0x4D830820,0x00201800}}, // 0100110110x00011000xx00000100000  bsolr 0x4
{                        "bsolrl NUM",{0x4D830821,0x00201800}}, // 0100110110x00011000xx00000100001  bsolrl 0x4
{                        "bsoctr NUM",{0x4D830C20,0x00201800}}, // 0100110110x00011000xx10000100000  bsoctr 0x4
{                       "bsoctrl NUM",{0x4D830C21,0x00201800}}, // 0100110110x00011000xx10000100001  bsoctrl 0x4
{                        "bltlr CREG",{0x4D840020,0x003C0000}}, // 0100110110xxxx000000000000100000  bltlr cr1
{                       "bltlrl CREG",{0x4D840021,0x003C0000}}, // 0100110110xxxx000000000000100001  bltlrl cr1
{                       "bltctr CREG",{0x4D840420,0x003C0000}}, // 0100110110xxxx000000010000100000  bltctr cr1
{                      "bltctrl CREG",{0x4D840421,0x003C0000}}, // 0100110110xxxx000000010000100001  bltctrl cr1
{                  "bltlr CREG , NUM",{0x4D840820,0x003C1800}}, // 0100110110xxxx00000xx00000100000  bltlr cr1, 0x4
{                 "bltlrl CREG , NUM",{0x4D840821,0x003C1800}}, // 0100110110xxxx00000xx00000100001  bltlrl cr1, 0x4
{                 "bltctr CREG , NUM",{0x4D840C20,0x003C1800}}, // 0100110110xxxx00000xx10000100000  bltctr cr1, 0x4
{                "bltctrl CREG , NUM",{0x4D840C21,0x003C1800}}, // 0100110110xxxx00000xx10000100001  bltctrl cr1, 0x4
{                        "bgtlr CREG",{0x4D850020,0x003C0000}}, // 0100110110xxxx010000000000100000  bgtlr cr1
{                       "bgtlrl CREG",{0x4D850021,0x003C0000}}, // 0100110110xxxx010000000000100001  bgtlrl cr1
{                       "bgtctr CREG",{0x4D850420,0x003C0000}}, // 0100110110xxxx010000010000100000  bgtctr cr1
{                      "bgtctrl CREG",{0x4D850421,0x003C0000}}, // 0100110110xxxx010000010000100001  bgtctrl cr1
{                  "bgtlr CREG , NUM",{0x4D850820,0x003C1800}}, // 0100110110xxxx01000xx00000100000  bgtlr cr1, 0x4
{                 "bgtlrl CREG , NUM",{0x4D850821,0x003C1800}}, // 0100110110xxxx01000xx00000100001  bgtlrl cr1, 0x4
{                 "bgtctr CREG , NUM",{0x4D850C20,0x003C1800}}, // 0100110110xxxx01000xx10000100000  bgtctr cr1, 0x4
{                "bgtctrl CREG , NUM",{0x4D850C21,0x003C1800}}, // 0100110110xxxx01000xx10000100001  bgtctrl cr1, 0x4
{                        "beqlr CREG",{0x4D860020,0x003C0000}}, // 0100110110xxxx100000000000100000  beqlr cr1
{                       "beqlrl CREG",{0x4D860021,0x003C0000}}, // 0100110110xxxx100000000000100001  beqlrl cr1
{                       "beqctr CREG",{0x4D860420,0x003C0000}}, // 0100110110xxxx100000010000100000  beqctr cr1
{                      "beqctrl CREG",{0x4D860421,0x003C0000}}, // 0100110110xxxx100000010000100001  beqctrl cr1
{                  "beqlr CREG , NUM",{0x4D860820,0x003C1800}}, // 0100110110xxxx10000xx00000100000  beqlr cr1, 0x4
{                 "beqlrl CREG , NUM",{0x4D860821,0x003C1800}}, // 0100110110xxxx10000xx00000100001  beqlrl cr1, 0x4
{                 "beqctr CREG , NUM",{0x4D860C20,0x003C1800}}, // 0100110110xxxx10000xx10000100000  beqctr cr1, 0x4
{                "beqctrl CREG , NUM",{0x4D860C21,0x003C1800}}, // 0100110110xxxx10000xx10000100001  beqctrl cr1, 0x4
{                        "bsolr CREG",{0x4D870020,0x003C0000}}, // 0100110110xxxx110000000000100000  bsolr cr1
{                       "bsolrl CREG",{0x4D870021,0x003C0000}}, // 0100110110xxxx110000000000100001  bsolrl cr1
{                       "bsoctr CREG",{0x4D870420,0x003C0000}}, // 0100110110xxxx110000010000100000  bsoctr cr1
{                      "bsoctrl CREG",{0x4D870421,0x003C0000}}, // 0100110110xxxx110000010000100001  bsoctrl cr1
{                  "bsolr CREG , NUM",{0x4D870820,0x003C1800}}, // 0100110110xxxx11000xx00000100000  bsolr cr1, 0x4
{                 "bsolrl CREG , NUM",{0x4D870821,0x003C1800}}, // 0100110110xxxx11000xx00000100001  bsolrl cr1, 0x4
{                 "bsoctr CREG , NUM",{0x4D870C20,0x003C1800}}, // 0100110110xxxx11000xx10000100000  bsoctr cr1, 0x4
{                "bsoctrl CREG , NUM",{0x4D870C21,0x003C1800}}, // 0100110110xxxx11000xx10000100001  bsoctrl cr1, 0x4
{                           "bltlr -",{0x4DC00020,0x00000000}}, // 01001101110000000000000000100000  bltlr-
{                          "bltlrl -",{0x4DC00021,0x00000000}}, // 01001101110000000000000000100001  bltlrl-
{                          "bltctr -",{0x4DC00420,0x00000000}}, // 01001101110000000000010000100000  bltctr-
{                         "bltctrl -",{0x4DC00421,0x00000000}}, // 01001101110000000000010000100001  bltctrl-
{                       "bltlr - NUM",{0x4DC00820,0x00001800}}, // 0100110111000000000xx00000100000  bltlr- 0x4
{                      "bltlrl - NUM",{0x4DC00821,0x00001800}}, // 0100110111000000000xx00000100001  bltlrl- 0x4
{                      "bltctr - NUM",{0x4DC00C20,0x00001800}}, // 0100110111000000000xx10000100000  bltctr- 0x4
{                     "bltctrl - NUM",{0x4DC00C21,0x00001800}}, // 0100110111000000000xx10000100001  bltctrl- 0x4
{                           "bgtlr -",{0x4DC10020,0x00000000}}, // 01001101110000010000000000100000  bgtlr-
{                          "bgtlrl -",{0x4DC10021,0x00000000}}, // 01001101110000010000000000100001  bgtlrl-
{                          "bgtctr -",{0x4DC10420,0x00000000}}, // 01001101110000010000010000100000  bgtctr-
{                         "bgtctrl -",{0x4DC10421,0x00000000}}, // 01001101110000010000010000100001  bgtctrl-
{                       "bgtlr - NUM",{0x4DC10820,0x00001800}}, // 0100110111000001000xx00000100000  bgtlr- 0x4
{                      "bgtlrl - NUM",{0x4DC10821,0x00001800}}, // 0100110111000001000xx00000100001  bgtlrl- 0x4
{                      "bgtctr - NUM",{0x4DC10C20,0x00001800}}, // 0100110111000001000xx10000100000  bgtctr- 0x4
{                     "bgtctrl - NUM",{0x4DC10C21,0x00001800}}, // 0100110111000001000xx10000100001  bgtctrl- 0x4
{                           "beqlr -",{0x4DC20020,0x00000000}}, // 01001101110000100000000000100000  beqlr-
{                          "beqlrl -",{0x4DC20021,0x00000000}}, // 01001101110000100000000000100001  beqlrl-
{                          "beqctr -",{0x4DC20420,0x00000000}}, // 01001101110000100000010000100000  beqctr-
{                         "beqctrl -",{0x4DC20421,0x00000000}}, // 01001101110000100000010000100001  beqctrl-
{                       "beqlr - NUM",{0x4DC20820,0x00001800}}, // 0100110111000010000xx00000100000  beqlr- 0x4
{                      "beqlrl - NUM",{0x4DC20821,0x00001800}}, // 0100110111000010000xx00000100001  beqlrl- 0x4
{                      "beqctr - NUM",{0x4DC20C20,0x00001800}}, // 0100110111000010000xx10000100000  beqctr- 0x4
{                     "beqctrl - NUM",{0x4DC20C21,0x00001800}}, // 0100110111000010000xx10000100001  beqctrl- 0x4
{                           "bsolr -",{0x4DC30020,0x00000000}}, // 01001101110000110000000000100000  bsolr-
{                          "bsolrl -",{0x4DC30021,0x00000000}}, // 01001101110000110000000000100001  bsolrl-
{                          "bsoctr -",{0x4DC30420,0x00000000}}, // 01001101110000110000010000100000  bsoctr-
{                         "bsoctrl -",{0x4DC30421,0x00000000}}, // 01001101110000110000010000100001  bsoctrl-
{                       "bsolr - NUM",{0x4DC30820,0x00001800}}, // 0100110111000011000xx00000100000  bsolr- 0x4
{                      "bsolrl - NUM",{0x4DC30821,0x00001800}}, // 0100110111000011000xx00000100001  bsolrl- 0x4
{                      "bsoctr - NUM",{0x4DC30C20,0x00001800}}, // 0100110111000011000xx10000100000  bsoctr- 0x4
{                     "bsoctrl - NUM",{0x4DC30C21,0x00001800}}, // 0100110111000011000xx10000100001  bsoctrl- 0x4
{                      "bltlr - CREG",{0x4DC40020,0x001C0000}}, // 01001101110xxx000000000000100000  bltlr- cr1
{                     "bltlrl - CREG",{0x4DC40021,0x001C0000}}, // 01001101110xxx000000000000100001  bltlrl- cr1
{                     "bltctr - CREG",{0x4DC40420,0x001C0000}}, // 01001101110xxx000000010000100000  bltctr- cr1
{                    "bltctrl - CREG",{0x4DC40421,0x001C0000}}, // 01001101110xxx000000010000100001  bltctrl- cr1
{                "bltlr - CREG , NUM",{0x4DC40820,0x001C1800}}, // 01001101110xxx00000xx00000100000  bltlr- cr1, 0x4
{               "bltlrl - CREG , NUM",{0x4DC40821,0x001C1800}}, // 01001101110xxx00000xx00000100001  bltlrl- cr1, 0x4
{               "bltctr - CREG , NUM",{0x4DC40C20,0x001C1800}}, // 01001101110xxx00000xx10000100000  bltctr- cr1, 0x4
{              "bltctrl - CREG , NUM",{0x4DC40C21,0x001C1800}}, // 01001101110xxx00000xx10000100001  bltctrl- cr1, 0x4
{                      "bgtlr - CREG",{0x4DC50020,0x001C0000}}, // 01001101110xxx010000000000100000  bgtlr- cr1
{                     "bgtlrl - CREG",{0x4DC50021,0x001C0000}}, // 01001101110xxx010000000000100001  bgtlrl- cr1
{                     "bgtctr - CREG",{0x4DC50420,0x001C0000}}, // 01001101110xxx010000010000100000  bgtctr- cr1
{                    "bgtctrl - CREG",{0x4DC50421,0x001C0000}}, // 01001101110xxx010000010000100001  bgtctrl- cr1
{                "bgtlr - CREG , NUM",{0x4DC50820,0x001C1800}}, // 01001101110xxx01000xx00000100000  bgtlr- cr1, 0x4
{               "bgtlrl - CREG , NUM",{0x4DC50821,0x001C1800}}, // 01001101110xxx01000xx00000100001  bgtlrl- cr1, 0x4
{               "bgtctr - CREG , NUM",{0x4DC50C20,0x001C1800}}, // 01001101110xxx01000xx10000100000  bgtctr- cr1, 0x4
{              "bgtctrl - CREG , NUM",{0x4DC50C21,0x001C1800}}, // 01001101110xxx01000xx10000100001  bgtctrl- cr1, 0x4
{                      "beqlr - CREG",{0x4DC60020,0x001C0000}}, // 01001101110xxx100000000000100000  beqlr- cr1
{                     "beqlrl - CREG",{0x4DC60021,0x001C0000}}, // 01001101110xxx100000000000100001  beqlrl- cr1
{                     "beqctr - CREG",{0x4DC60420,0x001C0000}}, // 01001101110xxx100000010000100000  beqctr- cr1
{                    "beqctrl - CREG",{0x4DC60421,0x001C0000}}, // 01001101110xxx100000010000100001  beqctrl- cr1
{                "beqlr - CREG , NUM",{0x4DC60820,0x001C1800}}, // 01001101110xxx10000xx00000100000  beqlr- cr1, 0x4
{               "beqlrl - CREG , NUM",{0x4DC60821,0x001C1800}}, // 01001101110xxx10000xx00000100001  beqlrl- cr1, 0x4
{               "beqctr - CREG , NUM",{0x4DC60C20,0x001C1800}}, // 01001101110xxx10000xx10000100000  beqctr- cr1, 0x4
{              "beqctrl - CREG , NUM",{0x4DC60C21,0x001C1800}}, // 01001101110xxx10000xx10000100001  beqctrl- cr1, 0x4
{                      "bsolr - CREG",{0x4DC70020,0x001C0000}}, // 01001101110xxx110000000000100000  bsolr- cr1
{                     "bsolrl - CREG",{0x4DC70021,0x001C0000}}, // 01001101110xxx110000000000100001  bsolrl- cr1
{                     "bsoctr - CREG",{0x4DC70420,0x001C0000}}, // 01001101110xxx110000010000100000  bsoctr- cr1
{                    "bsoctrl - CREG",{0x4DC70421,0x001C0000}}, // 01001101110xxx110000010000100001  bsoctrl- cr1
{                "bsolr - CREG , NUM",{0x4DC70820,0x001C1800}}, // 01001101110xxx11000xx00000100000  bsolr- cr1, 0x4
{               "bsolrl - CREG , NUM",{0x4DC70821,0x001C1800}}, // 01001101110xxx11000xx00000100001  bsolrl- cr1, 0x4
{               "bsoctr - CREG , NUM",{0x4DC70C20,0x001C1800}}, // 01001101110xxx11000xx10000100000  bsoctr- cr1, 0x4
{              "bsoctrl - CREG , NUM",{0x4DC70C21,0x001C1800}}, // 01001101110xxx11000xx10000100001  bsoctrl- cr1, 0x4
{                           "bltlr +",{0x4DE00020,0x00000000}}, // 01001101111000000000000000100000  bltlr+
{                          "bltlrl +",{0x4DE00021,0x00000000}}, // 01001101111000000000000000100001  bltlrl+
{                          "bltctr +",{0x4DE00420,0x00000000}}, // 01001101111000000000010000100000  bltctr+
{                         "bltctrl +",{0x4DE00421,0x00000000}}, // 01001101111000000000010000100001  bltctrl+
{                       "bltlr + NUM",{0x4DE00820,0x00001800}}, // 0100110111100000000xx00000100000  bltlr+ 0x4
{                      "bltlrl + NUM",{0x4DE00821,0x00001800}}, // 0100110111100000000xx00000100001  bltlrl+ 0x4
{                      "bltctr + NUM",{0x4DE00C20,0x00001800}}, // 0100110111100000000xx10000100000  bltctr+ 0x4
{                     "bltctrl + NUM",{0x4DE00C21,0x00001800}}, // 0100110111100000000xx10000100001  bltctrl+ 0x4
{                           "bgtlr +",{0x4DE10020,0x00000000}}, // 01001101111000010000000000100000  bgtlr+
{                          "bgtlrl +",{0x4DE10021,0x00000000}}, // 01001101111000010000000000100001  bgtlrl+
{                          "bgtctr +",{0x4DE10420,0x00000000}}, // 01001101111000010000010000100000  bgtctr+
{                         "bgtctrl +",{0x4DE10421,0x00000000}}, // 01001101111000010000010000100001  bgtctrl+
{                       "bgtlr + NUM",{0x4DE10820,0x00001800}}, // 0100110111100001000xx00000100000  bgtlr+ 0x4
{                      "bgtlrl + NUM",{0x4DE10821,0x00001800}}, // 0100110111100001000xx00000100001  bgtlrl+ 0x4
{                      "bgtctr + NUM",{0x4DE10C20,0x00001800}}, // 0100110111100001000xx10000100000  bgtctr+ 0x4
{                     "bgtctrl + NUM",{0x4DE10C21,0x00001800}}, // 0100110111100001000xx10000100001  bgtctrl+ 0x4
{                           "beqlr +",{0x4DE20020,0x00000000}}, // 01001101111000100000000000100000  beqlr+
{                          "beqlrl +",{0x4DE20021,0x00000000}}, // 01001101111000100000000000100001  beqlrl+
{                          "beqctr +",{0x4DE20420,0x00000000}}, // 01001101111000100000010000100000  beqctr+
{                         "beqctrl +",{0x4DE20421,0x00000000}}, // 01001101111000100000010000100001  beqctrl+
{                       "beqlr + NUM",{0x4DE20820,0x00001800}}, // 0100110111100010000xx00000100000  beqlr+ 0x4
{                      "beqlrl + NUM",{0x4DE20821,0x00001800}}, // 0100110111100010000xx00000100001  beqlrl+ 0x4
{                      "beqctr + NUM",{0x4DE20C20,0x00001800}}, // 0100110111100010000xx10000100000  beqctr+ 0x4
{                     "beqctrl + NUM",{0x4DE20C21,0x00001800}}, // 0100110111100010000xx10000100001  beqctrl+ 0x4
{                           "bsolr +",{0x4DE30020,0x00000000}}, // 01001101111000110000000000100000  bsolr+
{                          "bsolrl +",{0x4DE30021,0x00000000}}, // 01001101111000110000000000100001  bsolrl+
{                          "bsoctr +",{0x4DE30420,0x00000000}}, // 01001101111000110000010000100000  bsoctr+
{                         "bsoctrl +",{0x4DE30421,0x00000000}}, // 01001101111000110000010000100001  bsoctrl+
{                       "bsolr + NUM",{0x4DE30820,0x00001800}}, // 0100110111100011000xx00000100000  bsolr+ 0x4
{                      "bsolrl + NUM",{0x4DE30821,0x00001800}}, // 0100110111100011000xx00000100001  bsolrl+ 0x4
{                      "bsoctr + NUM",{0x4DE30C20,0x00001800}}, // 0100110111100011000xx10000100000  bsoctr+ 0x4
{                     "bsoctrl + NUM",{0x4DE30C21,0x00001800}}, // 0100110111100011000xx10000100001  bsoctrl+ 0x4
{                      "bltlr + CREG",{0x4DE40020,0x001C0000}}, // 01001101111xxx000000000000100000  bltlr+ cr1
{                     "bltlrl + CREG",{0x4DE40021,0x001C0000}}, // 01001101111xxx000000000000100001  bltlrl+ cr1
{                     "bltctr + CREG",{0x4DE40420,0x001C0000}}, // 01001101111xxx000000010000100000  bltctr+ cr1
{                    "bltctrl + CREG",{0x4DE40421,0x001C0000}}, // 01001101111xxx000000010000100001  bltctrl+ cr1
{                "bltlr + CREG , NUM",{0x4DE40820,0x001C1800}}, // 01001101111xxx00000xx00000100000  bltlr+ cr1, 0x4
{               "bltlrl + CREG , NUM",{0x4DE40821,0x001C1800}}, // 01001101111xxx00000xx00000100001  bltlrl+ cr1, 0x4
{               "bltctr + CREG , NUM",{0x4DE40C20,0x001C1800}}, // 01001101111xxx00000xx10000100000  bltctr+ cr1, 0x4
{              "bltctrl + CREG , NUM",{0x4DE40C21,0x001C1800}}, // 01001101111xxx00000xx10000100001  bltctrl+ cr1, 0x4
{                      "bgtlr + CREG",{0x4DE50020,0x001C0000}}, // 01001101111xxx010000000000100000  bgtlr+ cr1
{                     "bgtlrl + CREG",{0x4DE50021,0x001C0000}}, // 01001101111xxx010000000000100001  bgtlrl+ cr1
{                     "bgtctr + CREG",{0x4DE50420,0x001C0000}}, // 01001101111xxx010000010000100000  bgtctr+ cr1
{                    "bgtctrl + CREG",{0x4DE50421,0x001C0000}}, // 01001101111xxx010000010000100001  bgtctrl+ cr1
{                "bgtlr + CREG , NUM",{0x4DE50820,0x001C1800}}, // 01001101111xxx01000xx00000100000  bgtlr+ cr1, 0x4
{               "bgtlrl + CREG , NUM",{0x4DE50821,0x001C1800}}, // 01001101111xxx01000xx00000100001  bgtlrl+ cr1, 0x4
{               "bgtctr + CREG , NUM",{0x4DE50C20,0x001C1800}}, // 01001101111xxx01000xx10000100000  bgtctr+ cr1, 0x4
{              "bgtctrl + CREG , NUM",{0x4DE50C21,0x001C1800}}, // 01001101111xxx01000xx10000100001  bgtctrl+ cr1, 0x4
{                      "beqlr + CREG",{0x4DE60020,0x001C0000}}, // 01001101111xxx100000000000100000  beqlr+ cr1
{                     "beqlrl + CREG",{0x4DE60021,0x001C0000}}, // 01001101111xxx100000000000100001  beqlrl+ cr1
{                     "beqctr + CREG",{0x4DE60420,0x001C0000}}, // 01001101111xxx100000010000100000  beqctr+ cr1
{                    "beqctrl + CREG",{0x4DE60421,0x001C0000}}, // 01001101111xxx100000010000100001  beqctrl+ cr1
{                "beqlr + CREG , NUM",{0x4DE60820,0x001C1800}}, // 01001101111xxx10000xx00000100000  beqlr+ cr1, 0x4
{               "beqlrl + CREG , NUM",{0x4DE60821,0x001C1800}}, // 01001101111xxx10000xx00000100001  beqlrl+ cr1, 0x4
{               "beqctr + CREG , NUM",{0x4DE60C20,0x001C1800}}, // 01001101111xxx10000xx10000100000  beqctr+ cr1, 0x4
{              "beqctrl + CREG , NUM",{0x4DE60C21,0x001C1800}}, // 01001101111xxx10000xx10000100001  beqctrl+ cr1, 0x4
{                      "bsolr + CREG",{0x4DE70020,0x001C0000}}, // 01001101111xxx110000000000100000  bsolr+ cr1
{                     "bsolrl + CREG",{0x4DE70021,0x001C0000}}, // 01001101111xxx110000000000100001  bsolrl+ cr1
{                     "bsoctr + CREG",{0x4DE70420,0x001C0000}}, // 01001101111xxx110000010000100000  bsoctr+ cr1
{                    "bsoctrl + CREG",{0x4DE70421,0x001C0000}}, // 01001101111xxx110000010000100001  bsoctrl+ cr1
{                "bsolr + CREG , NUM",{0x4DE70820,0x001C1800}}, // 01001101111xxx11000xx00000100000  bsolr+ cr1, 0x4
{               "bsolrl + CREG , NUM",{0x4DE70821,0x001C1800}}, // 01001101111xxx11000xx00000100001  bsolrl+ cr1, 0x4
{               "bsoctr + CREG , NUM",{0x4DE70C20,0x001C1800}}, // 01001101111xxx11000xx10000100000  bsoctr+ cr1, 0x4
{              "bsoctrl + CREG , NUM",{0x4DE70C21,0x001C1800}}, // 01001101111xxx11000xx10000100001  bsoctrl+ cr1, 0x4
{                            "bdnzlr",{0x4E000020,0x01BF0000}}, // 0100111xx0xxxxxx0000000000100000  bdnzlr
{                           "bdnzlrl",{0x4E000021,0x01BF0000}}, // 0100111xx0xxxxxx0000000000100001  bdnzlrl
{                           "bdnzctr",{0x4E000420,0x01BF0000}}, // 0100111xx0xxxxxx0000010000100000  bdnzctr
{                          "bdnzctrl",{0x4E000421,0x01BF0000}}, // 0100111xx0xxxxxx0000010000100001  bdnzctrl
{                        "bdnzlr NUM",{0x4E000820,0x01BF1800}}, // 0100111xx0xxxxxx000xx00000100000  bdnzlr 0x4
{                       "bdnzlrl NUM",{0x4E000821,0x01BF1800}}, // 0100111xx0xxxxxx000xx00000100001  bdnzlrl 0x4
{                       "bdnzctr NUM",{0x4E000C20,0x01BF1800}}, // 0100111xx0xxxxxx000xx10000100000  bdnzctr 0x4
{                      "bdnzctrl NUM",{0x4E000C21,0x01BF1800}}, // 0100111xx0xxxxxx000xx10000100001  bdnzctrl 0x4
{                             "bdzlr",{0x4E400020,0x01BF0000}}, // 0100111xx1xxxxxx0000000000100000  bdzlr
{                            "bdzlrl",{0x4E400021,0x01BF0000}}, // 0100111xx1xxxxxx0000000000100001  bdzlrl
{                            "bdzctr",{0x4E400420,0x01BF0000}}, // 0100111xx1xxxxxx0000010000100000  bdzctr
{                           "bdzctrl",{0x4E400421,0x01BF0000}}, // 0100111xx1xxxxxx0000010000100001  bdzctrl
{                         "bdzlr NUM",{0x4E400820,0x01BF1800}}, // 0100111xx1xxxxxx000xx00000100000  bdzlr 0x4
{                        "bdzlrl NUM",{0x4E400821,0x01BF1800}}, // 0100111xx1xxxxxx000xx00000100001  bdzlrl 0x4
{                        "bdzctr NUM",{0x4E400C20,0x01BF1800}}, // 0100111xx1xxxxxx000xx10000100000  bdzctr 0x4
{                       "bdzctrl NUM",{0x4E400C21,0x01BF1800}}, // 0100111xx1xxxxxx000xx10000100001  bdzctrl 0x4
{                               "blr",{0x4E800020,0x00000000}}, // 01001110100000000000000000100000  blr
{                              "blrl",{0x4E800021,0x00000000}}, // 01001110100000000000000000100001  blrl
{                              "bctr",{0x4E800420,0x00000000}}, // 01001110100000000000010000100000  bctr
{                             "bctrl",{0x4E800421,0x00000000}}, // 01001110100000000000010000100001  bctrl
{                          "bdnzlr -",{0x4F000020,0x001F0000}}, // 01001111000xxxxx0000000000100000  bdnzlr-
{                         "bdnzlrl -",{0x4F000021,0x001F0000}}, // 01001111000xxxxx0000000000100001  bdnzlrl-
{                         "bdnzctr -",{0x4F000420,0x001F0000}}, // 01001111000xxxxx0000010000100000  bdnzctr-
{                        "bdnzctrl -",{0x4F000421,0x001F0000}}, // 01001111000xxxxx0000010000100001  bdnzctrl-
{                      "bdnzlr - NUM",{0x4F000820,0x001F1800}}, // 01001111000xxxxx000xx00000100000  bdnzlr- 0x4
{                     "bdnzlrl - NUM",{0x4F000821,0x001F1800}}, // 01001111000xxxxx000xx00000100001  bdnzlrl- 0x4
{                     "bdnzctr - NUM",{0x4F000C20,0x001F1800}}, // 01001111000xxxxx000xx10000100000  bdnzctr- 0x4
{                    "bdnzctrl - NUM",{0x4F000C21,0x001F1800}}, // 01001111000xxxxx000xx10000100001  bdnzctrl- 0x4
{                          "bdnzlr +",{0x4F200020,0x001F0000}}, // 01001111001xxxxx0000000000100000  bdnzlr+
{                         "bdnzlrl +",{0x4F200021,0x001F0000}}, // 01001111001xxxxx0000000000100001  bdnzlrl+
{                         "bdnzctr +",{0x4F200420,0x001F0000}}, // 01001111001xxxxx0000010000100000  bdnzctr+
{                        "bdnzctrl +",{0x4F200421,0x001F0000}}, // 01001111001xxxxx0000010000100001  bdnzctrl+
{                      "bdnzlr + NUM",{0x4F200820,0x001F1800}}, // 01001111001xxxxx000xx00000100000  bdnzlr+ 0x4
{                     "bdnzlrl + NUM",{0x4F200821,0x001F1800}}, // 01001111001xxxxx000xx00000100001  bdnzlrl+ 0x4
{                     "bdnzctr + NUM",{0x4F200C20,0x001F1800}}, // 01001111001xxxxx000xx10000100000  bdnzctr+ 0x4
{                    "bdnzctrl + NUM",{0x4F200C21,0x001F1800}}, // 01001111001xxxxx000xx10000100001  bdnzctrl+ 0x4
{                           "bdzlr -",{0x4F400020,0x001F0000}}, // 01001111010xxxxx0000000000100000  bdzlr-
{                          "bdzlrl -",{0x4F400021,0x001F0000}}, // 01001111010xxxxx0000000000100001  bdzlrl-
{                          "bdzctr -",{0x4F400420,0x001F0000}}, // 01001111010xxxxx0000010000100000  bdzctr-
{                         "bdzctrl -",{0x4F400421,0x001F0000}}, // 01001111010xxxxx0000010000100001  bdzctrl-
{                       "bdzlr - NUM",{0x4F400820,0x001F1800}}, // 01001111010xxxxx000xx00000100000  bdzlr- 0x4
{                      "bdzlrl - NUM",{0x4F400821,0x001F1800}}, // 01001111010xxxxx000xx00000100001  bdzlrl- 0x4
{                      "bdzctr - NUM",{0x4F400C20,0x001F1800}}, // 01001111010xxxxx000xx10000100000  bdzctr- 0x4
{                     "bdzctrl - NUM",{0x4F400C21,0x001F1800}}, // 01001111010xxxxx000xx10000100001  bdzctrl- 0x4
{                           "bdzlr +",{0x4F600020,0x001F0000}}, // 01001111011xxxxx0000000000100000  bdzlr+
{                          "bdzlrl +",{0x4F600021,0x001F0000}}, // 01001111011xxxxx0000000000100001  bdzlrl+
{                          "bdzctr +",{0x4F600420,0x001F0000}}, // 01001111011xxxxx0000010000100000  bdzctr+
{                         "bdzctrl +",{0x4F600421,0x001F0000}}, // 01001111011xxxxx0000010000100001  bdzctrl+
{                       "bdzlr + NUM",{0x4F600820,0x001F1800}}, // 01001111011xxxxx000xx00000100000  bdzlr+ 0x4
{                      "bdzlrl + NUM",{0x4F600821,0x001F1800}}, // 01001111011xxxxx000xx00000100001  bdzlrl+ 0x4
{                      "bdzctr + NUM",{0x4F600C20,0x001F1800}}, // 01001111011xxxxx000xx10000100000  bdzctr+ 0x4
{                     "bdzctrl + NUM",{0x4F600C21,0x001F1800}}, // 01001111011xxxxx000xx10000100001  bdzctrl+ 0x4
{"rlwimi GPR , GPR , NUM , NUM , NUM",{0x50000000,0x03FFFFFE}}, // 010100xxxxxxxxxxxxxxxxxxxxxxxxx0  rlwimi r0, r0, 0, 0, 0
{"rlwimi . GPR , GPR , NUM , NUM , NUM",{0x50000001,0x03FFFFFE}}, // 010100xxxxxxxxxxxxxxxxxxxxxxxxx1  rlwimi. r0, r0, 0, 0, 0
{"rlwinm GPR , GPR , NUM , NUM , NUM",{0x54000000,0x03FFFFFE}}, // 010101xxxxxxxxxxxxxxxxxxxxxxxxx0  rlwinm r0, r0, 0, 0, 0
{"rlwinm . GPR , GPR , NUM , NUM , NUM",{0x54000001,0x03FFFFFE}}, // 010101xxxxxxxxxxxxxxxxxxxxxxxxx1  rlwinm. r0, r0, 0, 0, 0
{              "slwi GPR , GPR , NUM",{0x5400003E,0x03FFF83E}}, // 010101xxxxxxxxxxxxxxx00000xxxxx0  slwi r0, r0, 0
{          "rotlwi . GPR , GPR , NUM",{0x5400003F,0x03FFF800}}, // 010101xxxxxxxxxxxxxxx00000111111  rotlwi. r0, r0, 0
{            "clrlwi GPR , GPR , NUM",{0x5400007E,0x03FF07C0}}, // 010101xxxxxxxxxx00000xxxxx111110  clrlwi r0, r0, 1
{          "clrlwi . GPR , GPR , NUM",{0x5400007F,0x03FF07C0}}, // 010101xxxxxxxxxx00000xxxxx111111  clrlwi. r0, r0, 1
{            "rotlwi GPR , GPR , NUM",{0x5400083E,0x03FFF800}}, // 010101xxxxxxxxxxxxxxx00000111110  rotlwi r0, r0, 1
{              "srwi GPR , GPR , NUM",{0x54000FFE,0x03FFFFC0}}, // 010101xxxxxxxxxxxxxxxxxxxx111110  srwi r0, r0, 0x1f
{ "rlwnm GPR , GPR , GPR , NUM , NUM",{0x5C000000,0x03FFFFFE}}, // 010111xxxxxxxxxxxxxxxxxxxxxxxxx0  rlwnm r0, r0, r0, 0, 0
{"rlwnm . GPR , GPR , GPR , NUM , NUM",{0x5C000001,0x03FFFFFE}}, // 010111xxxxxxxxxxxxxxxxxxxxxxxxx1  rlwnm. r0, r0, r0, 0, 0
{             "rotlw GPR , GPR , GPR",{0x5C00003E,0x03FFF800}}, // 010111xxxxxxxxxxxxxxx00000111110  rotlw r0, r0, r0
{           "rotlw . GPR , GPR , GPR",{0x5C00003F,0x03FFF800}}, // 010111xxxxxxxxxxxxxxx00000111111  rotlw. r0, r0, r0
{                               "nop",{0x60000000,0x00000000}}, // 01100000000000000000000000000000  nop
{               "ori GPR , GPR , NUM",{0x60000001,0x03FFFFFF}}, // 011000xxxxxxxxxxxxxxxxxxxxxxxxxx  ori r0, r0, 1
{              "oris GPR , GPR , NUM",{0x64000000,0x03FFFFFF}}, // 011001xxxxxxxxxxxxxxxxxxxxxxxxxx  oris r0, r0, 0
{                              "xnop",{0x68000000,0x00000000}}, // 01101000000000000000000000000000  xnop
{              "xori GPR , GPR , NUM",{0x68000001,0x03FFFFFF}}, // 011010xxxxxxxxxxxxxxxxxxxxxxxxxx  xori r0, r0, 1
{             "xoris GPR , GPR , NUM",{0x6C000000,0x03FFFFFF}}, // 011011xxxxxxxxxxxxxxxxxxxxxxxxxx  xoris r0, r0, 0
{            "andi . GPR , GPR , NUM",{0x70000000,0x03FFFFFF}}, // 011100xxxxxxxxxxxxxxxxxxxxxxxxxx  andi. r0, r0, 0
{           "andis . GPR , GPR , NUM",{0x74000000,0x03FFFFFF}}, // 011101xxxxxxxxxxxxxxxxxxxxxxxxxx  andis. r0, r0, 0
{            "rotldi GPR , GPR , NUM",{0x78000000,0x03FFF802}}, // 011110xxxxxxxxxxxxxxx000000000x0  rotldi r0, r0, 0
{          "rotldi . GPR , GPR , NUM",{0x78000001,0x03FFF802}}, // 011110xxxxxxxxxxxxxxx000000000x1  rotldi. r0, r0, 0
{      "rldicr GPR , GPR , NUM , NUM",{0x78000004,0x03FFFFE2}}, // 011110xxxxxxxxxxxxxxxxxxxxx001x0  rldicr r0, r0, 0, 0
{    "rldicr . GPR , GPR , NUM , NUM",{0x78000005,0x03FFFFE2}}, // 011110xxxxxxxxxxxxxxxxxxxxx001x1  rldicr. r0, r0, 0, 0
{       "rldic GPR , GPR , NUM , NUM",{0x78000008,0x03FFFFE2}}, // 011110xxxxxxxxxxxxxxxxxxxxx010x0  rldic r0, r0, 0, 0
{     "rldic . GPR , GPR , NUM , NUM",{0x78000009,0x03FFFFE2}}, // 011110xxxxxxxxxxxxxxxxxxxxx010x1  rldic. r0, r0, 0, 0
{      "rldimi GPR , GPR , NUM , NUM",{0x7800000C,0x03FFFFE2}}, // 011110xxxxxxxxxxxxxxxxxxxxx011x0  rldimi r0, r0, 0, 0
{    "rldimi . GPR , GPR , NUM , NUM",{0x7800000D,0x03FFFFE2}}, // 011110xxxxxxxxxxxxxxxxxxxxx011x1  rldimi. r0, r0, 0, 0
{             "rotld GPR , GPR , GPR",{0x78000010,0x03FFF800}}, // 011110xxxxxxxxxxxxxxx00000010000  rotld r0, r0, r0
{           "rotld . GPR , GPR , GPR",{0x78000011,0x03FFF800}}, // 011110xxxxxxxxxxxxxxx00000010001  rotld. r0, r0, r0
{       "rldcr GPR , GPR , GPR , NUM",{0x78000012,0x03FFFFE0}}, // 011110xxxxxxxxxxxxxxxxxxxxx10010  rldcr r0, r0, r0, 0
{     "rldcr . GPR , GPR , GPR , NUM",{0x78000013,0x03FFFFE0}}, // 011110xxxxxxxxxxxxxxxxxxxxx10011  rldcr. r0, r0, r0, 0
{            "clrldi GPR , GPR , NUM",{0x78000020,0x03FF07E0}}, // 011110xxxxxxxxxx00000xxxxxx00000  clrldi r0, r0, 0x20
{          "clrldi . GPR , GPR , NUM",{0x78000021,0x03FF07E0}}, // 011110xxxxxxxxxx00000xxxxxx00001  clrldi. r0, r0, 0x20
{      "rldicl GPR , GPR , NUM , NUM",{0x78000022,0x03FFFFE2}}, // 011110xxxxxxxxxxxxxxxxxxxxx000x0  rldicl r0, r0, 0x20, 0x20
{    "rldicl . GPR , GPR , NUM , NUM",{0x78000023,0x03FFFFE2}}, // 011110xxxxxxxxxxxxxxxxxxxxx000x1  rldicl. r0, r0, 0x20, 0x20
{       "rldcl GPR , GPR , GPR , NUM",{0x78000030,0x03FFFFE0}}, // 011110xxxxxxxxxxxxxxxxxxxxx10000  rldcl r0, r0, r0, 0x20
{     "rldcl . GPR , GPR , GPR , NUM",{0x78000031,0x03FFFFE0}}, // 011110xxxxxxxxxxxxxxxxxxxxx10001  rldcl. r0, r0, r0, 0x20
{              "sldi GPR , GPR , NUM",{0x780007C6,0x03FFFFE2}}, // 011110xxxxxxxxxxxxxxxxxxxxx001x0  sldi r0, r0, 0x20
{                    "cmpw GPR , GPR",{0x7C000000,0x001FF800}}, // 01111100000xxxxxxxxxx00000000000  cmpw r0, r0
{                "tw NUM , GPR , GPR",{0x7C000008,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00000001000  tw 0, r0, r0
{             "lvsl VREG , NUM , GPR",{0x7C00000C,0x03E0F800}}, // 011111xxxxx00000xxxxx00000001100  lvsl v0, 0, r0
{            "lvebx VREG , NUM , GPR",{0x7C00000E,0x03E0F800}}, // 011111xxxxx00000xxxxx00000001110  lvebx v0, 0, r0
{             "subfc GPR , GPR , GPR",{0x7C000010,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00000010000  subfc r0, r0, r0
{           "subfc . GPR , GPR , GPR",{0x7C000011,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00000010001  subfc. r0, r0, r0
{            "mulhdu GPR , GPR , GPR",{0x7C000012,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00000010010  mulhdu r0, r0, r0
{          "mulhdu . GPR , GPR , GPR",{0x7C000013,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00000010011  mulhdu. r0, r0, r0
{              "addc GPR , GPR , GPR",{0x7C000014,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00000010100  addc r0, r0, r0
{            "addc . GPR , GPR , GPR",{0x7C000015,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00000010101  addc. r0, r0, r0
{            "mulhwu GPR , GPR , GPR",{0x7C000016,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00000010110  mulhwu r0, r0, r0
{          "mulhwu . GPR , GPR , GPR",{0x7C000017,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00000010111  mulhwu. r0, r0, r0
{        "isel GPR , NUM , GPR , NUM",{0x7C00001E,0x03E0FFC0}}, // 011111xxxxx00000xxxxxxxxxx011110  isel r0, 0, r0, 0
{                          "mfcr GPR",{0x7C000026,0x03E00000}}, // 011111xxxxx000000000000000100110  mfcr r0
{             "lwarx GPR , NUM , GPR",{0x7C000028,0x03E0F800}}, // 011111xxxxx00000xxxxx00000101000  lwarx r0, 0, r0
{               "ldx GPR , NUM , GPR",{0x7C00002A,0x03E0F800}}, // 011111xxxxx00000xxxxx00000101010  ldx r0, 0, r0
{              "lwzx GPR , NUM , GPR",{0x7C00002E,0x03E0F800}}, // 011111xxxxx00000xxxxx00000101110  lwzx r0, 0, r0
{               "slw GPR , GPR , GPR",{0x7C000030,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00000110000  slw r0, r0, r0
{             "slw . GPR , GPR , GPR",{0x7C000031,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00000110001  slw. r0, r0, r0
{                  "cntlzw GPR , GPR",{0x7C000034,0x03FF0000}}, // 011111xxxxxxxxxx0000000000110100  cntlzw r0, r0
{                "cntlzw . GPR , GPR",{0x7C000035,0x03FF0000}}, // 011111xxxxxxxxxx0000000000110101  cntlzw. r0, r0
{               "sld GPR , GPR , GPR",{0x7C000036,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00000110110  sld r0, r0, r0
{             "sld . GPR , GPR , GPR",{0x7C000037,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00000110111  sld. r0, r0, r0
{               "and GPR , GPR , GPR",{0x7C000038,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00000111000  and r0, r0, r0
{             "and . GPR , GPR , GPR",{0x7C000039,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00000111001  and. r0, r0, r0
{                   "cmplw GPR , GPR",{0x7C000040,0x001FF800}}, // 01111100000xxxxxxxxxx00001000000  cmplw r0, r0
{             "lvsr VREG , NUM , GPR",{0x7C00004C,0x03E0F800}}, // 011111xxxxx00000xxxxx00001001100  lvsr v0, 0, r0
{            "lvehx VREG , NUM , GPR",{0x7C00004E,0x03E0F800}}, // 011111xxxxx00000xxxxx00001001110  lvehx v0, 0, r0
{              "subf GPR , GPR , GPR",{0x7C000050,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00001010000  subf r0, r0, r0
{            "subf . GPR , GPR , GPR",{0x7C000051,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00001010001  subf. r0, r0, r0
{              "ldux GPR , NUM , GPR",{0x7C00006A,0x03E0F800}}, // 011111xxxxx00000xxxxx00001101010  ldux r0, 0, r0
{                   "dcbst NUM , GPR",{0x7C00006C,0x0000F800}}, // 0111110000000000xxxxx00001101100  dcbst 0, r0
{             "lwzux GPR , NUM , GPR",{0x7C00006E,0x03E0F800}}, // 011111xxxxx00000xxxxx00001101110  lwzux r0, 0, r0
{                  "cntlzd GPR , GPR",{0x7C000074,0x03FF0000}}, // 011111xxxxxxxxxx0000000001110100  cntlzd r0, r0
{                "cntlzd . GPR , GPR",{0x7C000075,0x03FF0000}}, // 011111xxxxxxxxxx0000000001110101  cntlzd. r0, r0
{              "andc GPR , GPR , GPR",{0x7C000078,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00001111000  andc r0, r0, r0
{            "andc . GPR , GPR , GPR",{0x7C000079,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00001111001  andc. r0, r0, r0
{                              "wait",{0x7C00007C,0x00000000}}, // 01111100000000000000000001111100  wait
{                "td NUM , GPR , GPR",{0x7C000088,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00010001000  td 0, r0, r0
{            "lvewx VREG , NUM , GPR",{0x7C00008E,0x03E0F800}}, // 011111xxxxx00000xxxxx00010001110  lvewx v0, 0, r0
{             "mulhd GPR , GPR , GPR",{0x7C000092,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00010010010  mulhd r0, r0, r0
{           "mulhd . GPR , GPR , GPR",{0x7C000093,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00010010011  mulhd. r0, r0, r0
{             "mulhw GPR , GPR , GPR",{0x7C000096,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00010010110  mulhw r0, r0, r0
{           "mulhw . GPR , GPR , GPR",{0x7C000097,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00010010111  mulhw. r0, r0, r0
{                         "mfmsr GPR",{0x7C0000A6,0x03E00000}}, // 011111xxxxx000000000000010100110  mfmsr r0
{             "ldarx GPR , NUM , GPR",{0x7C0000A8,0x03E0F800}}, // 011111xxxxx00000xxxxx00010101000  ldarx r0, 0, r0
{                    "dcbf NUM , GPR",{0x7C0000AC,0x0000F800}}, // 0111110000000000xxxxx00010101100  dcbf 0, r0
{              "lbzx GPR , NUM , GPR",{0x7C0000AE,0x03E0F800}}, // 011111xxxxx00000xxxxx00010101110  lbzx r0, 0, r0
{              "lvx VREG , NUM , GPR",{0x7C0000CE,0x03E0F800}}, // 011111xxxxx00000xxxxx00011001110  lvx v0, 0, r0
{                     "neg GPR , GPR",{0x7C0000D0,0x03FF0000}}, // 011111xxxxxxxxxx0000000011010000  neg r0, r0
{                   "neg . GPR , GPR",{0x7C0000D1,0x03FF0000}}, // 011111xxxxxxxxxx0000000011010001  neg. r0, r0
{             "lbzux GPR , NUM , GPR",{0x7C0000EE,0x03E0F800}}, // 011111xxxxx00000xxxxx00011101110  lbzux r0, 0, r0
{               "nor GPR , GPR , GPR",{0x7C0000F8,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00011111000  nor r0, r0, r0
{             "nor . GPR , GPR , GPR",{0x7C0000F9,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00011111001  nor. r0, r0, r0
{                         "wrtee GPR",{0x7C000106,0x03FEF801}}, // 011111xxxxxxxxx0xxxxx0010000011x  wrtee r0
{           "stvebx VREG , NUM , GPR",{0x7C00010E,0x03E0F800}}, // 011111xxxxx00000xxxxx00100001110  stvebx v0, 0, r0
{             "subfe GPR , GPR , GPR",{0x7C000110,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00100010000  subfe r0, r0, r0
{           "subfe . GPR , GPR , GPR",{0x7C000111,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00100010001  subfe. r0, r0, r0
{              "adde GPR , GPR , GPR",{0x7C000114,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00100010100  adde r0, r0, r0
{            "adde . GPR , GPR , GPR",{0x7C000115,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00100010101  adde. r0, r0, r0
{                   "mtcrf NUM , GPR",{0x7C000120,0x03EFF000}}, // 011111xxxxx0xxxxxxxx000100100000  mtcrf 0, r0
{                         "mtmsr GPR",{0x7C000124,0x03FEF801}}, // 011111xxxxxxxxx0xxxxx0010010010x  mtmsr r0
{              "stdx GPR , NUM , GPR",{0x7C00012A,0x03E0F800}}, // 011111xxxxx00000xxxxx00100101010  stdx r0, 0, r0
{           "stwcx . GPR , NUM , GPR",{0x7C00012D,0x03E0F800}}, // 011111xxxxx00000xxxxx00100101101  stwcx. r0, 0, r0
{              "stwx GPR , NUM , GPR",{0x7C00012E,0x03E0F800}}, // 011111xxxxx00000xxxxx00100101110  stwx r0, 0, r0
{                        "wrteei NUM",{0x7C000146,0x03FFF801}}, // 011111xxxxxxxxxxxxxxx0010100011x  wrteei 0
{           "stvehx VREG , NUM , GPR",{0x7C00014E,0x03E0F800}}, // 011111xxxxx00000xxxxx00101001110  stvehx v0, 0, r0
{                        "mtmsrd GPR",{0x7C000164,0x03FEF801}}, // 011111xxxxxxxxx0xxxxx0010110010x  mtmsrd r0
{             "stdux GPR , NUM , GPR",{0x7C00016A,0x03E0F800}}, // 011111xxxxx00000xxxxx00101101010  stdux r0, 0, r0
{             "stwux GPR , NUM , GPR",{0x7C00016E,0x03E0F800}}, // 011111xxxxx00000xxxxx00101101110  stwux r0, 0, r0
{           "stvewx VREG , NUM , GPR",{0x7C00018E,0x03E0F800}}, // 011111xxxxx00000xxxxx00110001110  stvewx v0, 0, r0
{                  "subfze GPR , GPR",{0x7C000190,0x03FF0000}}, // 011111xxxxxxxxxx0000000110010000  subfze r0, r0
{                "subfze . GPR , GPR",{0x7C000191,0x03FF0000}}, // 011111xxxxxxxxxx0000000110010001  subfze. r0, r0
{                   "addze GPR , GPR",{0x7C000194,0x03FF0000}}, // 011111xxxxxxxxxx0000000110010100  addze r0, r0
{                 "addze . GPR , GPR",{0x7C000195,0x03FF0000}}, // 011111xxxxxxxxxx0000000110010101  addze. r0, r0
{                    "mtsr NUM , GPR",{0x7C0001A4,0x03FFF801}}, // 011111xxxxxxxxxxxxxxx0011010010x  mtsr 0, r0
{           "stdcx . GPR , NUM , GPR",{0x7C0001AD,0x03E0F800}}, // 011111xxxxx00000xxxxx00110101101  stdcx. r0, 0, r0
{              "stbx GPR , NUM , GPR",{0x7C0001AE,0x03E0F800}}, // 011111xxxxx00000xxxxx00110101110  stbx r0, 0, r0
{             "stvx VREG , NUM , GPR",{0x7C0001CE,0x03E0F800}}, // 011111xxxxx00000xxxxx00111001110  stvx v0, 0, r0
{                  "subfme GPR , GPR",{0x7C0001D0,0x03FF0000}}, // 011111xxxxxxxxxx0000000111010000  subfme r0, r0
{                "subfme . GPR , GPR",{0x7C0001D1,0x03FF0000}}, // 011111xxxxxxxxxx0000000111010001  subfme. r0, r0
{             "mulld GPR , GPR , GPR",{0x7C0001D2,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00111010010  mulld r0, r0, r0
{           "mulld . GPR , GPR , GPR",{0x7C0001D3,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00111010011  mulld. r0, r0, r0
{                   "addme GPR , GPR",{0x7C0001D4,0x03FF0000}}, // 011111xxxxxxxxxx0000000111010100  addme r0, r0
{                 "addme . GPR , GPR",{0x7C0001D5,0x03FF0000}}, // 011111xxxxxxxxxx0000000111010101  addme. r0, r0
{             "mullw GPR , GPR , GPR",{0x7C0001D6,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00111010110  mullw r0, r0, r0
{           "mullw . GPR , GPR , GPR",{0x7C0001D7,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00111010111  mullw. r0, r0, r0
{                  "mtsrin GPR , GPR",{0x7C0001E4,0x03FFF801}}, // 011111xxxxxxxxxxxxxxx0011110010x  mtsrin r0, r0
{                  "dcbtst NUM , GPR",{0x7C0001EC,0x0000F800}}, // 0111110000000000xxxxx00111101100  dcbtst 0, r0
{             "stbux GPR , NUM , GPR",{0x7C0001EE,0x03E0F800}}, // 011111xxxxx00000xxxxx00111101110  stbux r0, 0, r0
{               "add GPR , GPR , GPR",{0x7C000214,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01000010100  add r0, r0, r0
{             "add . GPR , GPR , GPR",{0x7C000215,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01000010101  add. r0, r0, r0
{                        "tlbiel GPR",{0x7C000224,0x0000F800}}, // 0111110000000000xxxxx01000100100  tlbiel r0
{                    "dcbt NUM , GPR",{0x7C00022C,0x0000F800}}, // 0111110000000000xxxxx01000101100  dcbt 0, r0
{              "lhzx GPR , NUM , GPR",{0x7C00022E,0x03E0F800}}, // 011111xxxxx00000xxxxx01000101110  lhzx r0, 0, r0
{               "eqv GPR , GPR , GPR",{0x7C000238,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01000111000  eqv r0, r0, r0
{             "eqv . GPR , GPR , GPR",{0x7C000239,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01000111001  eqv. r0, r0, r0
{                         "tlbie GPR",{0x7C000264,0x0000F800}}, // 0111110000000000xxxxx01001100100  tlbie r0
{             "lhzux GPR , NUM , GPR",{0x7C00026E,0x03E0F800}}, // 011111xxxxx00000xxxxx01001101110  lhzux r0, 0, r0
{               "xor GPR , GPR , GPR",{0x7C000278,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01001111000  xor r0, r0, r0
{             "xor . GPR , GPR , GPR",{0x7C000279,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01001111001  xor. r0, r0, r0
{                   "mfdcr GPR , NUM",{0x7C000286,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01010000110  mfdcr r0, 0
{          "lxvdsx VSREG , NUM , GPR",{0x7C000298,0x03E0F800}}, // 011111xxxxx00000xxxxx01010011000  lxvdsx vs0, 0, r0
{                   "mfspr GPR , NUM",{0x7C0002A6,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01010100110  mfspr r0, 0
{              "lwax GPR , NUM , GPR",{0x7C0002AA,0x03E0F800}}, // 011111xxxxx00000xxxxx01010101010  lwax r0, 0, r0
{               "dst GPR , GPR , NUM",{0x7C0002AC,0x007FF800}}, // 011111000xxxxxxxxxxxx01010101100  dst r0, r0, 0
{              "lhax GPR , NUM , GPR",{0x7C0002AE,0x03E0F800}}, // 011111xxxxx00000xxxxx01010101110  lhax r0, 0, r0
{             "lvxl VREG , NUM , GPR",{0x7C0002CE,0x03E0F800}}, // 011111xxxxx00000xxxxx01011001110  lvxl v0, 0, r0
{                             "tlbia",{0x7C0002E4,0x00000000}}, // 01111100000000000000001011100100  tlbia
{                    "mftb GPR , NUM",{0x7C0002E6,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01011100110  mftb r0, 0
{             "lwaux GPR , NUM , GPR",{0x7C0002EA,0x03E0F800}}, // 011111xxxxx00000xxxxx01011101010  lwaux r0, 0, r0
{             "dstst GPR , GPR , NUM",{0x7C0002EC,0x007FF800}}, // 011111000xxxxxxxxxxxx01011101100  dstst r0, r0, 0
{             "lhaux GPR , NUM , GPR",{0x7C0002EE,0x03E0F800}}, // 011111xxxxx00000xxxxx01011101110  lhaux r0, 0, r0
{                 "popcntw GPR , GPR",{0x7C0002F4,0x03FF0000}}, // 011111xxxxxxxxxx0000001011110100  popcntw r0, r0
{                  "slbmte GPR , GPR",{0x7C000324,0x03E0F800}}, // 011111xxxxx00000xxxxx01100100100  slbmte r0, r0
{              "sthx GPR , NUM , GPR",{0x7C00032E,0x03E0F800}}, // 011111xxxxx00000xxxxx01100101110  sthx r0, 0, r0
{               "orc GPR , GPR , GPR",{0x7C000338,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01100111000  orc r0, r0, r0
{             "orc . GPR , GPR , GPR",{0x7C000339,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01100111001  orc. r0, r0, r0
{                         "slbie GPR",{0x7C000364,0x0000F800}}, // 0111110000000000xxxxx01101100100  slbie r0
{             "sthux GPR , NUM , GPR",{0x7C00036E,0x03E0F800}}, // 011111xxxxx00000xxxxx01101101110  sthux r0, 0, r0
{                      "mr GPR , GPR",{0x7C000378,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01101111000  mr r0, r0
{              "or . GPR , GPR , GPR",{0x7C000379,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01101111001  or. r0, r0, r0
{                   "mtdcr NUM , GPR",{0x7C000386,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01110000110  mtdcr 0, r0
{                   "dccci GPR , GPR",{0x7C00038C,0x001FF800}}, // 01111100000xxxxxxxxxx01110001100  dccci r0, r0
{             "divdu GPR , GPR , GPR",{0x7C000392,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01110010010  divdu r0, r0, r0
{           "divdu . GPR , GPR , GPR",{0x7C000393,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01110010011  divdu. r0, r0, r0
{             "divwu GPR , GPR , GPR",{0x7C000396,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01110010110  divwu r0, r0, r0
{           "divwu . GPR , GPR , GPR",{0x7C000397,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01110010111  divwu. r0, r0, r0
{                   "mtspr NUM , GPR",{0x7C0003A6,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01110100110  mtspr 0, r0
{                    "dcbi NUM , GPR",{0x7C0003AC,0x0000F800}}, // 0111110000000000xxxxx01110101100  dcbi 0, r0
{              "nand GPR , GPR , GPR",{0x7C0003B8,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01110111000  nand r0, r0, r0
{            "nand . GPR , GPR , GPR",{0x7C0003B9,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01110111001  nand. r0, r0, r0
{            "stvxl VREG , NUM , GPR",{0x7C0003CE,0x03E0F800}}, // 011111xxxxx00000xxxxx01111001110  stvxl v0, 0, r0
{              "divd GPR , GPR , GPR",{0x7C0003D2,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01111010010  divd r0, r0, r0
{            "divd . GPR , GPR , GPR",{0x7C0003D3,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01111010011  divd. r0, r0, r0
{              "divw GPR , GPR , GPR",{0x7C0003D6,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01111010110  divw r0, r0, r0
{            "divw . GPR , GPR , GPR",{0x7C0003D7,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01111010111  divw. r0, r0, r0
{                             "slbia",{0x7C0003E4,0x00000000}}, // 01111100000000000000001111100100  slbia
{                 "popcntd GPR , GPR",{0x7C0003F4,0x03FF0000}}, // 011111xxxxxxxxxx0000001111110100  popcntd r0, r0
{             "ldbrx GPR , NUM , GPR",{0x7C000428,0x03E0F800}}, // 011111xxxxx00000xxxxx10000101000  ldbrx r0, 0, r0
{             "lwbrx GPR , NUM , GPR",{0x7C00042C,0x03E0F800}}, // 011111xxxxx00000xxxxx10000101100  lwbrx r0, 0, r0
{             "lfsx FREG , NUM , GPR",{0x7C00042E,0x03E0F800}}, // 011111xxxxx00000xxxxx10000101110  lfsx f0, 0, r0
{               "srw GPR , GPR , GPR",{0x7C000430,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx10000110000  srw r0, r0, r0
{             "srw . GPR , GPR , GPR",{0x7C000431,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx10000110001  srw. r0, r0, r0
{               "srd GPR , GPR , GPR",{0x7C000436,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx10000110110  srd r0, r0, r0
{             "srd . GPR , GPR , GPR",{0x7C000437,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx10000110111  srd. r0, r0, r0
{                           "tlbsync",{0x7C00046C,0x00000000}}, // 01111100000000000000010001101100  tlbsync
{            "lfsux FREG , NUM , GPR",{0x7C00046E,0x03E0F800}}, // 011111xxxxx00000xxxxx10001101110  lfsux f0, 0, r0
{            "lxsdx FREG , NUM , GPR",{0x7C000498,0x03E0F800}}, // 011111xxxxx00000xxxxx10010011000  lxsdx f0, 0, r0
{                    "mfsr GPR , NUM",{0x7C0004A6,0x03FFF801}}, // 011111xxxxxxxxxxxxxxx1001010011x  mfsr r0, 0
{              "lswi GPR , GPR , NUM",{0x7C0004AA,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx10010101010  lswi r0, r0, 0
{                          "sync NUM",{0x7C0004AC,0x00600000}}, // 011111000xx000000000010010101100  sync 0
{             "lfdx FREG , NUM , GPR",{0x7C0004AE,0x03E0F800}}, // 011111xxxxx00000xxxxx10010101110  lfdx f0, 0, r0
{            "lfdux FREG , NUM , GPR",{0x7C0004EE,0x03E0F800}}, // 011111xxxxx00000xxxxx10011101110  lfdux f0, 0, r0
{                  "mfsrin GPR , GPR",{0x7C000526,0x03FFF801}}, // 011111xxxxxxxxxxxxxxx1010010011x  mfsrin r0, r0
{            "stdbrx GPR , NUM , GPR",{0x7C000528,0x03E0F800}}, // 011111xxxxx00000xxxxx10100101000  stdbrx r0, 0, r0
{            "stwbrx GPR , NUM , GPR",{0x7C00052C,0x03E0F800}}, // 011111xxxxx00000xxxxx10100101100  stwbrx r0, 0, r0
{            "stfsx FREG , NUM , GPR",{0x7C00052E,0x03E0F800}}, // 011111xxxxx00000xxxxx10100101110  stfsx f0, 0, r0
{           "stfsux FREG , NUM , GPR",{0x7C00056E,0x03E0F800}}, // 011111xxxxx00000xxxxx10101101110  stfsux f0, 0, r0
{           "stxsdx FREG , NUM , GPR",{0x7C000598,0x03E0F800}}, // 011111xxxxx00000xxxxx10110011000  stxsdx f0, 0, r0
{          "stxsdx VSREG , NUM , GPR",{0x7C000599,0x03E0F800}}, // 011111xxxxx00000xxxxx10110011001  stxsdx vs32, 0, r0
{             "stswi GPR , GPR , NUM",{0x7C0005AA,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx10110101010  stswi r0, r0, 0
{            "stfdx FREG , NUM , GPR",{0x7C0005AE,0x03E0F800}}, // 011111xxxxx00000xxxxx10110101110  stfdx f0, 0, r0
{                    "dcba NUM , GPR",{0x7C0005EC,0x0000F800}}, // 0111110000000000xxxxx10111101100  dcba 0, r0
{           "stfdux FREG , NUM , GPR",{0x7C0005EE,0x03E0F800}}, // 011111xxxxx00000xxxxx10111101110  stfdux f0, 0, r0
{          "lxvw4x VSREG , NUM , GPR",{0x7C000618,0x03E0F800}}, // 011111xxxxx00000xxxxx11000011000  lxvw4x vs0, 0, r0
{                 "tlbivax GPR , GPR",{0x7C000624,0x001FF800}}, // 01111100000xxxxxxxxxx11000100100  tlbivax r0, r0
{             "lhbrx GPR , NUM , GPR",{0x7C00062C,0x03E0F800}}, // 011111xxxxx00000xxxxx11000101100  lhbrx r0, 0, r0
{              "sraw GPR , GPR , GPR",{0x7C000630,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx11000110000  sraw r0, r0, r0
{            "sraw . GPR , GPR , GPR",{0x7C000631,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx11000110001  sraw. r0, r0, r0
{              "srad GPR , GPR , GPR",{0x7C000634,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx11000110100  srad r0, r0, r0
{            "srad . GPR , GPR , GPR",{0x7C000635,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx11000110101  srad. r0, r0, r0
{                           "dss NUM",{0x7C00066C,0x00600000}}, // 011111000xx000000000011001101100  dss 0
{             "srawi GPR , GPR , NUM",{0x7C000670,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx11001110000  srawi r0, r0, 0
{           "srawi . GPR , GPR , NUM",{0x7C000671,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx11001110001  srawi. r0, r0, 0
{             "sradi GPR , GPR , NUM",{0x7C000674,0x03FFF802}}, // 011111xxxxxxxxxxxxxxx110011101x0  sradi r0, r0, 0
{           "sradi . GPR , GPR , NUM",{0x7C000675,0x03FFF802}}, // 011111xxxxxxxxxxxxxxx110011101x1  sradi. r0, r0, 0
{          "lxvd2x VSREG , NUM , GPR",{0x7C000698,0x03E0F800}}, // 011111xxxxx00000xxxxx11010011000  lxvd2x vs0, 0, r0
{                             "eieio",{0x7C0006AC,0x00000000}}, // 01111100000000000000011010101100  eieio
{                              "mbar",{0x7C0006AD,0x001FF801}}, // 01111100000xxxxxxxxxx1101010110x  mbar
{           "lfiwax FREG , NUM , GPR",{0x7C0006AE,0x03E0F800}}, // 011111xxxxx00000xxxxx11010101110  lfiwax f0, 0, r0
{           "lfiwzx FREG , NUM , GPR",{0x7C0006EE,0x03E0F800}}, // 011111xxxxx00000xxxxx11011101110  lfiwzx f0, 0, r0
{         "stxvw4x VSREG , NUM , GPR",{0x7C000718,0x03E0F801}}, // 011111xxxxx00000xxxxx1110001100x  stxvw4x vs0, 0, r0
{                   "tlbsx GPR , GPR",{0x7C000724,0x001FF800}}, // 01111100000xxxxxxxxxx11100100100  tlbsx r0, r0
{           "tlbsx . GPR , GPR , GPR",{0x7C000725,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx11100100101  tlbsx. r0, r0, r0
{                 "slbmfee GPR , GPR",{0x7C000726,0x03E0F800}}, // 011111xxxxx00000xxxxx11100100110  slbmfee r0, r0
{            "sthbrx GPR , NUM , GPR",{0x7C00072C,0x03E0F800}}, // 011111xxxxx00000xxxxx11100101100  sthbrx r0, 0, r0
{                   "extsh GPR , GPR",{0x7C000734,0x03FF0000}}, // 011111xxxxxxxxxx0000011100110100  extsh r0, r0
{                 "extsh . GPR , GPR",{0x7C000735,0x03FF0000}}, // 011111xxxxxxxxxx0000011100110101  extsh. r0, r0
{                             "tlbre",{0x7C000764,0x00000000}}, // 01111100000000000000011101100100  tlbre
{                   "extsb GPR , GPR",{0x7C000774,0x03FF0000}}, // 011111xxxxxxxxxx0000011101110100  extsb r0, r0
{                 "extsb . GPR , GPR",{0x7C000775,0x03FF0000}}, // 011111xxxxxxxxxx0000011101110101  extsb. r0, r0
{                   "iccci GPR , GPR",{0x7C00078C,0x001FF800}}, // 01111100000xxxxxxxxxx11110001100  iccci r0, r0
{         "stxvd2x VSREG , NUM , GPR",{0x7C000798,0x03E0F801}}, // 011111xxxxx00000xxxxx1111001100x  stxvd2x vs0, 0, r0
{                             "tlbwe",{0x7C0007A4,0x00000000}}, // 01111100000000000000011110100100  tlbwe
{                    "icbi NUM , GPR",{0x7C0007AC,0x0000F800}}, // 0111110000000000xxxxx11110101100  icbi 0, r0
{           "stfiwx FREG , NUM , GPR",{0x7C0007AE,0x03E0F800}}, // 011111xxxxx00000xxxxx11110101110  stfiwx f0, 0, r0
{                   "extsw GPR , GPR",{0x7C0007B4,0x03FF0000}}, // 011111xxxxxxxxxx0000011110110100  extsw r0, r0
{                 "extsw . GPR , GPR",{0x7C0007B5,0x03FF0000}}, // 011111xxxxxxxxxx0000011110110101  extsw. r0, r0
{                         "tlbli GPR",{0x7C0007E4,0x0000F800}}, // 0111110000000000xxxxx11111100100  tlbli r0
{                    "dcbz NUM , GPR",{0x7C0007EC,0x0000F800}}, // 0111110000000000xxxxx11111101100  dcbz 0, r0
{                "or GPR , GPR , GPR",{0x7C000B78,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01101111000  or r0, r0, r1
{                 "tlbrelo GPR , GPR",{0x7C000F64,0x03FFF000}}, // 011111xxxxxxxxxxxxxx111101100100  tlbrelo r0, r0
{                         "tlbld GPR",{0x7C000FA4,0x0000F800}}, // 0111110000000000xxxxx11110100100  tlbld r1
{                 "tlbrehi GPR , GPR",{0x7C001764,0x03FFF000}}, // 011111xxxxxxxxxxxxxx011101100100  tlbrehi r0, r0
{                         "mfbr0 GPR",{0x7C002286,0x03E00000}}, // 011111xxxxx000000010001010000110  mfbr0 r0
{                         "mtbr0 GPR",{0x7C002386,0x03E00000}}, // 011111xxxxx000000010001110000110  mtbr0 r0
{                     "mfspefscr GPR",{0x7C0082A6,0x03E00000}}, // 011111xxxxx000001000001010100110  mfspefscr r0
{                     "mtspefscr GPR",{0x7C0083A6,0x03E00000}}, // 011111xxxxx000001000001110100110  mtspefscr r0
{             "lvsl VREG , GPR , GPR",{0x7C01000C,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00000001100  lvsl v0, r1, r0
{            "lvebx VREG , GPR , GPR",{0x7C01000E,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00000001110  lvebx v0, r1, r0
{        "isel GPR , GPR , GPR , NUM",{0x7C01001E,0x03FFFFC0}}, // 011111xxxxxxxxxxxxxxxxxxxx011110  isel r0, r1, r0, 0
{             "lwarx GPR , GPR , GPR",{0x7C010028,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00000101000  lwarx r0, r1, r0
{               "ldx GPR , GPR , GPR",{0x7C01002A,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00000101010  ldx r0, r1, r0
{              "lwzx GPR , GPR , GPR",{0x7C01002E,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00000101110  lwzx r0, r1, r0
{             "lvsr VREG , GPR , GPR",{0x7C01004C,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00001001100  lvsr v0, r1, r0
{            "lvehx VREG , GPR , GPR",{0x7C01004E,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00001001110  lvehx v0, r1, r0
{              "ldux GPR , GPR , GPR",{0x7C01006A,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00001101010  ldux r0, r1, r0
{                   "dcbst GPR , GPR",{0x7C01006C,0x001FF800}}, // 01111100000xxxxxxxxxx00001101100  dcbst r1, r0
{             "lwzux GPR , GPR , GPR",{0x7C01006E,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00001101110  lwzux r0, r1, r0
{            "lvewx VREG , GPR , GPR",{0x7C01008E,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00010001110  lvewx v0, r1, r0
{             "ldarx GPR , GPR , GPR",{0x7C0100A8,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00010101000  ldarx r0, r1, r0
{                    "dcbf GPR , GPR",{0x7C0100AC,0x001FF800}}, // 01111100000xxxxxxxxxx00010101100  dcbf r1, r0
{              "lbzx GPR , GPR , GPR",{0x7C0100AE,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00010101110  lbzx r0, r1, r0
{              "lvx VREG , GPR , GPR",{0x7C0100CE,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00011001110  lvx v0, r1, r0
{             "lbzux GPR , GPR , GPR",{0x7C0100EE,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00011101110  lbzux r0, r1, r0
{           "stvebx VREG , GPR , GPR",{0x7C01010E,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00100001110  stvebx v0, r1, r0
{                   "mtmsr GPR , NUM",{0x7C010124,0x03FEF801}}, // 011111xxxxxxxxx1xxxxx0010010010x  mtmsr r0, 1
{              "stdx GPR , GPR , GPR",{0x7C01012A,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00100101010  stdx r0, r1, r0
{           "stwcx . GPR , GPR , GPR",{0x7C01012D,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00100101101  stwcx. r0, r1, r0
{              "stwx GPR , GPR , GPR",{0x7C01012E,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00100101110  stwx r0, r1, r0
{           "stvehx VREG , GPR , GPR",{0x7C01014E,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00101001110  stvehx v0, r1, r0
{                  "mtmsrd GPR , NUM",{0x7C010164,0x03FEF801}}, // 011111xxxxxxxxx1xxxxx0010110010x  mtmsrd r0, 1
{             "stdux GPR , GPR , GPR",{0x7C01016A,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00101101010  stdux r0, r1, r0
{             "stwux GPR , GPR , GPR",{0x7C01016E,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00101101110  stwux r0, r1, r0
{           "stvewx VREG , GPR , GPR",{0x7C01018E,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00110001110  stvewx v0, r1, r0
{           "stdcx . GPR , GPR , GPR",{0x7C0101AD,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00110101101  stdcx. r0, r1, r0
{              "stbx GPR , GPR , GPR",{0x7C0101AE,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00110101110  stbx r0, r1, r0
{             "stvx VREG , GPR , GPR",{0x7C0101CE,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00111001110  stvx v0, r1, r0
{                  "dcbtst GPR , GPR",{0x7C0101EC,0x001FF800}}, // 01111100000xxxxxxxxxx00111101100  dcbtst r1, r0
{             "stbux GPR , GPR , GPR",{0x7C0101EE,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx00111101110  stbux r0, r1, r0
{                    "dcbt GPR , GPR",{0x7C01022C,0x001FF800}}, // 01111100000xxxxxxxxxx01000101100  dcbt r1, r0
{              "lhzx GPR , GPR , GPR",{0x7C01022E,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01000101110  lhzx r0, r1, r0
{             "lhzux GPR , GPR , GPR",{0x7C01026E,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01001101110  lhzux r0, r1, r0
{          "lxvdsx VSREG , GPR , GPR",{0x7C010298,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01010011000  lxvdsx vs0, r1, r0
{                         "mfxer GPR",{0x7C0102A6,0x03E00000}}, // 011111xxxxx000010000001010100110  mfxer r0
{              "lwax GPR , GPR , GPR",{0x7C0102AA,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01010101010  lwax r0, r1, r0
{              "lhax GPR , GPR , GPR",{0x7C0102AE,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01010101110  lhax r0, r1, r0
{             "lvxl VREG , GPR , GPR",{0x7C0102CE,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01011001110  lvxl v0, r1, r0
{             "lwaux GPR , GPR , GPR",{0x7C0102EA,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01011101010  lwaux r0, r1, r0
{             "lhaux GPR , GPR , GPR",{0x7C0102EE,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01011101110  lhaux r0, r1, r0
{              "sthx GPR , GPR , GPR",{0x7C01032E,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01100101110  sthx r0, r1, r0
{             "sthux GPR , GPR , GPR",{0x7C01036E,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01101101110  sthux r0, r1, r0
{                         "mtxer GPR",{0x7C0103A6,0x03E00000}}, // 011111xxxxx000010000001110100110  mtxer r0
{                    "dcbi GPR , GPR",{0x7C0103AC,0x001FF800}}, // 01111100000xxxxxxxxxx01110101100  dcbi r1, r0
{            "stvxl VREG , GPR , GPR",{0x7C0103CE,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx01111001110  stvxl v0, r1, r0
{             "ldbrx GPR , GPR , GPR",{0x7C010428,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx10000101000  ldbrx r0, r1, r0
{             "lwbrx GPR , GPR , GPR",{0x7C01042C,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx10000101100  lwbrx r0, r1, r0
{             "lfsx FREG , GPR , GPR",{0x7C01042E,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx10000101110  lfsx f0, r1, r0
{            "lfsux FREG , GPR , GPR",{0x7C01046E,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx10001101110  lfsux f0, r1, r0
{            "lxsdx FREG , GPR , GPR",{0x7C010498,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx10010011000  lxsdx f0, r1, r0
{             "lfdx FREG , GPR , GPR",{0x7C0104AE,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx10010101110  lfdx f0, r1, r0
{            "lfdux FREG , GPR , GPR",{0x7C0104EE,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx10011101110  lfdux f0, r1, r0
{            "stdbrx GPR , GPR , GPR",{0x7C010528,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx10100101000  stdbrx r0, r1, r0
{            "stwbrx GPR , GPR , GPR",{0x7C01052C,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx10100101100  stwbrx r0, r1, r0
{            "stfsx FREG , GPR , GPR",{0x7C01052E,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx10100101110  stfsx f0, r1, r0
{           "stfsux FREG , GPR , GPR",{0x7C01056E,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx10101101110  stfsux f0, r1, r0
{           "stxsdx FREG , GPR , GPR",{0x7C010598,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx10110011000  stxsdx f0, r1, r0
{          "stxsdx VSREG , GPR , GPR",{0x7C010599,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx10110011001  stxsdx vs32, r1, r0
{            "stfdx FREG , GPR , GPR",{0x7C0105AE,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx10110101110  stfdx f0, r1, r0
{                    "dcba GPR , GPR",{0x7C0105EC,0x001FF800}}, // 01111100000xxxxxxxxxx10111101100  dcba r1, r0
{           "stfdux FREG , GPR , GPR",{0x7C0105EE,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx10111101110  stfdux f0, r1, r0
{          "lxvw4x VSREG , GPR , GPR",{0x7C010618,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx11000011000  lxvw4x vs0, r1, r0
{             "lhbrx GPR , GPR , GPR",{0x7C01062C,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx11000101100  lhbrx r0, r1, r0
{          "lxvd2x VSREG , GPR , GPR",{0x7C010698,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx11010011000  lxvd2x vs0, r1, r0
{           "lfiwax FREG , GPR , GPR",{0x7C0106AE,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx11010101110  lfiwax f0, r1, r0
{           "lfiwzx FREG , GPR , GPR",{0x7C0106EE,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx11011101110  lfiwzx f0, r1, r0
{         "stxvw4x VSREG , GPR , GPR",{0x7C010718,0x03FFF801}}, // 011111xxxxxxxxxxxxxxx1110001100x  stxvw4x vs0, r1, r0
{            "sthbrx GPR , GPR , GPR",{0x7C01072C,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx11100101100  sthbrx r0, r1, r0
{         "stxvd2x VSREG , GPR , GPR",{0x7C010798,0x03FFF801}}, // 011111xxxxxxxxxxxxxxx1111001100x  stxvd2x vs0, r1, r0
{                 "tlbwehi GPR , GPR",{0x7C0107A4,0x03FFF000}}, // 011111xxxxxxxxxxxxxx011110100100  tlbwehi r0, r1
{                    "icbi GPR , GPR",{0x7C0107AC,0x001FF800}}, // 01111100000xxxxxxxxxx11110101100  icbi r1, r0
{           "stfiwx FREG , GPR , GPR",{0x7C0107AE,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx11110101110  stfiwx f0, r1, r0
{                    "dcbz GPR , GPR",{0x7C0107EC,0x001FF800}}, // 01111100000xxxxxxxxxx11111101100  dcbz r1, r0
{                 "tlbwelo GPR , GPR",{0x7C010FA4,0x03FFF000}}, // 011111xxxxxxxxxxxxxx111110100100  tlbwelo r0, r1
{                         "mfbr1 GPR",{0x7C012286,0x03E00000}}, // 011111xxxxx000010010001010000110  mfbr1 r0
{                         "mtbr1 GPR",{0x7C012386,0x03E00000}}, // 011111xxxxx000010010001110000110  mtbr1 r0
{                         "mfbr2 GPR",{0x7C022286,0x03E00000}}, // 011111xxxxx000100010001010000110  mfbr2 r0
{                         "mtbr2 GPR",{0x7C022386,0x03E00000}}, // 011111xxxxx000100010001110000110  mtbr2 r0
{                         "mfbr3 GPR",{0x7C032286,0x03E00000}}, // 011111xxxxx000110010001010000110  mfbr3 r0
{                         "mtbr3 GPR",{0x7C032386,0x03E00000}}, // 011111xxxxx000110010001110000110  mtbr3 r0
{                        "mfrtcu GPR",{0x7C0402A6,0x03E00000}}, // 011111xxxxx001000000001010100110  mfrtcu r0
{                         "mfbr4 GPR",{0x7C042286,0x03E00000}}, // 011111xxxxx001000010001010000110  mfbr4 r0
{                         "mtbr4 GPR",{0x7C042386,0x03E00000}}, // 011111xxxxx001000010001110000110  mtbr4 r0
{                        "mfrtcl GPR",{0x7C0502A6,0x03E00000}}, // 011111xxxxx001010000001010100110  mfrtcl r0
{                         "mfbr5 GPR",{0x7C052286,0x03E00000}}, // 011111xxxxx001010010001010000110  mfbr5 r0
{                         "mtbr5 GPR",{0x7C052386,0x03E00000}}, // 011111xxxxx001010010001110000110  mtbr5 r0
{                         "mfbr6 GPR",{0x7C062286,0x03E00000}}, // 011111xxxxx001100010001010000110  mfbr6 r0
{                         "mtbr6 GPR",{0x7C062386,0x03E00000}}, // 011111xxxxx001100010001110000110  mtbr6 r0
{                         "mfbr7 GPR",{0x7C072286,0x03E00000}}, // 011111xxxxx001110010001010000110  mfbr7 r0
{                         "mtbr7 GPR",{0x7C072386,0x03E00000}}, // 011111xxxxx001110010001110000110  mtbr7 r0
{                          "mflr GPR",{0x7C0802A6,0x03E00000}}, // 011111xxxxx010000000001010100110  mflr r0
{                          "mtlr GPR",{0x7C0803A6,0x03E00000}}, // 011111xxxxx010000000001110100110  mtlr r0
{                         "mfctr GPR",{0x7C0902A6,0x03E00000}}, // 011111xxxxx010010000001010100110  mfctr r0
{                         "mtctr GPR",{0x7C0903A6,0x03E00000}}, // 011111xxxxx010010000001110100110  mtctr r0
{                         "mftbu GPR",{0x7C0D42E6,0x03E00000}}, // 011111xxxxx011010100001011100110  mftbu r0
{                         "mfpid GPR",{0x7C100AA6,0x03E00000}}, // 011111xxxxx100000000101010100110  mfpid r0
{                         "mtpid GPR",{0x7C100BA6,0x03E00000}}, // 011111xxxxx100000000101110100110  mtpid r0
{                  "mfocrf GPR , NUM",{0x7C101026,0x03EFF000}}, // 011111xxxxx1xxxxxxxx000000100110  mfocrf r0, 1
{                  "mtocrf NUM , GPR",{0x7C101120,0x03EFF000}}, // 011111xxxxx1xxxxxxxx000100100000  mtocrf 1, r0
{                 "mfibatu GPR , NUM",{0x7C1082A6,0x03E60000}}, // 011111xxxxx10xx01000001010100110  mfibatu r0, 0
{                 "mtibatu NUM , GPR",{0x7C1083A6,0x03E60000}}, // 011111xxxxx10xx01000001110100110  mtibatu 0, r0
{                        "mfdscr GPR",{0x7C1102A6,0x03E00000}}, // 011111xxxxx100010000001010100110  mfdscr r0
{                        "mtdscr GPR",{0x7C1103A6,0x03E00000}}, // 011111xxxxx100010000001110100110  mtdscr r0
{                 "mfibatl GPR , NUM",{0x7C1182A6,0x03E60000}}, // 011111xxxxx10xx11000001010100110  mfibatl r0, 0
{                 "mtibatl NUM , GPR",{0x7C1183A6,0x03E60000}}, // 011111xxxxx10xx11000001110100110  mtibatl 0, r0
{                       "mfdsisr GPR",{0x7C1202A6,0x03E00000}}, // 011111xxxxx100100000001010100110  mfdsisr r0
{                       "mtdsisr GPR",{0x7C1203A6,0x03E00000}}, // 011111xxxxx100100000001110100110  mtdsisr r0
{                         "mfdar GPR",{0x7C1302A6,0x03E00000}}, // 011111xxxxx100110000001010100110  mfdar r0
{                         "mtdar GPR",{0x7C1303A6,0x03E00000}}, // 011111xxxxx100110000001110100110  mtdar r0
{                         "mfesr GPR",{0x7C14F2A6,0x03E00000}}, // 011111xxxxx101001111001010100110  mfesr r0
{                         "mtesr GPR",{0x7C14F3A6,0x03E00000}}, // 011111xxxxx101001111001110100110  mtesr r0
{                        "mfdear GPR",{0x7C15F2A6,0x03E00000}}, // 011111xxxxx101011111001010100110  mfdear r0
{                        "mtdear GPR",{0x7C15F3A6,0x03E00000}}, // 011111xxxxx101011111001110100110  mtdear r0
{                         "mfasr GPR",{0x7C1842A6,0x03E00000}}, // 011111xxxxx110000100001010100110  mfasr r0
{                 "mfdbatu GPR , NUM",{0x7C1882A6,0x03E60000}}, // 011111xxxxx11xx01000001010100110  mfdbatu r0, 0
{                 "mtdbatu NUM , GPR",{0x7C1883A6,0x03E60000}}, // 011111xxxxx11xx01000001110100110  mtdbatu 0, r0
{                 "mfdbatl GPR , NUM",{0x7C1982A6,0x03E60000}}, // 011111xxxxx11xx11000001010100110  mfdbatl r0, 0
{                 "mtdbatl NUM , GPR",{0x7C1983A6,0x03E60000}}, // 011111xxxxx11xx11000001110100110  mtdbatl 0, r0
{                         "mftcr GPR",{0x7C1AF2A6,0x03E00000}}, // 011111xxxxx110101111001010100110  mftcr r0
{                         "mttcr GPR",{0x7C1AF3A6,0x03E00000}}, // 011111xxxxx110101111001110100110  mttcr r0
{                        "mfdccr GPR",{0x7C1AFAA6,0x03E00000}}, // 011111xxxxx110101111101010100110  mfdccr r0
{                        "mtdccr GPR",{0x7C1AFBA6,0x03E00000}}, // 011111xxxxx110101111101110100110  mtdccr r0
{                        "mficcr GPR",{0x7C1BFAA6,0x03E00000}}, // 011111xxxxx110111111101010100110  mficcr r0
{                        "mticcr GPR",{0x7C1BFBA6,0x03E00000}}, // 011111xxxxx110111111101110100110  mticcr r0
{                        "mfcfar GPR",{0x7C1C02A6,0x03E00000}}, // 011111xxxxx111000000001010100110  mfcfar r0
{                        "mtcfar GPR",{0x7C1C03A6,0x03E00000}}, // 011111xxxxx111000000001110100110  mtcfar r0
{                         "mttbl GPR",{0x7C1C43A6,0x03E00000}}, // 011111xxxxx111000100001110100110  mttbl r0
{                        "mftbhi GPR",{0x7C1CF2A6,0x03E00000}}, // 011111xxxxx111001111001010100110  mftbhi r0
{                        "mttbhi GPR",{0x7C1CF3A6,0x03E00000}}, // 011111xxxxx111001111001110100110  mttbhi r0
{                         "mfamr GPR",{0x7C1D02A6,0x03E00000}}, // 011111xxxxx111010000001010100110  mfamr r0
{                         "mtamr GPR",{0x7C1D03A6,0x03E00000}}, // 011111xxxxx111010000001110100110  mtamr r0
{                         "mttbu GPR",{0x7C1D43A6,0x03E00000}}, // 011111xxxxx111010100001110100110  mttbu r0
{                        "mftblo GPR",{0x7C1DF2A6,0x03E00000}}, // 011111xxxxx111011111001010100110  mftblo r0
{                        "mttblo GPR",{0x7C1DF3A6,0x03E00000}}, // 011111xxxxx111011111001110100110  mttblo r0
{                        "mfsrr2 GPR",{0x7C1EF2A6,0x03E00000}}, // 011111xxxxx111101111001010100110  mfsrr2 r0
{                        "mtsrr2 GPR",{0x7C1EF3A6,0x03E00000}}, // 011111xxxxx111101111001110100110  mtsrr2 r0
{                         "mfpvr GPR",{0x7C1F42A6,0x03E00000}}, // 011111xxxxx111110100001010100110  mfpvr r0
{                        "mfsrr3 GPR",{0x7C1FF2A6,0x03E00000}}, // 011111xxxxx111111111001010100110  mfsrr3 r0
{                        "mtsrr3 GPR",{0x7C1FF3A6,0x03E00000}}, // 011111xxxxx111111111001110100110  mtsrr3 r0
{                    "cmpd GPR , GPR",{0x7C200000,0x001FF800}}, // 01111100001xxxxxxxxxx00000000000  cmpd r0, r0
{                   "twlgt GPR , GPR",{0x7C200008,0x001FF800}}, // 01111100001xxxxxxxxxx00000001000  twlgt r0, r0
{                   "cmpld GPR , GPR",{0x7C200040,0x001FF800}}, // 01111100001xxxxxxxxxx00001000000  cmpld r0, r0
{                           "waitrsv",{0x7C20007C,0x00000000}}, // 01111100001000000000000001111100  waitrsv
{                   "tdlgt GPR , GPR",{0x7C200088,0x001FF800}}, // 01111100001xxxxxxxxxx00010001000  tdlgt r0, r0
{                   "tlbie GPR , GPR",{0x7C200264,0x03E0F800}}, // 011111xxxxx00000xxxxx01001100100  tlbie r0,r1
{                            "lwsync",{0x7C2004AC,0x00000000}}, // 01111100001000000000010010101100  lwsync
{                          "mbar NUM",{0x7C2006AC,0x03FFF801}}, // 011111xxxxxxxxxxxxxxx1101010110x  mbar 1
{             "tlbsx GPR , GPR , GPR",{0x7C200724,0x03FFF800}}, // 011111xxxxxxxxxxxxxxx11100100100  tlbsx r1, r0, r0
{                   "dcbzl NUM , GPR",{0x7C2007EC,0x0000F800}}, // 0111110000100000xxxxx11111101100  dcbzl 0, r0
{                   "dcbzl GPR , GPR",{0x7C2107EC,0x001FF800}}, // 01111100001xxxxxxxxxx11111101100  dcbzl r1, r0
{                   "twllt GPR , GPR",{0x7C400008,0x001FF800}}, // 01111100010xxxxxxxxxx00000001000  twllt r0, r0
{                          "waitimpl",{0x7C40007C,0x00000000}}, // 01111100010000000000000001111100  waitimpl
{                   "tdllt GPR , GPR",{0x7C400088,0x001FF800}}, // 01111100010xxxxxxxxxx00010001000  tdllt r0, r0
{                           "ptesync",{0x7C4004AC,0x00000000}}, // 01111100010000000000010010101100  ptesync
{                          "wait NUM",{0x7C60007C,0x00000000}}, // 01111100011000000000000001111100  wait 3
{             "cmpw CREG , GPR , GPR",{0x7C800000,0x039FF800}}, // 011111xxx00xxxxxxxxxx00000000000  cmpw cr1, r0, r0
{                    "tweq GPR , GPR",{0x7C800008,0x001FF800}}, // 01111100100xxxxxxxxxx00000001000  tweq r0, r0
{            "cmplw CREG , GPR , GPR",{0x7C800040,0x039FF800}}, // 011111xxx00xxxxxxxxxx00001000000  cmplw cr1, r0, r0
{                    "tdeq GPR , GPR",{0x7C800088,0x001FF800}}, // 01111100100xxxxxxxxxx00010001000  tdeq r0, r0
{             "cmpd CREG , GPR , GPR",{0x7CA00000,0x039FF800}}, // 011111xxx01xxxxxxxxxx00000000000  cmpd cr1, r0, r0
{            "cmpld CREG , GPR , GPR",{0x7CA00040,0x039FF800}}, // 011111xxx01xxxxxxxxxx00001000000  cmpld cr1, r0, r0
{                    "twgt GPR , GPR",{0x7D000008,0x001FF800}}, // 01111101000xxxxxxxxxx00000001000  twgt r0, r0
{                    "tdgt GPR , GPR",{0x7D000088,0x001FF800}}, // 01111101000xxxxxxxxxx00010001000  tdgt r0, r0
{                    "twlt GPR , GPR",{0x7E000008,0x001FF800}}, // 01111110000xxxxxxxxxx00000001000  twlt r0, r0
{                    "tdlt GPR , GPR",{0x7E000088,0x001FF800}}, // 01111110000xxxxxxxxxx00010001000  tdlt r0, r0
{              "dstt GPR , GPR , NUM",{0x7E0002AC,0x007FF800}}, // 011111100xxxxxxxxxxxx01010101100  dstt r0, r0, 0
{            "dststt GPR , GPR , NUM",{0x7E0002EC,0x007FF800}}, // 011111100xxxxxxxxxxxx01011101100  dststt r0, r0, 0
{                            "dssall",{0x7E00066C,0x00000000}}, // 01111110000000000000011001101100  dssall
{                    "twne GPR , GPR",{0x7F000008,0x001FF800}}, // 01111111000xxxxxxxxxx00000001000  twne r0, r0
{                    "tdne GPR , GPR",{0x7F000088,0x001FF800}}, // 01111111000xxxxxxxxxx00010001000  tdne r0, r0
{                              "trap",{0x7FE00008,0x00000000}}, // 01111111111000000000000000001000  trap
{                     "tdu GPR , GPR",{0x7FE00088,0x001FF800}}, // 01111111111xxxxxxxxxx00010001000  tdu r0, r0
{                     "twu GPR , GPR",{0x7FE00808,0x001FF800}}, // 01111111111xxxxxxxxxx00000001000  twu r0, r1
{             "lwz GPR , NUM ( NUM )",{0x80000000,0x03E0FFFF}}, // 100000xxxxx00000xxxxxxxxxxxxxxxx  lwz r0, 0(0)
{             "lwz GPR , NUM ( GPR )",{0x80010000,0x03FFFFFF}}, // 100000xxxxxxxxxxxxxxxxxxxxxxxxxx  lwz r0, 0(r1)
{            "lwzu GPR , NUM ( NUM )",{0x84000000,0x03E0FFFF}}, // 100001xxxxx00000xxxxxxxxxxxxxxxx  lwzu r0, 0(0)
{            "lwzu GPR , NUM ( GPR )",{0x84010000,0x03FFFFFF}}, // 100001xxxxxxxxxxxxxxxxxxxxxxxxxx  lwzu r0, 0(r1)
{             "lbz GPR , NUM ( NUM )",{0x88000000,0x03E0FFFF}}, // 100010xxxxx00000xxxxxxxxxxxxxxxx  lbz r0, 0(0)
{             "lbz GPR , NUM ( GPR )",{0x88010000,0x03FFFFFF}}, // 100010xxxxxxxxxxxxxxxxxxxxxxxxxx  lbz r0, 0(r1)
{            "lbzu GPR , NUM ( NUM )",{0x8C000000,0x03E0FFFF}}, // 100011xxxxx00000xxxxxxxxxxxxxxxx  lbzu r0, 0(0)
{            "lbzu GPR , NUM ( GPR )",{0x8C010000,0x03FFFFFF}}, // 100011xxxxxxxxxxxxxxxxxxxxxxxxxx  lbzu r0, 0(r1)
{             "stw GPR , NUM ( NUM )",{0x90000000,0x03E0FFFF}}, // 100100xxxxx00000xxxxxxxxxxxxxxxx  stw r0, 0(0)
{             "stw GPR , NUM ( GPR )",{0x90010000,0x03FFFFFF}}, // 100100xxxxxxxxxxxxxxxxxxxxxxxxxx  stw r0, 0(r1)
{            "stwu GPR , NUM ( NUM )",{0x94000000,0x03E0FFFF}}, // 100101xxxxx00000xxxxxxxxxxxxxxxx  stwu r0, 0(0)
{            "stwu GPR , NUM ( GPR )",{0x94010000,0x03FFFFFF}}, // 100101xxxxxxxxxxxxxxxxxxxxxxxxxx  stwu r0, 0(r1)
{             "stb GPR , NUM ( NUM )",{0x98000000,0x03E0FFFF}}, // 100110xxxxx00000xxxxxxxxxxxxxxxx  stb r0, 0(0)
{             "stb GPR , NUM ( GPR )",{0x98010000,0x03FFFFFF}}, // 100110xxxxxxxxxxxxxxxxxxxxxxxxxx  stb r0, 0(r1)
{            "stbu GPR , NUM ( NUM )",{0x9C000000,0x03E0FFFF}}, // 100111xxxxx00000xxxxxxxxxxxxxxxx  stbu r0, 0(0)
{            "stbu GPR , NUM ( GPR )",{0x9C010000,0x03FFFFFF}}, // 100111xxxxxxxxxxxxxxxxxxxxxxxxxx  stbu r0, 0(r1)
{             "lhz GPR , NUM ( NUM )",{0xA0000000,0x03E0FFFF}}, // 101000xxxxx00000xxxxxxxxxxxxxxxx  lhz r0, 0(0)
{             "lhz GPR , NUM ( GPR )",{0xA0010000,0x03FFFFFF}}, // 101000xxxxxxxxxxxxxxxxxxxxxxxxxx  lhz r0, 0(r1)
{            "lhzu GPR , NUM ( NUM )",{0xA4000000,0x03E0FFFF}}, // 101001xxxxx00000xxxxxxxxxxxxxxxx  lhzu r0, 0(0)
{            "lhzu GPR , NUM ( GPR )",{0xA4010000,0x03FFFFFF}}, // 101001xxxxxxxxxxxxxxxxxxxxxxxxxx  lhzu r0, 0(r1)
{             "lha GPR , NUM ( NUM )",{0xA8000000,0x03E0FFFF}}, // 101010xxxxx00000xxxxxxxxxxxxxxxx  lha r0, 0(0)
{             "lha GPR , NUM ( GPR )",{0xA8010000,0x03FFFFFF}}, // 101010xxxxxxxxxxxxxxxxxxxxxxxxxx  lha r0, 0(r1)
{            "lhau GPR , NUM ( NUM )",{0xAC000000,0x03E0FFFF}}, // 101011xxxxx00000xxxxxxxxxxxxxxxx  lhau r0, 0(0)
{            "lhau GPR , NUM ( GPR )",{0xAC010000,0x03FFFFFF}}, // 101011xxxxxxxxxxxxxxxxxxxxxxxxxx  lhau r0, 0(r1)
{             "sth GPR , NUM ( NUM )",{0xB0000000,0x03E0FFFF}}, // 101100xxxxx00000xxxxxxxxxxxxxxxx  sth r0, 0(0)
{             "sth GPR , NUM ( GPR )",{0xB0010000,0x03FFFFFF}}, // 101100xxxxxxxxxxxxxxxxxxxxxxxxxx  sth r0, 0(r1)
{            "sthu GPR , NUM ( NUM )",{0xB4000000,0x03E0FFFF}}, // 101101xxxxx00000xxxxxxxxxxxxxxxx  sthu r0, 0(0)
{            "sthu GPR , NUM ( GPR )",{0xB4010000,0x03FFFFFF}}, // 101101xxxxxxxxxxxxxxxxxxxxxxxxxx  sthu r0, 0(r1)
{             "lmw GPR , NUM ( NUM )",{0xB8000000,0x03E0FFFF}}, // 101110xxxxx00000xxxxxxxxxxxxxxxx  lmw r0, 0(0)
{             "lmw GPR , NUM ( GPR )",{0xB8010000,0x03FFFFFF}}, // 101110xxxxxxxxxxxxxxxxxxxxxxxxxx  lmw r0, 0(r1)
{            "stmw GPR , NUM ( NUM )",{0xBC000000,0x03E0FFFF}}, // 101111xxxxx00000xxxxxxxxxxxxxxxx  stmw r0, 0(0)
{            "stmw GPR , NUM ( GPR )",{0xBC010000,0x03FFFFFF}}, // 101111xxxxxxxxxxxxxxxxxxxxxxxxxx  stmw r0, 0(r1)
{            "lfs FREG , NUM ( NUM )",{0xC0000000,0x03E0FFFF}}, // 110000xxxxx00000xxxxxxxxxxxxxxxx  lfs f0, 0(0)
{            "lfs FREG , NUM ( GPR )",{0xC0010000,0x03FFFFFF}}, // 110000xxxxxxxxxxxxxxxxxxxxxxxxxx  lfs f0, 0(r1)
{           "lfsu FREG , NUM ( NUM )",{0xC4000000,0x03E0FFFF}}, // 110001xxxxx00000xxxxxxxxxxxxxxxx  lfsu f0, 0(0)
{           "lfsu FREG , NUM ( GPR )",{0xC4010000,0x03FFFFFF}}, // 110001xxxxxxxxxxxxxxxxxxxxxxxxxx  lfsu f0, 0(r1)
{            "lfd FREG , NUM ( NUM )",{0xC8000000,0x03E0FFFF}}, // 110010xxxxx00000xxxxxxxxxxxxxxxx  lfd f0, 0(0)
{            "lfd FREG , NUM ( GPR )",{0xC8010000,0x03FFFFFF}}, // 110010xxxxxxxxxxxxxxxxxxxxxxxxxx  lfd f0, 0(r1)
{           "lfdu FREG , NUM ( NUM )",{0xCC000000,0x03E0FFFF}}, // 110011xxxxx00000xxxxxxxxxxxxxxxx  lfdu f0, 0(0)
{           "lfdu FREG , NUM ( GPR )",{0xCC010000,0x03FFFFFF}}, // 110011xxxxxxxxxxxxxxxxxxxxxxxxxx  lfdu f0, 0(r1)
{           "stfs FREG , NUM ( NUM )",{0xD0000000,0x03E0FFFF}}, // 110100xxxxx00000xxxxxxxxxxxxxxxx  stfs f0, 0(0)
{           "stfs FREG , NUM ( GPR )",{0xD0010000,0x03FFFFFF}}, // 110100xxxxxxxxxxxxxxxxxxxxxxxxxx  stfs f0, 0(r1)
{          "stfsu FREG , NUM ( NUM )",{0xD4000000,0x03E0FFFF}}, // 110101xxxxx00000xxxxxxxxxxxxxxxx  stfsu f0, 0(0)
{          "stfsu FREG , NUM ( GPR )",{0xD4010000,0x03FFFFFF}}, // 110101xxxxxxxxxxxxxxxxxxxxxxxxxx  stfsu f0, 0(r1)
{           "stfd FREG , NUM ( NUM )",{0xD8000000,0x03E0FFFF}}, // 110110xxxxx00000xxxxxxxxxxxxxxxx  stfd f0, 0(0)
{           "stfd FREG , NUM ( GPR )",{0xD8010000,0x03FFFFFF}}, // 110110xxxxxxxxxxxxxxxxxxxxxxxxxx  stfd f0, 0(r1)
{          "stfdu FREG , NUM ( NUM )",{0xDC000000,0x03E0FFFF}}, // 110111xxxxx00000xxxxxxxxxxxxxxxx  stfdu f0, 0(0)
{          "stfdu FREG , NUM ( GPR )",{0xDC010000,0x03FFFFFF}}, // 110111xxxxxxxxxxxxxxxxxxxxxxxxxx  stfdu f0, 0(r1)
{              "ld GPR , NUM ( NUM )",{0xE8000000,0x03E0FFFC}}, // 111010xxxxx00000xxxxxxxxxxxxxx00  ld r0, 0(0)
{             "ldu GPR , NUM ( NUM )",{0xE8000001,0x03E0FFFC}}, // 111010xxxxx00000xxxxxxxxxxxxxx01  ldu r0, 0(0)
{             "lwa GPR , NUM ( NUM )",{0xE8000002,0x03E0FFFC}}, // 111010xxxxx00000xxxxxxxxxxxxxx10  lwa r0, 0(0)
{              "ld GPR , NUM ( GPR )",{0xE8010000,0x03FFFFFC}}, // 111010xxxxxxxxxxxxxxxxxxxxxxxx00  ld r0, 0(r1)
{             "ldu GPR , NUM ( GPR )",{0xE8010001,0x03FFFFFC}}, // 111010xxxxxxxxxxxxxxxxxxxxxxxx01  ldu r0, 0(r1)
{             "lwa GPR , NUM ( GPR )",{0xE8010002,0x03FFFFFC}}, // 111010xxxxxxxxxxxxxxxxxxxxxxxx10  lwa r0, 0(r1)
{          "fdivs FREG , FREG , FREG",{0xEC000024,0x03FFF800}}, // 111011xxxxxxxxxxxxxxx00000100100  fdivs f0, f0, f0
{        "fdivs . FREG , FREG , FREG",{0xEC000025,0x03FFF800}}, // 111011xxxxxxxxxxxxxxx00000100101  fdivs. f0, f0, f0
{          "fsubs FREG , FREG , FREG",{0xEC000028,0x03FFF800}}, // 111011xxxxxxxxxxxxxxx00000101000  fsubs f0, f0, f0
{        "fsubs . FREG , FREG , FREG",{0xEC000029,0x03FFF800}}, // 111011xxxxxxxxxxxxxxx00000101001  fsubs. f0, f0, f0
{          "fadds FREG , FREG , FREG",{0xEC00002A,0x03FFF800}}, // 111011xxxxxxxxxxxxxxx00000101010  fadds f0, f0, f0
{        "fadds . FREG , FREG , FREG",{0xEC00002B,0x03FFF800}}, // 111011xxxxxxxxxxxxxxx00000101011  fadds. f0, f0, f0
{                "fsqrts FREG , FREG",{0xEC00002C,0x03E0F800}}, // 111011xxxxx00000xxxxx00000101100  fsqrts f0, f0
{              "fsqrts . FREG , FREG",{0xEC00002D,0x03E0F800}}, // 111011xxxxx00000xxxxx00000101101  fsqrts. f0, f0
{                  "fres FREG , FREG",{0xEC000030,0x03E0F800}}, // 111011xxxxx00000xxxxx00000110000  fres f0, f0
{                "fres . FREG , FREG",{0xEC000031,0x03E0F800}}, // 111011xxxxx00000xxxxx00000110001  fres. f0, f0
{          "fmuls FREG , FREG , FREG",{0xEC000032,0x03FF07C0}}, // 111011xxxxxxxxxx00000xxxxx110010  fmuls f0, f0, f0
{        "fmuls . FREG , FREG , FREG",{0xEC000033,0x03FF07C0}}, // 111011xxxxxxxxxx00000xxxxx110011  fmuls. f0, f0, f0
{              "frsqrtes FREG , FREG",{0xEC000034,0x03E0F800}}, // 111011xxxxx00000xxxxx00000110100  frsqrtes f0, f0
{            "frsqrtes . FREG , FREG",{0xEC000035,0x03E0F800}}, // 111011xxxxx00000xxxxx00000110101  frsqrtes. f0, f0
{  "fmsubs FREG , FREG , FREG , FREG",{0xEC000038,0x03FFFFC0}}, // 111011xxxxxxxxxxxxxxxxxxxx111000  fmsubs f0, f0, f0, f0
{"fmsubs . FREG , FREG , FREG , FREG",{0xEC000039,0x03FFFFC0}}, // 111011xxxxxxxxxxxxxxxxxxxx111001  fmsubs. f0, f0, f0, f0
{  "fmadds FREG , FREG , FREG , FREG",{0xEC00003A,0x03FFFFC0}}, // 111011xxxxxxxxxxxxxxxxxxxx111010  fmadds f0, f0, f0, f0
{"fmadds . FREG , FREG , FREG , FREG",{0xEC00003B,0x03FFFFC0}}, // 111011xxxxxxxxxxxxxxxxxxxx111011  fmadds. f0, f0, f0, f0
{ "fnmsubs FREG , FREG , FREG , FREG",{0xEC00003C,0x03FFFFC0}}, // 111011xxxxxxxxxxxxxxxxxxxx111100  fnmsubs f0, f0, f0, f0
{"fnmsubs . FREG , FREG , FREG , FREG",{0xEC00003D,0x03FFFFC0}}, // 111011xxxxxxxxxxxxxxxxxxxx111101  fnmsubs. f0, f0, f0, f0
{ "fnmadds FREG , FREG , FREG , FREG",{0xEC00003E,0x03FFFFC0}}, // 111011xxxxxxxxxxxxxxxxxxxx111110  fnmadds f0, f0, f0, f0
{"fnmadds . FREG , FREG , FREG , FREG",{0xEC00003F,0x03FFFFC0}}, // 111011xxxxxxxxxxxxxxxxxxxx111111  fnmadds. f0, f0, f0, f0
{                "fcfids FREG , FREG",{0xEC00069C,0x03E0F800}}, // 111011xxxxx00000xxxxx11010011100  fcfids f0, f0
{              "fcfids . FREG , FREG",{0xEC00069D,0x03E0F800}}, // 111011xxxxx00000xxxxx11010011101  fcfids. f0, f0
{               "fcfidus FREG , FREG",{0xEC00079C,0x03E0F800}}, // 111011xxxxx00000xxxxx11110011100  fcfidus f0, f0
{             "fcfidus . FREG , FREG",{0xEC00079D,0x03E0F800}}, // 111011xxxxx00000xxxxx11110011101  fcfidus. f0, f0
{"xxsldwi VSREG , VSREG , VSREG , NUM",{0xF0000010,0x03FFFB07}}, // 111100xxxxxxxxxxxxxxx0xx00010xxx  xxsldwi vs0, vs0, vs0, 0
{"xxsel VSREG , VSREG , VSREG , VSREG",{0xF0000030,0x03FFFFCF}}, // 111100xxxxxxxxxxxxxxxxxxxx11xxxx  xxsel vs0, vs0, vs0, vs0
{       "xxspltd VSREG , VSREG , NUM",{0xF0000050,0x03FFFB07}}, // 111100xxxxxxxxxxxxxxx0xx01010xxx  xxspltd vs0, vs0, 0
{     "xxmrghd VSREG , VSREG , VSREG",{0xF0000052,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx00001010xxx  xxmrghd vs0, vs0, vs32
{     "xxmrghw VSREG , VSREG , VSREG",{0xF0000090,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx00010010xxx  xxmrghw vs0, vs0, vs0
{        "xsadddp FREG , FREG , FREG",{0xF0000100,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00100000000  xsadddp f0, f0, f0
{       "xsadddp VSREG , FREG , FREG",{0xF0000101,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00100000001  xsadddp vs32, f0, f0
{       "xsadddp FREG , FREG , VSREG",{0xF0000102,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00100000010  xsadddp f0, f0, vs32
{      "xsadddp VSREG , FREG , VSREG",{0xF0000103,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00100000011  xsadddp vs32, f0, vs32
{       "xsadddp FREG , VSREG , FREG",{0xF0000104,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00100000100  xsadddp f0, vs32, f0
{      "xsadddp VSREG , VSREG , FREG",{0xF0000105,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00100000101  xsadddp vs32, vs32, f0
{      "xsadddp FREG , VSREG , VSREG",{0xF0000106,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00100000110  xsadddp f0, vs32, vs32
{     "xsadddp VSREG , VSREG , VSREG",{0xF0000107,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00100000111  xsadddp vs32, vs32, vs32
{      "xsmaddadp FREG , FREG , FREG",{0xF0000108,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00100001000  xsmaddadp f0, f0, f0
{     "xsmaddadp VSREG , FREG , FREG",{0xF0000109,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00100001001  xsmaddadp vs32, f0, f0
{     "xsmaddadp FREG , FREG , VSREG",{0xF000010A,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00100001010  xsmaddadp f0, f0, vs32
{    "xsmaddadp VSREG , FREG , VSREG",{0xF000010B,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00100001011  xsmaddadp vs32, f0, vs32
{     "xsmaddadp FREG , VSREG , FREG",{0xF000010C,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00100001100  xsmaddadp f0, vs32, f0
{    "xsmaddadp VSREG , VSREG , FREG",{0xF000010D,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00100001101  xsmaddadp vs32, vs32, f0
{    "xsmaddadp FREG , VSREG , VSREG",{0xF000010E,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00100001110  xsmaddadp f0, vs32, vs32
{   "xsmaddadp VSREG , VSREG , VSREG",{0xF000010F,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00100001111  xsmaddadp vs32, vs32, vs32
{       "xscmpudp CREG , FREG , FREG",{0xF0000118,0x039FF800}}, // 111100xxx00xxxxxxxxxx00100011000  xscmpudp cr0, f0, f0
{      "xscmpudp CREG , FREG , VSREG",{0xF000011A,0x039FF800}}, // 111100xxx00xxxxxxxxxx00100011010  xscmpudp cr0, f0, vs32
{      "xscmpudp CREG , VSREG , FREG",{0xF000011C,0x039FF800}}, // 111100xxx00xxxxxxxxxx00100011100  xscmpudp cr0, vs32, f0
{     "xscmpudp CREG , VSREG , VSREG",{0xF000011E,0x039FF800}}, // 111100xxx00xxxxxxxxxx00100011110  xscmpudp cr0, vs32, vs32
{            "xscvdpuxws FREG , FREG",{0xF0000120,0x03E0F800}}, // 111100xxxxx00000xxxxx00100100000  xscvdpuxws f0, f0
{           "xscvdpuxws VSREG , FREG",{0xF0000121,0x03E0F800}}, // 111100xxxxx00000xxxxx00100100001  xscvdpuxws vs32, f0
{           "xscvdpuxws FREG , VSREG",{0xF0000122,0x03E0F800}}, // 111100xxxxx00000xxxxx00100100010  xscvdpuxws f0, vs32
{          "xscvdpuxws VSREG , VSREG",{0xF0000123,0x03E0F800}}, // 111100xxxxx00000xxxxx00100100011  xscvdpuxws vs32, vs32
{                "xsrdpi FREG , FREG",{0xF0000124,0x03E0F800}}, // 111100xxxxx00000xxxxx00100100100  xsrdpi f0, f0
{               "xsrdpi VSREG , FREG",{0xF0000125,0x03E0F800}}, // 111100xxxxx00000xxxxx00100100101  xsrdpi vs32, f0
{               "xsrdpi FREG , VSREG",{0xF0000126,0x03E0F800}}, // 111100xxxxx00000xxxxx00100100110  xsrdpi f0, vs32
{              "xsrdpi VSREG , VSREG",{0xF0000127,0x03E0F800}}, // 111100xxxxx00000xxxxx00100100111  xsrdpi vs32, vs32
{            "xsrsqrtedp FREG , FREG",{0xF0000128,0x03E0F800}}, // 111100xxxxx00000xxxxx00100101000  xsrsqrtedp f0, f0
{           "xsrsqrtedp VSREG , FREG",{0xF0000129,0x03E0F800}}, // 111100xxxxx00000xxxxx00100101001  xsrsqrtedp vs32, f0
{           "xsrsqrtedp FREG , VSREG",{0xF000012A,0x03E0F800}}, // 111100xxxxx00000xxxxx00100101010  xsrsqrtedp f0, vs32
{          "xsrsqrtedp VSREG , VSREG",{0xF000012B,0x03E0F800}}, // 111100xxxxx00000xxxxx00100101011  xsrsqrtedp vs32, vs32
{              "xssqrtdp FREG , FREG",{0xF000012C,0x03E0F800}}, // 111100xxxxx00000xxxxx00100101100  xssqrtdp f0, f0
{             "xssqrtdp VSREG , FREG",{0xF000012D,0x03E0F800}}, // 111100xxxxx00000xxxxx00100101101  xssqrtdp vs32, f0
{             "xssqrtdp FREG , VSREG",{0xF000012E,0x03E0F800}}, // 111100xxxxx00000xxxxx00100101110  xssqrtdp f0, vs32
{            "xssqrtdp VSREG , VSREG",{0xF000012F,0x03E0F800}}, // 111100xxxxx00000xxxxx00100101111  xssqrtdp vs32, vs32
{        "xssubdp FREG , FREG , FREG",{0xF0000140,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00101000000  xssubdp f0, f0, f0
{       "xssubdp VSREG , FREG , FREG",{0xF0000141,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00101000001  xssubdp vs32, f0, f0
{       "xssubdp FREG , FREG , VSREG",{0xF0000142,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00101000010  xssubdp f0, f0, vs32
{      "xssubdp VSREG , FREG , VSREG",{0xF0000143,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00101000011  xssubdp vs32, f0, vs32
{       "xssubdp FREG , VSREG , FREG",{0xF0000144,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00101000100  xssubdp f0, vs32, f0
{      "xssubdp VSREG , VSREG , FREG",{0xF0000145,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00101000101  xssubdp vs32, vs32, f0
{      "xssubdp FREG , VSREG , VSREG",{0xF0000146,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00101000110  xssubdp f0, vs32, vs32
{     "xssubdp VSREG , VSREG , VSREG",{0xF0000147,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00101000111  xssubdp vs32, vs32, vs32
{      "xsmaddmdp FREG , FREG , FREG",{0xF0000148,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00101001000  xsmaddmdp f0, f0, f0
{     "xsmaddmdp VSREG , FREG , FREG",{0xF0000149,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00101001001  xsmaddmdp vs32, f0, f0
{     "xsmaddmdp FREG , FREG , VSREG",{0xF000014A,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00101001010  xsmaddmdp f0, f0, vs32
{    "xsmaddmdp VSREG , FREG , VSREG",{0xF000014B,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00101001011  xsmaddmdp vs32, f0, vs32
{     "xsmaddmdp FREG , VSREG , FREG",{0xF000014C,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00101001100  xsmaddmdp f0, vs32, f0
{    "xsmaddmdp VSREG , VSREG , FREG",{0xF000014D,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00101001101  xsmaddmdp vs32, vs32, f0
{    "xsmaddmdp FREG , VSREG , VSREG",{0xF000014E,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00101001110  xsmaddmdp f0, vs32, vs32
{   "xsmaddmdp VSREG , VSREG , VSREG",{0xF000014F,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00101001111  xsmaddmdp vs32, vs32, vs32
{"xxpermdi VSREG , VSREG , VSREG , NUM",{0xF0000150,0x03FFFB07}}, // 111100xxxxxxxxxxxxxxx0xx01010xxx  xxpermdi vs0, vs0, vs0, 1
{       "xscmpodp CREG , FREG , FREG",{0xF0000158,0x039FF800}}, // 111100xxx00xxxxxxxxxx00101011000  xscmpodp cr0, f0, f0
{      "xscmpodp CREG , FREG , VSREG",{0xF000015A,0x039FF800}}, // 111100xxx00xxxxxxxxxx00101011010  xscmpodp cr0, f0, vs32
{      "xscmpodp CREG , VSREG , FREG",{0xF000015C,0x039FF800}}, // 111100xxx00xxxxxxxxxx00101011100  xscmpodp cr0, vs32, f0
{     "xscmpodp CREG , VSREG , VSREG",{0xF000015E,0x039FF800}}, // 111100xxx00xxxxxxxxxx00101011110  xscmpodp cr0, vs32, vs32
{            "xscvdpsxws FREG , FREG",{0xF0000160,0x03E0F800}}, // 111100xxxxx00000xxxxx00101100000  xscvdpsxws f0, f0
{           "xscvdpsxws VSREG , FREG",{0xF0000161,0x03E0F800}}, // 111100xxxxx00000xxxxx00101100001  xscvdpsxws vs32, f0
{           "xscvdpsxws FREG , VSREG",{0xF0000162,0x03E0F800}}, // 111100xxxxx00000xxxxx00101100010  xscvdpsxws f0, vs32
{          "xscvdpsxws VSREG , VSREG",{0xF0000163,0x03E0F800}}, // 111100xxxxx00000xxxxx00101100011  xscvdpsxws vs32, vs32
{               "xsrdpiz FREG , FREG",{0xF0000164,0x03E0F800}}, // 111100xxxxx00000xxxxx00101100100  xsrdpiz f0, f0
{              "xsrdpiz VSREG , FREG",{0xF0000165,0x03E0F800}}, // 111100xxxxx00000xxxxx00101100101  xsrdpiz vs32, f0
{              "xsrdpiz FREG , VSREG",{0xF0000166,0x03E0F800}}, // 111100xxxxx00000xxxxx00101100110  xsrdpiz f0, vs32
{             "xsrdpiz VSREG , VSREG",{0xF0000167,0x03E0F800}}, // 111100xxxxx00000xxxxx00101100111  xsrdpiz vs32, vs32
{                "xsredp FREG , FREG",{0xF0000168,0x03E0F800}}, // 111100xxxxx00000xxxxx00101101000  xsredp f0, f0
{               "xsredp VSREG , FREG",{0xF0000169,0x03E0F800}}, // 111100xxxxx00000xxxxx00101101001  xsredp vs32, f0
{               "xsredp FREG , VSREG",{0xF000016A,0x03E0F800}}, // 111100xxxxx00000xxxxx00101101010  xsredp f0, vs32
{              "xsredp VSREG , VSREG",{0xF000016B,0x03E0F800}}, // 111100xxxxx00000xxxxx00101101011  xsredp vs32, vs32
{        "xsmuldp FREG , FREG , FREG",{0xF0000180,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00110000000  xsmuldp f0, f0, f0
{       "xsmuldp VSREG , FREG , FREG",{0xF0000181,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00110000001  xsmuldp vs32, f0, f0
{       "xsmuldp FREG , FREG , VSREG",{0xF0000182,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00110000010  xsmuldp f0, f0, vs32
{      "xsmuldp VSREG , FREG , VSREG",{0xF0000183,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00110000011  xsmuldp vs32, f0, vs32
{       "xsmuldp FREG , VSREG , FREG",{0xF0000184,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00110000100  xsmuldp f0, vs32, f0
{      "xsmuldp VSREG , VSREG , FREG",{0xF0000185,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00110000101  xsmuldp vs32, vs32, f0
{      "xsmuldp FREG , VSREG , VSREG",{0xF0000186,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00110000110  xsmuldp f0, vs32, vs32
{     "xsmuldp VSREG , VSREG , VSREG",{0xF0000187,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00110000111  xsmuldp vs32, vs32, vs32
{      "xsmsubadp FREG , FREG , FREG",{0xF0000188,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00110001000  xsmsubadp f0, f0, f0
{     "xsmsubadp VSREG , FREG , FREG",{0xF0000189,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00110001001  xsmsubadp vs32, f0, f0
{     "xsmsubadp FREG , FREG , VSREG",{0xF000018A,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00110001010  xsmsubadp f0, f0, vs32
{    "xsmsubadp VSREG , FREG , VSREG",{0xF000018B,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00110001011  xsmsubadp vs32, f0, vs32
{     "xsmsubadp FREG , VSREG , FREG",{0xF000018C,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00110001100  xsmsubadp f0, vs32, f0
{    "xsmsubadp VSREG , VSREG , FREG",{0xF000018D,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00110001101  xsmsubadp vs32, vs32, f0
{    "xsmsubadp FREG , VSREG , VSREG",{0xF000018E,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00110001110  xsmsubadp f0, vs32, vs32
{   "xsmsubadp VSREG , VSREG , VSREG",{0xF000018F,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00110001111  xsmsubadp vs32, vs32, vs32
{     "xxmrglw VSREG , VSREG , VSREG",{0xF0000190,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx00110010xxx  xxmrglw vs0, vs0, vs0
{               "xsrdpip FREG , FREG",{0xF00001A4,0x03E0F800}}, // 111100xxxxx00000xxxxx00110100100  xsrdpip f0, f0
{              "xsrdpip VSREG , FREG",{0xF00001A5,0x03E0F800}}, // 111100xxxxx00000xxxxx00110100101  xsrdpip vs32, f0
{              "xsrdpip FREG , VSREG",{0xF00001A6,0x03E0F800}}, // 111100xxxxx00000xxxxx00110100110  xsrdpip f0, vs32
{             "xsrdpip VSREG , VSREG",{0xF00001A7,0x03E0F800}}, // 111100xxxxx00000xxxxx00110100111  xsrdpip vs32, vs32
{             "xstsqrtdp CREG , FREG",{0xF00001A8,0x0380F800}}, // 111100xxx0000000xxxxx00110101000  xstsqrtdp cr0, f0
{            "xstsqrtdp CREG , VSREG",{0xF00001AA,0x0380F800}}, // 111100xxx0000000xxxxx00110101010  xstsqrtdp cr0, vs32
{               "xsrdpic FREG , FREG",{0xF00001AC,0x03E0F800}}, // 111100xxxxx00000xxxxx00110101100  xsrdpic f0, f0
{              "xsrdpic VSREG , FREG",{0xF00001AD,0x03E0F800}}, // 111100xxxxx00000xxxxx00110101101  xsrdpic vs32, f0
{              "xsrdpic FREG , VSREG",{0xF00001AE,0x03E0F800}}, // 111100xxxxx00000xxxxx00110101110  xsrdpic f0, vs32
{             "xsrdpic VSREG , VSREG",{0xF00001AF,0x03E0F800}}, // 111100xxxxx00000xxxxx00110101111  xsrdpic vs32, vs32
{        "xsdivdp FREG , FREG , FREG",{0xF00001C0,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00111000000  xsdivdp f0, f0, f0
{       "xsdivdp VSREG , FREG , FREG",{0xF00001C1,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00111000001  xsdivdp vs32, f0, f0
{       "xsdivdp FREG , FREG , VSREG",{0xF00001C2,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00111000010  xsdivdp f0, f0, vs32
{      "xsdivdp VSREG , FREG , VSREG",{0xF00001C3,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00111000011  xsdivdp vs32, f0, vs32
{       "xsdivdp FREG , VSREG , FREG",{0xF00001C4,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00111000100  xsdivdp f0, vs32, f0
{      "xsdivdp VSREG , VSREG , FREG",{0xF00001C5,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00111000101  xsdivdp vs32, vs32, f0
{      "xsdivdp FREG , VSREG , VSREG",{0xF00001C6,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00111000110  xsdivdp f0, vs32, vs32
{     "xsdivdp VSREG , VSREG , VSREG",{0xF00001C7,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00111000111  xsdivdp vs32, vs32, vs32
{      "xsmsubmdp FREG , FREG , FREG",{0xF00001C8,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00111001000  xsmsubmdp f0, f0, f0
{     "xsmsubmdp VSREG , FREG , FREG",{0xF00001C9,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00111001001  xsmsubmdp vs32, f0, f0
{     "xsmsubmdp FREG , FREG , VSREG",{0xF00001CA,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00111001010  xsmsubmdp f0, f0, vs32
{    "xsmsubmdp VSREG , FREG , VSREG",{0xF00001CB,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00111001011  xsmsubmdp vs32, f0, vs32
{     "xsmsubmdp FREG , VSREG , FREG",{0xF00001CC,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00111001100  xsmsubmdp f0, vs32, f0
{    "xsmsubmdp VSREG , VSREG , FREG",{0xF00001CD,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00111001101  xsmsubmdp vs32, vs32, f0
{    "xsmsubmdp FREG , VSREG , VSREG",{0xF00001CE,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00111001110  xsmsubmdp f0, vs32, vs32
{   "xsmsubmdp VSREG , VSREG , VSREG",{0xF00001CF,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx00111001111  xsmsubmdp vs32, vs32, vs32
{               "xsrdpim FREG , FREG",{0xF00001E4,0x03E0F800}}, // 111100xxxxx00000xxxxx00111100100  xsrdpim f0, f0
{              "xsrdpim VSREG , FREG",{0xF00001E5,0x03E0F800}}, // 111100xxxxx00000xxxxx00111100101  xsrdpim vs32, f0
{              "xsrdpim FREG , VSREG",{0xF00001E6,0x03E0F800}}, // 111100xxxxx00000xxxxx00111100110  xsrdpim f0, vs32
{             "xsrdpim VSREG , VSREG",{0xF00001E7,0x03E0F800}}, // 111100xxxxx00000xxxxx00111100111  xsrdpim vs32, vs32
{       "xstdivdp CREG , FREG , FREG",{0xF00001E8,0x039FF800}}, // 111100xxx00xxxxxxxxxx00111101000  xstdivdp cr0, f0, f0
{      "xstdivdp CREG , FREG , VSREG",{0xF00001EA,0x039FF800}}, // 111100xxx00xxxxxxxxxx00111101010  xstdivdp cr0, f0, vs32
{      "xstdivdp CREG , VSREG , FREG",{0xF00001EC,0x039FF800}}, // 111100xxx00xxxxxxxxxx00111101100  xstdivdp cr0, vs32, f0
{     "xstdivdp CREG , VSREG , VSREG",{0xF00001EE,0x039FF800}}, // 111100xxx00xxxxxxxxxx00111101110  xstdivdp cr0, vs32, vs32
{     "xvaddsp VSREG , VSREG , VSREG",{0xF0000200,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx01000000xxx  xvaddsp vs0, vs0, vs0
{   "xvmaddasp VSREG , VSREG , VSREG",{0xF0000208,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx01000001xxx  xvmaddasp vs0, vs0, vs0
{   "xvcmpeqsp VSREG , VSREG , VSREG",{0xF0000218,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx01000011xxx  xvcmpeqsp vs0, vs0, vs0
{          "xvcvspuxws VSREG , VSREG",{0xF0000220,0x03E0F803}}, // 111100xxxxx00000xxxxx010001000xx  xvcvspuxws vs0, vs0
{              "xvrspi VSREG , VSREG",{0xF0000224,0x03E0F803}}, // 111100xxxxx00000xxxxx010001001xx  xvrspi vs0, vs0
{          "xvrsqrtesp VSREG , VSREG",{0xF0000228,0x03E0F803}}, // 111100xxxxx00000xxxxx010001010xx  xvrsqrtesp vs0, vs0
{            "xvsqrtsp VSREG , VSREG",{0xF000022C,0x03E0F803}}, // 111100xxxxx00000xxxxx010001011xx  xvsqrtsp vs0, vs0
{     "xvsubsp VSREG , VSREG , VSREG",{0xF0000240,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx01001000xxx  xvsubsp vs0, vs0, vs0
{   "xvmaddmsp VSREG , VSREG , VSREG",{0xF0000248,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx01001001xxx  xvmaddmsp vs0, vs0, vs0
{             "xxswapd VSREG , VSREG",{0xF0000250,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx01001010xxx  xxswapd vs0, vs0
{   "xvcmpgtsp VSREG , VSREG , VSREG",{0xF0000258,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx01001011xxx  xvcmpgtsp vs0, vs0, vs0
{          "xvcvspsxws VSREG , VSREG",{0xF0000260,0x03E0F803}}, // 111100xxxxx00000xxxxx010011000xx  xvcvspsxws vs0, vs0
{             "xvrspiz VSREG , VSREG",{0xF0000264,0x03E0F803}}, // 111100xxxxx00000xxxxx010011001xx  xvrspiz vs0, vs0
{              "xvresp VSREG , VSREG",{0xF0000268,0x03E0F803}}, // 111100xxxxx00000xxxxx010011010xx  xvresp vs0, vs0
{     "xvmulsp VSREG , VSREG , VSREG",{0xF0000280,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx01010000xxx  xvmulsp vs0, vs0, vs0
{   "xvmsubasp VSREG , VSREG , VSREG",{0xF0000288,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx01010001xxx  xvmsubasp vs0, vs0, vs0
{       "xxspltw VSREG , VSREG , NUM",{0xF0000290,0x03E3F803}}, // 111100xxxxx000xxxxxxx010100100xx  xxspltw vs0, vs0, 0
{   "xvcmpgesp VSREG , VSREG , VSREG",{0xF0000298,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx01010011xxx  xvcmpgesp vs0, vs0, vs0
{           "xvcvuxwsp VSREG , VSREG",{0xF00002A0,0x03E0F803}}, // 111100xxxxx00000xxxxx010101000xx  xvcvuxwsp vs0, vs0
{             "xvrspip VSREG , VSREG",{0xF00002A4,0x03E0F803}}, // 111100xxxxx00000xxxxx010101001xx  xvrspip vs0, vs0
{            "xvtsqrtsp CREG , VSREG",{0xF00002A8,0x0380F802}}, // 111100xxx0000000xxxxx010101010x0  xvtsqrtsp cr0, vs0
{             "xvrspic VSREG , VSREG",{0xF00002AC,0x03E0F803}}, // 111100xxxxx00000xxxxx010101011xx  xvrspic vs0, vs0
{     "xvdivsp VSREG , VSREG , VSREG",{0xF00002C0,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx01011000xxx  xvdivsp vs0, vs0, vs0
{   "xvmsubmsp VSREG , VSREG , VSREG",{0xF00002C8,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx01011001xxx  xvmsubmsp vs0, vs0, vs0
{           "xvcvsxwsp VSREG , VSREG",{0xF00002E0,0x03E0F803}}, // 111100xxxxx00000xxxxx010111000xx  xvcvsxwsp vs0, vs0
{             "xvrspim VSREG , VSREG",{0xF00002E4,0x03E0F803}}, // 111100xxxxx00000xxxxx010111001xx  xvrspim vs0, vs0
{     "xvtdivsp CREG , VSREG , VSREG",{0xF00002E8,0x039FF806}}, // 111100xxx00xxxxxxxxxx01011101xx0  xvtdivsp cr0, vs0, vs0
{     "xvadddp VSREG , VSREG , VSREG",{0xF0000300,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx01100000xxx  xvadddp vs0, vs0, vs0
{   "xvmaddadp VSREG , VSREG , VSREG",{0xF0000308,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx01100001xxx  xvmaddadp vs0, vs0, vs0
{   "xvcmpeqdp VSREG , VSREG , VSREG",{0xF0000318,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx01100011xxx  xvcmpeqdp vs0, vs0, vs0
{          "xvcvdpuxws VSREG , VSREG",{0xF0000320,0x03E0F803}}, // 111100xxxxx00000xxxxx011001000xx  xvcvdpuxws vs0, vs0
{              "xvrdpi VSREG , VSREG",{0xF0000324,0x03E0F803}}, // 111100xxxxx00000xxxxx011001001xx  xvrdpi vs0, vs0
{          "xvrsqrtedp VSREG , VSREG",{0xF0000328,0x03E0F803}}, // 111100xxxxx00000xxxxx011001010xx  xvrsqrtedp vs0, vs0
{            "xvsqrtdp VSREG , VSREG",{0xF000032C,0x03E0F803}}, // 111100xxxxx00000xxxxx011001011xx  xvsqrtdp vs0, vs0
{     "xvsubdp VSREG , VSREG , VSREG",{0xF0000340,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx01101000xxx  xvsubdp vs0, vs0, vs0
{   "xvmaddmdp VSREG , VSREG , VSREG",{0xF0000348,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx01101001xxx  xvmaddmdp vs0, vs0, vs0
{     "xxmrgld VSREG , VSREG , VSREG",{0xF0000352,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx01101010xxx  xxmrgld vs0, vs0, vs32
{   "xvcmpgtdp VSREG , VSREG , VSREG",{0xF0000358,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx01101011xxx  xvcmpgtdp vs0, vs0, vs0
{          "xvcvdpsxws VSREG , VSREG",{0xF0000360,0x03E0F803}}, // 111100xxxxx00000xxxxx011011000xx  xvcvdpsxws vs0, vs0
{             "xvrdpiz VSREG , VSREG",{0xF0000364,0x03E0F803}}, // 111100xxxxx00000xxxxx011011001xx  xvrdpiz vs0, vs0
{              "xvredp VSREG , VSREG",{0xF0000368,0x03E0F803}}, // 111100xxxxx00000xxxxx011011010xx  xvredp vs0, vs0
{     "xvmuldp VSREG , VSREG , VSREG",{0xF0000380,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx01110000xxx  xvmuldp vs0, vs0, vs0
{   "xvmsubadp VSREG , VSREG , VSREG",{0xF0000388,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx01110001xxx  xvmsubadp vs0, vs0, vs0
{   "xvcmpgedp VSREG , VSREG , VSREG",{0xF0000398,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx01110011xxx  xvcmpgedp vs0, vs0, vs0
{           "xvcvuxwdp VSREG , VSREG",{0xF00003A0,0x03E0F803}}, // 111100xxxxx00000xxxxx011101000xx  xvcvuxwdp vs0, vs0
{             "xvrdpip VSREG , VSREG",{0xF00003A4,0x03E0F803}}, // 111100xxxxx00000xxxxx011101001xx  xvrdpip vs0, vs0
{            "xvtsqrtdp CREG , VSREG",{0xF00003A8,0x0380F802}}, // 111100xxx0000000xxxxx011101010x0  xvtsqrtdp cr0, vs0
{             "xvrdpic VSREG , VSREG",{0xF00003AC,0x03E0F803}}, // 111100xxxxx00000xxxxx011101011xx  xvrdpic vs0, vs0
{     "xvdivdp VSREG , VSREG , VSREG",{0xF00003C0,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx01111000xxx  xvdivdp vs0, vs0, vs0
{   "xvmsubmdp VSREG , VSREG , VSREG",{0xF00003C8,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx01111001xxx  xvmsubmdp vs0, vs0, vs0
{           "xvcvsxwdp VSREG , VSREG",{0xF00003E0,0x03E0F803}}, // 111100xxxxx00000xxxxx011111000xx  xvcvsxwdp vs0, vs0
{             "xvrdpim VSREG , VSREG",{0xF00003E4,0x03E0F803}}, // 111100xxxxx00000xxxxx011111001xx  xvrdpim vs0, vs0
{     "xvtdivdp CREG , VSREG , VSREG",{0xF00003E8,0x039FF806}}, // 111100xxx00xxxxxxxxxx01111101xx0  xvtdivdp cr0, vs0, vs0
{      "xxland VSREG , VSREG , VSREG",{0xF0000410,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx10000010xxx  xxland vs0, vs0, vs0
{              "xscvdpsp FREG , FREG",{0xF0000424,0x03E0F800}}, // 111100xxxxx00000xxxxx10000100100  xscvdpsp f0, f0
{             "xscvdpsp VSREG , FREG",{0xF0000425,0x03E0F800}}, // 111100xxxxx00000xxxxx10000100101  xscvdpsp vs32, f0
{             "xscvdpsp FREG , VSREG",{0xF0000426,0x03E0F800}}, // 111100xxxxx00000xxxxx10000100110  xscvdpsp f0, vs32
{            "xscvdpsp VSREG , VSREG",{0xF0000427,0x03E0F800}}, // 111100xxxxx00000xxxxx10000100111  xscvdpsp vs32, vs32
{     "xxlandc VSREG , VSREG , VSREG",{0xF0000450,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx10001010xxx  xxlandc vs0, vs0, vs0
{       "xxlor VSREG , VSREG , VSREG",{0xF0000490,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx10010010xxx  xxlor vs0, vs0, vs0
{      "xxlxor VSREG , VSREG , VSREG",{0xF00004D0,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx10011010xxx  xxlxor vs0, vs0, vs0
{        "xsmaxdp FREG , FREG , FREG",{0xF0000500,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10100000000  xsmaxdp f0, f0, f0
{       "xsmaxdp VSREG , FREG , FREG",{0xF0000501,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10100000001  xsmaxdp vs32, f0, f0
{       "xsmaxdp FREG , FREG , VSREG",{0xF0000502,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10100000010  xsmaxdp f0, f0, vs32
{      "xsmaxdp VSREG , FREG , VSREG",{0xF0000503,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10100000011  xsmaxdp vs32, f0, vs32
{       "xsmaxdp FREG , VSREG , FREG",{0xF0000504,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10100000100  xsmaxdp f0, vs32, f0
{      "xsmaxdp VSREG , VSREG , FREG",{0xF0000505,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10100000101  xsmaxdp vs32, vs32, f0
{      "xsmaxdp FREG , VSREG , VSREG",{0xF0000506,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10100000110  xsmaxdp f0, vs32, vs32
{     "xsmaxdp VSREG , VSREG , VSREG",{0xF0000507,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10100000111  xsmaxdp vs32, vs32, vs32
{     "xsnmaddadp FREG , FREG , FREG",{0xF0000508,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10100001000  xsnmaddadp f0, f0, f0
{    "xsnmaddadp VSREG , FREG , FREG",{0xF0000509,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10100001001  xsnmaddadp vs32, f0, f0
{    "xsnmaddadp FREG , FREG , VSREG",{0xF000050A,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10100001010  xsnmaddadp f0, f0, vs32
{   "xsnmaddadp VSREG , FREG , VSREG",{0xF000050B,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10100001011  xsnmaddadp vs32, f0, vs32
{    "xsnmaddadp FREG , VSREG , FREG",{0xF000050C,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10100001100  xsnmaddadp f0, vs32, f0
{   "xsnmaddadp VSREG , VSREG , FREG",{0xF000050D,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10100001101  xsnmaddadp vs32, vs32, f0
{   "xsnmaddadp FREG , VSREG , VSREG",{0xF000050E,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10100001110  xsnmaddadp f0, vs32, vs32
{  "xsnmaddadp VSREG , VSREG , VSREG",{0xF000050F,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10100001111  xsnmaddadp vs32, vs32, vs32
{      "xxlnor VSREG , VSREG , VSREG",{0xF0000510,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx10100010xxx  xxlnor vs0, vs0, vs0
{            "xscvdpuxds FREG , FREG",{0xF0000520,0x03E0F800}}, // 111100xxxxx00000xxxxx10100100000  xscvdpuxds f0, f0
{           "xscvdpuxds VSREG , FREG",{0xF0000521,0x03E0F800}}, // 111100xxxxx00000xxxxx10100100001  xscvdpuxds vs32, f0
{           "xscvdpuxds FREG , VSREG",{0xF0000522,0x03E0F800}}, // 111100xxxxx00000xxxxx10100100010  xscvdpuxds f0, vs32
{          "xscvdpuxds VSREG , VSREG",{0xF0000523,0x03E0F800}}, // 111100xxxxx00000xxxxx10100100011  xscvdpuxds vs32, vs32
{              "xscvspdp FREG , FREG",{0xF0000524,0x03E0F800}}, // 111100xxxxx00000xxxxx10100100100  xscvspdp f0, f0
{             "xscvspdp VSREG , FREG",{0xF0000525,0x03E0F800}}, // 111100xxxxx00000xxxxx10100100101  xscvspdp vs32, f0
{             "xscvspdp FREG , VSREG",{0xF0000526,0x03E0F800}}, // 111100xxxxx00000xxxxx10100100110  xscvspdp f0, vs32
{            "xscvspdp VSREG , VSREG",{0xF0000527,0x03E0F800}}, // 111100xxxxx00000xxxxx10100100111  xscvspdp vs32, vs32
{        "xsmindp FREG , FREG , FREG",{0xF0000540,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10101000000  xsmindp f0, f0, f0
{       "xsmindp VSREG , FREG , FREG",{0xF0000541,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10101000001  xsmindp vs32, f0, f0
{       "xsmindp FREG , FREG , VSREG",{0xF0000542,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10101000010  xsmindp f0, f0, vs32
{      "xsmindp VSREG , FREG , VSREG",{0xF0000543,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10101000011  xsmindp vs32, f0, vs32
{       "xsmindp FREG , VSREG , FREG",{0xF0000544,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10101000100  xsmindp f0, vs32, f0
{      "xsmindp VSREG , VSREG , FREG",{0xF0000545,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10101000101  xsmindp vs32, vs32, f0
{      "xsmindp FREG , VSREG , VSREG",{0xF0000546,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10101000110  xsmindp f0, vs32, vs32
{     "xsmindp VSREG , VSREG , VSREG",{0xF0000547,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10101000111  xsmindp vs32, vs32, vs32
{     "xsnmaddmdp FREG , FREG , FREG",{0xF0000548,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10101001000  xsnmaddmdp f0, f0, f0
{    "xsnmaddmdp VSREG , FREG , FREG",{0xF0000549,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10101001001  xsnmaddmdp vs32, f0, f0
{    "xsnmaddmdp FREG , FREG , VSREG",{0xF000054A,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10101001010  xsnmaddmdp f0, f0, vs32
{   "xsnmaddmdp VSREG , FREG , VSREG",{0xF000054B,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10101001011  xsnmaddmdp vs32, f0, vs32
{    "xsnmaddmdp FREG , VSREG , FREG",{0xF000054C,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10101001100  xsnmaddmdp f0, vs32, f0
{   "xsnmaddmdp VSREG , VSREG , FREG",{0xF000054D,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10101001101  xsnmaddmdp vs32, vs32, f0
{   "xsnmaddmdp FREG , VSREG , VSREG",{0xF000054E,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10101001110  xsnmaddmdp f0, vs32, vs32
{  "xsnmaddmdp VSREG , VSREG , VSREG",{0xF000054F,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10101001111  xsnmaddmdp vs32, vs32, vs32
{            "xscvdpsxds FREG , FREG",{0xF0000560,0x03E0F800}}, // 111100xxxxx00000xxxxx10101100000  xscvdpsxds f0, f0
{           "xscvdpsxds VSREG , FREG",{0xF0000561,0x03E0F800}}, // 111100xxxxx00000xxxxx10101100001  xscvdpsxds vs32, f0
{           "xscvdpsxds FREG , VSREG",{0xF0000562,0x03E0F800}}, // 111100xxxxx00000xxxxx10101100010  xscvdpsxds f0, vs32
{          "xscvdpsxds VSREG , VSREG",{0xF0000563,0x03E0F800}}, // 111100xxxxx00000xxxxx10101100011  xscvdpsxds vs32, vs32
{               "xsabsdp FREG , FREG",{0xF0000564,0x03E0F800}}, // 111100xxxxx00000xxxxx10101100100  xsabsdp f0, f0
{              "xsabsdp VSREG , FREG",{0xF0000565,0x03E0F800}}, // 111100xxxxx00000xxxxx10101100101  xsabsdp vs32, f0
{              "xsabsdp FREG , VSREG",{0xF0000566,0x03E0F800}}, // 111100xxxxx00000xxxxx10101100110  xsabsdp f0, vs32
{             "xsabsdp VSREG , VSREG",{0xF0000567,0x03E0F800}}, // 111100xxxxx00000xxxxx10101100111  xsabsdp vs32, vs32
{      "xscpsgndp FREG , FREG , FREG",{0xF0000580,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10110000000  xscpsgndp f0, f0, f0
{     "xscpsgndp VSREG , FREG , FREG",{0xF0000581,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10110000001  xscpsgndp vs32, f0, f0
{     "xscpsgndp FREG , FREG , VSREG",{0xF0000582,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10110000010  xscpsgndp f0, f0, vs32
{    "xscpsgndp VSREG , FREG , VSREG",{0xF0000583,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10110000011  xscpsgndp vs32, f0, vs32
{     "xscpsgndp FREG , VSREG , FREG",{0xF0000584,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10110000100  xscpsgndp f0, vs32, f0
{    "xscpsgndp VSREG , VSREG , FREG",{0xF0000585,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10110000101  xscpsgndp vs32, vs32, f0
{    "xscpsgndp FREG , VSREG , VSREG",{0xF0000586,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10110000110  xscpsgndp f0, vs32, vs32
{   "xscpsgndp VSREG , VSREG , VSREG",{0xF0000587,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10110000111  xscpsgndp vs32, vs32, vs32
{     "xsnmsubadp FREG , FREG , FREG",{0xF0000588,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10110001000  xsnmsubadp f0, f0, f0
{    "xsnmsubadp VSREG , FREG , FREG",{0xF0000589,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10110001001  xsnmsubadp vs32, f0, f0
{    "xsnmsubadp FREG , FREG , VSREG",{0xF000058A,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10110001010  xsnmsubadp f0, f0, vs32
{   "xsnmsubadp VSREG , FREG , VSREG",{0xF000058B,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10110001011  xsnmsubadp vs32, f0, vs32
{    "xsnmsubadp FREG , VSREG , FREG",{0xF000058C,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10110001100  xsnmsubadp f0, vs32, f0
{   "xsnmsubadp VSREG , VSREG , FREG",{0xF000058D,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10110001101  xsnmsubadp vs32, vs32, f0
{   "xsnmsubadp FREG , VSREG , VSREG",{0xF000058E,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10110001110  xsnmsubadp f0, vs32, vs32
{  "xsnmsubadp VSREG , VSREG , VSREG",{0xF000058F,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10110001111  xsnmsubadp vs32, vs32, vs32
{             "xscvuxddp FREG , FREG",{0xF00005A0,0x03E0F800}}, // 111100xxxxx00000xxxxx10110100000  xscvuxddp f0, f0
{            "xscvuxddp VSREG , FREG",{0xF00005A1,0x03E0F800}}, // 111100xxxxx00000xxxxx10110100001  xscvuxddp vs32, f0
{            "xscvuxddp FREG , VSREG",{0xF00005A2,0x03E0F800}}, // 111100xxxxx00000xxxxx10110100010  xscvuxddp f0, vs32
{           "xscvuxddp VSREG , VSREG",{0xF00005A3,0x03E0F800}}, // 111100xxxxx00000xxxxx10110100011  xscvuxddp vs32, vs32
{              "xsnabsdp FREG , FREG",{0xF00005A4,0x03E0F800}}, // 111100xxxxx00000xxxxx10110100100  xsnabsdp f0, f0
{             "xsnabsdp VSREG , FREG",{0xF00005A5,0x03E0F800}}, // 111100xxxxx00000xxxxx10110100101  xsnabsdp vs32, f0
{             "xsnabsdp FREG , VSREG",{0xF00005A6,0x03E0F800}}, // 111100xxxxx00000xxxxx10110100110  xsnabsdp f0, vs32
{            "xsnabsdp VSREG , VSREG",{0xF00005A7,0x03E0F800}}, // 111100xxxxx00000xxxxx10110100111  xsnabsdp vs32, vs32
{     "xsnmsubmdp FREG , FREG , FREG",{0xF00005C8,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10111001000  xsnmsubmdp f0, f0, f0
{    "xsnmsubmdp VSREG , FREG , FREG",{0xF00005C9,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10111001001  xsnmsubmdp vs32, f0, f0
{    "xsnmsubmdp FREG , FREG , VSREG",{0xF00005CA,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10111001010  xsnmsubmdp f0, f0, vs32
{   "xsnmsubmdp VSREG , FREG , VSREG",{0xF00005CB,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10111001011  xsnmsubmdp vs32, f0, vs32
{    "xsnmsubmdp FREG , VSREG , FREG",{0xF00005CC,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10111001100  xsnmsubmdp f0, vs32, f0
{   "xsnmsubmdp VSREG , VSREG , FREG",{0xF00005CD,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10111001101  xsnmsubmdp vs32, vs32, f0
{   "xsnmsubmdp FREG , VSREG , VSREG",{0xF00005CE,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10111001110  xsnmsubmdp f0, vs32, vs32
{  "xsnmsubmdp VSREG , VSREG , VSREG",{0xF00005CF,0x03FFF800}}, // 111100xxxxxxxxxxxxxxx10111001111  xsnmsubmdp vs32, vs32, vs32
{             "xscvsxddp FREG , FREG",{0xF00005E0,0x03E0F800}}, // 111100xxxxx00000xxxxx10111100000  xscvsxddp f0, f0
{            "xscvsxddp VSREG , FREG",{0xF00005E1,0x03E0F800}}, // 111100xxxxx00000xxxxx10111100001  xscvsxddp vs32, f0
{            "xscvsxddp FREG , VSREG",{0xF00005E2,0x03E0F800}}, // 111100xxxxx00000xxxxx10111100010  xscvsxddp f0, vs32
{           "xscvsxddp VSREG , VSREG",{0xF00005E3,0x03E0F800}}, // 111100xxxxx00000xxxxx10111100011  xscvsxddp vs32, vs32
{               "xsnegdp FREG , FREG",{0xF00005E4,0x03E0F800}}, // 111100xxxxx00000xxxxx10111100100  xsnegdp f0, f0
{              "xsnegdp VSREG , FREG",{0xF00005E5,0x03E0F800}}, // 111100xxxxx00000xxxxx10111100101  xsnegdp vs32, f0
{              "xsnegdp FREG , VSREG",{0xF00005E6,0x03E0F800}}, // 111100xxxxx00000xxxxx10111100110  xsnegdp f0, vs32
{             "xsnegdp VSREG , VSREG",{0xF00005E7,0x03E0F800}}, // 111100xxxxx00000xxxxx10111100111  xsnegdp vs32, vs32
{     "xvmaxsp VSREG , VSREG , VSREG",{0xF0000600,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx11000000xxx  xvmaxsp vs0, vs0, vs0
{  "xvnmaddasp VSREG , VSREG , VSREG",{0xF0000608,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx11000001xxx  xvnmaddasp vs0, vs0, vs0
{ "xvcmpeqsp . VSREG , VSREG , VSREG",{0xF0000618,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx11000011xxx  xvcmpeqsp. vs0, vs0, vs0
{          "xvcvspuxds VSREG , VSREG",{0xF0000620,0x03E0F803}}, // 111100xxxxx00000xxxxx110001000xx  xvcvspuxds vs0, vs0
{            "xvcvdpsp VSREG , VSREG",{0xF0000624,0x03E0F803}}, // 111100xxxxx00000xxxxx110001001xx  xvcvdpsp vs0, vs0
{     "xvminsp VSREG , VSREG , VSREG",{0xF0000640,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx11001000xxx  xvminsp vs0, vs0, vs0
{  "xvnmaddmsp VSREG , VSREG , VSREG",{0xF0000648,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx11001001xxx  xvnmaddmsp vs0, vs0, vs0
{ "xvcmpgtsp . VSREG , VSREG , VSREG",{0xF0000658,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx11001011xxx  xvcmpgtsp. vs0, vs0, vs0
{          "xvcvspsxds VSREG , VSREG",{0xF0000660,0x03E0F803}}, // 111100xxxxx00000xxxxx110011000xx  xvcvspsxds vs0, vs0
{             "xvabssp VSREG , VSREG",{0xF0000664,0x03E0F803}}, // 111100xxxxx00000xxxxx110011001xx  xvabssp vs0, vs0
{             "xvmovsp VSREG , VSREG",{0xF0000680,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx11010000xxx  xvmovsp vs0, vs0
{   "xvcpsgnsp VSREG , VSREG , VSREG",{0xF0000682,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx11010000xxx  xvcpsgnsp vs0, vs0, vs32
{  "xvnmsubasp VSREG , VSREG , VSREG",{0xF0000688,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx11010001xxx  xvnmsubasp vs0, vs0, vs0
{ "xvcmpgesp . VSREG , VSREG , VSREG",{0xF0000698,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx11010011xxx  xvcmpgesp. vs0, vs0, vs0
{           "xvcvuxdsp VSREG , VSREG",{0xF00006A0,0x03E0F803}}, // 111100xxxxx00000xxxxx110101000xx  xvcvuxdsp vs0, vs0
{            "xvnabssp VSREG , VSREG",{0xF00006A4,0x03E0F803}}, // 111100xxxxx00000xxxxx110101001xx  xvnabssp vs0, vs0
{  "xvnmsubmsp VSREG , VSREG , VSREG",{0xF00006C8,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx11011001xxx  xvnmsubmsp vs0, vs0, vs0
{           "xvcvsxdsp VSREG , VSREG",{0xF00006E0,0x03E0F803}}, // 111100xxxxx00000xxxxx110111000xx  xvcvsxdsp vs0, vs0
{             "xvnegsp VSREG , VSREG",{0xF00006E4,0x03E0F803}}, // 111100xxxxx00000xxxxx110111001xx  xvnegsp vs0, vs0
{     "xvmaxdp VSREG , VSREG , VSREG",{0xF0000700,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx11100000xxx  xvmaxdp vs0, vs0, vs0
{  "xvnmaddadp VSREG , VSREG , VSREG",{0xF0000708,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx11100001xxx  xvnmaddadp vs0, vs0, vs0
{ "xvcmpeqdp . VSREG , VSREG , VSREG",{0xF0000718,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx11100011xxx  xvcmpeqdp. vs0, vs0, vs0
{          "xvcvdpuxds VSREG , VSREG",{0xF0000720,0x03E0F803}}, // 111100xxxxx00000xxxxx111001000xx  xvcvdpuxds vs0, vs0
{            "xvcvspdp VSREG , VSREG",{0xF0000724,0x03E0F803}}, // 111100xxxxx00000xxxxx111001001xx  xvcvspdp vs0, vs0
{     "xvmindp VSREG , VSREG , VSREG",{0xF0000740,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx11101000xxx  xvmindp vs0, vs0, vs0
{  "xvnmaddmdp VSREG , VSREG , VSREG",{0xF0000748,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx11101001xxx  xvnmaddmdp vs0, vs0, vs0
{ "xvcmpgtdp . VSREG , VSREG , VSREG",{0xF0000758,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx11101011xxx  xvcmpgtdp. vs0, vs0, vs0
{          "xvcvdpsxds VSREG , VSREG",{0xF0000760,0x03E0F803}}, // 111100xxxxx00000xxxxx111011000xx  xvcvdpsxds vs0, vs0
{             "xvabsdp VSREG , VSREG",{0xF0000764,0x03E0F803}}, // 111100xxxxx00000xxxxx111011001xx  xvabsdp vs0, vs0
{             "xvmovdp VSREG , VSREG",{0xF0000780,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx11110000xxx  xvmovdp vs0, vs0
{   "xvcpsgndp VSREG , VSREG , VSREG",{0xF0000782,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx11110000xxx  xvcpsgndp vs0, vs0, vs32
{  "xvnmsubadp VSREG , VSREG , VSREG",{0xF0000788,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx11110001xxx  xvnmsubadp vs0, vs0, vs0
{ "xvcmpgedp . VSREG , VSREG , VSREG",{0xF0000798,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx11110011xxx  xvcmpgedp. vs0, vs0, vs0
{           "xvcvuxddp VSREG , VSREG",{0xF00007A0,0x03E0F803}}, // 111100xxxxx00000xxxxx111101000xx  xvcvuxddp vs0, vs0
{            "xvnabsdp VSREG , VSREG",{0xF00007A4,0x03E0F803}}, // 111100xxxxx00000xxxxx111101001xx  xvnabsdp vs0, vs0
{  "xvnmsubmdp VSREG , VSREG , VSREG",{0xF00007C8,0x03FFF807}}, // 111100xxxxxxxxxxxxxxx11111001xxx  xvnmsubmdp vs0, vs0, vs0
{           "xvcvsxddp VSREG , VSREG",{0xF00007E0,0x03E0F803}}, // 111100xxxxx00000xxxxx111111000xx  xvcvsxddp vs0, vs0
{             "xvnegdp VSREG , VSREG",{0xF00007E4,0x03E0F803}}, // 111100xxxxx00000xxxxx111111001xx  xvnegdp vs0, vs0
{             "std GPR , NUM ( NUM )",{0xF8000000,0x03E0FFFC}}, // 111110xxxxx00000xxxxxxxxxxxxxx00  std r0, 0(0)
{            "stdu GPR , NUM ( NUM )",{0xF8000001,0x03E0FFFC}}, // 111110xxxxx00000xxxxxxxxxxxxxx01  stdu r0, 0(0)
{             "std GPR , NUM ( GPR )",{0xF8010000,0x03FFFFFC}}, // 111110xxxxxxxxxxxxxxxxxxxxxxxx00  std r0, 0(r1)
{            "stdu GPR , NUM ( GPR )",{0xF8010001,0x03FFFFFC}}, // 111110xxxxxxxxxxxxxxxxxxxxxxxx01  stdu r0, 0(r1)
{          "fcmpu CREG , FREG , FREG",{0xFC000000,0x039FF800}}, // 111111xxx00xxxxxxxxxx00000000000  fcmpu cr0, f0, f0
{         "fcpsgn FREG , FREG , FREG",{0xFC000010,0x03FFF800}}, // 111111xxxxxxxxxxxxxxx00000010000  fcpsgn f0, f0, f0
{       "fcpsgn . FREG , FREG , FREG",{0xFC000011,0x03FFF800}}, // 111111xxxxxxxxxxxxxxx00000010001  fcpsgn. f0, f0, f0
{                  "frsp FREG , FREG",{0xFC000018,0x03E0F800}}, // 111111xxxxx00000xxxxx00000011000  frsp f0, f0
{                "frsp . FREG , FREG",{0xFC000019,0x03E0F800}}, // 111111xxxxx00000xxxxx00000011001  frsp. f0, f0
{                 "fctiw FREG , FREG",{0xFC00001C,0x03E0F800}}, // 111111xxxxx00000xxxxx00000011100  fctiw f0, f0
{               "fctiw . FREG , FREG",{0xFC00001D,0x03E0F800}}, // 111111xxxxx00000xxxxx00000011101  fctiw. f0, f0
{                "fctiwz FREG , FREG",{0xFC00001E,0x03E0F800}}, // 111111xxxxx00000xxxxx00000011110  fctiwz f0, f0
{              "fctiwz . FREG , FREG",{0xFC00001F,0x03E0F800}}, // 111111xxxxx00000xxxxx00000011111  fctiwz. f0, f0
{           "fdiv FREG , FREG , FREG",{0xFC000024,0x03FFF800}}, // 111111xxxxxxxxxxxxxxx00000100100  fdiv f0, f0, f0
{         "fdiv . FREG , FREG , FREG",{0xFC000025,0x03FFF800}}, // 111111xxxxxxxxxxxxxxx00000100101  fdiv. f0, f0, f0
{           "fsub FREG , FREG , FREG",{0xFC000028,0x03FFF800}}, // 111111xxxxxxxxxxxxxxx00000101000  fsub f0, f0, f0
{         "fsub . FREG , FREG , FREG",{0xFC000029,0x03FFF800}}, // 111111xxxxxxxxxxxxxxx00000101001  fsub. f0, f0, f0
{           "fadd FREG , FREG , FREG",{0xFC00002A,0x03FFF800}}, // 111111xxxxxxxxxxxxxxx00000101010  fadd f0, f0, f0
{         "fadd . FREG , FREG , FREG",{0xFC00002B,0x03FFF800}}, // 111111xxxxxxxxxxxxxxx00000101011  fadd. f0, f0, f0
{                 "fsqrt FREG , FREG",{0xFC00002C,0x03E0F800}}, // 111111xxxxx00000xxxxx00000101100  fsqrt f0, f0
{               "fsqrt . FREG , FREG",{0xFC00002D,0x03E0F800}}, // 111111xxxxx00000xxxxx00000101101  fsqrt. f0, f0
{    "fsel FREG , FREG , FREG , FREG",{0xFC00002E,0x03FFFFC0}}, // 111111xxxxxxxxxxxxxxxxxxxx101110  fsel f0, f0, f0, f0
{  "fsel . FREG , FREG , FREG , FREG",{0xFC00002F,0x03FFFFC0}}, // 111111xxxxxxxxxxxxxxxxxxxx101111  fsel. f0, f0, f0, f0
{                   "fre FREG , FREG",{0xFC000030,0x03E0F800}}, // 111111xxxxx00000xxxxx00000110000  fre f0, f0
{                 "fre . FREG , FREG",{0xFC000031,0x03E0F800}}, // 111111xxxxx00000xxxxx00000110001  fre. f0, f0
{           "fmul FREG , FREG , FREG",{0xFC000032,0x03FF07C0}}, // 111111xxxxxxxxxx00000xxxxx110010  fmul f0, f0, f0
{         "fmul . FREG , FREG , FREG",{0xFC000033,0x03FF07C0}}, // 111111xxxxxxxxxx00000xxxxx110011  fmul. f0, f0, f0
{               "frsqrte FREG , FREG",{0xFC000034,0x03E0F800}}, // 111111xxxxx00000xxxxx00000110100  frsqrte f0, f0
{             "frsqrte . FREG , FREG",{0xFC000035,0x03E0F800}}, // 111111xxxxx00000xxxxx00000110101  frsqrte. f0, f0
{   "fmsub FREG , FREG , FREG , FREG",{0xFC000038,0x03FFFFC0}}, // 111111xxxxxxxxxxxxxxxxxxxx111000  fmsub f0, f0, f0, f0
{ "fmsub . FREG , FREG , FREG , FREG",{0xFC000039,0x03FFFFC0}}, // 111111xxxxxxxxxxxxxxxxxxxx111001  fmsub. f0, f0, f0, f0
{   "fmadd FREG , FREG , FREG , FREG",{0xFC00003A,0x03FFFFC0}}, // 111111xxxxxxxxxxxxxxxxxxxx111010  fmadd f0, f0, f0, f0
{ "fmadd . FREG , FREG , FREG , FREG",{0xFC00003B,0x03FFFFC0}}, // 111111xxxxxxxxxxxxxxxxxxxx111011  fmadd. f0, f0, f0, f0
{  "fnmsub FREG , FREG , FREG , FREG",{0xFC00003C,0x03FFFFC0}}, // 111111xxxxxxxxxxxxxxxxxxxx111100  fnmsub f0, f0, f0, f0
{"fnmsub . FREG , FREG , FREG , FREG",{0xFC00003D,0x03FFFFC0}}, // 111111xxxxxxxxxxxxxxxxxxxx111101  fnmsub. f0, f0, f0, f0
{  "fnmadd FREG , FREG , FREG , FREG",{0xFC00003E,0x03FFFFC0}}, // 111111xxxxxxxxxxxxxxxxxxxx111110  fnmadd f0, f0, f0, f0
{"fnmadd . FREG , FREG , FREG , FREG",{0xFC00003F,0x03FFFFC0}}, // 111111xxxxxxxxxxxxxxxxxxxx111111  fnmadd. f0, f0, f0, f0
{                        "mtfsb1 NUM",{0xFC00004C,0x03E00000}}, // 111111xxxxx000000000000001001100  mtfsb1 0
{                  "fneg FREG , FREG",{0xFC000050,0x03E0F800}}, // 111111xxxxx00000xxxxx00001010000  fneg f0, f0
{                "fneg . FREG , FREG",{0xFC000051,0x03E0F800}}, // 111111xxxxx00000xxxxx00001010001  fneg. f0, f0
{                        "mtfsb0 NUM",{0xFC00008C,0x03E00000}}, // 111111xxxxx000000000000010001100  mtfsb0 0
{                   "fmr FREG , FREG",{0xFC000090,0x03E0F800}}, // 111111xxxxx00000xxxxx00010010000  fmr f0, f0
{                 "fmr . FREG , FREG",{0xFC000091,0x03E0F800}}, // 111111xxxxx00000xxxxx00010010001  fmr. f0, f0
{                 "fnabs FREG , FREG",{0xFC000110,0x03E0F800}}, // 111111xxxxx00000xxxxx00100010000  fnabs f0, f0
{               "fnabs . FREG , FREG",{0xFC000111,0x03E0F800}}, // 111111xxxxx00000xxxxx00100010001  fnabs. f0, f0
{               "fctiwuz FREG , FREG",{0xFC00011E,0x03E0F800}}, // 111111xxxxx00000xxxxx00100011110  fctiwuz f0, f0
{             "fctiwuz . FREG , FREG",{0xFC00011F,0x03E0F800}}, // 111111xxxxx00000xxxxx00100011111  fctiwuz. f0, f0
{                  "fabs FREG , FREG",{0xFC000210,0x03E0F800}}, // 111111xxxxx00000xxxxx01000010000  fabs f0, f0
{                "fabs . FREG , FREG",{0xFC000211,0x03E0F800}}, // 111111xxxxx00000xxxxx01000010001  fabs. f0, f0
{                  "frin FREG , FREG",{0xFC000310,0x03E0F800}}, // 111111xxxxx00000xxxxx01100010000  frin f0, f0
{                "frin . FREG , FREG",{0xFC000311,0x03E0F800}}, // 111111xxxxx00000xxxxx01100010001  frin. f0, f0
{                  "friz FREG , FREG",{0xFC000350,0x03E0F800}}, // 111111xxxxx00000xxxxx01101010000  friz f0, f0
{                "friz . FREG , FREG",{0xFC000351,0x03E0F800}}, // 111111xxxxx00000xxxxx01101010001  friz. f0, f0
{                  "frip FREG , FREG",{0xFC000390,0x03E0F800}}, // 111111xxxxx00000xxxxx01110010000  frip f0, f0
{                "frip . FREG , FREG",{0xFC000391,0x03E0F800}}, // 111111xxxxx00000xxxxx01110010001  frip. f0, f0
{                  "frim FREG , FREG",{0xFC0003D0,0x03E0F800}}, // 111111xxxxx00000xxxxx01111010000  frim f0, f0
{                "frim . FREG , FREG",{0xFC0003D1,0x03E0F800}}, // 111111xxxxx00000xxxxx01111010001  frim. f0, f0
{                         "mffs FREG",{0xFC00048E,0x03E00000}}, // 111111xxxxx000000000010010001110  mffs f0
{                  "mtfsf NUM , FREG",{0xFC00058E,0x01FEF800}}, // 1111110xxxxxxxx0xxxxx10110001110  mtfsf 0, f0
{                 "fctid FREG , FREG",{0xFC00065C,0x03E0F800}}, // 111111xxxxx00000xxxxx11001011100  fctid f0, f0
{               "fctid . FREG , FREG",{0xFC00065D,0x03E0F800}}, // 111111xxxxx00000xxxxx11001011101  fctid. f0, f0
{                "fctidz FREG , FREG",{0xFC00065E,0x03E0F800}}, // 111111xxxxx00000xxxxx11001011110  fctidz f0, f0
{              "fctidz . FREG , FREG",{0xFC00065F,0x03E0F800}}, // 111111xxxxx00000xxxxx11001011111  fctidz. f0, f0
{                 "fcfid FREG , FREG",{0xFC00069C,0x03E0F800}}, // 111111xxxxx00000xxxxx11010011100  fcfid f0, f0
{               "fcfid . FREG , FREG",{0xFC00069D,0x03E0F800}}, // 111111xxxxx00000xxxxx11010011101  fcfid. f0, f0
{               "fctiduz FREG , FREG",{0xFC00075E,0x03E0F800}}, // 111111xxxxx00000xxxxx11101011110  fctiduz f0, f0
{             "fctiduz . FREG , FREG",{0xFC00075F,0x03E0F800}}, // 111111xxxxx00000xxxxx11101011111  fctiduz. f0, f0
{                "fcfidu FREG , FREG",{0xFC00079C,0x03E0F800}}, // 111111xxxxx00000xxxxx11110011100  fcfidu f0, f0
{              "fcfidu . FREG , FREG",{0xFC00079D,0x03E0F800}}, // 111111xxxxx00000xxxxx11110011101  fcfidu. f0, f0
};

/*****************************************************************************/
/* capstone */
/*****************************************************************************/
const char *cs_err_to_string(cs_err e)
{
	switch(e) {
		case CS_ERR_OK: return "CS_ERR_OK";
		case CS_ERR_MEM: return "CS_ERR_MEM";
		case CS_ERR_ARCH: return "CS_ERR_ARCH";
		case CS_ERR_HANDLE: return "CS_ERR_HANDLE";
		case CS_ERR_CSH: return "CS_ERR_CSH";
		case CS_ERR_MODE: return "CS_ERR_MODE";
		case CS_ERR_OPTION: return "CS_ERR_OPTION";
		case CS_ERR_DETAIL: return "CS_ERR_DETAIL";
		case CS_ERR_MEMSETUP: return "CS_ERR_MEMSETUP";
		case CS_ERR_VERSION: return "CS_ERR_VERSION";
		case CS_ERR_DIET: return "CS_ERR_DIET";
		case CS_ERR_SKIPDATA: return "CS_ERR_SKIPDATA";
		case CS_ERR_X86_ATT: return "CS_ERR_X86_ATT";
		case CS_ERR_X86_INTEL: return "CS_ERR_X86_INTEL";
		default: return "WTF";
	}
}

int disasm_capstone(uint8_t *data, uint32_t addr, string& result, string& err)
{
	int rc = -1;
	static bool init = false;

	/* capstone vars */
	static csh handle;
	cs_insn *insn = NULL;
	size_t count = 0;

	if (!init) {
		/* initialize capstone handle */
		cs_mode mode = (cs_mode)(CS_MODE_LITTLE_ENDIAN);

		if(cs_open(CS_ARCH_PPC, mode, &handle) != CS_ERR_OK) {
			MYLOG("ERROR: cs_open()\n");
			goto cleanup;
		}
		init = true;
	}

	count = cs_disasm(handle, data,
		/* code_size */ 4,
		/* address */ addr,
		/* instr count */ 1,
		/* result */ &insn
	);

	if(count != 1) {
		cs_err e = cs_errno(handle);

		if(e == CS_ERR_OK) {
			result = "undefined";
		}
		else {
			char msg[128];
			snprintf(
				msg, sizeof(msg), "ERROR: cs_disasm() returned %zu cs_err=%d (%s)\n", count, e, cs_err_to_string(e));
			err = msg;
			goto cleanup;
		}
	}
	else {
		result = insn->mnemonic;
		result += " ";
		result += insn->op_str;
	}

	rc = 0;
	cleanup:
	if(insn) cs_free(insn, count);
	return rc;
}

/*****************************************************************************/
/* instruction tokenizing */
/*****************************************************************************/

#define TT_GPR 1
#define TT_VREG 2
#define TT_FLAG 3
#define TT_CREG 4
#define TT_VSREG 5
#define TT_FREG 6
#define TT_NUM 7
#define TT_PUNC 8
#define TT_OPC 9

struct token {
	int type;
	uint32_t ival;
	string sval;
};

int tokenize(string src, vector<token>& result, string& err)
{
	int rc = -1, n=0;
	char *endptr;
	const char *inbuf = src.c_str();

	result.clear();

	/* grab opcode */
	while(isalnum(inbuf[n]))
		n++;
	result.push_back({TT_OPC, 0, string(inbuf, n)});
	inbuf += n;

	/* loop over the rest */
	while(inbuf[0]) {
		char c = inbuf[0];
		char d = inbuf[1];

		/* skip spaces */
		if(c == ' ') {
			inbuf += 1;
		}
		/* GPR's */
		else if(c=='r') {
			uint32_t value = strtoul(inbuf+1, &endptr, 10);
			result.push_back({TT_GPR, value, ""});
			inbuf = endptr;
		}
		/* vs registers */
		else if(c=='v' && inbuf[1]=='s') {
			uint32_t value = strtoul(inbuf+2, &endptr, 10);
			result.push_back({TT_VSREG, value, ""});
			inbuf = endptr;
		}
		/* v registers */
		else if(c=='v') {
			uint32_t value = strtoul(inbuf+1, &endptr, 10);
			result.push_back({TT_VREG, value, ""});
			inbuf = endptr;
		}
		/* f registers */
		else if(c=='f') {
			uint32_t value = strtoul(inbuf+1, &endptr, 10);
			result.push_back({TT_FREG, value, ""});
			inbuf = endptr;
		}
		/* cr registers */
		else if(c=='c' && inbuf[1]=='r') {
			uint32_t value = strtoul(inbuf+2, &endptr, 10);
			result.push_back({TT_CREG, value, ""});
			inbuf = endptr;
		}
		/* FLAGS: lt, gt, eq, so */
		else if((c=='l' && d=='t') || (c=='g' && d=='t') ||
		  (c=='e' && d=='q') || (c=='s' && d=='o')) {

			result.push_back({TT_FLAG, 0, string(inbuf, 2)});
			inbuf += 2;
		}
		/* hexadecimal immediates */
		else if((c=='0' && d=='x') || (c=='-' && d=='0' && inbuf[2]=='x')) {
			uint32_t value = strtoul(inbuf, &endptr, 16);
			result.push_back({TT_NUM, value, ""});
			inbuf = endptr;
		}
		/* decimal immediates */
		else if(isdigit(c) || (c=='-' && isdigit(d))) {
			uint32_t value = strtoul(inbuf, &endptr, 10);
			result.push_back({TT_NUM, value, ""});
			inbuf = endptr;
		}
		/* punctuation */
		else if(c=='(' || c==')' || c==',' || c=='.' || c=='*' || c=='+' || c=='-') {
			result.push_back({TT_PUNC, 0, string(inbuf,1)});
			inbuf += 1;
		}
		/* wtf? */
		else {
			err = "error at: " + string(inbuf);
			goto cleanup;
		}
	}

	rc = 0;
	cleanup:
	return rc;
}

const char* token_type_tostr(int tt)
{
	switch(tt) {
		case TT_GPR: return "GPR";
		case TT_VREG: return "VREG";
		case TT_FLAG: return "FLAG";
		case TT_CREG: return "CREG";
		case TT_VSREG: return "VSREG";
		case TT_FREG: return "FREG";
		case TT_NUM: return "NUM";
		case TT_PUNC: return "PUNC";
		case TT_OPC: return "OPC";
	}
	return "ERR_RESOLVING_TOKEN_TYPE";
}

string tokens_to_signature(vector<token>& tokens)
{
	string result;
	for(unsigned i=0; i<tokens.size(); ++i) {
		if(i)
			result += " ";

		token t = tokens[i];

		switch(t.type) {
			case TT_GPR:
			case TT_VREG:
			case TT_CREG:
			case TT_FREG:
			case TT_VSREG:
			case TT_NUM:
			case TT_FLAG:
				result += token_type_tostr(t.type);
				break;
			case TT_PUNC:
			case TT_OPC:
				result += t.sval;
				break;
		}
	}

	return result;
}

void tokens_print(vector<token>& tokens)
{
	for(unsigned i=0; i<tokens.size(); ++i) {
		token t = tokens[i];

		switch(t.type) {
			case TT_GPR:
			case TT_VREG:
			case TT_CREG:
			case TT_FREG:
			case TT_VSREG:
			case TT_NUM:
				printf("%s: %d\n", token_type_tostr(t.type), t.ival);
				break;
			case TT_PUNC:
			case TT_OPC:
				printf("%s: %s\n", token_type_tostr(t.type), t.sval.c_str());
				break;
		}
	}
}

/*****************************************************************************/
/* genetic */
/*****************************************************************************/

int count_bits(uint32_t x)
{
	x = x - ((x >> 1) & 0x55555555);
	x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
	return ((((x + (x >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24);
}

float hamming_similar(int a, int b)
{
	return (32-count_bits(a ^ b)) / 32.0f;
}

float fitness(vector<token> dst, vector<token> src) {
	size_t n = dst.size();

	/* same number of tokens */
	if(n != src.size())
		return 0;

	/* */
	float score = 0;
	float scorePerToken = 100.0f / (float)n;

	/* for each token... */
	for(size_t i=0; i<n; ++i) {
		/* same type */
		if(src[i].type != dst[i].type)
			return 0;

		switch(src[i].type) {
			case TT_VREG:
			case TT_FREG:
			case TT_GPR:
			case TT_VSREG:
			case TT_CREG:
			case TT_NUM:
				score += hamming_similar(src[i].ival, dst[i].ival) * scorePerToken;
				break;
			/* opcodes and flags must string match */
			case TT_OPC:
			case TT_FLAG:
			case TT_PUNC:
				if(src[i].sval == dst[i].sval)
					score += scorePerToken;
				break;
			default:
				printf("ERROR!!!!\n");
		}
	}

	return score;
}

float score(vector<token> baseline, uint32_t newcomer, uint32_t addr)
{
	vector<token> toks_child;
	string err;
	string src;

	if(disasm_capstone((uint8_t *)&newcomer, addr, src, err))
		return -1;

	/* compare mnemonics before doing more work */
	string mnem = baseline[0].sval;
	if(src.compare(0, mnem.size(), mnem) != 0) {
		return 0;
	}

	/* mnemonics are the same, tokenize now... */
	if(tokenize(src, toks_child, err)) {
		printf("ERROR: %s\n", err.c_str());
		return 0;
	}

	return fitness(baseline, toks_child);
}

struct match {
	uint32_t src_hi, src_lo; // source bit range
	uint32_t dst_hi, dst_lo; // destination bit range
};

// force certain regions of bits to match
uint32_t enforce_bit_match(uint32_t inp, unsigned bit, vector<match> matches)
{
	for(auto iter=matches.begin(); iter != matches.end(); ++iter) {
		struct match m = *iter;

		/* did we change a bit in the source region? */
		if(bit >= m.src_lo && bit <= m.src_hi) {
			/* compute masks */
			uint32_t a = 1<<m.src_hi;
			uint32_t b = 1<<m.src_lo;
			uint32_t src_mask = (a|(a-1)) ^ (b-1);

			a = 1<<m.dst_hi;
			b = 1<<m.dst_lo;
			uint32_t dst_mask = (a|(a-1)) ^ (b-1);

			/* mask and shift */
			inp = (inp & (~dst_mask));
			if(m.src_hi > m.dst_hi) {
				inp |= ((inp & src_mask) >> (m.src_hi - m.dst_hi));
			}
			else {
				inp |= ((inp & src_mask) << (m.dst_hi - m.src_hi));
			}
		}
	}

	return inp;
}

// for certain instructions with difficult inter-field dependencies
// inputs:
//     seed: the seed value that may need the special case
//  insword: instruction word
//      bit: last bit changed
uint32_t special_handling(uint32_t seed, uint32_t insword, int bit)
{
	switch(seed) {
		/* sldi is extended mnemonic for rldicr (when mask = 63-shift) and hops
			to it or other extended mnemonics easily */
		case 0x780007C6:
			/* if shift field changed, update mask */
			if(bit==1 || (bit>=11 && bit<=15)) {
				uint32_t shift = ((insword>>1)&1) | ((insword>>10)&0x3E);
				uint32_t mask = 63-shift;
				return (insword&0xFFFFF81F) | (mask<<5);
			}
			/* if mask field changed, update shift */
			if(bit>=5 && bit<=10) {
				uint32_t mask = (insword>>5)&0x3F;
				uint32_t shift = 63-mask;
				return (insword&0xFFFF07FD) | ((shift&0x3E)<<11) | ((shift&0x1)<<1);
			}
			/* neither field updated */
			return insword;

		case 0x54000FFE: // srwi
			if(bit>=6 && bit<=10) {
				uint32_t tmp = 32 - ((insword>>6) & 0x1F);
				return (insword&0xFFFF07FF) | (tmp<<11);
			}
			if(bit>=11 && bit<=15) {
				uint32_t tmp = 32 - ((insword>>11) & 0x1F);
				return (insword&0xFFFFF83F) | (tmp<<6);
			}
			/* neither field updated */
			return insword;

		case 0x5400003E: // slwi
			if(bit>=1 && bit<=5) {
				uint32_t tmp = 31 - ((insword>>1) & 0x1F);
				return (insword&0xFFFF07FF) | (tmp<<11);
			}
			if(bit>=11 && bit<=15) {
				uint32_t tmp = 31 - ((insword>>11) & 0x1F);
				return (insword&0xFFFFFFC1) | (tmp<<1);
			}
			/* neither field updated */
			return insword;

		/* crclr is when crxor has three 5-bit fields match! unlikely! */
		case 0x4c000182:
		{
			vector<struct match> matches = {{25,21,20,16},{25,21,15,11},
											{20,16,25,21},{20,16,15,11},
											{15,11,25,21},{15,11,20,16}};

			return enforce_bit_match(insword, bit, matches);
		}

		/* xxpermdi is 111100xxxxxxxxxxxxxxx0xx01010xxx */
		// xxspltd T,A,0 <=> xxpermdi T,A,A,0b00
		// xxspltd T,A,1 <=> xxpermdi T,A,A,0b11
		// xxmrghd T,A,B <=> xxpermdi T,A,B,0b00
		// xxmrgld T,A,B <=> xxpermdi T,A,B,0b11
		// xxswapd T,A   <=> xxpermdi T,A,A,0b10

		/* xxspltd is extended mnemonic for xxpermdi (when A==B): */
		case 0xF0000050:
		{
			vector<struct match> matches = {{20,16,15,11},{15,11,20,19},{9,9,8,8},{8,8,9,9},{2,2,1,1},{1,1,2,2}};
			return enforce_bit_match(insword, bit, matches);
		}

		/* xvmovdp is extended mnemonic for something
			111100 AAAAA BBBBB CCCCC 11110000CBA
			require BBBBBB == CCCCCC */
		case 0xF0000250: // xxswapd
		case 0xF0000780: // xvmovdp
		case 0xF0000680: // xvmovsp
		{
			vector<struct match> matches = {{20,16,15,11},{15,11,20,19},{2,2,1,1},{1,1,2,2}};
			return enforce_bit_match(insword, bit, matches);
		}

		/* mr is extended mnemonic for or (when RS==RB): */
		case 0x7C000378:
		{
			vector<struct match> matches = {{25,21,15,11},{15,11,25,21}};
			return enforce_bit_match(insword, bit, matches);
		}

        /* tdi/twi so easily falls into extended mnemonics */
		case 0x0800000A: // tdi
		case 0x0C000000: // twi
			if(bit>=21 && bit<=25) {
				uint32_t foo, bar;
				foo = bar = (insword & 0x03E00000) >> 21;
				switch(foo) {
					case 1: foo=3; break; // get off tdlgti/twlgti
					case 2: foo=3; break; // get off tdllti/twllti
					case 4: foo=5; break; // get off tdeqi/tweqi
					case 8: foo=9; break; // get off tdgti/twgti
					case 16: foo=17; break; // get off tdlti/twlti
					case 24: foo=25; break; // get off tdnei/twnei
					case 63: foo=0; break; // get off tdui/twui
				}
				if(foo != bar)
					insword = (insword & 0xFC1FFFFF) | (foo << 21);
			}
			/* no bit change in sensitive region */
			return insword;

		default:
			return insword;
	}
}

/*****************************************************************************/
/* string processing crap */
/*****************************************************************************/

int split_newlines(const string& chunk, vector<string> &lines)
{
	lines.clear();

	const char *p = chunk.c_str();

	unsigned i=0, left=0;
	while(1) {
		if(p[i]=='\x00') {
			if(left < i) {
				lines.push_back(string(p,left,i-left));
			}

			break;
		}

		if(p[i]=='\x0a') {
			if(left < i) {
				lines.push_back(string(p,left,i-left));
			}

			left = i = (i+1);
		}
		else if(i+1 < chunk.size() && p[i]=='\x0d' && p[i+1]=='\x0a') {
			if(left < i) {
				lines.push_back(string(p,left,i-left));
			}

			left = i = (i+2);
		}
		else {
			i += 1;
		}
	}

	return 0;
}

int trim_lines(vector<string> &lines)
{
	vector<string> filtered;

	for(size_t i=0; i<lines.size(); ++i) {
		const char *p = lines[i].c_str();
		int left = 0, right = (int)lines[i].size()-1;

		while(isspace(p[left]))
			left += 1;

		while(right>=0 && isspace(p[right]))
			right -= 1;

		if(right >= left)
			filtered.push_back(string(p, left, right-left+1));
	}

	lines = filtered;

	return 0;
}

// \S - one or more spaces
// \s - zero or more spaces
// \H - hex number (captures)
// \I - identifier (captures)
// \X - anything
bool fmt_match(string fmt, string str, vector<string>& result)
{
	bool match = false;
	size_t i=0, j=0;
	size_t nfmt=fmt.size(), nstr=str.size();

	result.clear();
	while(1) {
		string fcode = fmt.substr(i,2);

		if(fcode=="\\S") {
			if(!isspace(str[j]))
				goto cleanup;
			while(isspace(str[j]))
				j += 1;
			i += 2;
		}
		else
		if(fcode=="\\s") {
			while(isspace(str[j]))
				j += 1;
			i += 2;
		}
		else
		if(fcode=="\\I") {
			if(!isalpha(str[j]))
				goto cleanup;
			size_t start = j;
			j += 1;
			while(isalnum(str[j]) || str[j]=='_')
				j += 1;
			result.push_back(str.substr(start, j-start));
			i += 2;
		}
		else
		if(fcode=="\\H") {
			const char *raw = str.c_str();
			char *endptr;
			strtoul(raw + j, &endptr, 16);
			size_t len = endptr - (raw+j);
			if(!len) goto cleanup;
			result.push_back(str.substr(j, len));
			i += 2;
			j += len;
		}
		else
		if(fcode=="\\X") {
			i += 2;
			j = nstr;
		}
		else
		if(fmt[i] == str[j]) {
			i += 1;
			j += 1;
		}
		else {
			goto cleanup;
		}

		if(i==nfmt && j==nstr) break;
	}

	match = true;
	cleanup:
	return match;
}

/*****************************************************************************/
/* assembler calls */
/*****************************************************************************/

#define FAILURES_LIMIT 10000
int assemble_single(string src, uint32_t addr, uint8_t *result, string& err,
  int& failures)
{
	int rc = -1;

	/* decompose instruction into tokens */
	vector<token> toks_src;
	vector<token> toks_child;

	if(tokenize(src, toks_src, err)) {
		err = "invalid syntax";
		return -1;
	}

	/* form signature, look it up */
	string sig_src = tokens_to_signature(toks_src);

	MYLOG("src:%s has signature:%s\n", src.c_str(), sig_src.c_str());

	if(lookup.find(sig_src) == lookup.end()) {
		err = "invalid syntax";
		return -1;
	}

	auto info = lookup[sig_src];
	uint32_t vary_mask = info.mask;

	/* for relative branches, shift the target address to 0 */
	if(toks_src[0].sval[0]=='b' && toks_src[0].sval.back() != 'a' &&
	  toks_src.back().type == TT_NUM) {
		toks_src.back().ival -= addr;
		addr = 0;
	}

	/* start with the parent */
	uint32_t parent = info.seed;
	float init_score, top_score;
	init_score = top_score = score(toks_src, parent, addr);

	/* cache the xor masks */
	int n_flips = 0;
	int flipper_idx[32];
	uint32_t flipper[32];
	for(int i=0; i<32; ++i) {
		if(vary_mask & (1 << i)) {
			flipper_idx[n_flips] = i;
			flipper[n_flips++] = 1<<i;
		}
	}

	failures = 0;
	int failstreak = 0;

	/* vary the parent */
	int b1i=0;
	while(1) {
		/* winner? */
		if(top_score > 99.99) {
			MYLOG("%08X wins!\n", parent);
			memcpy(result, &parent, 4);
			break;
		}

		bool overtake = false;

		for(; b1i<n_flips; b1i = (b1i+1) % n_flips) {
			uint32_t child = parent ^ flipper[b1i];
			child = special_handling(info.seed, child, flipper_idx[b1i]);

			float s = score(toks_src, child, addr);
			if(s > top_score) {
				parent = child;
				top_score = s;
				overtake = true;
				break;
			}

			failures++;
			if(failures > FAILURES_LIMIT) {
				MYLOG("failure limit reached, not assembling!\n");
				err = "cannot assemble, valid operands?";
				goto cleanup;
			}

			failstreak++;
			if(failstreak >= n_flips) {
				/* generate a new parent that's at least as good as the seed */
				while(1) {
					parent = info.seed;
					for(int i=0; i<n_flips; ++i) {
						if(rand()%2) {
							parent ^= flipper[i];
							parent = special_handling(info.seed, parent, flipper_idx[i]);
						}
					}

					top_score = score(toks_src, parent, addr);

					if(top_score >= init_score) {
						MYLOG("perturbing the parent to: %08X (score:%f) (vs:%f)\n", parent, top_score, init_score);
						break;
					}
					else {
						string tmp;
						disasm_capstone((uint8_t *)&parent, addr, tmp, err);
						MYLOG("%08X: %s perturb fail %f\n", parent, tmp.c_str(), top_score);
						failures++;
					}

					if(failures > FAILURES_LIMIT) {
						err = "cannot assemble, valid operands?";
						MYLOG("failure limit reached, not assembling!\n");
						goto cleanup;
					}
				}
				failstreak = 0;
				break;
			}
		}

		if(overtake) {
			failstreak = 0;
			if(0) {
				string tmp;
				disasm_capstone((uint8_t *)&parent, addr, tmp, err);
				MYLOG("%08X: %s overtakes with 1-bit flip (%d) after %d failures, score %f\n", parent, tmp.c_str(), b1i, failures, top_score);
			}
		}
	}

	rc = 0;
	cleanup:
	return rc;
}

int assemble_multiline(const string& code, vector<uint8_t>& result, string& err)
{
	int rc = -1;
	vector<string> lines, fields;

	split_newlines(code, lines);
	trim_lines(lines);

	bool lilEndian = false;

	uint64_t vaddr = 0;
	map<string,uint64_t> symbols;

	/* FIRST PASS */
	for(unsigned i=0; i<lines.size(); ++i) {
		MYLOG("line %d: -%s-\n", i, lines[i].c_str());

		/* .org directive */
		if(fmt_match(".org\\S\\H", lines[i], fields)) {
			vaddr = strtol(fields[0].c_str(), 0, 16);
			if(vaddr & 0x3) {
				err = "ERROR: .org address is not 4-byte aligned";
				goto cleanup;
			}
			MYLOG("PASS1, set vaddr to: %" PRIx64 "\n", vaddr);
		}
		/* .endian directive */
		else
		if(fmt_match(".endian\\S\\I", lines[i], fields)) {
			if(fields[0] == "big")
				lilEndian = false;
			else
			if(fields[0] == "little")
				lilEndian = true;
			else {
				err = "invalid argument to .endian directive (expected big or little)";
			}
		}
		/* .equ directive */
		else
		if(fmt_match(".equ\\S\\I\\s,\\s\\H", lines[i], fields)) {
			uint32_t value = strtol(fields[1].c_str(), 0, 16);
			symbols[fields[0]] = value;
			MYLOG("PASS1, set symbol %s: %08X\n", fields[0].c_str(), value);
		}
		/* labels */
		else
		if(fmt_match("\\I:", lines[i], fields)) {
			symbols[fields[0]] = vaddr;
			MYLOG("PASS1, set label %s: %" PRIx64 "\n", fields[0].c_str(), vaddr);
		}
	}

	/* SECOND PASS */
	vaddr = 0;
	for(unsigned i=0; i<lines.size(); ++i) {
		vector<string> fields;

		MYLOG("line %d: -%s-\n", i, lines[i].c_str());

		/* .org directive */
		if(fmt_match(".org\\S\\H", lines[i], fields)) {
			vaddr = strtol(fields[0].c_str(), 0, 16);
			MYLOG("set vaddr to: %" PRIx64 "\n", vaddr);
		}
		/* .endian directive */
		else
		if(fmt_match(".endian\\S\\I", lines[i], fields)) {
			if(fields[0] == "big")
				lilEndian = false;
			else
			if(fields[0] == "little")
				lilEndian = true;
			else {
				err = "invalid argument to .endian directive (expected big or little)";
			}
		}
		/* .equ directive */
		else
		if(fmt_match(".equ\\S\\I\\s,\\s\\H", lines[i], fields)) {

		}
		/* labels */
		else
		if(fmt_match("\\I:", lines[i], fields)) {

		}
		/* comments */
		else
		if(fmt_match("\\s//\\X", lines[i], fields)) {

		}
		/* instructions */
		else {
			uint8_t encoding[4];

			/* replace the last word (if it exists) with a label/symbol */
			string line = lines[i], token;
			int left = (int)line.size()-1;
			while(left>=0 && isalnum(line[left]))
				left--;
			left += 1;
			token = line.substr(left, line.size()-left);
			if(fmt_match("\\I", token, fields)) {
				if(symbols.find(token) != symbols.end()) {
					char buf[16];
					int64_t value = symbols[token];
					if(value < 0) {
						snprintf(buf, sizeof(buf), "-0x%08X", (unsigned)(-1 * value));
					}
					else {
						snprintf(buf, sizeof(buf), "0x%08X", (unsigned)value);
					}
					line.replace(left, line.size()-left, buf);
				}
				else {
					MYLOG("not found in symbol table\n");
				}
			}
			else {
				MYLOG("not an identifier\n");
			}

			/* now actually assemble */
			MYLOG("assembling: %s at address %" PRIx64 "\n", line.c_str(), vaddr);
			int failures;
			if(assemble_single(line, (uint32_t)vaddr, encoding, err, failures)) {
				MYLOG("assemble_single failed, err contains: %s\n", err.c_str());
				goto cleanup;
			}

			/* return results */
			if(lilEndian == true) {
				for(int i=0; i<4; ++i) {
					MYLOG("LILEND returning byte %02X\n", encoding[i]);
					result.push_back(encoding[i]);
				}
			}
			else {
				for(int i=3; i>=0; --i) {
					MYLOG("BIGEND returning byte %02X\n", encoding[i]);
					result.push_back(encoding[i]);
				}
			}

			/* next! */
			vaddr += 4;
		}
	}

	rc = 0;
	cleanup:
	return rc;
}


