#include <stdio.h>
#include <string.h>

#include "decode.h"
#include "priv.h"

// Documentation:
//  * [ProgrammingEnvironments32]: "Programming Environments Manual for 32-bit
//    Implementations of the PowerPC^TM Architecture" by Freescale/NXP
//

size_t GetInstructionLength(const uint8_t* data, size_t data_length, uint32_t decodeFlags)
{
	(void)data;
	(void)data_length;
	(void)decodeFlags;

	return 4;
}

static InstructionId DecodeAltivec0x04(uint32_t word32, uint32_t decodeFlags)
{
	uint32_t subop = word32 & 0x3f;

	uint32_t a = GetA(word32);
	uint32_t b = GetB(word32);
	uint32_t d = GetD(word32);

	switch (subop)
	{
		case 0x20:
			return PPC_ID_AV_VMHADDSHS;

		case 0x21:
			return PPC_ID_AV_VMHRADDSHS;

		case 0x22:
			return PPC_ID_AV_VMLADDUHM;

		case 0x24:
			return PPC_ID_AV_VMSUMUBM;

		case 0x25:
			return PPC_ID_AV_VMSUMMBM;

		case 0x26:
			return PPC_ID_AV_VMSUMUHM;

		case 0x27:
			return PPC_ID_AV_VMSUMUHS;

		case 0x28:
			return PPC_ID_AV_VMSUMSHM;

		case 0x29:
			return PPC_ID_AV_VMSUMSHS;

		case 0x2a:
			return PPC_ID_AV_VSEL;

		case 0x2b:
			return PPC_ID_AV_VPERM;

		case 0x2c:
			if ((word32 & 0x400) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VSLDOI;

		case 0x2d:
			return PPC_ID_AV_VPERMXOR;

		case 0x2e:
			return PPC_ID_AV_VMADDFP;

		case 0x2f:
			return PPC_ID_AV_VNMSUBFP;

		case 0x30:
			return PPC_ID_AV_MADDHD;

		case 0x31:
			return PPC_ID_AV_MADDHDU;

		case 0x33:
			return PPC_ID_AV_MADDLD;

		case 0x3b:
			return PPC_ID_AV_VPERMR;

		case 0x3c:
			return PPC_ID_AV_VADDEUQM;

		case 0x3d:
			return PPC_ID_AV_VADDECUQ;

		case 0x3e:
			return PPC_ID_AV_VSUBEUQM;

		case 0x3f:
			return PPC_ID_AV_VSUBECUQ;

		default:
			;
	}

	subop = word32 & 0x7ff;
	switch (subop)
	{
		case 0x000:
			return PPC_ID_AV_VADDUBM;

		case 0x001:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VMUL10CUQ;

		case 0x002:
			return PPC_ID_AV_VMAXUB;

		case 0x004:
			return PPC_ID_AV_VRLB;


		case 0x006:
		case 0x406:
			return PPC_ID_AV_VCMPEQUBx;

		case 0x007:
		case 0x407:
			return PPC_ID_AV_VCMPNEBx;

		case 0x008:
			return PPC_ID_AV_VMULOUB;

		case 0x00a:
			return PPC_ID_AV_VADDFP;

		case 0x00c:
			return PPC_ID_AV_VMRGHB;

		case 0x00e:
			return PPC_ID_AV_VPKUHUM;

		case 0x040:
			return PPC_ID_AV_VADDUHM;

		case 0x041:
			return PPC_ID_AV_VMUL10ECUQ;

		case 0x042:
			return PPC_ID_AV_VMAXUH;

		case 0x044:
			return PPC_ID_AV_VRLH;


		case 0x046:
		case 0x446:
			return PPC_ID_AV_VCMPEQUHx;

		case 0x047:
		case 0x447:
			return PPC_ID_AV_VCMPNEHx;

		case 0x048:
			return PPC_ID_AV_VMULOUH;

		case 0x04a:
			return PPC_ID_AV_VSUBFP;

		case 0x04c:
			return PPC_ID_AV_VMRGHH;

		case 0x04e:
			return PPC_ID_AV_VPKUWUM;

		case 0x080:
			return PPC_ID_AV_VADDUWM;

		case 0x082:
			return PPC_ID_AV_VMAXUW;

		case 0x084:
			return PPC_ID_AV_VRLW;

		case 0x085:
			return PPC_ID_AV_VRLWMI;

		case 0x086:
		case 0x486:
			return PPC_ID_AV_VCMPEQUWx;

		case 0x087:
		case 0x487:
			return PPC_ID_AV_VCMPNEWx;

		case 0x88:
			return PPC_ID_AV_VMULOUW;

		case 0x89:
			return PPC_ID_AV_VMULUWM;

		case 0x08c:
			return PPC_ID_AV_VMRGHW;

		case 0x08e:
			return PPC_ID_AV_VPKUHUS;

		case 0x0c0:
			return PPC_ID_AV_VADDUDM;

		case 0x0c2:
			return PPC_ID_AV_VMAXUD;

		case 0x0c4:
			return PPC_ID_AV_VRLD;

		case 0x0c5:
			return PPC_ID_AV_VRLDMI;

		case 0x0c6:
		case 0x4c6:
			return PPC_ID_AV_VCMPEQFPx;

		case 0x0c7:
		case 0x4c7:
			return PPC_ID_AV_VCMPEQUDx;

		case 0x0ce:
			return PPC_ID_AV_VPKUWUS;

		case 0x100:
			return PPC_ID_AV_VADDUQM;

		case 0x102:
			return PPC_ID_AV_VMAXSB;

		case 0x104:
			return PPC_ID_AV_VSLB;

		case 0x107:
		case 0x507:
			return PPC_ID_AV_VCMPNEZBx;

		case 0x108:
			return PPC_ID_AV_VMULOSB;

		case 0x10a:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VREFP;

		case 0x10c:
			return PPC_ID_AV_VMRGLB;

		case 0x10e:
			return PPC_ID_AV_VPKSHUS;

		case 0x140:
			return PPC_ID_AV_VADDCUQ;

		case 0x142:
			return PPC_ID_AV_VMAXSH;

		case 0x144:
			return PPC_ID_AV_VSLH;

		case 0x147:
		case 0x547:
			return PPC_ID_AV_VCMPNEZHx;

		case 0x148:
			return PPC_ID_AV_VMULOSH;

		case 0x14a:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VRSQRTEFP;

		case 0x14c:
			return PPC_ID_AV_VMRGLH;

		case 0x14e:
			return PPC_ID_AV_VPKSWUS;

		case 0x180:
			return PPC_ID_AV_VADDCUW;

		case 0x182:
			return PPC_ID_AV_VMAXSW;

		case 0x184:
			return PPC_ID_AV_VSLW;

		case 0x185:
			return PPC_ID_AV_VRLWNM;

		case 0x187:
		case 0x587:
			return PPC_ID_AV_VCMPNEZWx;

		case 0x188:
			return PPC_ID_AV_VMULOSW;

		case 0x18a:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VEXPTEFP;

		case 0x18c:
			return PPC_ID_AV_VMRGLW;

		case 0x18e:
			return PPC_ID_AV_VPKSHSS;

		case 0x1c2:
			return PPC_ID_AV_VMAXSD;

		case 0x1c4:
			return PPC_ID_AV_VSL;

		case 0x1c5:
			return PPC_ID_AV_VRLDNM;

		case 0x1c6:
		case 0x5c6:
			return PPC_ID_AV_VCMPGEFPx;

		case 0x1ca:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VLOGEFP;

		case 0x1ce:
			return PPC_ID_AV_VPKSWSS;

		case 0x200:
			return PPC_ID_AV_VADDUBS;

		case 0x201:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VMUL10UQ;

		case 0x202:
			return PPC_ID_AV_VMINUB;

		case 0x204:
			return PPC_ID_AV_VSRB;


		case 0x206:
		case 0x606:
			return PPC_ID_AV_VCMPGTUBx;

		case 0x208:
			return PPC_ID_AV_VMULEUB;

		case 0x20a:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VRFIN;

		case 0x20c:
			return PPC_ID_AV_VSPLTB;

		case 0x20d:
			if ((word32 & 0x00100000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VEXTRACTUB;

		case 0x20e:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VUPKHSB;

		case 0x240:
			return PPC_ID_AV_VADDUHS;

		case 0x241:
			return PPC_ID_AV_VMUL10EUQ;

		case 0x242:
			return PPC_ID_AV_VMINUH;

		case 0x244:
			return PPC_ID_AV_VSRH;

		case 0x246:
		case 0x646:
			return PPC_ID_AV_VCMPGTUHx;

		case 0x248:
			return PPC_ID_AV_VMULEUH;

		case 0x24a:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VRFIZ;

		case 0x24c:
			return PPC_ID_AV_VSPLTH;

		case 0x24d:
			if ((word32 & 0x00100000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VEXTRACTUH;

		case 0x24e:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VUPKHSH;

		case 0x280:
			return PPC_ID_AV_VADDUWS;

		case 0x282:
			return PPC_ID_AV_VMINUW;

		case 0x284:
			return PPC_ID_AV_VSRW;

		case 0x286:
		case 0x686:
			return PPC_ID_AV_VCMPGTUWx;

		case 0x288:
			return PPC_ID_AV_VMULEUW;

		case 0x28a:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VRFIP;

		case 0x28c:
			return PPC_ID_AV_VSPLTW;

		case 0x28d:
			if ((word32 & 0x00100000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VEXTRACTUW;

		case 0x28e:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VUPKLSB;

		case 0x2c2:
			return PPC_ID_AV_VMINUD;

		case 0x2c4:
			return PPC_ID_AV_VSR;

		case 0x2c6:
		case 0x6c6:
			return PPC_ID_AV_VCMPGTFPx;

		case 0x2c7:
		case 0x6c7:
			return PPC_ID_AV_VCMPGTUDx;

		case 0x2ca:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VRFIM;

		case 0x2cd:
			if ((word32 & 0x00100000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VEXTRACTD;

		case 0x2ce:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VUPKLSH;

		case 0x300:
			return PPC_ID_AV_VADDSBS;

		case 0x302:
			return PPC_ID_AV_VMINSB;

		case 0x304:
			return PPC_ID_AV_VSRAB;

		case 0x306:
		case 0x706:
			return PPC_ID_AV_VCMPGTSBx;

		case 0x308:
			return PPC_ID_AV_VMULESB;

		case 0x30a:
			return PPC_ID_AV_VCFUX;

		case 0x30c:
			if ((b) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VSPLTISB;

		case 0x30d:
			if ((word32 & 0x00100000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VINSERTB;

		case 0x30e:
			return PPC_ID_AV_VPKPX;

		case 0x340:
			return PPC_ID_AV_VADDSHS;

		case 0x341:
			return PPC_ID_AV_BCDCPSGN;

		case 0x342:
			return PPC_ID_AV_VMINSH;

		case 0x344:
			return PPC_ID_AV_VSRAH;

		case 0x346:
		case 0x746:
			return PPC_ID_AV_VCMPGTSHx;

		case 0x348:
			return PPC_ID_AV_VMULESH;

		case 0x34a:
			return PPC_ID_AV_VCFSX;

		case 0x34c:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VSPLTISH;

		case 0x34d:
			if ((word32 & 0x00100000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VINSERTH;

		case 0x34e:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VUPKHPX;

		case 0x380:
			return PPC_ID_AV_VADDSWS;

		case 0x382:
			return PPC_ID_AV_VMINSW;

		case 0x384:
			return PPC_ID_AV_VSRAW;

		case 0x386:
		case 0x786:
			return PPC_ID_AV_VCMPGTSWx;

		case 0x388:
			return PPC_ID_AV_VMULESW;

		case 0x38a:
			return PPC_ID_AV_VCTUXS;

		case 0x38c:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VSPLTISW;

		case 0x38d:
			if ((word32 & 0x00100000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VINSERTW;

		case 0x3c2:
			return PPC_ID_AV_VMINSD;

		case 0x3c4:
			return PPC_ID_AV_VSRAD;

		case 0x3c6:
		case 0x7c6:
			return PPC_ID_AV_VCMPBFPx;

		case 0x3c7:
		case 0x7c7:
			return PPC_ID_AV_VCMPGTSDx;

		case 0x3ca:
			return PPC_ID_AV_VCTSXS;

		case 0x3cd:
			if ((word32 & 0x00100000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VINSERTD;

		case 0x3ce:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VUPKLPX;

		case 0x400:
			return PPC_ID_AV_VSUBUBM;

		case 0x401:
		case 0x601:
			return PPC_ID_AV_BCDADD;

		case 0x402:
			return PPC_ID_AV_VAVGUB;

		case 0x403:
			return PPC_ID_AV_VABSDUB;

		case 0x404:
			return PPC_ID_AV_VAND;

		case 0x408:
			return PPC_ID_AV_VPMSUMB;

		case 0x40a:
			return PPC_ID_AV_VMAXFP;

		case 0x40c:
			return PPC_ID_AV_VSLO;

		case 0x440:
			return PPC_ID_AV_VSUBUHM;

		case 0x441:
		case 0x641:
			return PPC_ID_AV_BCDSUB;

		case 0x442:
			return PPC_ID_AV_VAVGUH;

		case 0x443:
			return PPC_ID_AV_VABSDUH;

		case 0x444:
			return PPC_ID_AV_VANDC;

		case 0x448:
			return PPC_ID_AV_VPMSUMH;

		case 0x44a:
			return PPC_ID_AV_VMINFP;

		case 0x44c:
			return PPC_ID_AV_VSRO;

		case 0x44e:
			return PPC_ID_AV_VPKUDUM;

		case 0x480:
			return PPC_ID_AV_VSUBUWM;

		case 0x481:
			return PPC_ID_AV_BCDUS;

		case 0x482:
			return PPC_ID_AV_VAVGUW;

		case 0x483:
			return PPC_ID_AV_VABSDUW;

		case 0x484:
			if (a == b)
				return PPC_ID_AV_VMR;
			else
				return PPC_ID_AV_VOR;

		case 0x488:
			return PPC_ID_AV_VPMSUMW;

		case 0x4c0:
			return PPC_ID_AV_VSUBUDM;

		case 0x4c1:
		case 0x6c1:
			return PPC_ID_AV_BCDS;

		case 0x4c4:
			return PPC_ID_AV_VXOR;

		case 0x4c8:
			return PPC_ID_AV_VPMSUMD;

		case 0x4ce:
			return PPC_ID_AV_VPKUDUS;

		case 0x500:
			return PPC_ID_AV_VSUBUQM;

		case 0x501:
		case 0x701:
			return PPC_ID_AV_BCDTRUNC;

		case 0x502:
			return PPC_ID_AV_VAVGSB;

		case 0x504:
			if (a == b)
				return PPC_ID_AV_VNOT;
			else 
				return PPC_ID_AV_VNOR;

		case 0x508:
			return PPC_ID_AV_VCIPHER;

		case 0x509:
			return PPC_ID_AV_VCIPHERLAST;

		case 0x50c:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VGBBD;

		case 0x540:
			return PPC_ID_AV_VSUBCUQ;

		case 0x541:
			return PPC_ID_AV_BCDUTRUNC;

		case 0x542:
			return PPC_ID_AV_VAVGSH;

		case 0x544:
			return PPC_ID_AV_VORC;

		case 0x548:
			return PPC_ID_AV_VNCIPHER;

		case 0x549:
			return PPC_ID_AV_VNCIPHERLAST;

		case 0x54c:
			return PPC_ID_AV_VBPERMQ;

		case 0x54e:
			return PPC_ID_AV_VPKSDUS;

		case 0x580:
			return PPC_ID_AV_VSUBCUW;

		case 0x581:
		case 0x781:
			switch (a)
			{
			case 0x00:
				if (subop == 0x581)
					return PPC_ID_AV_BCDCTSQ;
				else
					return PPC_ID_INVALID;

			case 0x02:
				return PPC_ID_AV_BCDCFSQ;

			case 0x04:
				return PPC_ID_AV_BCDCTZ;

			case 0x05:
				if (subop == 0x581)
					return PPC_ID_AV_BCDCTN;
				else
					return PPC_ID_INVALID;

			case 0x06:
				return PPC_ID_AV_BCDCFZ;

			case 0x07:
				return PPC_ID_AV_BCDCFN;

			case 0x1f:
				return PPC_ID_AV_BCDSETSGN;

			default:
				return PPC_ID_INVALID;
			}

		case 0x582:
			return PPC_ID_AV_VAVGSW;

		case 0x584:
			return PPC_ID_AV_VNAND;

		case 0x5c1:
		case 0x7c1:
			return PPC_ID_AV_BCDSR;

		case 0x5c4:
			return PPC_ID_AV_VSLD;

		case 0x5c8:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VSBOX;

		case 0x5cc:
			return PPC_ID_AV_VBPERMD;

		case 0x5ce:
			return PPC_ID_AV_VPKSDSS;

		case 0x600:
			return PPC_ID_AV_VSUBUBS;

		case 0x602:
			switch (a)
			{
			case 0x00:
				return PPC_ID_AV_VCLZLSBB;

			case 0x01:
				return PPC_ID_AV_VCTZLSBB;

			case 0x06:
				return PPC_ID_AV_VNEGW;

			case 0x07:
				return PPC_ID_AV_VNEGD;

			case 0x08:
				return PPC_ID_AV_VPRTYBW;

			case 0x09:
				return PPC_ID_AV_VPRTYBD;

			case 0x0a:
				return PPC_ID_AV_VPRTYBQ;

			case 0x10:
				return PPC_ID_AV_VEXTSB2W;

			case 0x11:
				return PPC_ID_AV_VEXTSH2W;

			case 0x18:
				return PPC_ID_AV_VEXTSB2D;

			case 0x19:
				return PPC_ID_AV_VEXTSH2D;

			case 0x1a:
				return PPC_ID_AV_VEXTSW2D;

			case 0x1c:
				return PPC_ID_AV_VCTZB;

			case 0x1d:
				return PPC_ID_AV_VCTZH;

			case 0x1e:
				return PPC_ID_AV_VCTZW;

			case 0x1f:
				return PPC_ID_AV_VCTZD;

			default:
				return PPC_ID_INVALID;
			}

		case 0x604:
			if ((a != 0) || (b != 0))
				return PPC_ID_INVALID;

			return PPC_ID_AV_MFVSCR;

		case 0x60d:
			return PPC_ID_AV_VEXTUBLX;

		case 0x608:
			return PPC_ID_AV_VSUM4UBS;

		case 0x640:
			return PPC_ID_AV_VSUBUHS;

		case 0x644:
			if ((d != 0) || (a != 0))
				return PPC_ID_INVALID;

			return PPC_ID_AV_MTVSCR;

		case 0x648:
			return PPC_ID_AV_VSUM4SHS;

		case 0x64d:
			return PPC_ID_AV_VEXTUHLX;

		case 0x64e:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VUPKHSW;

		case 0x680:
			return PPC_ID_AV_VSUBUWS;

		case 0x682:
			return PPC_ID_AV_VSHASIGMAW;

		case 0x684:
			return PPC_ID_AV_VEQV;

		case 0x688:
			return PPC_ID_AV_VSUM2SWS;

		case 0x68c:
			return PPC_ID_AV_VMRGOW;

		case 0x68d:
			return PPC_ID_AV_VEXTUWLX;

		case 0x6c2:
			return PPC_ID_AV_VSHASIGMAD;

		case 0x6c4:
			return PPC_ID_AV_VSRD;

		case 0x6ce:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VUPKLSW;

		case 0x700:
			return PPC_ID_AV_VSUBSBS;

		case 0x702:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VCLZB;

		case 0x703:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VPOPCNTB;

		case 0x704:
			return PPC_ID_AV_VSRV;

		case 0x708:
			return PPC_ID_AV_VSUM4SBS;

		case 0x70d:
			return PPC_ID_AV_VEXTUBRX;

		case 0x740:
			return PPC_ID_AV_VSUBSHS;

		case 0x742:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VCLZH;

		case 0x743:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VPOPCNTH;

		case 0x744:
			return PPC_ID_AV_VSLV;

		case 0x74d:
			return PPC_ID_AV_VEXTUHRX;

		case 0x780:
			return PPC_ID_AV_VSUBSWS;

		case 0x782:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VCLZW;

		case 0x783:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VPOPCNTW;

		case 0x788:
			return PPC_ID_AV_VSUMSWS;

		case 0x78c:
			return PPC_ID_AV_VMRGEW;

		case 0x78d:
			return PPC_ID_AV_VEXTUWRX;

		case 0x7c2:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VCLZD;

		case 0x7c3:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VPOPCNTD;

		default:
			return PPC_ID_INVALID;
	}
}

static InstructionId DecodeSpe0x04(uint32_t word32, uint32_t decodeFlags)
{
	uint32_t a = GetA(word32);
	uint32_t b = GetB(word32);
	uint32_t subop = word32 & 0x7ff;

	switch (subop)
	{
		case 512:
			return PPC_ID_SPE_EVADDW;

		case 514:
			return PPC_ID_SPE_EVADDIW;

		case 516:
			return PPC_ID_SPE_EVSUBFW;

		case 518:
			return PPC_ID_SPE_EVSUBIFW;

		case 520:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVABS;

		case 521:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVNEG;

		case 522:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVEXTSB;

		case 523:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVEXTSH;

		case 524:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVRNDW;

		case 525:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVCNTLZW;

		case 526:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVCNTLSW;

		case 527:
			return PPC_ID_SPE_BRINC;

		case 529:
			return PPC_ID_SPE_EVAND;

		case 530:
			return PPC_ID_SPE_EVANDC;

		case 534:
			return PPC_ID_SPE_EVXOR;

		case 535:
			if (a == b)
				return PPC_ID_SPE_EVMR;
			else
				return PPC_ID_SPE_EVOR;

		case 536:
			if (a == b)
				return PPC_ID_SPE_EVNOT;
			else
				return PPC_ID_SPE_EVNOR;

		case 537:
			return PPC_ID_SPE_EVEQV;

		case 539:
			return PPC_ID_SPE_EVORC;

		case 542:
			return PPC_ID_SPE_EVNAND;

		case 544:
			return PPC_ID_SPE_EVSRWU;

		case 545:
			return PPC_ID_SPE_EVSRWS;

		case 546:
			return PPC_ID_SPE_EVSRWIU;

		case 547:
			return PPC_ID_SPE_EVSRWIS;

		case 548:
			return PPC_ID_SPE_EVSLW;

		case 550:
			return PPC_ID_SPE_EVSLWI;

		case 552:
			return PPC_ID_SPE_EVRLW;

		case 553:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVSPLATI;

		case 554:
			return PPC_ID_SPE_EVRLWI;

		case 555:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVSPLATFI;

		case 556:
			return PPC_ID_SPE_EVMERGEHI;

		case 557:
			return PPC_ID_SPE_EVMERGELO;

		case 558:
			return PPC_ID_SPE_EVMERGEHILO;

		case 559:
			return PPC_ID_SPE_EVMERGELOHI;

		case 560:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVCMPGTU;

		case 561:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVCMPGTS;

		case 562:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVCMPLTU;

		case 563:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVCMPLTS;

		case 564:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVCMPEQ;

		case 632:
			return PPC_ID_SPE_EVSEL;

		case 633:
			return PPC_ID_SPE_EVSEL;

		case 634:
			return PPC_ID_SPE_EVSEL;

		case 635:
			return PPC_ID_SPE_EVSEL;

		case 636:
			return PPC_ID_SPE_EVSEL;

		case 637:
			return PPC_ID_SPE_EVSEL;

		case 638:
			return PPC_ID_SPE_EVSEL;

		case 639:
			return PPC_ID_SPE_EVSEL;

		case 640:
			return PPC_ID_SPE_EVFSADD;

		case 641:
			return PPC_ID_SPE_EVFSSUB;

		case 644:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSABS;

		case 645:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSNABS;

		case 646:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSNEG;

		case 648:
			return PPC_ID_SPE_EVFSMUL;

		case 649:
			return PPC_ID_SPE_EVFSDIV;

		case 652:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSCMPGT;

		case 653:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSCMPLT;

		case 654:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSCMPEQ;

		case 656:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSCFUI;

		case 657:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSCFSI;

		case 658:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSCFUF;

		case 659:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSCFSF;

		case 660:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSCTUI;

		case 661:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSCTSI;

		case 662:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSCTUF;

		case 663:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSCTSF;

		case 664:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSCTUIZ;

		case 666:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSCTSIZ;

		case 668:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSTSTGT;

		case 669:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSTSTLT;

		case 670:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSTSTEQ;

		case 704:
			return PPC_ID_SPE_EFSADD;

		case 705:
			return PPC_ID_SPE_EFSSUB;

		case 708:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFSABS;

		case 709:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFSNABS;

		case 710:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFSNEG;

		case 712:
			return PPC_ID_SPE_EFSMUL;

		case 713:
			return PPC_ID_SPE_EFSDIV;

		case 716:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFSCMPGT;

		case 717:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFSCMPLT;

		case 718:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFSCMPEQ;

		case 719:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFSCFD;

		case 720:
			return PPC_ID_SPE_EFSCFUI;

		case 721:
			return PPC_ID_SPE_EFSCFSI;

		case 722:
			return PPC_ID_SPE_EFSCFUF;

		case 723:
			return PPC_ID_SPE_EFSCFSF;

		case 724:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFSCTUI;

		case 725:
			return PPC_ID_SPE_EFSCTSI;

		case 726:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFSCTUF;

		case 727:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFSCTSF;

		case 728:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFSCTUIZ;

		case 730:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFSCTSIZ;

		case 732:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFSTSTGT;

		case 733:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFSTSTLT;

		case 734:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFSTSTEQ;

		case 736:
			return PPC_ID_SPE_EFDADD;

		case 737:
			return PPC_ID_SPE_EFDSUB;

		case 738:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDCFUID;

		case 739:
			return PPC_ID_SPE_EFDCFSID;

		case 740:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDABS;

		case 741:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDNABS;

		case 742:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDNEG;

		case 744:
			return PPC_ID_SPE_EFDMUL;

		case 745:
			return PPC_ID_SPE_EFDDIV;

		case 746:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDCTUIDZ;

		case 747:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDCTSIDZ;

		case 748:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDCMPGT;

		case 749:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDCMPLT;

		case 750:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDCMPEQ;

		case 751:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDCFS;

		case 752:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDCFUI;

		case 753:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDCFSI;

		case 754:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDCFUF;

		case 755:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDCFSF;

		case 756:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDCTUI;

		case 757:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDCTSI;

		case 758:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDCTUF;

		case 759:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDCTSF;

		case 760:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDCTUIZ;

		case 762:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDCTSIZ;

		case 764:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDTSTGT;

		case 765:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDTSTLT;

		case 766:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDTSTEQ;

		case 768:
			return PPC_ID_SPE_EVLDDX;

		case 769:
			return PPC_ID_SPE_EVLDD;

		case 770:
			return PPC_ID_SPE_EVLDWX;

		case 771:
			return PPC_ID_SPE_EVLDW;

		case 772:
			return PPC_ID_SPE_EVLDHX;

		case 773:
			return PPC_ID_SPE_EVLDH;

		case 776:
			return PPC_ID_SPE_EVLHHESPLATX;

		case 777:
			return PPC_ID_SPE_EVLHHESPLAT;

		case 780:
			return PPC_ID_SPE_EVLHHOUSPLATX;

		case 781:
			return PPC_ID_SPE_EVLHHOUSPLAT;

		case 782:
			return PPC_ID_SPE_EVLHHOSSPLATX;

		case 783:
			return PPC_ID_SPE_EVLHHOSSPLAT;

		case 784:
			return PPC_ID_SPE_EVLWHEX;

		case 785:
			return PPC_ID_SPE_EVLWHE;

		case 788:
			return PPC_ID_SPE_EVLWHOUX;

		case 789:
			return PPC_ID_SPE_EVLWHOU;

		case 790:
			return PPC_ID_SPE_EVLWHOSX;

		case 791:
			return PPC_ID_SPE_EVLWHOS;

		case 792:
			return PPC_ID_SPE_EVLWWSPLATX;

		case 793:
			return PPC_ID_SPE_EVLWWSPLAT;

		case 796:
			return PPC_ID_SPE_EVLWHSPLATX;

		case 797:
			return PPC_ID_SPE_EVLWHSPLAT;

		case 800:
			return PPC_ID_SPE_EVSTDDX;

		case 801:
			return PPC_ID_SPE_EVSTDD;

		case 802:
			return PPC_ID_SPE_EVSTDWX;

		case 803:
			return PPC_ID_SPE_EVSTDW;

		case 804:
			return PPC_ID_SPE_EVSTDHX;

		case 805:
			return PPC_ID_SPE_EVSTDH;

		case 816:
			return PPC_ID_SPE_EVSTWHEX;

		case 817:
			return PPC_ID_SPE_EVSTWHE;

		case 820:
			return PPC_ID_SPE_EVSTWHOX;

		case 821:
			return PPC_ID_SPE_EVSTWHO;

		case 824:
			return PPC_ID_SPE_EVSTWWEX;

		case 825:
			return PPC_ID_SPE_EVSTWWE;

		case 828:
			return PPC_ID_SPE_EVSTWWOX;

		case 829:
			return PPC_ID_SPE_EVSTWWO;

		case 1027:
			return PPC_ID_SPE_EVMHESSF;

		case 1031:
			return PPC_ID_SPE_EVMHOSSF;

		case 1032:
			return PPC_ID_SPE_EVMHEUMI;

		case 1033:
			return PPC_ID_SPE_EVMHESMI;

		case 1035:
			return PPC_ID_SPE_EVMHESMF;

		case 1036:
			return PPC_ID_SPE_EVMHOUMI;

		case 1037:
			return PPC_ID_SPE_EVMHOSMI;

		case 1039:
			return PPC_ID_SPE_EVMHOSMF;

		case 1059:
			return PPC_ID_SPE_EVMHESSFA;

		case 1063:
			return PPC_ID_SPE_EVMHOSSFA;

		case 1064:
			return PPC_ID_SPE_EVMHEUMIA;

		case 1065:
			return PPC_ID_SPE_EVMHESMIA;

		case 1067:
			return PPC_ID_SPE_EVMHESMFA;

		case 1068:
			return PPC_ID_SPE_EVMHOUMIA;

		case 1069:
			return PPC_ID_SPE_EVMHOSMIA;

		case 1071:
			return PPC_ID_SPE_EVMHOSMFA;

		case 1095:
			return PPC_ID_SPE_EVMWHSSF;

		case 1096:
			return PPC_ID_SPE_EVMWLUMI;

		case 1100:
			return PPC_ID_SPE_EVMWHUMI;

		case 1101:
			return PPC_ID_SPE_EVMWHSMI;

		case 1103:
			return PPC_ID_SPE_EVMWHSMF;

		case 1107:
			return PPC_ID_SPE_EVMWSSF;

		case 1112:
			return PPC_ID_SPE_EVMWUMI;

		case 1113:
			return PPC_ID_SPE_EVMWSMI;

		case 1115:
			return PPC_ID_SPE_EVMWSMF;

		case 1127:
			return PPC_ID_SPE_EVMWHSSFA;

		case 1128:
			return PPC_ID_SPE_EVMWLUMIA;

		case 1132:
			return PPC_ID_SPE_EVMWHUMIA;

		case 1133:
			return PPC_ID_SPE_EVMWHSMIA;

		case 1135:
			return PPC_ID_SPE_EVMWHSMFA;

		case 1139:
			return PPC_ID_SPE_EVMWSSFA;

		case 1144:
			return PPC_ID_SPE_EVMWUMIA;

		case 1145:
			return PPC_ID_SPE_EVMWSMIA;

		case 1147:
			return PPC_ID_SPE_EVMWSMFA;

		case 1216:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVADDUSIAAW;

		case 1217:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVADDSSIAAW;

		case 1218:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVSUBFUSIAAW;

		case 1219:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVSUBFSSIAAW;

		case 1220:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVMRA;

		case 1222:
			return PPC_ID_SPE_EVDIVWS;

		case 1223:
			return PPC_ID_SPE_EVDIVWU;

		case 1224:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVADDUMIAAW;

		case 1225:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVADDSMIAAW;

		case 1226:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVSUBFUMIAAW;

		case 1227:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVSUBFSMIAAW;

		case 1280:
			return PPC_ID_SPE_EVMHEUSIAAW;

		case 1281:
			return PPC_ID_SPE_EVMHESSIAAW;

		case 1283:
			return PPC_ID_SPE_EVMHESSFAAW;

		case 1284:
			return PPC_ID_SPE_EVMHOUSIAAW;

		case 1285:
			return PPC_ID_SPE_EVMHOSSIAAW;

		case 1287:
			return PPC_ID_SPE_EVMHOSSFAAW;

		case 1288:
			return PPC_ID_SPE_EVMHEUMIAAW;

		case 1289:
			return PPC_ID_SPE_EVMHESMIAAW;

		case 1291:
			return PPC_ID_SPE_EVMHESMFAAW;

		case 1292:
			return PPC_ID_SPE_EVMHOUMIAAW;

		case 1293:
			return PPC_ID_SPE_EVMHOSMIAAW;

		case 1295:
			return PPC_ID_SPE_EVMHOSMFAAW;

		case 1320:
			return PPC_ID_SPE_EVMHEGUMIAA;

		case 1321:
			return PPC_ID_SPE_EVMHEGSMIAA;

		case 1323:
			return PPC_ID_SPE_EVMHEGSMFAA;

		case 1324:
			return PPC_ID_SPE_EVMHOGUMIAA;

		case 1325:
			return PPC_ID_SPE_EVMHOGSMIAA;

		case 1327:
			return PPC_ID_SPE_EVMHOGSMFAA;

		case 1344:
			return PPC_ID_SPE_EVMWLUSIAAW;

		case 1345:
			return PPC_ID_SPE_EVMWLSSIAAW;

		case 1352:
			return PPC_ID_SPE_EVMWLUMIAAW;

		case 1353:
			return PPC_ID_SPE_EVMWLSMIAAW;

		case 1363:
			return PPC_ID_SPE_EVMWSSFAA;

		case 1368:
			return PPC_ID_SPE_EVMWUMIAA;

		case 1369:
			return PPC_ID_SPE_EVMWSMIAA;

		case 1371:
			return PPC_ID_SPE_EVMWSMFAA;

		case 1408:
			return PPC_ID_SPE_EVMHEUSIANW;

		case 1409:
			return PPC_ID_SPE_EVMHESSIANW;

		case 1411:
			return PPC_ID_SPE_EVMHESSFANW;

		case 1412:
			return PPC_ID_SPE_EVMHOUSIANW;

		case 1413:
			return PPC_ID_SPE_EVMHOSSIANW;

		case 1415:
			return PPC_ID_SPE_EVMHOSSFANW;

		case 1416:
			return PPC_ID_SPE_EVMHEUMIANW;

		case 1417:
			return PPC_ID_SPE_EVMHESMIANW;

		case 1419:
			return PPC_ID_SPE_EVMHESMFANW;

		case 1420:
			return PPC_ID_SPE_EVMHOUMIANW;

		case 1421:
			return PPC_ID_SPE_EVMHOSMIANW;

		case 1423:
			return PPC_ID_SPE_EVMHOSMFANW;

		case 1448:
			return PPC_ID_SPE_EVMHEGUMIAN;

		case 1449:
			return PPC_ID_SPE_EVMHEGSMIAN;

		case 1451:
			return PPC_ID_SPE_EVMHEGSMFAN;

		case 1452:
			return PPC_ID_SPE_EVMHOGUMIAN;

		case 1453:
			return PPC_ID_SPE_EVMHOGSMIAN;

		case 1455:
			return PPC_ID_SPE_EVMHOGSMFAN;

		case 1472:
			return PPC_ID_SPE_EVMWLUSIANW;

		case 1473:
			return PPC_ID_SPE_EVMWLSSIANW;

		case 1480:
			return PPC_ID_SPE_EVMWLUMIANW;

		case 1481:
			return PPC_ID_SPE_EVMWLSMIANW;

		case 1491:
			return PPC_ID_SPE_EVMWSSFAN;

		case 1496:
			return PPC_ID_SPE_EVMWUMIAN;

		case 1497:
			return PPC_ID_SPE_EVMWSMIAN;

		case 1499:
			return PPC_ID_SPE_EVMWSMFAN;

		default:
			   return PPC_ID_INVALID;
	}
}

static InstructionId Decode0x13(uint32_t word32, uint32_t decodeFlags)
{
	uint32_t a = GetA(word32);
	uint32_t b = GetB(word32);
	uint32_t d = GetD(word32);

	uint32_t subop = (word32 >> 1) & 0x1f;
	switch (subop)
	{
		case 0x2:
			if ((word32 & 0x001fffff) == 4)
				return PPC_ID_LNIA;

			return PPC_ID_ADDPCIS;

		default:
			;
	}

	subop = word32 & 0x7ff;
	switch (subop)
	{
		case 0x000:
			if ((word32 & 0x0063f800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_MCRF;

		case 0x020:
		case 0x021:
			// for PowerPC, this is 0x0000f800, but POWER
			// introduces BH bits
			if ((word32 & 0x0000e000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_BCLRx;

		case 0x024:
			if ((word32 & 0x03fff800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_RFID;

		case 0x042:
			if (a == b)
				return PPC_ID_CRNOT;
			else
				return PPC_ID_CRNOR;

		case 0x04c:
			if ((word32 & 0x03fff800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_RFMCI;

		case 0x04e:
			if ((word32 & 0x03fff800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_RFDI;

		case 0x064:
			if ((word32 & 0x03fff800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_RFI;

		case 0x066:
			if ((word32 & 0x03fff800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_RFCI;

		case 0x102:
			return PPC_ID_CRANDC;

		case 0x12c:
			if ((word32 & 0x3fff800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_ISYNC;

		case 0x182:
			if (d == a && d == b)
				return PPC_ID_CRCLR;
			else
				return PPC_ID_CRXOR;

		case 0x1c2:
			return PPC_ID_CRNAND;

		case 0x202:
			return PPC_ID_CRAND;

		case 0x242:
			if (d == a && d == b)
				return PPC_ID_CRSET;
			else
				return PPC_ID_CREQV;

		case 0x342:
			return PPC_ID_CRORC;

		case 0x382:
			if (a == b)
				return PPC_ID_CRMOVE;
			else
				return PPC_ID_CROR;

		case 0x420:
		case 0x421:
			// TODO: return invalid when BO[2] == 0 (ie when & 0x00800000 == 0)
			//       keeping it in makes it easier to compare against capstone
			//       for now

			// for PowerPC, this is 0x0000f800, but POWER
			// introduces BH bits
			if ((word32 & 0x0000e000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_BCCTRx;

		default:
			return PPC_ID_INVALID;
	}
}

static InstructionId Decode0x1E(uint32_t word32, uint32_t decodeFlags)
{
	uint32_t sh = GetSH64(word32);
	uint32_t mx = GetMX64(word32);

	uint32_t subop = (word32 >> 1) & 0xf;
	switch (subop)
	{
		case 0x0:
		case 0x1:
			if (mx == 0)
				return PPC_ID_ROTLDIx;
			else if (sh == 0)
				return PPC_ID_CLRLDIx;
			else
				return PPC_ID_RLDICLx;

		case 0x2:
		case 0x3:
			if (sh + mx == 63)
				return PPC_ID_SLDIx;
			else
				return PPC_ID_RLDICRx;

		case 0x4:
		case 0x5:
			return PPC_ID_RLDICx;

		case 0x6:
		case 0x7:
			return PPC_ID_RLDIMIx;

		case 0x8:
			if (mx == 0)
				return PPC_ID_ROTLDx;
			else
				return PPC_ID_RLDCLx;

		case 0x9:
			return PPC_ID_RLDCRx;

		default:
			return PPC_ID_INVALID;
	}
}

static InstructionId Decode0x1F(uint32_t word32, uint32_t decodeFlags)
{
	uint32_t a = GetA(word32);
	uint32_t b = GetB(word32);
	uint32_t d = GetD(word32);
	uint32_t s = GetS(word32);

	uint32_t subop = word32 & 0x3f;
	switch (subop)
	{
		case 0x1e:
			return PPC_ID_ISEL;

		default:   break;
	}

	subop = word32 & 0x7ff;
	switch (subop)
	{
		case 0x000:
			if ((word32 & 0x00400000) == 0)
			{
				if ((word32 & 0x00200000) != 0)
				{
					if ((decodeFlags & DECODE_FLAGS_PPC64) == 0)
						return PPC_ID_INVALID;

					return PPC_ID_CMPD;
				}
				else
				{
					return PPC_ID_CMPW;
				}
			}

			return PPC_ID_INVALID;

		case 0x008:
		{
			uint32_t to = (word32 >> 21) & 0x1f;

			switch (to)
			{
				case 1: return PPC_ID_TWLGT;
				case 2: return PPC_ID_TWLLT;
				case 4: return PPC_ID_TWEQ;
				case 8: return PPC_ID_TWGT;
				case 16: return PPC_ID_TWLT;
				case 24: return PPC_ID_TWNE;
				case 31:
				{
					if ((GetA(word32) == 0) && (GetB(word32) == 0))
						return PPC_ID_TRAP;

					return PPC_ID_TWU;
				}
				default: return PPC_ID_TW;
			}
		}

		case 0x00c:
			if ((decodeFlags & DECODE_FLAGS_ALTIVEC) != 0)
				return PPC_ID_AV_LVSL;

			return PPC_ID_INVALID;

		case 0x00e:
			if ((decodeFlags & DECODE_FLAGS_ALTIVEC) != 0)
				return PPC_ID_AV_LVEBX;

			return PPC_ID_INVALID;

		case 0x010:
		case 0x011:
		case 0x410:
		case 0x411:
			return PPC_ID_SUBFCx;

		case 0x012:
		case 0x013:
			if ((decodeFlags & DECODE_FLAGS_PPC64) == 0)
				return PPC_ID_INVALID;

			return PPC_ID_MULHDUx;

		case 0x014:
		case 0x015:
		case 0x414:
		case 0x415:
			return PPC_ID_ADDCx;

		case 0x016:
		case 0x017:
			return PPC_ID_MULHWUx;

		case 0x018:
		case 0x019:
			return PPC_ID_VSX_LXSIWZX;

		case 0x026:
			if ((word32 & 0x00100000) != 0)
			{
				if ((word32 & 0x800) != 0)
					return PPC_ID_INVALID;

				uint32_t fxm = (word32 >> 12) & 0xff;
				if (fxm == 0)
					return PPC_ID_INVALID;

				return PPC_ID_MFOCRF;
			}

			if ((word32 & 0x000ff800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_MFCR;

		case 0x028:
		case 0x029:
			return PPC_ID_LWARX;

		case 0x02a:
			return PPC_ID_LDX;

		case 0x02c:
			if ((word32 & 0x02000000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_ICBT;

		case 0x02e:
			return PPC_ID_LWZX;

		case 0x030:
		case 0x031:
			return PPC_ID_SLWx;

		case 0x034:
		case 0x035:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_CNTLZWx;

		case 0x036:
		case 0x037:
			return PPC_ID_SLDx;

		case 0x038:
		case 0x039:
			return PPC_ID_ANDx;

		case 0x03e:
			return PPC_ID_LWEPX;

		case 0x040:
			if ((word32 & 0x00400000) == 0)
			{
				if ((word32 & 0x00200000) != 0)
				{
					if ((decodeFlags & DECODE_FLAGS_PPC64) == 0)
						return PPC_ID_INVALID;

					return PPC_ID_CMPLD;
				}
				else
				{
					return PPC_ID_CMPLW;
				}

				break;
			}

			return PPC_ID_INVALID;

		case 0x04c:
			if ((decodeFlags & DECODE_FLAGS_ALTIVEC) != 0)
				return PPC_ID_AV_LVSR;

			return PPC_ID_INVALID;

		case 0x04e:
			if ((decodeFlags & DECODE_FLAGS_ALTIVEC) != 0)
				return PPC_ID_AV_LVEHX;

			return PPC_ID_INVALID;

		case 0x050:
		case 0x051:
		case 0x450:
		case 0x451:
			return PPC_ID_SUBFx;

		case 0x066:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_MFFPRD;

		case 0x067:
			if (b != 0)
				return PPC_ID_INVALID;

			// either MFVSRD or MFVRD; we use MFVRD for backwards
			// compatibility with capstone
			return PPC_ID_VSX_MFVSRD;

		case 0x068:
		case 0x069:
			return PPC_ID_LBARX;

		case 0x06a:
			return PPC_ID_LDUX;

		case 0x06c:
			if (d != 0)
				return PPC_ID_INVALID;

			return PPC_ID_DCBST;

		case 0x06e:
			return PPC_ID_LWZUX;

		case 0x074:
		case 0x075:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_CNTLZDx;

		case 0x078:
		case 0x079:
			return PPC_ID_ANDCx;

		case 0x07e:
			if (d != 0)
				return PPC_ID_INVALID;

			return PPC_ID_DCBSTEP;

		case 0x03c:
		{
			if ((word32 & 0x039ff800) != 0)
				return false;

			uint32_t wc = (word32 >> 21) & 0x3;
			switch (wc)
			{
				case 0: return PPC_ID_WAIT;
				case 1: return PPC_ID_WAITRSV;
				case 2: return PPC_ID_WAITIMPL;

				default: return PPC_ID_WAIT;
			}
		}

		case 0x088:
		{
			uint32_t to = (word32 >> 21) & 0x1f;

			switch (to)
			{
				case 1: return PPC_ID_TDLGT;
				case 2: return PPC_ID_TDLLT;
				case 4: return PPC_ID_TDEQ;
				case 8: return PPC_ID_TDGT;
				case 16: return PPC_ID_TDLT;
				case 24: return PPC_ID_TDNE;
				case 31: return PPC_ID_TDU;
				default: return PPC_ID_TD;
			}
		}

		case 0x08e:
			if ((decodeFlags & DECODE_FLAGS_ALTIVEC) != 0)
				return PPC_ID_AV_LVEWX;

			return PPC_ID_INVALID;

		case 0x092:
		case 0x093:
			if ((decodeFlags & DECODE_FLAGS_PPC64) != 0)
				return PPC_ID_MULHDx;

			return PPC_ID_INVALID;


		case 0x096:
		case 0x097:
			return PPC_ID_MULHWx;

		case 0x098:
		case 0x099:
			return PPC_ID_VSX_LXSIWAX;

		case 0x0a6:
			if ((a != 0) || (b != 0))
				return PPC_ID_INVALID;

			return PPC_ID_MFMSR;

		case 0x0a8:
		case 0x0a9:
			return PPC_ID_LDARX;

		case 0x0ac:
		{
			if ((word32 & 0x03800000) != 0)
				return PPC_ID_INVALID;

			uint32_t l = (word32 >> 21) & 0x3;
			switch (l)
			{
				case 1:
					return PPC_ID_DCBFL;

				case 3:
					return PPC_ID_DCBFLP;

				default:
					return PPC_ID_DCBF;
			}
		}

		case 0x0ae:
			return PPC_ID_LBZX;

		case 0x0be:
			return PPC_ID_LBEPX;

		case 0x0ce:
			if ((decodeFlags & DECODE_FLAGS_ALTIVEC) != 0)
				return PPC_ID_AV_LVX;

			return PPC_ID_INVALID;

		case 0x0d0:
		case 0x0d1:
		case 0x4d0:
		case 0x4d1:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_NEGx;

		case 0xe6:
		case 0xe7:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_MFVSRWZ;

		case 0x0e8:
		case 0x0e9:
			return PPC_ID_LHARX;

		case 0x0ee:
			return PPC_ID_LBZUX;

		case 0x0f4:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_POPCNTB;

		case 0x0f8:
		case 0x0f9:
			return PPC_ID_NORx;

		case 0x0fe:
			if ((word32 & 0x03800000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_DCBFEP;

		case 0x100:
			if ((word32 & 0x0003f800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SETB;

		case 0x106:
			if ((a != 0) || (b != 0))
				return PPC_ID_INVALID;

			return PPC_ID_WRTEE;

		case 0x10e:
			if ((decodeFlags & DECODE_FLAGS_ALTIVEC) != 0)
				return PPC_ID_AV_STVEBX;

			return PPC_ID_INVALID;

		case 0x110:
		case 0x111:
		case 0x510:
		case 0x511:
			return PPC_ID_SUBFEx;

		case 0x114:
		case 0x115:
		case 0x514:
		case 0x515:
			return PPC_ID_ADDEx;

		case 0x118:
		case 0x119:
			return PPC_ID_VSX_STXSIWX;

		case 0x120:
			if ((word32 & 0x00100000) != 0)
			{
				if ((word32 & 0x800) != 0)
					return PPC_ID_INVALID;

				uint32_t fxm = (word32 >> 12) & 0xff;
				if (fxm == 0)
					return PPC_ID_INVALID;

				return PPC_ID_MTOCRF;
			}

			if ((word32 & 0x00000800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_MTCRF;

		case 0x124:
			if ((a != 0) || (b != 0))
				return PPC_ID_INVALID;

			return PPC_ID_MTMSR;

		case 0x12a:
			if ((decodeFlags & DECODE_FLAGS_PPC64) == 0)
				return PPC_ID_INVALID;

			return PPC_ID_STDX;

		case 0x12d:
			return PPC_ID_STWCX;

		case 0x12e:
			return PPC_ID_STWX;

		case 0x13a:
			return PPC_ID_STDEPX;

		case 0x13e:
			return PPC_ID_STWEPX;

		case 0x146:
			if ((word32 & 0x03ff7800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_WRTEEI;

		case 0x14e:
			if ((decodeFlags & DECODE_FLAGS_ALTIVEC) != 0)
				return PPC_ID_AV_STVEHX;

			return PPC_ID_INVALID;

		case 0x164:
			if ((a != 0) || (b != 0))
				return PPC_ID_INVALID;

			return PPC_ID_MTMSRD;

		case 0x166:
		case 0x167:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_MTVSRD;

		case 0x16a:
			return PPC_ID_STDUX;

		case 0x16e:
			return PPC_ID_STWUX;

		case 0x180:
			if ((word32 & 0x00400000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_CMPRB;

		case 0x18d:
			if ((word32 & 0x02000000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_ICBLQ;

		case 0x18e:
			if ((decodeFlags & DECODE_FLAGS_ALTIVEC) != 0)
				return PPC_ID_AV_STVEWX;

			return PPC_ID_INVALID;

		case 0x190:
		case 0x191:
		case 0x590:
		case 0x591:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SUBFZEx;

		case 0x194:
		case 0x195:
		case 0x594:
		case 0x595:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_ADDZEx;

		case 0x1a4:
			if ((word32 & 0x0010f800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_MTSR;

		case 0x1a6:
		case 0x1a7:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_MTVSRWA;

		case 0x1ad:
			return PPC_ID_STDCX;

		case 0x1ae:
			return PPC_ID_STBX;

		case 0x1be:
			return PPC_ID_STBEPX;

		case 0x1c0:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_CMPEQB;

		case 0x1cc:
			if ((word32 & 0x02000000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_ICBLC;

		case 0x1ce:
			if ((decodeFlags & DECODE_FLAGS_ALTIVEC) != 0)
				return PPC_ID_AV_STVX;

			return PPC_ID_INVALID;

		case 0x1d0:
		case 0x1d1:
		case 0x5d0:
		case 0x5d1:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SUBFMEx;

		case 0x1d2:
		case 0x1d3:
		case 0x5d2:
		case 0x5d3:
			if ((decodeFlags & DECODE_FLAGS_PPC64) == 0)
				return PPC_ID_INVALID;

			return PPC_ID_MULLDx;

		case 0x1d4:
		case 0x1d5:
		case 0x5d4:
		case 0x5d5:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_ADDMEx;

		case 0x1d6:
		case 0x1d7:
		case 0x5d6:
		case 0x5d7:
			return PPC_ID_MULLWx;

		case 0x1e4:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_MTSRIN;

		case 0x1e6:
		case 0x1e7:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_MTVSRWZ;

		case 0x1ec:
		{
			uint32_t th = (word32 >> 21) & 0x1f;
			if (th == 0x10)
				return PPC_ID_DCBTSTT;
			else
				return PPC_ID_DCBTST;
		}

		case 0x1ee:
			return PPC_ID_STBUX;

		case 0x1f8:
			return PPC_ID_BPERMD;

		case 0x1fe:
			return PPC_ID_DCBTSTEP;

		case 0x212:
			return PPC_ID_MODUD;

		case 0x214:
		case 0x215:
		case 0x614:
		case 0x615:
			return PPC_ID_ADDx;

		case 0x216:
			return PPC_ID_MODUW;

		case 0x218:
		case 0x219:
			return PPC_ID_VSX_LXVX;

		case 0x21a:
		case 0x21b:
			return PPC_ID_VSX_LXVL;

		case 0x224:
			if ((d != 0) || (a != 0))
				return PPC_ID_INVALID;
			
			return PPC_ID_TLBIEL;

		case 0x22c:
		{
			uint32_t th = (word32 >> 21) & 0x1f;
			if (th == 0x10)
				return PPC_ID_DCBTT;
			else
				return PPC_ID_DCBT;
		}

		case 0x22e:
			return PPC_ID_LHZX;

		case 0x238:
		case 0x239:
			return PPC_ID_EQVx;

		case 0x23e:
			return PPC_ID_LHEPX;

		case 0x25a:
		case 0x25b:
			return PPC_ID_VSX_LXVLL;

		case 0x25c:
			return PPC_ID_MFBHRBE;

		case 0x264:
			if (a != 0)
				return PPC_ID_INVALID;
			
			return PPC_ID_TLBIE;

		case 0x266:
		case 0x267:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_MFVSRLD;

		case 0x26c:
			return PPC_ID_ECIWX;

		case 0x26e:
			return PPC_ID_LHZUX;

		case 0x278:
		case 0x279:
			return PPC_ID_XORx;

		case 0x27e:
			return PPC_ID_DCBTEP;

		case 0x286:
		{
			uint32_t dcr = GetSpecialRegisterCommon(word32);

			switch (dcr)
			{
				case 0x80: return PPC_ID_MFBR0;
				case 0x81: return PPC_ID_MFBR1;
				case 0x82: return PPC_ID_MFBR2;
				case 0x83: return PPC_ID_MFBR3;
				case 0x84: return PPC_ID_MFBR4;
				case 0x85: return PPC_ID_MFBR5;
				case 0x86: return PPC_ID_MFBR6;
				case 0x87: return PPC_ID_MFBR7;

				default:   return PPC_ID_MFDCR;
			}
		}

		case 0x298:
		case 0x299:
			if ((decodeFlags & DECODE_FLAGS_VSX) == 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_LXVDSX;

		case 0x29c:
			return PPC_ID_MFPMR;

		case 0x2a4:
			if (a != 0 || b != 0 || d != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SLBSYNC;

		case 0x2a6:
		{
			uint32_t spr = GetSpecialRegisterCommon(word32);

			// there are a bunch of other MF<some specific SPR>
			// instructions; instead of handling them all, we just
			// give a few common SPRs their own special opcodes, and
			// bundle the rest into MFSPR
			//
			// this avoids adding a bazillion separate instructions
			// that need to be lifted separately, AND are highly
			// arch-dependent
			switch (spr)
			{
				case 1:    return PPC_ID_MFXER;
				case 8:    return PPC_ID_MFLR;
				case 9:    return PPC_ID_MFCTR;

				default:   return PPC_ID_MFSPR;
			}
		}

		case 0x2aa:
			return PPC_ID_LWAX;

		case 0x2ac:
			if ((decodeFlags & DECODE_FLAGS_ALTIVEC) == 0)
				return PPC_ID_INVALID;

			if ((word32 & 0x01800000) != 0)
				return PPC_ID_INVALID;

			if ((word32 & 0x02000000) != 0)
				return PPC_ID_AV_DSTT;
			else
				return PPC_ID_AV_DST;

		case 0x2ae:
			return PPC_ID_LHAX;

		case 0x2ce:
			if ((decodeFlags & DECODE_FLAGS_ALTIVEC) != 0)
				return PPC_ID_AV_LVXL;

			return PPC_ID_INVALID;

		case 0x2d8:
		case 0x2d9:
			return PPC_ID_VSX_LXVWSX;

		case 0x2e4:
			if ((word32 & 0x03fff800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_TLBIA;

		case 0x2e6:
		{
			uint32_t special = GetSpecialRegisterCommon(word32);
			switch (special)
			{
				case 269: return PPC_ID_MFTBU;

				default: return PPC_ID_MFTB;
			}
		}

		case 0x2ea:
			if ((decodeFlags & DECODE_FLAGS_PPC64) == 0)
				return PPC_ID_INVALID;

			return PPC_ID_LWAUX;

		case 0x2ec:
			if ((decodeFlags & DECODE_FLAGS_ALTIVEC) == 0)
				return PPC_ID_INVALID;

			if ((word32 & 0x01800000) != 0)
				return PPC_ID_INVALID;

			if ((word32 & 0x02000000) != 0)
				return PPC_ID_AV_DSTSTT;
			else
				return PPC_ID_AV_DSTST;

		case 0x2ee:
			return PPC_ID_LHAUX;

		case 0x2f4:
			if (b != 0)
				return PPC_ID_INVALID;

			// TODO: [Category: Server]
			// TODO: [Category: Embedded.Phased-In]
			return PPC_ID_POPCNTW;

		case 0x312:
		case 0x313:
		case 0x712:
		case 0x713:
			return PPC_ID_DIVDEUx;

		case 0x316:
		case 0x317:
		case 0x716:
		case 0x717:
			return PPC_ID_DIVWEUx;

		case 0x318:
		case 0x319:
			return PPC_ID_VSX_STXVX;

		case 0x31a:
		case 0x31b:
			return PPC_ID_VSX_STXVL;

		case 0x324:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SLBMTE;

		case 0x326:
		case 0x327:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_MTVSRWS;

		case 0x32e:
			return PPC_ID_STHX;

		case 0x338:
		case 0x339:
			return PPC_ID_ORCx;

		case 0x33e:
			return PPC_ID_STHEPX;

		case 0x352:
		case 0x353:
		case 0x752:
		case 0x753:
			return PPC_ID_DIVDEx;

		case 0x356:
		case 0x357:
		case 0x756:
		case 0x757:
			return PPC_ID_DIVWEx;

		case 0x35a:
		case 0x35b:
			return PPC_ID_VSX_STXVLL;

		case 0x35c:
			if ((a != 0) || (b != 0) || (d != 0))
				return PPC_ID_INVALID;

			return PPC_ID_CLRBHRB;

		case 0x364:
			if ((d != 0) || (a != 0))
				return PPC_ID_INVALID;
			
			return PPC_ID_SLBIE;

		case 0x366:
		case 0x367:
			return PPC_ID_VSX_MTVSRDD;

		case 0x36c:
			return PPC_ID_ECOWX;

		case 0x36e:
			return PPC_ID_STHUX;

		case 0x378:
		case 0x379:
			// TODO: it would be nice to disassemble "mr.", but
			//       capstone doesn't handle this (and technically
			//       "mr." isn't listed as a valid instruction in
			//       the documentation, but it IS a bit more user
			//       friendly for disassembly purposes)
			if (b == s && ((word32 & 0x1) == 0))
				return PPC_ID_MRx;
			else
				return PPC_ID_ORx;

		case 0x386:
		{
			uint32_t dcr = GetSpecialRegisterCommon(word32);

			switch (dcr)
			{
				case 0x80: return PPC_ID_MTBR0;
				case 0x81: return PPC_ID_MTBR1;
				case 0x82: return PPC_ID_MTBR2;
				case 0x83: return PPC_ID_MTBR3;
				case 0x84: return PPC_ID_MTBR4;
				case 0x85: return PPC_ID_MTBR5;
				case 0x86: return PPC_ID_MTBR6;
				case 0x87: return PPC_ID_MTBR7;

				default: return PPC_ID_MTDCR;
			}
		}

		case 0x38c:
		{
			if ((word32 & 0x021ff800) != 0)
				return PPC_ID_INVALID;

			uint32_t ct = (word32 >> 21) & 0xf;

			if (ct == 0)
				return PPC_ID_DCCCI;
			else
				return PPC_ID_DCI;
		}

		case 0x392:
		case 0x393:
		case 0x792:
		case 0x793:
			return PPC_ID_DIVDUx;

		case 0x396:
		case 0x397:
		case 0x796:
		case 0x797:
			return PPC_ID_DIVWUx;

		case 0x39c:
			return PPC_ID_MTPMR;

		case 0x3a4:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SLBIEG;

		case 0x3a6:
		{
			uint32_t spr = GetSpecialRegisterCommon(word32);

			switch (spr)
			{
				// there are a bunch of other MF<some specific SPR>
				// instructions; instead of handling them all, we just
				// give a few common SPRs their own special opcodes, and
				// bundle the rest into MFSPR
				//
				// this avoids adding a bazillion separate instructions
				// that need to be lifted separately, AND are highly
				// arch-dependent
				case 1:    return PPC_ID_MTXER;
				case 8:    return PPC_ID_MTLR;
				case 9:    return PPC_ID_MTCTR;

				default:   return PPC_ID_MTSPR;
			}
		}

		case 0x3ac:
			if (d != 0)
				return PPC_ID_INVALID;

			return PPC_ID_DCBI;

		case 0x3b8:
		case 0x3b9:
			return PPC_ID_NANDx;

		case 0x3cc:
			if ((word32 & 0x02000000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_ICBTLS;

		case 0x3ce:
			if ((decodeFlags & DECODE_FLAGS_ALTIVEC) != 0)
				return PPC_ID_AV_STVXL;

			return PPC_ID_INVALID;

		case 0x3d2:
		case 0x3d3:
		case 0x7d2:
		case 0x7d3:
			return PPC_ID_DIVDx;

		case 0x3d6:
		case 0x3d7:
		case 0x7d6:
		case 0x7d7:
			return PPC_ID_DIVWx;

		case 0x3e4:
			if ((word32 & 0x03fff800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SLBIA;

		case 0x3f4:
			if (b != 0)
				return PPC_ID_INVALID;

			// TODO: [Category: Server.64-bit]
			// TODO: [Category: Embedded.64-bit.Phased-In]
			return PPC_ID_POPCNTD;

		case 0x3f8:
			return PPC_ID_CMPB;

		case 0x400:
			if ((word32 & 0x00fff800) != 0)
				return PPC_ID_INVALID;

			break;

		case 0x418:
		case 0x419:
			return PPC_ID_VSX_LXSSPX;

		case 0x428:
			if ((decodeFlags & DECODE_FLAGS_PPC64) == 0)
				return PPC_ID_INVALID;

			return PPC_ID_LDBRX;

		case 0x42a:
			return PPC_ID_LSWX;

		case 0x42c:
			return PPC_ID_LWBRX;

		case 0x42e:
			return PPC_ID_LFSX;

		case 0x430:
		case 0x431:
			return PPC_ID_SRWx;

		case 0x434:
		case 0x435:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_CNTTZWx;

		case 0x436:
		case 0x437:
			return PPC_ID_SRDx;

		case 0x46c:
			if ((word32 & 0x03fff800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_TLBSYNC;

		case 0x46e:
			return PPC_ID_LFSUX;

		case 0x474:
		case 0x475:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_CNTTZDx;

		case 0x480:
			if ((word32 & 0x007ff800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_MCRXRX;

		case 0x48c:
			return PPC_ID_LWAT;

		case 0x498:
		case 0x499:
			if ((decodeFlags & DECODE_FLAGS_VSX) == 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_LXSDX;

		case 0x4a6:
			if ((word32 & 0x0010f801) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_MFSR;

		case 0x4aa:
			return PPC_ID_LSWI;

		case 0x4ac:
		{
			if ((word32 & 0x039ff800) != 0)
				return PPC_ID_INVALID;

			uint32_t l = (word32 >> 21) & 0x3;
			switch (l)
			{
				case 0:  return PPC_ID_SYNC;
				case 1:  return PPC_ID_LWSYNC;
				case 2:  return PPC_ID_PTESYNC;

				default: return PPC_ID_SYNC;

			}
		}

		case 0x4ae:
			return PPC_ID_LFDX;

		case 0x4be:
			return PPC_ID_LFDEPX;

		case 0x4cc:
			return PPC_ID_LDAT;

		case 0x4ee:
			return PPC_ID_LFDUX;

		case 0x4e4:
			if ((word32 & 0x03fff800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_TLBIA;

		case 0x518:
		case 0x519:
			return PPC_ID_VSX_STXSSPX;

		case 0x51d:
			if ((word32 & 0x03eff800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_TBEGIN;

		case 0x526:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_MFSRIN;

		case 0x528:
			if ((decodeFlags & DECODE_FLAGS_PPC64) == 0)
				return PPC_ID_INVALID;

			return PPC_ID_STDBRX;

		case 0x52a:
			return PPC_ID_STSWX;

		case 0x52c:
			return PPC_ID_STWBRX;

		case 0x52e:
			return PPC_ID_STFSX;

		case 0x55d:
			if ((word32 & 0x01fff800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_TEND;

		case 0x56d:
			return PPC_ID_STBCX;

		case 0x56e:
			return PPC_ID_STFSUX;

		case 0x58c:
			return PPC_ID_STWAT;

		case 0x598:
		case 0x599:
			if ((decodeFlags & DECODE_FLAGS_VSX) == 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_STXSDX;

		case 0x59c:
			if ((word32 & 0x007ff800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_TCHECK;

		case 0x5aa:
			return PPC_ID_STSWI;

		case 0x5ad:
			return PPC_ID_STHCX;

		case 0x5ae:
			return PPC_ID_STFDX;

		case 0x5be:
			return PPC_ID_STFDEPX;

		case 0x5cc:
			return PPC_ID_STDAT;

		case 0x5dd:
			if ((word32 & 0x03dff800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_TSR;

		case 0x5e6:
			if ((word32 & 0x001cf800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_DARN;

		case 0x5ec:
			if (d != 0)
				return PPC_ID_INVALID;

			return PPC_ID_DCBA;

		case 0x5ee:
			return PPC_ID_STFDUX;

		case 0x60c:
			if (d != 1)
				return PPC_ID_INVALID;

			return PPC_ID_COPY;

		case 0x612:
			return PPC_ID_MODSD;

		case 0x616:
			return PPC_ID_MODSW;

		case 0x618:
		case 0x619:
			if ((decodeFlags & DECODE_FLAGS_VSX) == 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_LXVW4X;

		case 0x61a:
		case 0x61b:
			return PPC_ID_VSX_LXSIBZX;

		case 0x61d:
			return PPC_ID_TABORTWC;

		case 0x624:
			if ((word32 & 0x03e00000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_TLBIVAX;

		case 0x62a:
			return PPC_ID_LWZCIX;

		case 0x62c:
			return PPC_ID_LHBRX;

		case 0x630:
		case 0x631:
			return PPC_ID_SRAWx;

		case 0x634:
		case 0x635:
			if ((decodeFlags & DECODE_FLAGS_PPC64) == 0)
				return PPC_ID_INVALID;

			return PPC_ID_SRADx;

		case 0x658:
		case 0x659:
			return PPC_ID_VSX_LXVH8X;

		case 0x65a:
		case 0x65b:
			return PPC_ID_VSX_LXSIHZX;

		case 0x65d:
			return PPC_ID_TABORTDC;

		case 0x66a:
			return PPC_ID_LHZCIX;

		case 0x66c:
		{
			if ((word32 & 0x019ff800) != 0)
				return PPC_ID_INVALID;

			uint32_t all = ((word32 >> 25) & 0x1) != 0;

			if (all)
			{
				if ((word32 & 0x00600000) != 0)
					return PPC_ID_INVALID;
				else
					return PPC_ID_AV_DSSALL;
			}
			else
			{
				return PPC_ID_AV_DSS;
			}
		}

		case 0x670:
		case 0x671:
			return PPC_ID_SRAWIx;

		case 0x674:
		case 0x675:
		case 0x676:
		case 0x677:
			if ((decodeFlags & DECODE_FLAGS_PPC64) == 0)
				return PPC_ID_INVALID;

			return PPC_ID_SRADIx;

		case 0x68c:
			if (a != 0 || b != 0 || d != 0)
				return PPC_ID_INVALID;

			return PPC_ID_CP_ABORT;

		case 0x698:
		case 0x699:
			if ((decodeFlags & DECODE_FLAGS_VSX) == 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_LXVD2X;

		case 0x69d:
			return PPC_ID_TABORTWCI;

		case 0x6a6:
			if ((word32 & 0x001e0000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SLBMFEV;

		case 0x6aa:
			return PPC_ID_LBZCIX;

		case 0x6ac:
			if ((a != 0) || (b != 0))
				return PPC_ID_INVALID;

			if (d == 0)
				return PPC_ID_EIEIO;
			else
				return PPC_ID_MBAR;

		case 0x6ae:
			return PPC_ID_LFIWAX;

		case 0x6d8:
		case 0x6d9:
			return PPC_ID_VSX_LXVB16X;

		case 0x6dd:
			return PPC_ID_TABORTDCI;

		case 0x6ea:
			return PPC_ID_LDCIX;

		case 0x6ec:
			if ((a != 0) || (b != 0) || (d != 0))
				return PPC_ID_INVALID;

			return PPC_ID_MSGSYNC;

		case 0x6ee:
			return PPC_ID_LFIWZX;

		case 0x6f4:
		case 0x6f5:
		case 0x6f6:
		case 0x6f7:
			return PPC_ID_EXTSWSLIx;

		case 0x70d:
			if (d != 1)
				return PPC_ID_INVALID;

			return PPC_ID_PASTE;

		case 0x718:
		case 0x719:
			if ((decodeFlags & DECODE_FLAGS_VSX) == 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_STXVW4X;

		case 0x71a:
		case 0x71b:
			return PPC_ID_VSX_STXSIBX;

		case 0x71d:
			if (d != 0 || b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_TABORT;

		case 0x724:
			if ((word32 & 0x03e00000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_TLBSX;

		case 0x726:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SLBMFEE;

		case 0x72a:
			return PPC_ID_STWCIX;

		case 0x72c:
			return PPC_ID_STHBRX;

		case 0x734:
		case 0x735:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_EXTSHx;

		case 0x758:
		case 0x759:
			return PPC_ID_VSX_STXVH8X;

		case 0x75a:
		case 0x75b:
			return PPC_ID_VSX_STXSIHX;

		case 0x75d:
			if ((d != 0) || (b != 0))
				return PPC_ID_INVALID;

			return PPC_ID_TRECLAIM;

		case 0x764:
			if ((word32 & 0x800) != 0)
				return PPC_ID_TLBREHI;
			else
				return PPC_ID_TLBRELO;

		case 0x76a:
			return PPC_ID_STHCIX;

		case 0x774:
		case 0x775:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_EXTSBx;

		case 0x78c:
		{
			if ((word32 & 0x021ff801) != 0)
				return PPC_ID_INVALID;

			uint32_t ct = (word32 >> 21) & 0xf;

			if (ct == 0)
				return PPC_ID_ICCCI;
			else
				return PPC_ID_ICI;
		}

		case 0x798:
		case 0x799:
			if ((decodeFlags & DECODE_FLAGS_VSX) == 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_STXVD2X;

		case 0x7a4:
			if ((word32 & 0x800) != 0)
				return PPC_ID_TLBWELO;
			else
				return PPC_ID_TLBWEHI;

		case 0x7aa:
			return PPC_ID_STBCIX;

		case 0x7ac:
			if (d != 0)
				return PPC_ID_INVALID;
			
			return PPC_ID_ICBI;

		case 0x7ae:
			return PPC_ID_STFIWX;

		case 0x7b4:
		case 0x7b5:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_EXTSWx;

		case 0x7be:
			if (d != 0)
				return PPC_ID_INVALID;

			return PPC_ID_ICBIEP;

		case 0x7d8:
		case 0x7d9:
			return PPC_ID_VSX_STXVB16X;

		case 0x7dd:
			if ((a != 0) || (b != 0) || (d != 0))
				return PPC_ID_INVALID;

			return PPC_ID_TRECHKPT;

		case 0x7e4:
			if (d != 0 || a != 0)
				return PPC_ID_INVALID;

			// NOTE: this is only valid for 603 processors?
			return PPC_ID_TLBLI;

		case 0x7ea:
			return PPC_ID_STDCIX;

		case 0x7ec:
		{
			// NOTE: I can't find anything about the "DCBZL" opcode
			//       anywhere, but this seems to match capstone
			if ((word32 & 0x03e00000) == 0x00200000)
				return PPC_ID_DCBZL;
			else if ((word32 & 0x03e00000) == 0)
				return PPC_ID_DCBZ;
			else
				return PPC_ID_INVALID;
		}

		case 0x7fe:
			if (d != 0)
				return PPC_ID_INVALID;

			return PPC_ID_DCBZEP;

		default:
			return PPC_ID_INVALID;
	}

	return true;
}

static InstructionId Decode0x3B(uint32_t word32, uint32_t flags)
{
	uint32_t a = GetA(word32);
	uint32_t b = GetB(word32);
	uint32_t c = GetC(word32);

	uint32_t subop = word32 & 0x3f;
	switch (subop)
	{
		case 0x24:
		case 0x25:
			if (c != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FDIVSx;

		case 0x28:
		case 0x29:
			if (c != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FSUBSx;

		case 0x2a:
		case 0x2b:
			if (c != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FADDSx;

		case 0x2c:
		case 0x2d:
			if ((a != 0) || (c != 0))
				return PPC_ID_INVALID;

			return PPC_ID_FSQRTSx;

		case 0x30:
		case 0x31:
			if ((a != 0) || (c != 0))
				return PPC_ID_INVALID;

			return PPC_ID_FRESx;

		case 0x32:
		case 0x33:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FMULSx;

		case 0x34:
		case 0x35:
			if ((a != 0) || (c != 0))
				return PPC_ID_INVALID;

			return PPC_ID_FRSQRTESx;

		case 0x38:
		case 0x39:
			return PPC_ID_FMSUBSx;

		case 0x3a:
		case 0x3b:
			return PPC_ID_FMADDSx;

		case 0x3c:
		case 0x3d:
			return PPC_ID_FNMSUBSx;

		case 0x3e:
		case 0x3f:
			return PPC_ID_FNMADDSx;

		default:
			break;
	}

	subop = word32 & 0x7ff;
	switch (subop)
	{
		case 0x69c:
		case 0x69d:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FCFIDSx;

		case 0x79c:
		case 0x79d:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FCFIDUSx;

		default:
			return PPC_ID_INVALID;
	}

	return true;
}

static InstructionId DecodeVsx0x3C(uint32_t word32, uint32_t flags)
{
	uint32_t subop = (word32 >> 4) & 0x3;
	uint32_t vsxA = GetVsxA(word32);
	uint32_t vsxB = GetVsxB(word32);

	switch (subop)
	{
		case 0x3: return PPC_ID_VSX_XXSEL;
		default:  break;
	}

	subop = (word32 >> 1) & 0x3ff;
	switch (subop)
	{
		case 0x168:
			if ((word32 & 0x00180000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XXSPLTIB;

		case 0x396:
			return PPC_ID_VSX_XSIEXPDP;

		default:
			;
	}

	subop = (word32 >> 2) & 0x1ff;
	switch (subop)
	{
		case 0x00a:
			if ((word32 & 0x001f0000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSRSQRTESP;

		case 0x00b:
			if ((word32 & 0x001f0000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSSQRTSP;

		case 0x01a:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSRESP;

		case 0x048:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSCVDPUXWS;

		case 0x049:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSRDPI;

		case 0x04a:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSRSQRTEDP;

		case 0x04b:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSSQRTDP;

		case 0x058:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSCVDPSXWS;

		case 0x059:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSRDPIZ;

		case 0x05a:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSREDP;

		case 0x069:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSRDPIP;

		case 0x6a:
			if ((word32 & 0x007f0001) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSTSQRTDP;

		case 0x06b:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSRDPIC;

		case 0x079:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSRDPIM;

		case 0x088:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVCVSPUXWS;

		case 0x089:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVRSPI;

		case 0x08a:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVRSQRTESP;

		case 0x08b:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVSQRTSP;

		case 0x098:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVCVSPSXWS;

		case 0x099:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVRSPIZ;

		case 0x09a:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVRESP;

		case 0x0a4:
			if ((word32 & 0x001c0004) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XXSPLTW;

		case 0x0a5:
			if ((word32 & 0x00100000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XXEXTRACTUW;

		case 0x0a8:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVCVUXWSP;

		case 0x0a9:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVRSPIP;

		case 0x0aa:
			if ((word32 & 0x007f0001) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVTSQRTSP;

		case 0x0ab:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVRSPIC;

		case 0x0b5:
			if ((word32 & 0x00100000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XXINSERTW;

		case 0x0b8:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVCVSXWSP;

		case 0x0b9:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVRSPIM;

		case 0x0c8:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVCVDPUXWS;

		case 0x0c9:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVRDPI;

		case 0x0ca:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVRSQRTEDP;

		case 0x0cb:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVSQRTDP;

		case 0x0d8:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVCVDPSXWS;

		case 0x0d9:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVRDPIZ;

		case 0x0da:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVREDP;

		case 0x0e8:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVCVUXWDP;

		case 0x0e9:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVRDPIP;

		case 0xea:
			if ((word32 & 0x007f0001) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVTSQRTDP;

		case 0x0eb:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVRDPIC;

		case 0x0f8:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVCVSXWDP;

		case 0x0f9:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVRDPIM;

		case 0x109:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSCVDPSP;

		case 0x10b:
			if ((word32 & 0x001f0000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSCVDPSPN;

		case 0x119:
			if ((word32 & 0x001f0000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSRSP;

		case 0x128:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSCVUXDSP;

		case 0x12a:
			if ((word32 & 0x1) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSTSTDCSP;

		case 0x138:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSCVSXDSP;

		case 0x148:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSCVDPUXDS;

		case 0x149:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSCVSPDP;

		case 0x14b:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSCVSPDPN;

		case 0x158:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSCVDPSXDS;

		case 0x159:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSABSDP;

		case 0x15b:
		{
			uint32_t subsubop = (word32 >> 16) & 0x1f;
			switch (subsubop)
			{
				case 0x00:
					if ((word32 & 0x1) != 0)
						return PPC_ID_INVALID;

					return PPC_ID_VSX_XSXEXPDP;

				case 0x01:
					if ((word32 & 0x1) != 0)
						return PPC_ID_INVALID;

					return PPC_ID_VSX_XSXSIGDP;

				case 0x10:
					return PPC_ID_VSX_XSCVHPDP;

				case 0x11:
					return PPC_ID_VSX_XSCVDPHP;

				default:
					return PPC_ID_INVALID;
			}
		}

		case 0x168:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSCVUXDDP;

		case 0x169:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSNABSDP;

		case 0x16a:
			if ((word32 & 0x1) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSTSTDCDP;

		case 0x178:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSCVSXDDP;

		case 0x179:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSNEGDP;

		case 0x188:
			if ((word32 & 0x001f0000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVCVSPUXDS;

		case 0x189:
			if ((word32 & 0x001f0000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVCVDPSP;

		case 0x198:
			if ((word32 & 0x001f0000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVCVSPSXDS;

		case 0x199:
			if ((word32 & 0x001f0000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVABSSP;

		case 0x1a8:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVCVUXDSP;

		case 0x1a9:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVNABSSP;

		case 0x1b8:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVCVSXDSP;

		case 0x1b9:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVNEGSP;

		case 0x1c8:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVCVDPUXDS;

		case 0x1c9:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVCVSPDP;

		case 0x1d8:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVCVDPSXDS;

		case 0x1d9:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVABSDP;

		case 0x1db:
		{
			uint32_t subsubop = (word32 >> 16) & 0x1f;
			switch (subsubop)
			{
				case 0x00:
					return PPC_ID_VSX_XVXEXPDP;

				case 0x01:
					return PPC_ID_VSX_XVXSIGDP;

				case 0x07:
					return PPC_ID_VSX_XXBRH;

				case 0x08:
					return PPC_ID_VSX_XVXEXPSP;

				case 0x09:
					return PPC_ID_VSX_XVXSIGSP;

				case 0x0f:
					return PPC_ID_VSX_XXBRW;

				case 0x17:
					return PPC_ID_VSX_XXBRD;

				case 0x18:
					return PPC_ID_VSX_XVCVHPSP;

				case 0x19:
					return PPC_ID_VSX_XVCVSPHP;

				case 0x1f:
					return PPC_ID_VSX_XXBRQ;

				default:
					return PPC_ID_INVALID;

			}
		}

		case 0x1e8:
			if ((word32 & 0x001f0000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVCVUXDDP;

		case 0x1e9:
			if ((word32 & 0x001f0000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVNABSDP;

		case 0x1f8:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVCVSXDDP;

		case 0x1f9:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVNEGDP;

		default:
			break;
	}

	subop = (word32 >> 3) & 0xff;
	switch (subop)
	{
		case 0x00:
			return PPC_ID_VSX_XSADDSP;

		case 0x01:
			return PPC_ID_VSX_XSMADDASP;

		case 0x02:
		case 0x22:
		case 0x42:
		case 0x62:
			return PPC_ID_VSX_XXSLDWI;

		case 0x03:
			return PPC_ID_VSX_XSCMPEQDP;

		case 0x08:
			return PPC_ID_VSX_XSSUBSP;

		case 0x09:
			return PPC_ID_VSX_XSMADDMSP;

		case 0x0a:
		case 0x2a:
		case 0x4a:
		case 0x6a:
		{
			uint32_t dm = (word32 >> 8) & 0x3;

			if (vsxA == vsxB)
			{
				switch (dm)
				{
					case 0:  return PPC_ID_VSX_XXSPLTD;
					case 2:  return PPC_ID_VSX_XXSWAPD;
					case 3:  return PPC_ID_VSX_XXSPLTD;
					default: return PPC_ID_VSX_XXPERMDI;
				}
			}
			else
			{
				switch (dm)
				{
					case 0:  return PPC_ID_VSX_XXMRGHD;
					case 3:  return PPC_ID_VSX_XXMRGLD;
					default: return PPC_ID_VSX_XXPERMDI;
				}
			}
		}

		case 0x0b:
			return PPC_ID_VSX_XSCMPGTDP;

		case 0x10:
			return PPC_ID_VSX_XSMULSP;

		case 0x11:
			return PPC_ID_VSX_XSMSUBASP;

		case 0x12:
			return PPC_ID_VSX_XXMRGHW;

		case 0x13:
			return PPC_ID_VSX_XSCMPGEDP;

		case 0x18:
			return PPC_ID_VSX_XSDIVSP;

		case 0x19:
			return PPC_ID_VSX_XSMSUBMSP;

		case 0x1a:
			return PPC_ID_VSX_XXPERM;

		case 0x20:
			return PPC_ID_VSX_XSADDDP;

		case 0x21:
			return PPC_ID_VSX_XSMADDADP;

		case 0x23:
			if ((word32 & 0x00600001) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSCMPUDP;

		case 0x28:
			return PPC_ID_VSX_XSSUBDP;

		case 0x29:
			return PPC_ID_VSX_XSMADDMDP;

		case 0x2b:
			if ((word32 & 0x00600001) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSCMPODP;

		case 0x30:
			return PPC_ID_VSX_XSMULDP;

		case 0x31:
			return PPC_ID_VSX_XSMSUBADP;

		case 0x32:
			return PPC_ID_VSX_XXMRGLW;

		case 0x38:
			return PPC_ID_VSX_XSDIVDP;

		case 0x39:
			return PPC_ID_VSX_XSMSUBMDP;

		case 0x3a:
			return PPC_ID_VSX_XXPERMR;

		case 0x3b:
			if ((word32 & 0x00600001) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSCMPEXPDP;

		case 0x3d:
			if ((word32 & 0x00600001) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSTDIVDP;

		case 0x40:
			return PPC_ID_VSX_XVADDSP;

		case 0x41:
			return PPC_ID_VSX_XVMADDASP;

		case 0x43:
		case 0xc3:
			return PPC_ID_VSX_XVCMPEQSPx;

		case 0x48:
			return PPC_ID_VSX_XVSUBSP;

		case 0x49:
			return PPC_ID_VSX_XVMADDMSP;

		case 0x4b:
		case 0xcb:
			return PPC_ID_VSX_XVCMPGTSPx;

		case 0x50:
			return PPC_ID_VSX_XVMULSP;

		case 0x51:
			return PPC_ID_VSX_XVMSUBASP;

		case 0x53:
		case 0xd3:
			return PPC_ID_VSX_XVCMPGESPx;

		case 0x58:
			return PPC_ID_VSX_XVDIVSP;

		case 0x59:
			return PPC_ID_VSX_XVMSUBMSP;

		case 0x5d:
			if ((word32 & 0x00600001) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVTDIVSP;

		case 0x60:
			return PPC_ID_VSX_XVADDDP;

		case 0x61:
			return PPC_ID_VSX_XVMADDADP;

		case 0x63:
		case 0xe3:
			return PPC_ID_VSX_XVCMPEQDPx;

		case 0x68:
			return PPC_ID_VSX_XVSUBDP;

		case 0x69:
			return PPC_ID_VSX_XVMADDMDP;

		case 0x6b:
		case 0xeb:
			return PPC_ID_VSX_XVCMPGTDPx;

		case 0x70:
			return PPC_ID_VSX_XVMULDP;

		case 0x71:
			return PPC_ID_VSX_XVMSUBADP;

		case 0x73:
		case 0xf3:
			return PPC_ID_VSX_XVCMPGEDPx;

		case 0x78:
			return PPC_ID_VSX_XVDIVDP;

		case 0x79:
			return PPC_ID_VSX_XVMSUBMDP;

		case 0x7d:
			if ((word32 & 0x00600001) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVTDIVDP;

		case 0x80:
			return PPC_ID_VSX_XSMAXCDP;

		case 0x81:
			return PPC_ID_VSX_XSNMADDASP;

		case 0x82:
			return PPC_ID_VSX_XXLAND;

		case 0x88:
			return PPC_ID_VSX_XSMINCDP;

		case 0x89:
			return PPC_ID_VSX_XSNMADDMSP;

		case 0x8a:
			return PPC_ID_VSX_XXLANDC;

		case 0x90:
			return PPC_ID_VSX_XSMAXJDP;

		case 0x91:
			return PPC_ID_VSX_XSNMSUBASP;

		case 0x92:
			return PPC_ID_VSX_XXLOR;

		case 0x98:
			return PPC_ID_VSX_XSMINJDP;

		case 0x99:
			return PPC_ID_VSX_XSNMSUBMSP;

		case 0x9a:
			return PPC_ID_VSX_XXLXOR;

		case 0xa0:
			return PPC_ID_VSX_XSMAXDP;

		case 0xa1:
			return PPC_ID_VSX_XSNMADDADP;

		case 0xa9:
			return PPC_ID_VSX_XSNMADDMDP;

		case 0xa2:
			return PPC_ID_VSX_XXLNOR;

		case 0xa8:
			return PPC_ID_VSX_XSMINDP;

		case 0xaa:
			return PPC_ID_VSX_XXLORC;

		case 0xb0:
			return PPC_ID_VSX_XSCPSGNDP;

		case 0xb1:
			return PPC_ID_VSX_XSNMSUBADP;

		case 0xb2:
			return PPC_ID_VSX_XXLNAND;

		case 0xb9:
			return PPC_ID_VSX_XSNMSUBMDP;

		case 0xba:
			return PPC_ID_VSX_XXLEQV;

		case 0xc0:
			return PPC_ID_VSX_XVMAXSP;

		case 0xc1:
			return PPC_ID_VSX_XVNMADDASP;

		case 0xc8:
			return PPC_ID_VSX_XVMINSP;

		case 0xc9:
			return PPC_ID_VSX_XVNMADDMSP;

		case 0xd0:
			if (vsxA == vsxB)
				return PPC_ID_VSX_XVMOVSP;
			else
				return PPC_ID_VSX_XVCPSGNSP;

		case 0xd1:
			return PPC_ID_VSX_XVNMSUBASP;

		case 0xd5:
		case 0xdd:
			return PPC_ID_VSX_XVTSTDCSP;

		case 0xd8:
			return PPC_ID_VSX_XVIEXPSP;

		case 0xd9:
			return PPC_ID_VSX_XVNMSUBMSP;

		case 0xe0:
			return PPC_ID_VSX_XVMAXDP;

		case 0xe1:
			return PPC_ID_VSX_XVNMADDADP;

		case 0xe8:
			return PPC_ID_VSX_XVMINDP;

		case 0xe9:
			return PPC_ID_VSX_XVNMADDMDP;

		case 0xf0:
			if (vsxA == vsxB)
				return PPC_ID_VSX_XVMOVDP;
			else
				return PPC_ID_VSX_XVCPSGNDP;

		case 0xf1:
			return PPC_ID_VSX_XVNMSUBADP;

		case 0xf5:
		case 0xfd:
			return PPC_ID_VSX_XVTSTDCDP;

		case 0xf8:
			return PPC_ID_VSX_XVIEXPDP;

		case 0xf9:
			return PPC_ID_VSX_XVNMSUBMDP;

		default:
			return PPC_ID_INVALID;
	}
}

static InstructionId DecodeVsx0x3D(uint32_t word32, uint32_t flags)
{
	uint32_t subop = word32 & 0x7;
	switch (subop)
	{
		case 1:
			return PPC_ID_VSX_LXV;

		case 2:
		case 6:
			return PPC_ID_VSX_STXSD;

		case 3:
		case 7:
			return PPC_ID_VSX_STXSSP;

		case 5:
			return PPC_ID_VSX_STXV;

		default:
			return PPC_ID_INVALID;
	}
}

static InstructionId Decode0x3F(uint32_t word32, uint32_t flags)
{
	uint32_t a = GetA(word32);
	uint32_t b = GetB(word32);

	uint32_t subop = word32 & 0x3f;
	switch (subop)
	{
		case 0x02e:
		case 0x02f:
			return PPC_ID_FSELx;

		case 0x032:
		case 0x033:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FMULx;

		case 0x038:
		case 0x039:
			return PPC_ID_FMSUBx;

		case 0x03a:
		case 0x03b:
			return PPC_ID_FMADDx;

		case 0x03c:
		case 0x03d:
			return PPC_ID_FNMSUBx;

		case 0x03e:
		case 0x03f:
			return PPC_ID_FNMADDx;

		default:
			break;
	}

	subop = word32 & 0x7ff;
	switch (subop)
	{
		case 0x000:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FCMPU;

		case 0x008:
		case 0x009:
			if ((flags & DECODE_FLAGS_VSX) != 0)
				return PPC_ID_VSX_XSADDQPx;
			else
				return PPC_ID_INVALID;

		case 0x00a:
		case 0x00b:
		case 0x20a:
		case 0x20b:
		case 0x40a:
		case 0x40b:
		case 0x60a:
		case 0x60b:
			if ((word32 & 0x001e0000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSRQPIx;

		case 0x010:
		case 0x011:
			return PPC_ID_FCPSGNx;

		case 0x018:
		case 0x019:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FRSPx;

		case 0x01c:
		case 0x01d:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FCTIWx;

		case 0x01e:
		case 0x01f:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FCTIWZx;

		case 0x024:
		case 0x025:
			return PPC_ID_FDIVx;

		case 0x028:
		case 0x029:
			return PPC_ID_FSUBx;

		case 0x02a:
		case 0x02b:
			return PPC_ID_FADDx;

		case 0x02c:
		case 0x02d:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FSQRTx;

		case 0x030:
		case 0x031:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FREx;

		case 0x034:
		case 0x035:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FRSQRTEx;

		case 0x040:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FCMPO;

		case 0x048:
		case 0x049:
			if ((flags & DECODE_FLAGS_VSX) != 0)
				return PPC_ID_VSX_XSMULQPx;
			else
				return PPC_ID_INVALID;

		case 0x04a:
		case 0x24a:
		case 0x44a:
		case 0x64a:
			if ((flags & DECODE_FLAGS_VSX) != 0)
			{
				if ((word32 & 0x001e0000) != 0)
					return PPC_ID_INVALID;

				return PPC_ID_VSX_XSRQPXP;
			}
			else
			{
				return PPC_ID_INVALID;
			}

		case 0x04c:
		case 0x04d:
			if ((a != 0) || (b != 0))
				return PPC_ID_INVALID;

			return PPC_ID_MTFSB1x;

		case 0x050:
		case 0x051:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FNEGx;

		case 0x080:
			if ((word32 & 0x0063f800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_MCRFS;

		case 0x08c:
		case 0x08d:
			if ((a != 0) || (b != 0))
				return PPC_ID_INVALID;

			return PPC_ID_MTFSB0x;

		case 0x090:
		case 0x091:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FMRx;

		case 0x0c8:
			if ((flags & DECODE_FLAGS_VSX) != 0)
				return PPC_ID_VSX_XSCPSGNQP;
			else
				return PPC_ID_INVALID;

		case 0x100:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FTDIV;

		case 0x108:
			if ((flags & DECODE_FLAGS_VSX) != 0)
			{
				if ((word32 & 0x00600000) != 0)
					return PPC_ID_INVALID;

				return PPC_ID_VSX_XSCMPOQP;
			}
			else
			{
				return PPC_ID_INVALID;
			}

		case 0x10c:
		case 0x10d:
			if ((word32 & 0x007e0800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_MTFSFIx;

		case 0x110:
		case 0x111:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FNABSx;

		case 0x11c:
		case 0x11d:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FCTIWUx;

		case 0x11e:
		case 0x11f:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FCTIWUZx;

		case 0x140:
			if ((word32 & 0x007f0000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FTSQRT;

		case 0x148:
			if ((flags & DECODE_FLAGS_VSX) != 0)
			{
				if ((word32 & 0x00600000) != 0)
					return PPC_ID_INVALID;

				return PPC_ID_VSX_XSCMPEXPQP;
			}
			else
			{
				return PPC_ID_INVALID;
			}

		case 0x210:
		case 0x211:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FABSx;

		case 0x308:
		case 0x309:
			if ((flags & DECODE_FLAGS_VSX) != 0)
				return PPC_ID_VSX_XSMADDQPx;
			else
				return PPC_ID_INVALID;

		case 0x310:
		case 0x311:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FRINx;

		case 0x348:
		case 0x349:
			if ((flags & DECODE_FLAGS_VSX) != 0)
				return PPC_ID_VSX_XSMSUBQPx;
			else
				return PPC_ID_INVALID;

		case 0x350:
		case 0x351:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FRIZx;

		case 0x388:
		case 0x389:
			if ((flags & DECODE_FLAGS_VSX) != 0)
				return PPC_ID_VSX_XSNMADDQPx;
			else
				return PPC_ID_INVALID;

		case 0x390:
		case 0x391:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FRIPx;

		case 0x3c8:
		case 0x3c9:
			if ((flags & DECODE_FLAGS_VSX) != 0)
				return PPC_ID_VSX_XSNMSUBQPx;
			else
				return PPC_ID_INVALID;

		case 0x3d0:
		case 0x3d1:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FRIMx;

		case 0x408:
		case 0x409:
			if ((flags & DECODE_FLAGS_VSX) != 0)
				return PPC_ID_VSX_XSSUBQPx;
			else
				return PPC_ID_INVALID;

		case 0x448:
		case 0x449:
			if ((flags & DECODE_FLAGS_VSX) != 0)
				return PPC_ID_VSX_XSDIVQPx;
			else
				return PPC_ID_INVALID;

		case 0x48e:
		case 0x48f:
		{
			uint32_t subsubop = (word32 >> 16) & 0x1f;
			switch (subsubop)
			{
				case 0x00:
					if ((word32 & 0x0000f800) != 0)
						return PPC_ID_INVALID;

					return PPC_ID_MFFSx;

				case 0x01:
					if ((word32 & 0x0000f801) != 0)
						return PPC_ID_INVALID;

					return PPC_ID_MFFSCE;

				case 0x14:
					if ((word32 & 0x1) != 0)
						return PPC_ID_INVALID;

					return PPC_ID_MFFSCDRN;

				case 0x15:
					if ((word32 & 0x0000c001) != 0)
						return PPC_ID_INVALID;

					return PPC_ID_MFFSCDRNI;

				case 0x16:
					if ((word32 & 0x1) != 0)
						return PPC_ID_INVALID;

					return PPC_ID_MFFSCRN;

				case 0x17:
					if ((word32 & 0x0000e001) != 0)
						return PPC_ID_INVALID;

					return PPC_ID_MFFSCRNI;

				case 0x18:
					if ((word32 & 0x0000f801) != 0)
						return PPC_ID_INVALID;

					return PPC_ID_MFFSL;

				default:
					return PPC_ID_INVALID;
			}
		}

		case 0x508:
			if ((flags & DECODE_FLAGS_VSX) != 0)
			{
				if ((word32 & 0x00600000) != 0)
					return PPC_ID_INVALID;

				return PPC_ID_VSX_XSCMPUQP;
			}
			else
			{
				return PPC_ID_INVALID;
			}

		case 0x588:
			if ((flags & DECODE_FLAGS_VSX) != 0)
				return PPC_ID_VSX_XSTSTDCQP;
			else
				return PPC_ID_INVALID;

		case 0x58e:
		case 0x58f:
			return PPC_ID_MTFSFx;

		case 0x648:
		case 0x649:
			if ((flags & DECODE_FLAGS_VSX) != 0)
			{
				uint32_t subsubop = (word32 >> 16) & 0x1f;
				switch (subsubop)
				{
					case 0x00:
						if ((word32 & 0x1) != 0)
							return PPC_ID_INVALID;

						return PPC_ID_VSX_XSABSQP;

					case 0x02:
						if ((word32 & 0x1) != 0)
							return PPC_ID_INVALID;

						return PPC_ID_VSX_XSXEXPQP;

					case 0x08:
						if ((word32 & 0x1) != 0)
							return PPC_ID_INVALID;

						return PPC_ID_VSX_XSNABSQP;

					case 0x10:
						if ((word32 & 0x1) != 0)
							return PPC_ID_INVALID;

						return PPC_ID_VSX_XSNEGQP;

					case 0x12:
						if ((word32 & 0x1) != 0)
							return PPC_ID_INVALID;

						return PPC_ID_VSX_XSXSIGQP;

					case 0x1b:
						return PPC_ID_VSX_XSSQRTQPx;

					default:
						return PPC_ID_INVALID;
				}
			}
			else
			{
				return PPC_ID_INVALID;
			}

		case 0x65c:
		case 0x65d:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FCTIDx;

		case 0x65e:
		case 0x65f:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FCTIDZx;

		case 0x688:
		case 0x689:
			if ((flags & DECODE_FLAGS_VSX) != 0)
			{
				uint32_t subsubop = (word32 >> 16) & 0x1f;
				switch (subsubop)
				{
					case 0x01:
						if ((word32 & 0x1) != 0)
							return PPC_ID_INVALID;

						return PPC_ID_VSX_XSCVQPUWZ;

					case 0x02:
						if ((word32 & 0x1) != 0)
							return PPC_ID_INVALID;

						return PPC_ID_VSX_XSCVUDQP;

					case 0x09:
						if ((word32 & 0x1) != 0)
							return PPC_ID_INVALID;

						return PPC_ID_VSX_XSCVQPSWZ;

					case 0x0a:
						if ((word32 & 0x1) != 0)
							return PPC_ID_INVALID;

						return PPC_ID_VSX_XSCVSDQP;

					case 0x11:
						if ((word32 & 0x1) != 0)
							return PPC_ID_INVALID;

						return PPC_ID_VSX_XSCVQPUDZ;

					case 0x14:
						return PPC_ID_VSX_XSCVQPDPx;

					case 0x16:
						if ((word32 & 0x1) != 0)
							return PPC_ID_INVALID;

						return PPC_ID_VSX_XSCVDPQP;

					case 0x19:
						if ((word32 & 0x1) != 0)
							return PPC_ID_INVALID;

						return PPC_ID_VSX_XSCVQPSDZ;

					default:
						return PPC_ID_INVALID;
				}
			}
			else
			{
				return PPC_ID_INVALID;
			}

		case 0x69c:
		case 0x69d:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FCFIDx;

		case 0x6c8:
			if ((flags & DECODE_FLAGS_VSX) != 0)
				return PPC_ID_VSX_XSIEXPQP;
			else
				return PPC_ID_INVALID;

		case 0x75c:
		case 0x75d:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FCTIDUx;

		case 0x75e:
		case 0x75f:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FCTIDUZx;

		case 0x79c:
		case 0x79d:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FCFIDUx;

		default:
			return PPC_ID_INVALID;
	}

	return true;
}

static InstructionId Decode32(uint32_t word32, uint32_t decodeFlags)
{
	uint32_t a = GetA(word32);

	uint32_t primary = (word32 >> 26) & 0x3f;
	switch (primary)
	{
		case 0x00:
		{
			// "ATTN" instruction documented in section 12.1.1 of
			// the user manual for the IBM A2 processor
			if ((word32 & 0x7fe) != 0x200)
				return PPC_ID_INVALID;

			return PPC_ID_ATTN;
		}

		case 0x02:
		{
			if ((decodeFlags & DECODE_FLAGS_PPC64) == 0)
				return PPC_ID_INVALID;

			uint32_t to = (word32 >> 21) & 0x1f;
			switch (to)
			{
				case 1: return PPC_ID_TDLGTI;
				case 2: return PPC_ID_TDLLTI;
				case 4: return PPC_ID_TDEQI;
				case 8: return PPC_ID_TDGTI;
				case 16: return PPC_ID_TDLTI;
				case 24: return PPC_ID_TDNEI;
				case 31: return PPC_ID_TDUI;
				default: return PPC_ID_TDI;
			}
		}

		case 0x03:
		{
			uint32_t to = (word32 >> 21) & 0x1f;

			switch (to)
			{
				case 1: return PPC_ID_TWLGTI;
				case 2: return PPC_ID_TWLLTI;
				case 4: return PPC_ID_TWEQI;
				case 8: return PPC_ID_TWGTI;
				case 16: return PPC_ID_TWLTI;
				case 24: return PPC_ID_TWNEI;
				case 31: return PPC_ID_TWUI;
				default: return PPC_ID_TWI;
			}
		}

		case 0x04:
		{
			if ((decodeFlags & DECODE_FLAGS_ALTIVEC))
				return DecodeAltivec0x04(word32, decodeFlags);
			else if ((decodeFlags & DECODE_FLAGS_SPE))
				return DecodeSpe0x04(word32, decodeFlags);
			else
				return PPC_ID_INVALID;
		}

		case 0x07:
			return PPC_ID_MULLI;

		case 0x08:
			return PPC_ID_SUBFIC;


		case 0x0a:
			if ((word32 & 0x00400000) == 0)
			{
				if ((word32 & 0x00200000) != 0)
				{
					if ((decodeFlags & DECODE_FLAGS_PPC64) != 0)
						return PPC_ID_CMPLDI;
					else
						return PPC_ID_INVALID;
				}
				else
				{
					return PPC_ID_CMPLWI;
				}
			}

			return PPC_ID_INVALID;

		case 0x0b:
			if ((word32 & 0x00400000) == 0)
			{
				if ((word32 & 0x00200000) != 0)
				{
					if ((decodeFlags & DECODE_FLAGS_PPC64) != 0)
						return PPC_ID_CMPDI;
					else
						return PPC_ID_INVALID;

				}
				else
				{
					return PPC_ID_CMPWI;
				}
			}

			return PPC_ID_INVALID;

		case 0x0c:
			return PPC_ID_ADDICx;

		case 0x0d:
			return PPC_ID_ADDICx;

		case 0x0e:
			if (a == 0)
				return PPC_ID_LI;
			else
				return PPC_ID_ADDI;

		case 0x0f:
			if (a == 0)
				return PPC_ID_LIS;
			else
				return PPC_ID_ADDIS;

		case 0x10:
			return PPC_ID_BCx;

		case 0x11:
			if ((word32 & 0x03fff01f) != 2)
				return PPC_ID_INVALID;

			return PPC_ID_SC;

		case 0x12:
			return PPC_ID_Bx;

		case 0x13:
			return Decode0x13(word32, decodeFlags);

		case 0x14:
			return PPC_ID_RLWIMIx;

		case 0x15:
		{
			uint32_t me = GetME(word32);
			uint32_t mb = GetMB(word32);
			uint32_t sh = GetSH(word32);

			if (mb == 0 && ((sh + me) == 31))
				return PPC_ID_SLWIx;
			else if (mb == 0 && me == 31)
				return PPC_ID_ROTLWIx;
			else if (me == 31 && ((sh + mb) == 32))
				return PPC_ID_SRWIx;
			else if (sh == 0 && mb == 0)
				return PPC_ID_CLRRWIx;
			else if (sh == 0 && me == 31)
				return PPC_ID_CLRLWIx;
			else
				return PPC_ID_RLWINMx;
		}

		case 0x17:
		{
			uint32_t me = GetME(word32);
			uint32_t mb = GetMB(word32);

			if (mb == 0 && me == 31)
				return PPC_ID_ROTLWx;
			else
				return PPC_ID_RLWNMx;
		}

		case 0x18:
			if (word32 == 0x60000000)
				return PPC_ID_NOP;
			else
				return PPC_ID_ORI;

		case 0x19:
			return PPC_ID_ORIS;

		case 0x1a:
			if (word32 == 0x68000000)
				return PPC_ID_XNOP;
			else
				return PPC_ID_XORI;

		case 0x1b:
			return PPC_ID_XORIS;

		case 0x1c:
			return PPC_ID_ANDI;

		case 0x1d:
			return PPC_ID_ANDIS;

		case 0x1e:
			if ((decodeFlags & DECODE_FLAGS_PPC64) == 0)
				return PPC_ID_INVALID;
			
			return Decode0x1E(word32, decodeFlags);

		case 0x1f:
			return Decode0x1F(word32, decodeFlags);

		case 0x20:
			return PPC_ID_LWZ;

		case 0x21:
			return PPC_ID_LWZU;

		case 0x22:
			return PPC_ID_LBZ;

		case 0x23:
			return PPC_ID_LBZU;

		case 0x24:
			return PPC_ID_STW;

		case 0x25:
			return PPC_ID_STWU;

		case 0x26:
			return PPC_ID_STB;

		case 0x27:
			return PPC_ID_STBU;

		case 0x28:
			return PPC_ID_LHZ;

		case 0x29:
			return PPC_ID_LHZU;

		case 0x2a:
			return PPC_ID_LHA;

		case 0x2b:
			return PPC_ID_LHAU;

		case 0x2c:
			return PPC_ID_STH;

		case 0x2d:
			return PPC_ID_STHU;

		case 0x2e:
			return PPC_ID_LMW;

		case 0x2f:
			return PPC_ID_STMW;

		case 0x30:
			return PPC_ID_LFS;

		case 0x31:
			return PPC_ID_LFSU;

		case 0x32:
			return PPC_ID_LFD;

		case 0x33:
			return PPC_ID_LFDU;

		case 0x34:
			return PPC_ID_STFS;

		case 0x35:
			return PPC_ID_STFSU;

		case 0x36:
			return PPC_ID_STFD;

		case 0x37:
			return PPC_ID_STFDU;

		case 0x3a:
			if ((decodeFlags & DECODE_FLAGS_PPC64) == 0)
				return PPC_ID_INVALID;

			switch (word32 & 0x3)
			{
				case 0:  return PPC_ID_LD;
				case 1:  return PPC_ID_LDU;
				case 2:  return PPC_ID_LWA;
				default: return PPC_ID_INVALID;
			}

		case 0x3b:
			return Decode0x3B(word32, decodeFlags);

		case 0x3c:
			if ((decodeFlags & DECODE_FLAGS_VSX) != 0)
				return DecodeVsx0x3C(word32, decodeFlags);
			else
				return PPC_ID_INVALID;

		case 0x3d:
			if ((decodeFlags & DECODE_FLAGS_VSX) != 0)
				return DecodeVsx0x3D(word32, decodeFlags);
			else
				return PPC_ID_INVALID;

		case 0x3e:
			if ((decodeFlags & DECODE_FLAGS_PPC64) == 0)
				return PPC_ID_INVALID;

			switch (word32 & 0x3)
			{
				case 0:  return PPC_ID_STD;
				case 1:  return PPC_ID_STDU;
				default: return PPC_ID_INVALID;
			}

		case 0x3f:
			return Decode0x3F(word32, decodeFlags);

		default:
			return PPC_ID_INVALID;
	}
}

bool Decompose32(Instruction* instruction, uint32_t word32, uint64_t address, uint32_t flags)
{
	memset(instruction, 0, sizeof *instruction);

	instruction->id = Decode32(word32, flags);
	if (instruction->id == PPC_ID_INVALID)
		return false;

	FillOperands32(instruction, word32, address);
	return true;
}
