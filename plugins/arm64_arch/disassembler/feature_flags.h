/* GENERATED FILE */
#pragma once
// 107 HasXXX() functions used by decode:
#define HasFeature(feat) (ctx->decode_features[(feat) / 64] & ((uint64_t)1 << ((feat) % 64)))

#define HasAES() HasFeature(ARCH_FEATURE_AES)
#define HasAdvSIMD() HasFeature(ARCH_FEATURE_AdvSIMD)
#define HasBF16() HasFeature(ARCH_FEATURE_BF16)
#define HasBTI() HasFeature(ARCH_FEATURE_BTI)
#define HasCHK() HasFeature(ARCH_FEATURE_CHK)
#define HasCLRBHB() HasFeature(ARCH_FEATURE_CLRBHB)
#define HasCMH() HasFeature(ARCH_FEATURE_CMH)
#define HasCMPBR() HasFeature(ARCH_FEATURE_CMPBR)
#define HasCPA() HasFeature(ARCH_FEATURE_CPA)
#define HasCRC32() HasFeature(ARCH_FEATURE_CRC32)
#define HasCSSC() HasFeature(ARCH_FEATURE_CSSC)
#define HasD128() HasFeature(ARCH_FEATURE_D128)
#define HasDGH() HasFeature(ARCH_FEATURE_DGH)
#define HasDotProd() HasFeature(ARCH_FEATURE_DotProd)
#define HasF16F32DOT() HasFeature(ARCH_FEATURE_F16F32DOT)
#define HasF16F32MM() HasFeature(ARCH_FEATURE_F16F32MM)
#define HasF16MM() HasFeature(ARCH_FEATURE_F16MM)
#define HasF32MM() HasFeature(ARCH_FEATURE_F32MM)
#define HasF64MM() HasFeature(ARCH_FEATURE_F64MM)
#define HasF8F16MM() HasFeature(ARCH_FEATURE_F8F16MM)
#define HasF8F32MM() HasFeature(ARCH_FEATURE_F8F32MM)
#define HasFAMINMAX() HasFeature(ARCH_FEATURE_FAMINMAX)
#define HasFCMA() HasFeature(ARCH_FEATURE_FCMA)
#define HasFHM() HasFeature(ARCH_FEATURE_FHM)
#define HasFP() HasFeature(ARCH_FEATURE_FP)
#define HasFP16() HasFeature(ARCH_FEATURE_FP16)
#define HasFP8() HasFeature(ARCH_FEATURE_FP8)
#define HasFP8DOT2() HasFeature(ARCH_FEATURE_FP8DOT2)
#define HasFP8DOT4() HasFeature(ARCH_FEATURE_FP8DOT4)
#define HasFP8FMA() HasFeature(ARCH_FEATURE_FP8FMA)
#define HasFPRCVT() HasFeature(ARCH_FEATURE_FPRCVT)
#define HasFRINTTS() HasFeature(ARCH_FEATURE_FRINTTS)
#define HasFlagM() HasFeature(ARCH_FEATURE_FlagM)
#define HasFlagM2() HasFeature(ARCH_FEATURE_FlagM2)
#define HasGCS() HasFeature(ARCH_FEATURE_GCS)
#define HasHBC() HasFeature(ARCH_FEATURE_HBC)
#define HasI8MM() HasFeature(ARCH_FEATURE_I8MM)
#define HasJSCVT() HasFeature(ARCH_FEATURE_JSCVT)
#define HasLOR() HasFeature(ARCH_FEATURE_LOR)
#define HasLRCPC() HasFeature(ARCH_FEATURE_LRCPC)
#define HasLRCPC2() HasFeature(ARCH_FEATURE_LRCPC2)
#define HasLRCPC3() HasFeature(ARCH_FEATURE_LRCPC3)
#define HasLS64() HasFeature(ARCH_FEATURE_LS64)
#define HasLS64_ACCDATA() HasFeature(ARCH_FEATURE_LS64_ACCDATA)
#define HasLS64_V() HasFeature(ARCH_FEATURE_LS64_V)
#define HasLSCP() HasFeature(ARCH_FEATURE_LSCP)
#define HasLSE() HasFeature(ARCH_FEATURE_LSE)
#define HasLSE128() HasFeature(ARCH_FEATURE_LSE128)
#define HasLSFE() HasFeature(ARCH_FEATURE_LSFE)
#define HasLSUI() HasFeature(ARCH_FEATURE_LSUI)
#define HasLUT() HasFeature(ARCH_FEATURE_LUT)
#define HasMOPS() HasFeature(ARCH_FEATURE_MOPS)
#define HasMTE() HasFeature(ARCH_FEATURE_MTE)
#define HasMTE2() HasFeature(ARCH_FEATURE_MTE2)
#define HasPAuth() HasFeature(ARCH_FEATURE_PAuth)
#define HasPAuth_LR() HasFeature(ARCH_FEATURE_PAuth_LR)
#define HasPCDPHINT() HasFeature(ARCH_FEATURE_PCDPHINT)
#define HasRAS() HasFeature(ARCH_FEATURE_RAS)
#define HasRDM() HasFeature(ARCH_FEATURE_RDM)
#define HasRPRFM() HasFeature(ARCH_FEATURE_RPRFM)
#define HasSB() HasFeature(ARCH_FEATURE_SB)
#define HasSHA1() HasFeature(ARCH_FEATURE_SHA1)
#define HasSHA256() HasFeature(ARCH_FEATURE_SHA256)
#define HasSHA3() HasFeature(ARCH_FEATURE_SHA3)
#define HasSHA512() HasFeature(ARCH_FEATURE_SHA512)
#define HasSM3() HasFeature(ARCH_FEATURE_SM3)
#define HasSM4() HasFeature(ARCH_FEATURE_SM4)
#define HasSME() HasFeature(ARCH_FEATURE_SME)
#define HasSME2() HasFeature(ARCH_FEATURE_SME2)
#define HasSME2p1() HasFeature(ARCH_FEATURE_SME2p1)
#define HasSME2p2() HasFeature(ARCH_FEATURE_SME2p2)
#define HasSME2p3() HasFeature(ARCH_FEATURE_SME2p3)
#define HasSME_B16B16() HasFeature(ARCH_FEATURE_SME_B16B16)
#define HasSME_F16F16() HasFeature(ARCH_FEATURE_SME_F16F16)
#define HasSME_F64F64() HasFeature(ARCH_FEATURE_SME_F64F64)
#define HasSME_F8F16() HasFeature(ARCH_FEATURE_SME_F8F16)
#define HasSME_F8F32() HasFeature(ARCH_FEATURE_SME_F8F32)
#define HasSME_I16I64() HasFeature(ARCH_FEATURE_SME_I16I64)
#define HasSME_LUTv2() HasFeature(ARCH_FEATURE_SME_LUTv2)
#define HasSME_MOP4() HasFeature(ARCH_FEATURE_SME_MOP4)
#define HasSME_TMOP() HasFeature(ARCH_FEATURE_SME_TMOP)
#define HasSPE() HasFeature(ARCH_FEATURE_SPE)
#define HasSSVE_FEXPA() HasFeature(ARCH_FEATURE_SSVE_FEXPA)
#define HasSSVE_FP8DOT2() HasFeature(ARCH_FEATURE_SSVE_FP8DOT2)
#define HasSSVE_FP8DOT4() HasFeature(ARCH_FEATURE_SSVE_FP8DOT4)
#define HasSSVE_FP8FMA() HasFeature(ARCH_FEATURE_SSVE_FP8FMA)
#define HasSVE() HasFeature(ARCH_FEATURE_SVE)
#define HasSVE2() HasFeature(ARCH_FEATURE_SVE2)
#define HasSVE2p1() HasFeature(ARCH_FEATURE_SVE2p1)
#define HasSVE2p2() HasFeature(ARCH_FEATURE_SVE2p2)
#define HasSVE2p3() HasFeature(ARCH_FEATURE_SVE2p3)
#define HasSVE_AES() HasFeature(ARCH_FEATURE_SVE_AES)
#define HasSVE_AES2() HasFeature(ARCH_FEATURE_SVE_AES2)
#define HasSVE_B16B16() HasFeature(ARCH_FEATURE_SVE_B16B16)
#define HasSVE_B16MM() HasFeature(ARCH_FEATURE_SVE_B16MM)
#define HasSVE_BFSCALE() HasFeature(ARCH_FEATURE_SVE_BFSCALE)
#define HasSVE_BitPerm() HasFeature(ARCH_FEATURE_SVE_BitPerm)
#define HasSVE_F16F32MM() HasFeature(ARCH_FEATURE_SVE_F16F32MM)
#define HasSVE_PMULL128() HasFeature(ARCH_FEATURE_SVE_PMULL128)
#define HasSVE_SHA3() HasFeature(ARCH_FEATURE_SVE_SHA3)
#define HasSVE_SM4() HasFeature(ARCH_FEATURE_SVE_SM4)
#define HasSYSINSTR128() HasFeature(ARCH_FEATURE_SYSINSTR128)
#define HasSYSREG128() HasFeature(ARCH_FEATURE_SYSREG128)
#define HasTHE() HasFeature(ARCH_FEATURE_THE)
#define HasTRF() HasFeature(ARCH_FEATURE_TRF)
#define HasWFxT() HasFeature(ARCH_FEATURE_WFxT)
#define HasXS() HasFeature(ARCH_FEATURE_XS)

// 115 HaveXXX()/IsImplemented(FEAT_XXX) functions used by pcode:
#define HaveFeature(feat) (ctx->pcode_features[(feat) / 64] & ((uint64_t)1 << ((feat) % 64)))
#define HaveAES() HaveFeature(ARCH_FEATURE_AES)
#define HaveAdvSIMD() HaveFeature(ARCH_FEATURE_AdvSIMD)
#define HaveBF16() HaveFeature(ARCH_FEATURE_BF16)
#define HaveBTI() HaveFeature(ARCH_FEATURE_BTI)
#define HaveCHK() HaveFeature(ARCH_FEATURE_CHK)
#define HaveCLRBHB() HaveFeature(ARCH_FEATURE_CLRBHB)
#define HaveCMH() HaveFeature(ARCH_FEATURE_CMH)
#define HaveCMPBR() HaveFeature(ARCH_FEATURE_CMPBR)
#define HaveCPA() HaveFeature(ARCH_FEATURE_CPA)
#define HaveCRC32() HaveFeature(ARCH_FEATURE_CRC32)
#define HaveCSSC() HaveFeature(ARCH_FEATURE_CSSC)
#define HaveD128() HaveFeature(ARCH_FEATURE_D128)
#define HaveDGH() HaveFeature(ARCH_FEATURE_DGH)
#define HaveDIT() HaveFeature(ARCH_FEATURE_DIT)
#define HaveDotProd() HaveFeature(ARCH_FEATURE_DotProd)
#define HaveEBEP() HaveFeature(ARCH_FEATURE_EBEP)
#define HaveF16F32DOT() HaveFeature(ARCH_FEATURE_F16F32DOT)
#define HaveF16F32MM() HaveFeature(ARCH_FEATURE_F16F32MM)
#define HaveF16MM() HaveFeature(ARCH_FEATURE_F16MM)
#define HaveF32MM() HaveFeature(ARCH_FEATURE_F32MM)
#define HaveF64MM() HaveFeature(ARCH_FEATURE_F64MM)
#define HaveF8F16MM() HaveFeature(ARCH_FEATURE_F8F16MM)
#define HaveF8F32MM() HaveFeature(ARCH_FEATURE_F8F32MM)
#define HaveFAMINMAX() HaveFeature(ARCH_FEATURE_FAMINMAX)
#define HaveFCMA() HaveFeature(ARCH_FEATURE_FCMA)
#define HaveFHM() HaveFeature(ARCH_FEATURE_FHM)
#define HaveFP() HaveFeature(ARCH_FEATURE_FP)
#define HaveFP16() HaveFeature(ARCH_FEATURE_FP16)
#define HaveFP8() HaveFeature(ARCH_FEATURE_FP8)
#define HaveFP8DOT2() HaveFeature(ARCH_FEATURE_FP8DOT2)
#define HaveFP8DOT4() HaveFeature(ARCH_FEATURE_FP8DOT4)
#define HaveFP8FMA() HaveFeature(ARCH_FEATURE_FP8FMA)
#define HaveFPRCVT() HaveFeature(ARCH_FEATURE_FPRCVT)
#define HaveFRINTTS() HaveFeature(ARCH_FEATURE_FRINTTS)
#define HaveFlagM() HaveFeature(ARCH_FEATURE_FlagM)
#define HaveFlagM2() HaveFeature(ARCH_FEATURE_FlagM2)
#define HaveGCS() HaveFeature(ARCH_FEATURE_GCS)
#define HaveHBC() HaveFeature(ARCH_FEATURE_HBC)
#define HaveI8MM() HaveFeature(ARCH_FEATURE_I8MM)
#define HaveJSCVT() HaveFeature(ARCH_FEATURE_JSCVT)
#define HaveLOR() HaveFeature(ARCH_FEATURE_LOR)
#define HaveLRCPC() HaveFeature(ARCH_FEATURE_LRCPC)
#define HaveLRCPC2() HaveFeature(ARCH_FEATURE_LRCPC2)
#define HaveLRCPC3() HaveFeature(ARCH_FEATURE_LRCPC3)
#define HaveLS64() HaveFeature(ARCH_FEATURE_LS64)
#define HaveLS64_ACCDATA() HaveFeature(ARCH_FEATURE_LS64_ACCDATA)
#define HaveLS64_V() HaveFeature(ARCH_FEATURE_LS64_V)
#define HaveLSCP() HaveFeature(ARCH_FEATURE_LSCP)
#define HaveLSE() HaveFeature(ARCH_FEATURE_LSE)
#define HaveLSE128() HaveFeature(ARCH_FEATURE_LSE128)
#define HaveLSFE() HaveFeature(ARCH_FEATURE_LSFE)
#define HaveLSUI() HaveFeature(ARCH_FEATURE_LSUI)
#define HaveLUT() HaveFeature(ARCH_FEATURE_LUT)
#define HaveMOPS() HaveFeature(ARCH_FEATURE_MOPS)
#define HaveMTE() HaveFeature(ARCH_FEATURE_MTE)
#define HaveMTE2() HaveFeature(ARCH_FEATURE_MTE2)
#define HaveNMI() HaveFeature(ARCH_FEATURE_NMI)
#define HavePAN() HaveFeature(ARCH_FEATURE_PAN)
#define HavePAuth() HaveFeature(ARCH_FEATURE_PAuth)
#define HavePAuth_LR() HaveFeature(ARCH_FEATURE_PAuth_LR)
#define HavePCDPHINT() HaveFeature(ARCH_FEATURE_PCDPHINT)
#define HavePMULL() HaveFeature(ARCH_FEATURE_PMULL)
#define HaveRAS() HaveFeature(ARCH_FEATURE_RAS)
#define HaveRDM() HaveFeature(ARCH_FEATURE_RDM)
#define HaveRPRFM() HaveFeature(ARCH_FEATURE_RPRFM)
#define HaveSB() HaveFeature(ARCH_FEATURE_SB)
#define HaveSHA1() HaveFeature(ARCH_FEATURE_SHA1)
#define HaveSHA256() HaveFeature(ARCH_FEATURE_SHA256)
#define HaveSHA3() HaveFeature(ARCH_FEATURE_SHA3)
#define HaveSHA512() HaveFeature(ARCH_FEATURE_SHA512)
#define HaveSM3() HaveFeature(ARCH_FEATURE_SM3)
#define HaveSM4() HaveFeature(ARCH_FEATURE_SM4)
#define HaveSME() HaveFeature(ARCH_FEATURE_SME)
#define HaveSME2() HaveFeature(ARCH_FEATURE_SME2)
#define HaveSME2p1() HaveFeature(ARCH_FEATURE_SME2p1)
#define HaveSME2p2() HaveFeature(ARCH_FEATURE_SME2p2)
#define HaveSME2p3() HaveFeature(ARCH_FEATURE_SME2p3)
#define HaveSME_B16B16() HaveFeature(ARCH_FEATURE_SME_B16B16)
#define HaveSME_F16F16() HaveFeature(ARCH_FEATURE_SME_F16F16)
#define HaveSME_F64F64() HaveFeature(ARCH_FEATURE_SME_F64F64)
#define HaveSME_F8F16() HaveFeature(ARCH_FEATURE_SME_F8F16)
#define HaveSME_F8F32() HaveFeature(ARCH_FEATURE_SME_F8F32)
#define HaveSME_I16I64() HaveFeature(ARCH_FEATURE_SME_I16I64)
#define HaveSME_LUTv2() HaveFeature(ARCH_FEATURE_SME_LUTv2)
#define HaveSME_MOP4() HaveFeature(ARCH_FEATURE_SME_MOP4)
#define HaveSME_TMOP() HaveFeature(ARCH_FEATURE_SME_TMOP)
#define HaveSPE() HaveFeature(ARCH_FEATURE_SPE)
#define HaveSSBS() HaveFeature(ARCH_FEATURE_SSBS)
#define HaveSSVE_FEXPA() HaveFeature(ARCH_FEATURE_SSVE_FEXPA)
#define HaveSVE() HaveFeature(ARCH_FEATURE_SVE)
#define HaveSVE2() HaveFeature(ARCH_FEATURE_SVE2)
#define HaveSVE2FP8DOT2() HaveFeature(ARCH_FEATURE_SVE2FP8DOT2)
#define HaveSVE2FP8DOT4() HaveFeature(ARCH_FEATURE_SVE2FP8DOT4)
#define HaveSVE2FP8FMA() HaveFeature(ARCH_FEATURE_SVE2FP8FMA)
#define HaveSVE2p1() HaveFeature(ARCH_FEATURE_SVE2p1)
#define HaveSVE2p2() HaveFeature(ARCH_FEATURE_SVE2p2)
#define HaveSVE2p3() HaveFeature(ARCH_FEATURE_SVE2p3)
#define HaveSVE_AES() HaveFeature(ARCH_FEATURE_SVE_AES)
#define HaveSVE_AES2() HaveFeature(ARCH_FEATURE_SVE_AES2)
#define HaveSVE_B16B16() HaveFeature(ARCH_FEATURE_SVE_B16B16)
#define HaveSVE_B16MM() HaveFeature(ARCH_FEATURE_SVE_B16MM)
#define HaveSVE_BFSCALE() HaveFeature(ARCH_FEATURE_SVE_BFSCALE)
#define HaveSVE_BitPerm() HaveFeature(ARCH_FEATURE_SVE_BitPerm)
#define HaveSVE_F16F32MM() HaveFeature(ARCH_FEATURE_SVE_F16F32MM)
#define HaveSVE_PMULL128() HaveFeature(ARCH_FEATURE_SVE_PMULL128)
#define HaveSVE_SHA3() HaveFeature(ARCH_FEATURE_SVE_SHA3)
#define HaveSVE_SM4() HaveFeature(ARCH_FEATURE_SVE_SM4)
#define HaveSYSINSTR128() HaveFeature(ARCH_FEATURE_SYSINSTR128)
#define HaveSYSREG128() HaveFeature(ARCH_FEATURE_SYSREG128)
#define HaveTHE() HaveFeature(ARCH_FEATURE_THE)
#define HaveTRF() HaveFeature(ARCH_FEATURE_TRF)
#define HaveUAO() HaveFeature(ARCH_FEATURE_UAO)
#define HaveVHE() HaveFeature(ARCH_FEATURE_VHE)
#define HaveWFxT() HaveFeature(ARCH_FEATURE_WFxT)
#define HaveXS() HaveFeature(ARCH_FEATURE_XS)

#define ARCH_FEATURE_AES                0  // Referenced by decode and pcode
#define ARCH_FEATURE_AdvSIMD            1  // Referenced by decode and pcode
#define ARCH_FEATURE_BF16               2  // Referenced by decode and pcode
#define ARCH_FEATURE_BTI                3  // Referenced by decode and pcode
#define ARCH_FEATURE_CHK                4  // Referenced by decode and pcode
#define ARCH_FEATURE_CLRBHB             5  // Referenced by decode and pcode
#define ARCH_FEATURE_CMH                6  // Referenced by decode and pcode
#define ARCH_FEATURE_CMPBR              7  // Referenced by decode and pcode
#define ARCH_FEATURE_CPA                8  // Referenced by decode and pcode
#define ARCH_FEATURE_CRC32              9  // Referenced by decode and pcode
#define ARCH_FEATURE_CSSC              10  // Referenced by decode and pcode
#define ARCH_FEATURE_D128              11  // Referenced by decode and pcode
#define ARCH_FEATURE_DGH               12  // Referenced by decode and pcode
#define ARCH_FEATURE_DIT               13  // Referenced by pcode
#define ARCH_FEATURE_DotProd           14  // Referenced by decode and pcode
#define ARCH_FEATURE_EBEP              15  // Referenced by pcode
#define ARCH_FEATURE_F16F32DOT         16  // Referenced by decode and pcode
#define ARCH_FEATURE_F16F32MM          17  // Referenced by decode and pcode
#define ARCH_FEATURE_F16MM             18  // Referenced by decode and pcode
#define ARCH_FEATURE_F32MM             19  // Referenced by decode and pcode
#define ARCH_FEATURE_F64MM             20  // Referenced by decode and pcode
#define ARCH_FEATURE_F8F16MM           21  // Referenced by decode and pcode
#define ARCH_FEATURE_F8F32MM           22  // Referenced by decode and pcode
#define ARCH_FEATURE_FAMINMAX          23  // Referenced by decode and pcode
#define ARCH_FEATURE_FCMA              24  // Referenced by decode and pcode
#define ARCH_FEATURE_FHM               25  // Referenced by decode and pcode
#define ARCH_FEATURE_FP                26  // Referenced by decode and pcode
#define ARCH_FEATURE_FP16              27  // Referenced by decode and pcode
#define ARCH_FEATURE_FP8               28  // Referenced by decode and pcode
#define ARCH_FEATURE_FP8DOT2           29  // Referenced by decode and pcode
#define ARCH_FEATURE_FP8DOT4           30  // Referenced by decode and pcode
#define ARCH_FEATURE_FP8FMA            31  // Referenced by decode and pcode
#define ARCH_FEATURE_FPRCVT            32  // Referenced by decode and pcode
#define ARCH_FEATURE_FRINTTS           33  // Referenced by decode and pcode
#define ARCH_FEATURE_FlagM             34  // Referenced by decode and pcode
#define ARCH_FEATURE_FlagM2            35  // Referenced by decode and pcode
#define ARCH_FEATURE_GCS               36  // Referenced by decode and pcode
#define ARCH_FEATURE_HBC               37  // Referenced by decode and pcode
#define ARCH_FEATURE_I8MM              38  // Referenced by decode and pcode
#define ARCH_FEATURE_JSCVT             39  // Referenced by decode and pcode
#define ARCH_FEATURE_LOR               40  // Referenced by decode and pcode
#define ARCH_FEATURE_LRCPC             41  // Referenced by decode and pcode
#define ARCH_FEATURE_LRCPC2            42  // Referenced by decode and pcode
#define ARCH_FEATURE_LRCPC3            43  // Referenced by decode and pcode
#define ARCH_FEATURE_LS64              44  // Referenced by decode and pcode
#define ARCH_FEATURE_LS64_ACCDATA      45  // Referenced by decode and pcode
#define ARCH_FEATURE_LS64_V            46  // Referenced by decode and pcode
#define ARCH_FEATURE_LSCP              47  // Referenced by decode and pcode
#define ARCH_FEATURE_LSE               48  // Referenced by decode and pcode
#define ARCH_FEATURE_LSE128            49  // Referenced by decode and pcode
#define ARCH_FEATURE_LSFE              50  // Referenced by decode and pcode
#define ARCH_FEATURE_LSUI              51  // Referenced by decode and pcode
#define ARCH_FEATURE_LUT               52  // Referenced by decode and pcode
#define ARCH_FEATURE_MOPS              53  // Referenced by decode and pcode
#define ARCH_FEATURE_MTE               54  // Referenced by decode and pcode
#define ARCH_FEATURE_MTE2              55  // Referenced by decode and pcode
#define ARCH_FEATURE_NMI               56  // Referenced by pcode
#define ARCH_FEATURE_PAN               57  // Referenced by pcode
#define ARCH_FEATURE_PAuth             58  // Referenced by decode and pcode
#define ARCH_FEATURE_PAuth_LR          59  // Referenced by decode and pcode
#define ARCH_FEATURE_PCDPHINT          60  // Referenced by decode and pcode
#define ARCH_FEATURE_PMULL             61  // Referenced by pcode
#define ARCH_FEATURE_RAS               62  // Referenced by decode and pcode
#define ARCH_FEATURE_RDM               63  // Referenced by decode and pcode
#define ARCH_FEATURE_RPRFM             64  // Referenced by decode and pcode
#define ARCH_FEATURE_SB                65  // Referenced by decode and pcode
#define ARCH_FEATURE_SHA1              66  // Referenced by decode and pcode
#define ARCH_FEATURE_SHA256            67  // Referenced by decode and pcode
#define ARCH_FEATURE_SHA3              68  // Referenced by decode and pcode
#define ARCH_FEATURE_SHA512            69  // Referenced by decode and pcode
#define ARCH_FEATURE_SM3               70  // Referenced by decode and pcode
#define ARCH_FEATURE_SM4               71  // Referenced by decode and pcode
#define ARCH_FEATURE_SME               72  // Referenced by decode and pcode
#define ARCH_FEATURE_SME2              73  // Referenced by decode and pcode
#define ARCH_FEATURE_SME2p1            74  // Referenced by decode and pcode
#define ARCH_FEATURE_SME2p2            75  // Referenced by decode and pcode
#define ARCH_FEATURE_SME2p3            76  // Referenced by decode and pcode
#define ARCH_FEATURE_SME_B16B16        77  // Referenced by decode and pcode
#define ARCH_FEATURE_SME_F16F16        78  // Referenced by decode and pcode
#define ARCH_FEATURE_SME_F64F64        79  // Referenced by decode and pcode
#define ARCH_FEATURE_SME_F8F16         80  // Referenced by decode and pcode
#define ARCH_FEATURE_SME_F8F32         81  // Referenced by decode and pcode
#define ARCH_FEATURE_SME_I16I64        82  // Referenced by decode and pcode
#define ARCH_FEATURE_SME_LUTv2         83  // Referenced by decode and pcode
#define ARCH_FEATURE_SME_MOP4          84  // Referenced by decode and pcode
#define ARCH_FEATURE_SME_TMOP          85  // Referenced by decode and pcode
#define ARCH_FEATURE_SPE               86  // Referenced by decode and pcode
#define ARCH_FEATURE_SSBS              87  // Referenced by pcode
#define ARCH_FEATURE_SSVE_FEXPA        88  // Referenced by decode and pcode
#define ARCH_FEATURE_SSVE_FP8DOT2      89  // Referenced by decode
#define ARCH_FEATURE_SSVE_FP8DOT4      90  // Referenced by decode
#define ARCH_FEATURE_SSVE_FP8FMA       91  // Referenced by decode
#define ARCH_FEATURE_SVE               92  // Referenced by decode and pcode
#define ARCH_FEATURE_SVE2              93  // Referenced by decode and pcode
#define ARCH_FEATURE_SVE2FP8DOT2       94  // Referenced by pcode
#define ARCH_FEATURE_SVE2FP8DOT4       95  // Referenced by pcode
#define ARCH_FEATURE_SVE2FP8FMA        96  // Referenced by pcode
#define ARCH_FEATURE_SVE2p1            97  // Referenced by decode and pcode
#define ARCH_FEATURE_SVE2p2            98  // Referenced by decode and pcode
#define ARCH_FEATURE_SVE2p3            99  // Referenced by decode and pcode
#define ARCH_FEATURE_SVE_AES          100  // Referenced by decode and pcode
#define ARCH_FEATURE_SVE_AES2         101  // Referenced by decode and pcode
#define ARCH_FEATURE_SVE_B16B16       102  // Referenced by decode and pcode
#define ARCH_FEATURE_SVE_B16MM        103  // Referenced by decode and pcode
#define ARCH_FEATURE_SVE_BFSCALE      104  // Referenced by decode and pcode
#define ARCH_FEATURE_SVE_BitPerm      105  // Referenced by decode and pcode
#define ARCH_FEATURE_SVE_F16F32MM     106  // Referenced by decode and pcode
#define ARCH_FEATURE_SVE_PMULL128     107  // Referenced by decode and pcode
#define ARCH_FEATURE_SVE_SHA3         108  // Referenced by decode and pcode
#define ARCH_FEATURE_SVE_SM4          109  // Referenced by decode and pcode
#define ARCH_FEATURE_SYSINSTR128      110  // Referenced by decode and pcode
#define ARCH_FEATURE_SYSREG128        111  // Referenced by decode and pcode
#define ARCH_FEATURE_THE              112  // Referenced by decode and pcode
#define ARCH_FEATURE_TRF              113  // Referenced by decode and pcode
#define ARCH_FEATURE_UAO              114  // Referenced by pcode
#define ARCH_FEATURE_VHE              115  // Referenced by pcode
#define ARCH_FEATURE_WFxT             116  // Referenced by decode and pcode
#define ARCH_FEATURE_XS               117  // Referenced by decode and pcode

#define ARCH_FEATURES_ENABLE_ALL(feature_field)  do { \
	    _Static_assert(sizeof(feature_field) * 8 > ARCH_FEATURE_XS, "Feature field too small for largest feature value"); \
	    memset((feature_field), 0xFF, sizeof(feature_field)); \
	} while(0)
	   
