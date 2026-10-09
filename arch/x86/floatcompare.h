#pragma once

#include "il.h"

namespace X86
{
// Intel comparison predicates in immediate order. Keep quiet/signaling variants
// distinct even when they produce the same mask bits.
// Quiet still signals invalid for SNaNs; MXCSR exceptions remain unmodeled.
enum FloatCompareOrdering { Ordered, Unordered };
enum FloatCompareExceptions { Quiet, Signaling };

struct FloatComparePredicate
{
	const char* mnemonic;
	const char* enumName;
	FloatCompareOrdering ordering;
	FloatCompareExceptions exceptions;
};

inline constexpr FloatComparePredicate FloatComparePredicates[] = {
	{"eq", "CMP_EQ_OQ", Ordered, Quiet},
	{"lt", "CMP_LT_OS", Ordered, Signaling},
	{"le", "CMP_LE_OS", Ordered, Signaling},
	{"unord", "CMP_UNORD_Q", Unordered, Quiet},
	{"neq", "CMP_NEQ_UQ", Unordered, Quiet},
	{"nlt", "CMP_NLT_US", Unordered, Signaling},
	{"nle", "CMP_NLE_US", Unordered, Signaling},
	{"ord", "CMP_ORD_Q", Ordered, Quiet},
	{"eq_uq", "CMP_EQ_UQ", Unordered, Quiet},
	{"nge", "CMP_NGE_US", Unordered, Signaling},
	{"ngt", "CMP_NGT_US", Unordered, Signaling},
	{"false", "CMP_FALSE_OQ", Ordered, Quiet},
	{"neq_oq", "CMP_NEQ_OQ", Ordered, Quiet},
	{"ge", "CMP_GE_OS", Ordered, Signaling},
	{"gt", "CMP_GT_OS", Ordered, Signaling},
	{"true", "CMP_TRUE_UQ", Unordered, Quiet},
	{"eq_os", "CMP_EQ_OS", Ordered, Signaling},
	{"lt_oq", "CMP_LT_OQ", Ordered, Quiet},
	{"le_oq", "CMP_LE_OQ", Ordered, Quiet},
	{"unord_s", "CMP_UNORD_S", Unordered, Signaling},
	{"neq_us", "CMP_NEQ_US", Unordered, Signaling},
	{"nlt_uq", "CMP_NLT_UQ", Unordered, Quiet},
	{"nle_uq", "CMP_NLE_UQ", Unordered, Quiet},
	{"ord_s", "CMP_ORD_S", Ordered, Signaling},
	{"eq_us", "CMP_EQ_US", Unordered, Signaling},
	{"nge_uq", "CMP_NGE_UQ", Unordered, Quiet},
	{"ngt_uq", "CMP_NGT_UQ", Unordered, Quiet},
	{"false_os", "CMP_FALSE_OS", Ordered, Signaling},
	{"neq_os", "CMP_NEQ_OS", Ordered, Signaling},
	{"ge_oq", "CMP_GE_OQ", Ordered, Quiet},
	{"gt_oq", "CMP_GT_OQ", Ordered, Quiet},
	{"true_us", "CMP_TRUE_US", Unordered, Signaling}
};

struct FloatCompareFamily
{
	xed_iclass_enum_t instruction;
	uint32_t registerIntrinsic;
	uint32_t memoryIntrinsic;
	const char* suffix;
	bool vex;
	X86_INTRINSIC pseudoIntrinsics[32];

	uint32_t PredicateCount() const { return vex ? 32 : 8; }
	std::string Name(uint8_t immediate) const
	{
		return std::string(vex ? "vcmp" : "cmp") + FloatComparePredicates[immediate & (PredicateCount() - 1)].mnemonic + suffix;
	}
};

inline constexpr FloatCompareFamily FloatCompareFamilies[] = {
	{XED_ICLASS_CMPSS, INTRINSIC_XED_IFORM_CMPSS_XMMss_XMMss_IMMb,
		INTRINSIC_XED_IFORM_CMPSS_XMMss_MEMss_IMMb, "ss", false,
		{
			INTRINSIC_CMPEQSS, INTRINSIC_CMPLTSS, INTRINSIC_CMPLESS, INTRINSIC_CMPUNORDSS,
			INTRINSIC_CMPNEQSS, INTRINSIC_CMPNLTSS, INTRINSIC_CMPNLESS, INTRINSIC_CMPORDSS
		}},
	{XED_ICLASS_CMPSD_XMM, INTRINSIC_XED_IFORM_CMPSD_XMM_XMMsd_XMMsd_IMMb,
		INTRINSIC_XED_IFORM_CMPSD_XMM_XMMsd_MEMsd_IMMb, "sd", false,
		{
			INTRINSIC_CMPEQSD, INTRINSIC_CMPLTSD, INTRINSIC_CMPLESD, INTRINSIC_CMPUNORDSD,
			INTRINSIC_CMPNEQSD, INTRINSIC_CMPNLTSD, INTRINSIC_CMPNLESD, INTRINSIC_CMPORDSD
		}},
	{XED_ICLASS_CMPPS, INTRINSIC_XED_IFORM_CMPPS_XMMps_XMMps_IMMb,
		INTRINSIC_XED_IFORM_CMPPS_XMMps_MEMps_IMMb, "ps", false,
		{
			INTRINSIC_CMPEQPS, INTRINSIC_CMPLTPS, INTRINSIC_CMPLEPS, INTRINSIC_CMPUNORDPS,
			INTRINSIC_CMPNEQPS, INTRINSIC_CMPNLTPS, INTRINSIC_CMPNLEPS, INTRINSIC_CMPORDPS
		}},
	{XED_ICLASS_CMPPD, INTRINSIC_XED_IFORM_CMPPD_XMMpd_XMMpd_IMMb,
		INTRINSIC_XED_IFORM_CMPPD_XMMpd_MEMpd_IMMb, "pd", false,
		{
			INTRINSIC_CMPEQPD, INTRINSIC_CMPLTPD, INTRINSIC_CMPLEPD, INTRINSIC_CMPUNORDPD,
			INTRINSIC_CMPNEQPD, INTRINSIC_CMPNLTPD, INTRINSIC_CMPNLEPD, INTRINSIC_CMPORDPD
		}},
	{XED_ICLASS_VCMPSS, INTRINSIC_XED_IFORM_VCMPSS_XMMdq_XMMdq_XMMd_IMMb,
		INTRINSIC_XED_IFORM_VCMPSS_XMMdq_XMMdq_MEMd_IMMb, "ss", true,
		{
			INTRINSIC_VCMPEQSS, INTRINSIC_VCMPLTSS, INTRINSIC_VCMPLESS, INTRINSIC_VCMPUNORDSS,
			INTRINSIC_VCMPNEQSS, INTRINSIC_VCMPNLTSS, INTRINSIC_VCMPNLESS, INTRINSIC_VCMPORDSS,
			INTRINSIC_VCMPEQ_UQSS, INTRINSIC_VCMPNGESS, INTRINSIC_VCMPNGTSS, INTRINSIC_VCMPFALSESS,
			INTRINSIC_VCMPNEQ_OQSS, INTRINSIC_VCMPGESS, INTRINSIC_VCMPGTSS, INTRINSIC_VCMPTRUESS,
			INTRINSIC_VCMPEQ_OSSS, INTRINSIC_VCMPLT_OQSS, INTRINSIC_VCMPLE_OQSS, INTRINSIC_VCMPUNORD_SSS,
			INTRINSIC_VCMPNEQ_USSS, INTRINSIC_VCMPNLT_UQSS, INTRINSIC_VCMPNLE_UQSS, INTRINSIC_VCMPORD_SSS,
			INTRINSIC_VCMPEQ_USSS, INTRINSIC_VCMPNGE_UQSS, INTRINSIC_VCMPNGT_UQSS, INTRINSIC_VCMPFALSE_OSSS,
			INTRINSIC_VCMPNEQ_OSSS, INTRINSIC_VCMPGE_OQSS, INTRINSIC_VCMPGT_OQSS, INTRINSIC_VCMPTRUE_USSS
		}},
	{XED_ICLASS_VCMPSD, INTRINSIC_XED_IFORM_VCMPSD_XMMdq_XMMdq_XMMq_IMMb,
		INTRINSIC_XED_IFORM_VCMPSD_XMMdq_XMMdq_MEMq_IMMb, "sd", true,
		{
			INTRINSIC_VCMPEQSD, INTRINSIC_VCMPLTSD, INTRINSIC_VCMPLESD, INTRINSIC_VCMPUNORDSD,
			INTRINSIC_VCMPNEQSD, INTRINSIC_VCMPNLTSD, INTRINSIC_VCMPNLESD, INTRINSIC_VCMPORDSD,
			INTRINSIC_VCMPEQ_UQSD, INTRINSIC_VCMPNGESD, INTRINSIC_VCMPNGTSD, INTRINSIC_VCMPFALSESD,
			INTRINSIC_VCMPNEQ_OQSD, INTRINSIC_VCMPGESD, INTRINSIC_VCMPGTSD, INTRINSIC_VCMPTRUESD,
			INTRINSIC_VCMPEQ_OSSD, INTRINSIC_VCMPLT_OQSD, INTRINSIC_VCMPLE_OQSD, INTRINSIC_VCMPUNORD_SSD,
			INTRINSIC_VCMPNEQ_USSD, INTRINSIC_VCMPNLT_UQSD, INTRINSIC_VCMPNLE_UQSD, INTRINSIC_VCMPORD_SSD,
			INTRINSIC_VCMPEQ_USSD, INTRINSIC_VCMPNGE_UQSD, INTRINSIC_VCMPNGT_UQSD, INTRINSIC_VCMPFALSE_OSSD,
			INTRINSIC_VCMPNEQ_OSSD, INTRINSIC_VCMPGE_OQSD, INTRINSIC_VCMPGT_OQSD, INTRINSIC_VCMPTRUE_USSD
		}}
};

inline const FloatCompareFamily* GetFloatCompareFamily(const xed_decoded_inst_t* xedd)
{
	// EVEX mask outputs use a different contract.
	if (xed_classify_avx512(xedd))
		return nullptr;
	for (const auto& family : FloatCompareFamilies)
		if (family.instruction == xed_decoded_inst_get_iclass(xedd))
			return &family;
	return nullptr;
}

inline const FloatCompareFamily* GetFloatComparePseudoIntrinsicFamily(uint32_t intrinsic, uint32_t* predicate = nullptr)
{
	for (const auto& family : FloatCompareFamilies)
		for (uint32_t i = 0; i < family.PredicateCount(); i++)
			if (intrinsic == family.pseudoIntrinsics[i])
			{
				if (predicate)
					*predicate = i;
				return &family;
			}
	return nullptr;
}

inline const FloatCompareFamily* GetFloatCompareIntrinsicFamily(uint32_t intrinsic)
{
	for (const auto& family : FloatCompareFamilies)
		if (intrinsic == family.registerIntrinsic || intrinsic == family.memoryIntrinsic)
			return &family;
	return nullptr;
}
}
