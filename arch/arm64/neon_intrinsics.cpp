#include "neon_intrinsics.h"
#include "il_macros.h"

string NeonGetIntrinsicName(uint32_t intrinsic)
{
	switch (intrinsic)
	{
	case ARM64_INTRIN_VADD_S8:
		return "vadd_s8";
	case ARM64_INTRIN_VADDQ_S8:
		return "vaddq_s8";
	case ARM64_INTRIN_VADD_S16:
		return "vadd_s16";
	case ARM64_INTRIN_VADDQ_S16:
		return "vaddq_s16";
	case ARM64_INTRIN_VADD_S32:
		return "vadd_s32";
	case ARM64_INTRIN_VADDQ_S32:
		return "vaddq_s32";
	case ARM64_INTRIN_VADD_S64:
		return "vadd_s64";
	case ARM64_INTRIN_VADDQ_S64:
		return "vaddq_s64";
	case ARM64_INTRIN_VADD_U8:
		return "vadd_u8";
	case ARM64_INTRIN_VADDQ_U8:
		return "vaddq_u8";
	case ARM64_INTRIN_VADD_U16:
		return "vadd_u16";
	case ARM64_INTRIN_VADDQ_U16:
		return "vaddq_u16";
	case ARM64_INTRIN_VADD_U32:
		return "vadd_u32";
	case ARM64_INTRIN_VADDQ_U32:
		return "vaddq_u32";
	case ARM64_INTRIN_VADD_U64:
		return "vadd_u64";
	case ARM64_INTRIN_VADDQ_U64:
		return "vaddq_u64";
	case ARM64_INTRIN_VADD_F32:
		return "vadd_f32";
	case ARM64_INTRIN_VADDQ_F32:
		return "vaddq_f32";
	case ARM64_INTRIN_VADD_F64:
		return "vadd_f64";
	case ARM64_INTRIN_VADDQ_F64:
		return "vaddq_f64";
	case ARM64_INTRIN_VADDD_S64:
		return "vaddd_s64";
	case ARM64_INTRIN_VADDD_U64:
		return "vaddd_u64";
	case ARM64_INTRIN_VADDL_S8:
		return "vaddl_s8";
	case ARM64_INTRIN_VADDL_S16:
		return "vaddl_s16";
	case ARM64_INTRIN_VADDL_S32:
		return "vaddl_s32";
	case ARM64_INTRIN_VADDL_U8:
		return "vaddl_u8";
	case ARM64_INTRIN_VADDL_U16:
		return "vaddl_u16";
	case ARM64_INTRIN_VADDL_U32:
		return "vaddl_u32";
	case ARM64_INTRIN_VADDL_HIGH_S8:
		return "vaddl_high_s8";
	case ARM64_INTRIN_VADDL_HIGH_S16:
		return "vaddl_high_s16";
	case ARM64_INTRIN_VADDL_HIGH_S32:
		return "vaddl_high_s32";
	case ARM64_INTRIN_VADDL_HIGH_U8:
		return "vaddl_high_u8";
	case ARM64_INTRIN_VADDL_HIGH_U16:
		return "vaddl_high_u16";
	case ARM64_INTRIN_VADDL_HIGH_U32:
		return "vaddl_high_u32";
	case ARM64_INTRIN_VADDW_S8:
		return "vaddw_s8";
	case ARM64_INTRIN_VADDW_S16:
		return "vaddw_s16";
	case ARM64_INTRIN_VADDW_S32:
		return "vaddw_s32";
	case ARM64_INTRIN_VADDW_U8:
		return "vaddw_u8";
	case ARM64_INTRIN_VADDW_U16:
		return "vaddw_u16";
	case ARM64_INTRIN_VADDW_U32:
		return "vaddw_u32";
	case ARM64_INTRIN_VADDW_HIGH_S8:
		return "vaddw_high_s8";
	case ARM64_INTRIN_VADDW_HIGH_S16:
		return "vaddw_high_s16";
	case ARM64_INTRIN_VADDW_HIGH_S32:
		return "vaddw_high_s32";
	case ARM64_INTRIN_VADDW_HIGH_U8:
		return "vaddw_high_u8";
	case ARM64_INTRIN_VADDW_HIGH_U16:
		return "vaddw_high_u16";
	case ARM64_INTRIN_VADDW_HIGH_U32:
		return "vaddw_high_u32";
	case ARM64_INTRIN_VHADD_S8:
		return "vhadd_s8";
	case ARM64_INTRIN_VHADDQ_S8:
		return "vhaddq_s8";
	case ARM64_INTRIN_VHADD_S16:
		return "vhadd_s16";
	case ARM64_INTRIN_VHADDQ_S16:
		return "vhaddq_s16";
	case ARM64_INTRIN_VHADD_S32:
		return "vhadd_s32";
	case ARM64_INTRIN_VHADDQ_S32:
		return "vhaddq_s32";
	case ARM64_INTRIN_VHADD_U8:
		return "vhadd_u8";
	case ARM64_INTRIN_VHADDQ_U8:
		return "vhaddq_u8";
	case ARM64_INTRIN_VHADD_U16:
		return "vhadd_u16";
	case ARM64_INTRIN_VHADDQ_U16:
		return "vhaddq_u16";
	case ARM64_INTRIN_VHADD_U32:
		return "vhadd_u32";
	case ARM64_INTRIN_VHADDQ_U32:
		return "vhaddq_u32";
	case ARM64_INTRIN_VRHADD_S8:
		return "vrhadd_s8";
	case ARM64_INTRIN_VRHADDQ_S8:
		return "vrhaddq_s8";
	case ARM64_INTRIN_VRHADD_S16:
		return "vrhadd_s16";
	case ARM64_INTRIN_VRHADDQ_S16:
		return "vrhaddq_s16";
	case ARM64_INTRIN_VRHADD_S32:
		return "vrhadd_s32";
	case ARM64_INTRIN_VRHADDQ_S32:
		return "vrhaddq_s32";
	case ARM64_INTRIN_VRHADD_U8:
		return "vrhadd_u8";
	case ARM64_INTRIN_VRHADDQ_U8:
		return "vrhaddq_u8";
	case ARM64_INTRIN_VRHADD_U16:
		return "vrhadd_u16";
	case ARM64_INTRIN_VRHADDQ_U16:
		return "vrhaddq_u16";
	case ARM64_INTRIN_VRHADD_U32:
		return "vrhadd_u32";
	case ARM64_INTRIN_VRHADDQ_U32:
		return "vrhaddq_u32";
	case ARM64_INTRIN_VQADD_S8:
		return "vqadd_s8";
	case ARM64_INTRIN_VQADDQ_S8:
		return "vqaddq_s8";
	case ARM64_INTRIN_VQADD_S16:
		return "vqadd_s16";
	case ARM64_INTRIN_VQADDQ_S16:
		return "vqaddq_s16";
	case ARM64_INTRIN_VQADD_S32:
		return "vqadd_s32";
	case ARM64_INTRIN_VQADDQ_S32:
		return "vqaddq_s32";
	case ARM64_INTRIN_VQADD_S64:
		return "vqadd_s64";
	case ARM64_INTRIN_VQADDQ_S64:
		return "vqaddq_s64";
	case ARM64_INTRIN_VQADD_U8:
		return "vqadd_u8";
	case ARM64_INTRIN_VQADDQ_U8:
		return "vqaddq_u8";
	case ARM64_INTRIN_VQADD_U16:
		return "vqadd_u16";
	case ARM64_INTRIN_VQADDQ_U16:
		return "vqaddq_u16";
	case ARM64_INTRIN_VQADD_U32:
		return "vqadd_u32";
	case ARM64_INTRIN_VQADDQ_U32:
		return "vqaddq_u32";
	case ARM64_INTRIN_VQADD_U64:
		return "vqadd_u64";
	case ARM64_INTRIN_VQADDQ_U64:
		return "vqaddq_u64";
	case ARM64_INTRIN_VQADDB_S8:
		return "vqaddb_s8";
	case ARM64_INTRIN_VQADDH_S16:
		return "vqaddh_s16";
	case ARM64_INTRIN_VQADDS_S32:
		return "vqadds_s32";
	case ARM64_INTRIN_VQADDD_S64:
		return "vqaddd_s64";
	case ARM64_INTRIN_VQADDB_U8:
		return "vqaddb_u8";
	case ARM64_INTRIN_VQADDH_U16:
		return "vqaddh_u16";
	case ARM64_INTRIN_VQADDS_U32:
		return "vqadds_u32";
	case ARM64_INTRIN_VQADDD_U64:
		return "vqaddd_u64";
	case ARM64_INTRIN_VUQADD_S8:
		return "vuqadd_s8";
	case ARM64_INTRIN_VUQADDQ_S8:
		return "vuqaddq_s8";
	case ARM64_INTRIN_VUQADD_S16:
		return "vuqadd_s16";
	case ARM64_INTRIN_VUQADDQ_S16:
		return "vuqaddq_s16";
	case ARM64_INTRIN_VUQADD_S32:
		return "vuqadd_s32";
	case ARM64_INTRIN_VUQADDQ_S32:
		return "vuqaddq_s32";
	case ARM64_INTRIN_VUQADD_S64:
		return "vuqadd_s64";
	case ARM64_INTRIN_VUQADDQ_S64:
		return "vuqaddq_s64";
	case ARM64_INTRIN_VUQADDB_S8:
		return "vuqaddb_s8";
	case ARM64_INTRIN_VUQADDH_S16:
		return "vuqaddh_s16";
	case ARM64_INTRIN_VUQADDS_S32:
		return "vuqadds_s32";
	case ARM64_INTRIN_VUQADDD_S64:
		return "vuqaddd_s64";
	case ARM64_INTRIN_VSQADD_U8:
		return "vsqadd_u8";
	case ARM64_INTRIN_VSQADDQ_U8:
		return "vsqaddq_u8";
	case ARM64_INTRIN_VSQADD_U16:
		return "vsqadd_u16";
	case ARM64_INTRIN_VSQADDQ_U16:
		return "vsqaddq_u16";
	case ARM64_INTRIN_VSQADD_U32:
		return "vsqadd_u32";
	case ARM64_INTRIN_VSQADDQ_U32:
		return "vsqaddq_u32";
	case ARM64_INTRIN_VSQADD_U64:
		return "vsqadd_u64";
	case ARM64_INTRIN_VSQADDQ_U64:
		return "vsqaddq_u64";
	case ARM64_INTRIN_VSQADDB_U8:
		return "vsqaddb_u8";
	case ARM64_INTRIN_VSQADDH_U16:
		return "vsqaddh_u16";
	case ARM64_INTRIN_VSQADDS_U32:
		return "vsqadds_u32";
	case ARM64_INTRIN_VSQADDD_U64:
		return "vsqaddd_u64";
	case ARM64_INTRIN_VADDHN_S16:
		return "vaddhn_s16";
	case ARM64_INTRIN_VADDHN_S32:
		return "vaddhn_s32";
	case ARM64_INTRIN_VADDHN_S64:
		return "vaddhn_s64";
	case ARM64_INTRIN_VADDHN_U16:
		return "vaddhn_u16";
	case ARM64_INTRIN_VADDHN_U32:
		return "vaddhn_u32";
	case ARM64_INTRIN_VADDHN_U64:
		return "vaddhn_u64";
	case ARM64_INTRIN_VADDHN_HIGH_S16:
		return "vaddhn_high_s16";
	case ARM64_INTRIN_VADDHN_HIGH_S32:
		return "vaddhn_high_s32";
	case ARM64_INTRIN_VADDHN_HIGH_S64:
		return "vaddhn_high_s64";
	case ARM64_INTRIN_VADDHN_HIGH_U16:
		return "vaddhn_high_u16";
	case ARM64_INTRIN_VADDHN_HIGH_U32:
		return "vaddhn_high_u32";
	case ARM64_INTRIN_VADDHN_HIGH_U64:
		return "vaddhn_high_u64";
	case ARM64_INTRIN_VRADDHN_S16:
		return "vraddhn_s16";
	case ARM64_INTRIN_VRADDHN_S32:
		return "vraddhn_s32";
	case ARM64_INTRIN_VRADDHN_S64:
		return "vraddhn_s64";
	case ARM64_INTRIN_VRADDHN_U16:
		return "vraddhn_u16";
	case ARM64_INTRIN_VRADDHN_U32:
		return "vraddhn_u32";
	case ARM64_INTRIN_VRADDHN_U64:
		return "vraddhn_u64";
	case ARM64_INTRIN_VRADDHN_HIGH_S16:
		return "vraddhn_high_s16";
	case ARM64_INTRIN_VRADDHN_HIGH_S32:
		return "vraddhn_high_s32";
	case ARM64_INTRIN_VRADDHN_HIGH_S64:
		return "vraddhn_high_s64";
	case ARM64_INTRIN_VRADDHN_HIGH_U16:
		return "vraddhn_high_u16";
	case ARM64_INTRIN_VRADDHN_HIGH_U32:
		return "vraddhn_high_u32";
	case ARM64_INTRIN_VRADDHN_HIGH_U64:
		return "vraddhn_high_u64";
	case ARM64_INTRIN_VMUL_S8:
		return "vmul_s8";
	case ARM64_INTRIN_VMULQ_S8:
		return "vmulq_s8";
	case ARM64_INTRIN_VMUL_S16:
		return "vmul_s16";
	case ARM64_INTRIN_VMULQ_S16:
		return "vmulq_s16";
	case ARM64_INTRIN_VMUL_S32:
		return "vmul_s32";
	case ARM64_INTRIN_VMULQ_S32:
		return "vmulq_s32";
	case ARM64_INTRIN_VMUL_U8:
		return "vmul_u8";
	case ARM64_INTRIN_VMULQ_U8:
		return "vmulq_u8";
	case ARM64_INTRIN_VMUL_U16:
		return "vmul_u16";
	case ARM64_INTRIN_VMULQ_U16:
		return "vmulq_u16";
	case ARM64_INTRIN_VMUL_U32:
		return "vmul_u32";
	case ARM64_INTRIN_VMULQ_U32:
		return "vmulq_u32";
	case ARM64_INTRIN_VMUL_F32:
		return "vmul_f32";
	case ARM64_INTRIN_VMULQ_F32:
		return "vmulq_f32";
	case ARM64_INTRIN_VMUL_P8:
		return "vmul_p8";
	case ARM64_INTRIN_VMULQ_P8:
		return "vmulq_p8";
	case ARM64_INTRIN_VMUL_F64:
		return "vmul_f64";
	case ARM64_INTRIN_VMULQ_F64:
		return "vmulq_f64";
	case ARM64_INTRIN_VMULX_F32:
		return "vmulx_f32";
	case ARM64_INTRIN_VMULXQ_F32:
		return "vmulxq_f32";
	case ARM64_INTRIN_VMULX_F64:
		return "vmulx_f64";
	case ARM64_INTRIN_VMULXQ_F64:
		return "vmulxq_f64";
	case ARM64_INTRIN_VMULXS_F32:
		return "vmulxs_f32";
	case ARM64_INTRIN_VMULXD_F64:
		return "vmulxd_f64";
	case ARM64_INTRIN_VMULX_LANE_F32:
		return "vmulx_lane_f32";
	case ARM64_INTRIN_VMULXQ_LANE_F32:
		return "vmulxq_lane_f32";
	case ARM64_INTRIN_VMULX_LANE_F64:
		return "vmulx_lane_f64";
	case ARM64_INTRIN_VMULXQ_LANE_F64:
		return "vmulxq_lane_f64";
	case ARM64_INTRIN_VMULXS_LANE_F32:
		return "vmulxs_lane_f32";
	case ARM64_INTRIN_VMULXD_LANE_F64:
		return "vmulxd_lane_f64";
	case ARM64_INTRIN_VMULX_LANEQ_F32:
		return "vmulx_laneq_f32";
	case ARM64_INTRIN_VMULXQ_LANEQ_F32:
		return "vmulxq_laneq_f32";
	case ARM64_INTRIN_VMULX_LANEQ_F64:
		return "vmulx_laneq_f64";
	case ARM64_INTRIN_VMULXQ_LANEQ_F64:
		return "vmulxq_laneq_f64";
	case ARM64_INTRIN_VMULXS_LANEQ_F32:
		return "vmulxs_laneq_f32";
	case ARM64_INTRIN_VMULXD_LANEQ_F64:
		return "vmulxd_laneq_f64";
	case ARM64_INTRIN_VDIV_F32:
		return "vdiv_f32";
	case ARM64_INTRIN_VDIVQ_F32:
		return "vdivq_f32";
	case ARM64_INTRIN_VDIV_F64:
		return "vdiv_f64";
	case ARM64_INTRIN_VDIVQ_F64:
		return "vdivq_f64";
	case ARM64_INTRIN_VMLA_S8:
		return "vmla_s8";
	case ARM64_INTRIN_VMLAQ_S8:
		return "vmlaq_s8";
	case ARM64_INTRIN_VMLA_S16:
		return "vmla_s16";
	case ARM64_INTRIN_VMLAQ_S16:
		return "vmlaq_s16";
	case ARM64_INTRIN_VMLA_S32:
		return "vmla_s32";
	case ARM64_INTRIN_VMLAQ_S32:
		return "vmlaq_s32";
	case ARM64_INTRIN_VMLA_U8:
		return "vmla_u8";
	case ARM64_INTRIN_VMLAQ_U8:
		return "vmlaq_u8";
	case ARM64_INTRIN_VMLA_U16:
		return "vmla_u16";
	case ARM64_INTRIN_VMLAQ_U16:
		return "vmlaq_u16";
	case ARM64_INTRIN_VMLA_U32:
		return "vmla_u32";
	case ARM64_INTRIN_VMLAQ_U32:
		return "vmlaq_u32";
	case ARM64_INTRIN_VMLA_F32:
		return "vmla_f32";
	case ARM64_INTRIN_VMLAQ_F32:
		return "vmlaq_f32";
	case ARM64_INTRIN_VMLA_F64:
		return "vmla_f64";
	case ARM64_INTRIN_VMLAQ_F64:
		return "vmlaq_f64";
	case ARM64_INTRIN_VMLAL_S8:
		return "vmlal_s8";
	case ARM64_INTRIN_VMLAL_S16:
		return "vmlal_s16";
	case ARM64_INTRIN_VMLAL_S32:
		return "vmlal_s32";
	case ARM64_INTRIN_VMLAL_U8:
		return "vmlal_u8";
	case ARM64_INTRIN_VMLAL_U16:
		return "vmlal_u16";
	case ARM64_INTRIN_VMLAL_U32:
		return "vmlal_u32";
	case ARM64_INTRIN_VMLAL_HIGH_S8:
		return "vmlal_high_s8";
	case ARM64_INTRIN_VMLAL_HIGH_S16:
		return "vmlal_high_s16";
	case ARM64_INTRIN_VMLAL_HIGH_S32:
		return "vmlal_high_s32";
	case ARM64_INTRIN_VMLAL_HIGH_U8:
		return "vmlal_high_u8";
	case ARM64_INTRIN_VMLAL_HIGH_U16:
		return "vmlal_high_u16";
	case ARM64_INTRIN_VMLAL_HIGH_U32:
		return "vmlal_high_u32";
	case ARM64_INTRIN_VMLS_S8:
		return "vmls_s8";
	case ARM64_INTRIN_VMLSQ_S8:
		return "vmlsq_s8";
	case ARM64_INTRIN_VMLS_S16:
		return "vmls_s16";
	case ARM64_INTRIN_VMLSQ_S16:
		return "vmlsq_s16";
	case ARM64_INTRIN_VMLS_S32:
		return "vmls_s32";
	case ARM64_INTRIN_VMLSQ_S32:
		return "vmlsq_s32";
	case ARM64_INTRIN_VMLS_U8:
		return "vmls_u8";
	case ARM64_INTRIN_VMLSQ_U8:
		return "vmlsq_u8";
	case ARM64_INTRIN_VMLS_U16:
		return "vmls_u16";
	case ARM64_INTRIN_VMLSQ_U16:
		return "vmlsq_u16";
	case ARM64_INTRIN_VMLS_U32:
		return "vmls_u32";
	case ARM64_INTRIN_VMLSQ_U32:
		return "vmlsq_u32";
	case ARM64_INTRIN_VMLS_F32:
		return "vmls_f32";
	case ARM64_INTRIN_VMLSQ_F32:
		return "vmlsq_f32";
	case ARM64_INTRIN_VMLS_F64:
		return "vmls_f64";
	case ARM64_INTRIN_VMLSQ_F64:
		return "vmlsq_f64";
	case ARM64_INTRIN_VMLSL_S8:
		return "vmlsl_s8";
	case ARM64_INTRIN_VMLSL_S16:
		return "vmlsl_s16";
	case ARM64_INTRIN_VMLSL_S32:
		return "vmlsl_s32";
	case ARM64_INTRIN_VMLSL_U8:
		return "vmlsl_u8";
	case ARM64_INTRIN_VMLSL_U16:
		return "vmlsl_u16";
	case ARM64_INTRIN_VMLSL_U32:
		return "vmlsl_u32";
	case ARM64_INTRIN_VMLSL_HIGH_S8:
		return "vmlsl_high_s8";
	case ARM64_INTRIN_VMLSL_HIGH_S16:
		return "vmlsl_high_s16";
	case ARM64_INTRIN_VMLSL_HIGH_S32:
		return "vmlsl_high_s32";
	case ARM64_INTRIN_VMLSL_HIGH_U8:
		return "vmlsl_high_u8";
	case ARM64_INTRIN_VMLSL_HIGH_U16:
		return "vmlsl_high_u16";
	case ARM64_INTRIN_VMLSL_HIGH_U32:
		return "vmlsl_high_u32";
	case ARM64_INTRIN_VFMA_F32:
		return "vfma_f32";
	case ARM64_INTRIN_VFMAQ_F32:
		return "vfmaq_f32";
	case ARM64_INTRIN_VFMA_F64:
		return "vfma_f64";
	case ARM64_INTRIN_VFMAQ_F64:
		return "vfmaq_f64";
	case ARM64_INTRIN_VFMA_LANE_F32:
		return "vfma_lane_f32";
	case ARM64_INTRIN_VFMAQ_LANE_F32:
		return "vfmaq_lane_f32";
	case ARM64_INTRIN_VFMA_LANE_F64:
		return "vfma_lane_f64";
	case ARM64_INTRIN_VFMAQ_LANE_F64:
		return "vfmaq_lane_f64";
	case ARM64_INTRIN_VFMAS_LANE_F32:
		return "vfmas_lane_f32";
	case ARM64_INTRIN_VFMAD_LANE_F64:
		return "vfmad_lane_f64";
	case ARM64_INTRIN_VFMA_LANEQ_F32:
		return "vfma_laneq_f32";
	case ARM64_INTRIN_VFMAQ_LANEQ_F32:
		return "vfmaq_laneq_f32";
	case ARM64_INTRIN_VFMA_LANEQ_F64:
		return "vfma_laneq_f64";
	case ARM64_INTRIN_VFMAQ_LANEQ_F64:
		return "vfmaq_laneq_f64";
	case ARM64_INTRIN_VFMAS_LANEQ_F32:
		return "vfmas_laneq_f32";
	case ARM64_INTRIN_VFMAD_LANEQ_F64:
		return "vfmad_laneq_f64";
	case ARM64_INTRIN_VFMS_F32:
		return "vfms_f32";
	case ARM64_INTRIN_VFMSQ_F32:
		return "vfmsq_f32";
	case ARM64_INTRIN_VFMS_F64:
		return "vfms_f64";
	case ARM64_INTRIN_VFMSQ_F64:
		return "vfmsq_f64";
	case ARM64_INTRIN_VFMS_LANE_F32:
		return "vfms_lane_f32";
	case ARM64_INTRIN_VFMSQ_LANE_F32:
		return "vfmsq_lane_f32";
	case ARM64_INTRIN_VFMS_LANE_F64:
		return "vfms_lane_f64";
	case ARM64_INTRIN_VFMSQ_LANE_F64:
		return "vfmsq_lane_f64";
	case ARM64_INTRIN_VFMSS_LANE_F32:
		return "vfmss_lane_f32";
	case ARM64_INTRIN_VFMSD_LANE_F64:
		return "vfmsd_lane_f64";
	case ARM64_INTRIN_VFMS_LANEQ_F32:
		return "vfms_laneq_f32";
	case ARM64_INTRIN_VFMSQ_LANEQ_F32:
		return "vfmsq_laneq_f32";
	case ARM64_INTRIN_VFMS_LANEQ_F64:
		return "vfms_laneq_f64";
	case ARM64_INTRIN_VFMSQ_LANEQ_F64:
		return "vfmsq_laneq_f64";
	case ARM64_INTRIN_VFMSS_LANEQ_F32:
		return "vfmss_laneq_f32";
	case ARM64_INTRIN_VFMSD_LANEQ_F64:
		return "vfmsd_laneq_f64";
	case ARM64_INTRIN_VQDMULH_S16:
		return "vqdmulh_s16";
	case ARM64_INTRIN_VQDMULHQ_S16:
		return "vqdmulhq_s16";
	case ARM64_INTRIN_VQDMULH_S32:
		return "vqdmulh_s32";
	case ARM64_INTRIN_VQDMULHQ_S32:
		return "vqdmulhq_s32";
	case ARM64_INTRIN_VQDMULHH_S16:
		return "vqdmulhh_s16";
	case ARM64_INTRIN_VQDMULHS_S32:
		return "vqdmulhs_s32";
	case ARM64_INTRIN_VQRDMULH_S16:
		return "vqrdmulh_s16";
	case ARM64_INTRIN_VQRDMULHQ_S16:
		return "vqrdmulhq_s16";
	case ARM64_INTRIN_VQRDMULH_S32:
		return "vqrdmulh_s32";
	case ARM64_INTRIN_VQRDMULHQ_S32:
		return "vqrdmulhq_s32";
	case ARM64_INTRIN_VQRDMULHH_S16:
		return "vqrdmulhh_s16";
	case ARM64_INTRIN_VQRDMULHS_S32:
		return "vqrdmulhs_s32";
	case ARM64_INTRIN_VQDMLAL_S16:
		return "vqdmlal_s16";
	case ARM64_INTRIN_VQDMLAL_S32:
		return "vqdmlal_s32";
	case ARM64_INTRIN_VQDMLALH_S16:
		return "vqdmlalh_s16";
	case ARM64_INTRIN_VQDMLALS_S32:
		return "vqdmlals_s32";
	case ARM64_INTRIN_VQDMLAL_HIGH_S16:
		return "vqdmlal_high_s16";
	case ARM64_INTRIN_VQDMLAL_HIGH_S32:
		return "vqdmlal_high_s32";
	case ARM64_INTRIN_VQDMLSL_S16:
		return "vqdmlsl_s16";
	case ARM64_INTRIN_VQDMLSL_S32:
		return "vqdmlsl_s32";
	case ARM64_INTRIN_VQDMLSLH_S16:
		return "vqdmlslh_s16";
	case ARM64_INTRIN_VQDMLSLS_S32:
		return "vqdmlsls_s32";
	case ARM64_INTRIN_VQDMLSL_HIGH_S16:
		return "vqdmlsl_high_s16";
	case ARM64_INTRIN_VQDMLSL_HIGH_S32:
		return "vqdmlsl_high_s32";
	case ARM64_INTRIN_VMULL_S8:
		return "vmull_s8";
	case ARM64_INTRIN_VMULL_S16:
		return "vmull_s16";
	case ARM64_INTRIN_VMULL_S32:
		return "vmull_s32";
	case ARM64_INTRIN_VMULL_U8:
		return "vmull_u8";
	case ARM64_INTRIN_VMULL_U16:
		return "vmull_u16";
	case ARM64_INTRIN_VMULL_U32:
		return "vmull_u32";
	case ARM64_INTRIN_VMULL_P8:
		return "vmull_p8";
	case ARM64_INTRIN_VMULL_HIGH_S8:
		return "vmull_high_s8";
	case ARM64_INTRIN_VMULL_HIGH_S16:
		return "vmull_high_s16";
	case ARM64_INTRIN_VMULL_HIGH_S32:
		return "vmull_high_s32";
	case ARM64_INTRIN_VMULL_HIGH_U8:
		return "vmull_high_u8";
	case ARM64_INTRIN_VMULL_HIGH_U16:
		return "vmull_high_u16";
	case ARM64_INTRIN_VMULL_HIGH_U32:
		return "vmull_high_u32";
	case ARM64_INTRIN_VMULL_HIGH_P8:
		return "vmull_high_p8";
	case ARM64_INTRIN_VQDMULL_S16:
		return "vqdmull_s16";
	case ARM64_INTRIN_VQDMULL_S32:
		return "vqdmull_s32";
	case ARM64_INTRIN_VQDMULLH_S16:
		return "vqdmullh_s16";
	case ARM64_INTRIN_VQDMULLS_S32:
		return "vqdmulls_s32";
	case ARM64_INTRIN_VQDMULL_HIGH_S16:
		return "vqdmull_high_s16";
	case ARM64_INTRIN_VQDMULL_HIGH_S32:
		return "vqdmull_high_s32";
	case ARM64_INTRIN_VSUB_S8:
		return "vsub_s8";
	case ARM64_INTRIN_VSUBQ_S8:
		return "vsubq_s8";
	case ARM64_INTRIN_VSUB_S16:
		return "vsub_s16";
	case ARM64_INTRIN_VSUBQ_S16:
		return "vsubq_s16";
	case ARM64_INTRIN_VSUB_S32:
		return "vsub_s32";
	case ARM64_INTRIN_VSUBQ_S32:
		return "vsubq_s32";
	case ARM64_INTRIN_VSUB_S64:
		return "vsub_s64";
	case ARM64_INTRIN_VSUBQ_S64:
		return "vsubq_s64";
	case ARM64_INTRIN_VSUB_U8:
		return "vsub_u8";
	case ARM64_INTRIN_VSUBQ_U8:
		return "vsubq_u8";
	case ARM64_INTRIN_VSUB_U16:
		return "vsub_u16";
	case ARM64_INTRIN_VSUBQ_U16:
		return "vsubq_u16";
	case ARM64_INTRIN_VSUB_U32:
		return "vsub_u32";
	case ARM64_INTRIN_VSUBQ_U32:
		return "vsubq_u32";
	case ARM64_INTRIN_VSUB_U64:
		return "vsub_u64";
	case ARM64_INTRIN_VSUBQ_U64:
		return "vsubq_u64";
	case ARM64_INTRIN_VSUB_F32:
		return "vsub_f32";
	case ARM64_INTRIN_VSUBQ_F32:
		return "vsubq_f32";
	case ARM64_INTRIN_VSUB_F64:
		return "vsub_f64";
	case ARM64_INTRIN_VSUBQ_F64:
		return "vsubq_f64";
	case ARM64_INTRIN_VSUBD_S64:
		return "vsubd_s64";
	case ARM64_INTRIN_VSUBD_U64:
		return "vsubd_u64";
	case ARM64_INTRIN_VSUBL_S8:
		return "vsubl_s8";
	case ARM64_INTRIN_VSUBL_S16:
		return "vsubl_s16";
	case ARM64_INTRIN_VSUBL_S32:
		return "vsubl_s32";
	case ARM64_INTRIN_VSUBL_U8:
		return "vsubl_u8";
	case ARM64_INTRIN_VSUBL_U16:
		return "vsubl_u16";
	case ARM64_INTRIN_VSUBL_U32:
		return "vsubl_u32";
	case ARM64_INTRIN_VSUBL_HIGH_S8:
		return "vsubl_high_s8";
	case ARM64_INTRIN_VSUBL_HIGH_S16:
		return "vsubl_high_s16";
	case ARM64_INTRIN_VSUBL_HIGH_S32:
		return "vsubl_high_s32";
	case ARM64_INTRIN_VSUBL_HIGH_U8:
		return "vsubl_high_u8";
	case ARM64_INTRIN_VSUBL_HIGH_U16:
		return "vsubl_high_u16";
	case ARM64_INTRIN_VSUBL_HIGH_U32:
		return "vsubl_high_u32";
	case ARM64_INTRIN_VSUBW_S8:
		return "vsubw_s8";
	case ARM64_INTRIN_VSUBW_S16:
		return "vsubw_s16";
	case ARM64_INTRIN_VSUBW_S32:
		return "vsubw_s32";
	case ARM64_INTRIN_VSUBW_U8:
		return "vsubw_u8";
	case ARM64_INTRIN_VSUBW_U16:
		return "vsubw_u16";
	case ARM64_INTRIN_VSUBW_U32:
		return "vsubw_u32";
	case ARM64_INTRIN_VSUBW_HIGH_S8:
		return "vsubw_high_s8";
	case ARM64_INTRIN_VSUBW_HIGH_S16:
		return "vsubw_high_s16";
	case ARM64_INTRIN_VSUBW_HIGH_S32:
		return "vsubw_high_s32";
	case ARM64_INTRIN_VSUBW_HIGH_U8:
		return "vsubw_high_u8";
	case ARM64_INTRIN_VSUBW_HIGH_U16:
		return "vsubw_high_u16";
	case ARM64_INTRIN_VSUBW_HIGH_U32:
		return "vsubw_high_u32";
	case ARM64_INTRIN_VHSUB_S8:
		return "vhsub_s8";
	case ARM64_INTRIN_VHSUBQ_S8:
		return "vhsubq_s8";
	case ARM64_INTRIN_VHSUB_S16:
		return "vhsub_s16";
	case ARM64_INTRIN_VHSUBQ_S16:
		return "vhsubq_s16";
	case ARM64_INTRIN_VHSUB_S32:
		return "vhsub_s32";
	case ARM64_INTRIN_VHSUBQ_S32:
		return "vhsubq_s32";
	case ARM64_INTRIN_VHSUB_U8:
		return "vhsub_u8";
	case ARM64_INTRIN_VHSUBQ_U8:
		return "vhsubq_u8";
	case ARM64_INTRIN_VHSUB_U16:
		return "vhsub_u16";
	case ARM64_INTRIN_VHSUBQ_U16:
		return "vhsubq_u16";
	case ARM64_INTRIN_VHSUB_U32:
		return "vhsub_u32";
	case ARM64_INTRIN_VHSUBQ_U32:
		return "vhsubq_u32";
	case ARM64_INTRIN_VQSUB_S8:
		return "vqsub_s8";
	case ARM64_INTRIN_VQSUBQ_S8:
		return "vqsubq_s8";
	case ARM64_INTRIN_VQSUB_S16:
		return "vqsub_s16";
	case ARM64_INTRIN_VQSUBQ_S16:
		return "vqsubq_s16";
	case ARM64_INTRIN_VQSUB_S32:
		return "vqsub_s32";
	case ARM64_INTRIN_VQSUBQ_S32:
		return "vqsubq_s32";
	case ARM64_INTRIN_VQSUB_S64:
		return "vqsub_s64";
	case ARM64_INTRIN_VQSUBQ_S64:
		return "vqsubq_s64";
	case ARM64_INTRIN_VQSUB_U8:
		return "vqsub_u8";
	case ARM64_INTRIN_VQSUBQ_U8:
		return "vqsubq_u8";
	case ARM64_INTRIN_VQSUB_U16:
		return "vqsub_u16";
	case ARM64_INTRIN_VQSUBQ_U16:
		return "vqsubq_u16";
	case ARM64_INTRIN_VQSUB_U32:
		return "vqsub_u32";
	case ARM64_INTRIN_VQSUBQ_U32:
		return "vqsubq_u32";
	case ARM64_INTRIN_VQSUB_U64:
		return "vqsub_u64";
	case ARM64_INTRIN_VQSUBQ_U64:
		return "vqsubq_u64";
	case ARM64_INTRIN_VQSUBB_S8:
		return "vqsubb_s8";
	case ARM64_INTRIN_VQSUBH_S16:
		return "vqsubh_s16";
	case ARM64_INTRIN_VQSUBS_S32:
		return "vqsubs_s32";
	case ARM64_INTRIN_VQSUBD_S64:
		return "vqsubd_s64";
	case ARM64_INTRIN_VQSUBB_U8:
		return "vqsubb_u8";
	case ARM64_INTRIN_VQSUBH_U16:
		return "vqsubh_u16";
	case ARM64_INTRIN_VQSUBS_U32:
		return "vqsubs_u32";
	case ARM64_INTRIN_VQSUBD_U64:
		return "vqsubd_u64";
	case ARM64_INTRIN_VSUBHN_S16:
		return "vsubhn_s16";
	case ARM64_INTRIN_VSUBHN_S32:
		return "vsubhn_s32";
	case ARM64_INTRIN_VSUBHN_S64:
		return "vsubhn_s64";
	case ARM64_INTRIN_VSUBHN_U16:
		return "vsubhn_u16";
	case ARM64_INTRIN_VSUBHN_U32:
		return "vsubhn_u32";
	case ARM64_INTRIN_VSUBHN_U64:
		return "vsubhn_u64";
	case ARM64_INTRIN_VSUBHN_HIGH_S16:
		return "vsubhn_high_s16";
	case ARM64_INTRIN_VSUBHN_HIGH_S32:
		return "vsubhn_high_s32";
	case ARM64_INTRIN_VSUBHN_HIGH_S64:
		return "vsubhn_high_s64";
	case ARM64_INTRIN_VSUBHN_HIGH_U16:
		return "vsubhn_high_u16";
	case ARM64_INTRIN_VSUBHN_HIGH_U32:
		return "vsubhn_high_u32";
	case ARM64_INTRIN_VSUBHN_HIGH_U64:
		return "vsubhn_high_u64";
	case ARM64_INTRIN_VRSUBHN_S16:
		return "vrsubhn_s16";
	case ARM64_INTRIN_VRSUBHN_S32:
		return "vrsubhn_s32";
	case ARM64_INTRIN_VRSUBHN_S64:
		return "vrsubhn_s64";
	case ARM64_INTRIN_VRSUBHN_U16:
		return "vrsubhn_u16";
	case ARM64_INTRIN_VRSUBHN_U32:
		return "vrsubhn_u32";
	case ARM64_INTRIN_VRSUBHN_U64:
		return "vrsubhn_u64";
	case ARM64_INTRIN_VRSUBHN_HIGH_S16:
		return "vrsubhn_high_s16";
	case ARM64_INTRIN_VRSUBHN_HIGH_S32:
		return "vrsubhn_high_s32";
	case ARM64_INTRIN_VRSUBHN_HIGH_S64:
		return "vrsubhn_high_s64";
	case ARM64_INTRIN_VRSUBHN_HIGH_U16:
		return "vrsubhn_high_u16";
	case ARM64_INTRIN_VRSUBHN_HIGH_U32:
		return "vrsubhn_high_u32";
	case ARM64_INTRIN_VRSUBHN_HIGH_U64:
		return "vrsubhn_high_u64";
	case ARM64_INTRIN_VCEQ_S8:
		return "vceq_s8";
	case ARM64_INTRIN_VCEQQ_S8:
		return "vceqq_s8";
	case ARM64_INTRIN_VCEQ_S16:
		return "vceq_s16";
	case ARM64_INTRIN_VCEQQ_S16:
		return "vceqq_s16";
	case ARM64_INTRIN_VCEQ_S32:
		return "vceq_s32";
	case ARM64_INTRIN_VCEQQ_S32:
		return "vceqq_s32";
	case ARM64_INTRIN_VCEQ_U8:
		return "vceq_u8";
	case ARM64_INTRIN_VCEQQ_U8:
		return "vceqq_u8";
	case ARM64_INTRIN_VCEQ_U16:
		return "vceq_u16";
	case ARM64_INTRIN_VCEQQ_U16:
		return "vceqq_u16";
	case ARM64_INTRIN_VCEQ_U32:
		return "vceq_u32";
	case ARM64_INTRIN_VCEQQ_U32:
		return "vceqq_u32";
	case ARM64_INTRIN_VCEQ_F32:
		return "vceq_f32";
	case ARM64_INTRIN_VCEQQ_F32:
		return "vceqq_f32";
	case ARM64_INTRIN_VCEQ_P8:
		return "vceq_p8";
	case ARM64_INTRIN_VCEQQ_P8:
		return "vceqq_p8";
	case ARM64_INTRIN_VCEQ_S64:
		return "vceq_s64";
	case ARM64_INTRIN_VCEQQ_S64:
		return "vceqq_s64";
	case ARM64_INTRIN_VCEQ_U64:
		return "vceq_u64";
	case ARM64_INTRIN_VCEQQ_U64:
		return "vceqq_u64";
	case ARM64_INTRIN_VCEQ_P64:
		return "vceq_p64";
	case ARM64_INTRIN_VCEQQ_P64:
		return "vceqq_p64";
	case ARM64_INTRIN_VCEQ_F64:
		return "vceq_f64";
	case ARM64_INTRIN_VCEQQ_F64:
		return "vceqq_f64";
	case ARM64_INTRIN_VCEQD_S64:
		return "vceqd_s64";
	case ARM64_INTRIN_VCEQD_U64:
		return "vceqd_u64";
	case ARM64_INTRIN_VCEQS_F32:
		return "vceqs_f32";
	case ARM64_INTRIN_VCEQD_F64:
		return "vceqd_f64";
	case ARM64_INTRIN_VCEQZ_S8:
		return "vceqz_s8";
	case ARM64_INTRIN_VCEQZQ_S8:
		return "vceqzq_s8";
	case ARM64_INTRIN_VCEQZ_S16:
		return "vceqz_s16";
	case ARM64_INTRIN_VCEQZQ_S16:
		return "vceqzq_s16";
	case ARM64_INTRIN_VCEQZ_S32:
		return "vceqz_s32";
	case ARM64_INTRIN_VCEQZQ_S32:
		return "vceqzq_s32";
	case ARM64_INTRIN_VCEQZ_U8:
		return "vceqz_u8";
	case ARM64_INTRIN_VCEQZQ_U8:
		return "vceqzq_u8";
	case ARM64_INTRIN_VCEQZ_U16:
		return "vceqz_u16";
	case ARM64_INTRIN_VCEQZQ_U16:
		return "vceqzq_u16";
	case ARM64_INTRIN_VCEQZ_U32:
		return "vceqz_u32";
	case ARM64_INTRIN_VCEQZQ_U32:
		return "vceqzq_u32";
	case ARM64_INTRIN_VCEQZ_F32:
		return "vceqz_f32";
	case ARM64_INTRIN_VCEQZQ_F32:
		return "vceqzq_f32";
	case ARM64_INTRIN_VCEQZ_P8:
		return "vceqz_p8";
	case ARM64_INTRIN_VCEQZQ_P8:
		return "vceqzq_p8";
	case ARM64_INTRIN_VCEQZ_S64:
		return "vceqz_s64";
	case ARM64_INTRIN_VCEQZQ_S64:
		return "vceqzq_s64";
	case ARM64_INTRIN_VCEQZ_U64:
		return "vceqz_u64";
	case ARM64_INTRIN_VCEQZQ_U64:
		return "vceqzq_u64";
	case ARM64_INTRIN_VCEQZ_P64:
		return "vceqz_p64";
	case ARM64_INTRIN_VCEQZQ_P64:
		return "vceqzq_p64";
	case ARM64_INTRIN_VCEQZ_F64:
		return "vceqz_f64";
	case ARM64_INTRIN_VCEQZQ_F64:
		return "vceqzq_f64";
	case ARM64_INTRIN_VCEQZD_S64:
		return "vceqzd_s64";
	case ARM64_INTRIN_VCEQZD_U64:
		return "vceqzd_u64";
	case ARM64_INTRIN_VCEQZS_F32:
		return "vceqzs_f32";
	case ARM64_INTRIN_VCEQZD_F64:
		return "vceqzd_f64";
	case ARM64_INTRIN_VCGE_S8:
		return "vcge_s8";
	case ARM64_INTRIN_VCGEQ_S8:
		return "vcgeq_s8";
	case ARM64_INTRIN_VCGE_S16:
		return "vcge_s16";
	case ARM64_INTRIN_VCGEQ_S16:
		return "vcgeq_s16";
	case ARM64_INTRIN_VCGE_S32:
		return "vcge_s32";
	case ARM64_INTRIN_VCGEQ_S32:
		return "vcgeq_s32";
	case ARM64_INTRIN_VCGE_U8:
		return "vcge_u8";
	case ARM64_INTRIN_VCGEQ_U8:
		return "vcgeq_u8";
	case ARM64_INTRIN_VCGE_U16:
		return "vcge_u16";
	case ARM64_INTRIN_VCGEQ_U16:
		return "vcgeq_u16";
	case ARM64_INTRIN_VCGE_U32:
		return "vcge_u32";
	case ARM64_INTRIN_VCGEQ_U32:
		return "vcgeq_u32";
	case ARM64_INTRIN_VCGE_F32:
		return "vcge_f32";
	case ARM64_INTRIN_VCGEQ_F32:
		return "vcgeq_f32";
	case ARM64_INTRIN_VCGE_S64:
		return "vcge_s64";
	case ARM64_INTRIN_VCGEQ_S64:
		return "vcgeq_s64";
	case ARM64_INTRIN_VCGE_U64:
		return "vcge_u64";
	case ARM64_INTRIN_VCGEQ_U64:
		return "vcgeq_u64";
	case ARM64_INTRIN_VCGE_F64:
		return "vcge_f64";
	case ARM64_INTRIN_VCGEQ_F64:
		return "vcgeq_f64";
	case ARM64_INTRIN_VCGED_S64:
		return "vcged_s64";
	case ARM64_INTRIN_VCGED_U64:
		return "vcged_u64";
	case ARM64_INTRIN_VCGES_F32:
		return "vcges_f32";
	case ARM64_INTRIN_VCGED_F64:
		return "vcged_f64";
	case ARM64_INTRIN_VCGEZ_S8:
		return "vcgez_s8";
	case ARM64_INTRIN_VCGEZQ_S8:
		return "vcgezq_s8";
	case ARM64_INTRIN_VCGEZ_S16:
		return "vcgez_s16";
	case ARM64_INTRIN_VCGEZQ_S16:
		return "vcgezq_s16";
	case ARM64_INTRIN_VCGEZ_S32:
		return "vcgez_s32";
	case ARM64_INTRIN_VCGEZQ_S32:
		return "vcgezq_s32";
	case ARM64_INTRIN_VCGEZ_S64:
		return "vcgez_s64";
	case ARM64_INTRIN_VCGEZQ_S64:
		return "vcgezq_s64";
	case ARM64_INTRIN_VCGEZ_F32:
		return "vcgez_f32";
	case ARM64_INTRIN_VCGEZQ_F32:
		return "vcgezq_f32";
	case ARM64_INTRIN_VCGEZ_F64:
		return "vcgez_f64";
	case ARM64_INTRIN_VCGEZQ_F64:
		return "vcgezq_f64";
	case ARM64_INTRIN_VCGEZD_S64:
		return "vcgezd_s64";
	case ARM64_INTRIN_VCGEZS_F32:
		return "vcgezs_f32";
	case ARM64_INTRIN_VCGEZD_F64:
		return "vcgezd_f64";
	case ARM64_INTRIN_VCLE_S8:
		return "vcle_s8";
	case ARM64_INTRIN_VCLEQ_S8:
		return "vcleq_s8";
	case ARM64_INTRIN_VCLE_S16:
		return "vcle_s16";
	case ARM64_INTRIN_VCLEQ_S16:
		return "vcleq_s16";
	case ARM64_INTRIN_VCLE_S32:
		return "vcle_s32";
	case ARM64_INTRIN_VCLEQ_S32:
		return "vcleq_s32";
	case ARM64_INTRIN_VCLE_U8:
		return "vcle_u8";
	case ARM64_INTRIN_VCLEQ_U8:
		return "vcleq_u8";
	case ARM64_INTRIN_VCLE_U16:
		return "vcle_u16";
	case ARM64_INTRIN_VCLEQ_U16:
		return "vcleq_u16";
	case ARM64_INTRIN_VCLE_U32:
		return "vcle_u32";
	case ARM64_INTRIN_VCLEQ_U32:
		return "vcleq_u32";
	case ARM64_INTRIN_VCLE_F32:
		return "vcle_f32";
	case ARM64_INTRIN_VCLEQ_F32:
		return "vcleq_f32";
	case ARM64_INTRIN_VCLE_S64:
		return "vcle_s64";
	case ARM64_INTRIN_VCLEQ_S64:
		return "vcleq_s64";
	case ARM64_INTRIN_VCLE_U64:
		return "vcle_u64";
	case ARM64_INTRIN_VCLEQ_U64:
		return "vcleq_u64";
	case ARM64_INTRIN_VCLE_F64:
		return "vcle_f64";
	case ARM64_INTRIN_VCLEQ_F64:
		return "vcleq_f64";
	case ARM64_INTRIN_VCLED_S64:
		return "vcled_s64";
	case ARM64_INTRIN_VCLED_U64:
		return "vcled_u64";
	case ARM64_INTRIN_VCLES_F32:
		return "vcles_f32";
	case ARM64_INTRIN_VCLED_F64:
		return "vcled_f64";
	case ARM64_INTRIN_VCLEZ_S8:
		return "vclez_s8";
	case ARM64_INTRIN_VCLEZQ_S8:
		return "vclezq_s8";
	case ARM64_INTRIN_VCLEZ_S16:
		return "vclez_s16";
	case ARM64_INTRIN_VCLEZQ_S16:
		return "vclezq_s16";
	case ARM64_INTRIN_VCLEZ_S32:
		return "vclez_s32";
	case ARM64_INTRIN_VCLEZQ_S32:
		return "vclezq_s32";
	case ARM64_INTRIN_VCLEZ_S64:
		return "vclez_s64";
	case ARM64_INTRIN_VCLEZQ_S64:
		return "vclezq_s64";
	case ARM64_INTRIN_VCLEZ_F32:
		return "vclez_f32";
	case ARM64_INTRIN_VCLEZQ_F32:
		return "vclezq_f32";
	case ARM64_INTRIN_VCLEZ_F64:
		return "vclez_f64";
	case ARM64_INTRIN_VCLEZQ_F64:
		return "vclezq_f64";
	case ARM64_INTRIN_VCLEZD_S64:
		return "vclezd_s64";
	case ARM64_INTRIN_VCLEZS_F32:
		return "vclezs_f32";
	case ARM64_INTRIN_VCLEZD_F64:
		return "vclezd_f64";
	case ARM64_INTRIN_VCGT_S8:
		return "vcgt_s8";
	case ARM64_INTRIN_VCGTQ_S8:
		return "vcgtq_s8";
	case ARM64_INTRIN_VCGT_S16:
		return "vcgt_s16";
	case ARM64_INTRIN_VCGTQ_S16:
		return "vcgtq_s16";
	case ARM64_INTRIN_VCGT_S32:
		return "vcgt_s32";
	case ARM64_INTRIN_VCGTQ_S32:
		return "vcgtq_s32";
	case ARM64_INTRIN_VCGT_U8:
		return "vcgt_u8";
	case ARM64_INTRIN_VCGTQ_U8:
		return "vcgtq_u8";
	case ARM64_INTRIN_VCGT_U16:
		return "vcgt_u16";
	case ARM64_INTRIN_VCGTQ_U16:
		return "vcgtq_u16";
	case ARM64_INTRIN_VCGT_U32:
		return "vcgt_u32";
	case ARM64_INTRIN_VCGTQ_U32:
		return "vcgtq_u32";
	case ARM64_INTRIN_VCGT_F32:
		return "vcgt_f32";
	case ARM64_INTRIN_VCGTQ_F32:
		return "vcgtq_f32";
	case ARM64_INTRIN_VCGT_S64:
		return "vcgt_s64";
	case ARM64_INTRIN_VCGTQ_S64:
		return "vcgtq_s64";
	case ARM64_INTRIN_VCGT_U64:
		return "vcgt_u64";
	case ARM64_INTRIN_VCGTQ_U64:
		return "vcgtq_u64";
	case ARM64_INTRIN_VCGT_F64:
		return "vcgt_f64";
	case ARM64_INTRIN_VCGTQ_F64:
		return "vcgtq_f64";
	case ARM64_INTRIN_VCGTD_S64:
		return "vcgtd_s64";
	case ARM64_INTRIN_VCGTD_U64:
		return "vcgtd_u64";
	case ARM64_INTRIN_VCGTS_F32:
		return "vcgts_f32";
	case ARM64_INTRIN_VCGTD_F64:
		return "vcgtd_f64";
	case ARM64_INTRIN_VCGTZ_S8:
		return "vcgtz_s8";
	case ARM64_INTRIN_VCGTZQ_S8:
		return "vcgtzq_s8";
	case ARM64_INTRIN_VCGTZ_S16:
		return "vcgtz_s16";
	case ARM64_INTRIN_VCGTZQ_S16:
		return "vcgtzq_s16";
	case ARM64_INTRIN_VCGTZ_S32:
		return "vcgtz_s32";
	case ARM64_INTRIN_VCGTZQ_S32:
		return "vcgtzq_s32";
	case ARM64_INTRIN_VCGTZ_S64:
		return "vcgtz_s64";
	case ARM64_INTRIN_VCGTZQ_S64:
		return "vcgtzq_s64";
	case ARM64_INTRIN_VCGTZ_F32:
		return "vcgtz_f32";
	case ARM64_INTRIN_VCGTZQ_F32:
		return "vcgtzq_f32";
	case ARM64_INTRIN_VCGTZ_F64:
		return "vcgtz_f64";
	case ARM64_INTRIN_VCGTZQ_F64:
		return "vcgtzq_f64";
	case ARM64_INTRIN_VCGTZD_S64:
		return "vcgtzd_s64";
	case ARM64_INTRIN_VCGTZS_F32:
		return "vcgtzs_f32";
	case ARM64_INTRIN_VCGTZD_F64:
		return "vcgtzd_f64";
	case ARM64_INTRIN_VCLT_S8:
		return "vclt_s8";
	case ARM64_INTRIN_VCLTQ_S8:
		return "vcltq_s8";
	case ARM64_INTRIN_VCLT_S16:
		return "vclt_s16";
	case ARM64_INTRIN_VCLTQ_S16:
		return "vcltq_s16";
	case ARM64_INTRIN_VCLT_S32:
		return "vclt_s32";
	case ARM64_INTRIN_VCLTQ_S32:
		return "vcltq_s32";
	case ARM64_INTRIN_VCLT_U8:
		return "vclt_u8";
	case ARM64_INTRIN_VCLTQ_U8:
		return "vcltq_u8";
	case ARM64_INTRIN_VCLT_U16:
		return "vclt_u16";
	case ARM64_INTRIN_VCLTQ_U16:
		return "vcltq_u16";
	case ARM64_INTRIN_VCLT_U32:
		return "vclt_u32";
	case ARM64_INTRIN_VCLTQ_U32:
		return "vcltq_u32";
	case ARM64_INTRIN_VCLT_F32:
		return "vclt_f32";
	case ARM64_INTRIN_VCLTQ_F32:
		return "vcltq_f32";
	case ARM64_INTRIN_VCLT_S64:
		return "vclt_s64";
	case ARM64_INTRIN_VCLTQ_S64:
		return "vcltq_s64";
	case ARM64_INTRIN_VCLT_U64:
		return "vclt_u64";
	case ARM64_INTRIN_VCLTQ_U64:
		return "vcltq_u64";
	case ARM64_INTRIN_VCLT_F64:
		return "vclt_f64";
	case ARM64_INTRIN_VCLTQ_F64:
		return "vcltq_f64";
	case ARM64_INTRIN_VCLTD_S64:
		return "vcltd_s64";
	case ARM64_INTRIN_VCLTD_U64:
		return "vcltd_u64";
	case ARM64_INTRIN_VCLTS_F32:
		return "vclts_f32";
	case ARM64_INTRIN_VCLTD_F64:
		return "vcltd_f64";
	case ARM64_INTRIN_VCLTZ_S8:
		return "vcltz_s8";
	case ARM64_INTRIN_VCLTZQ_S8:
		return "vcltzq_s8";
	case ARM64_INTRIN_VCLTZ_S16:
		return "vcltz_s16";
	case ARM64_INTRIN_VCLTZQ_S16:
		return "vcltzq_s16";
	case ARM64_INTRIN_VCLTZ_S32:
		return "vcltz_s32";
	case ARM64_INTRIN_VCLTZQ_S32:
		return "vcltzq_s32";
	case ARM64_INTRIN_VCLTZ_S64:
		return "vcltz_s64";
	case ARM64_INTRIN_VCLTZQ_S64:
		return "vcltzq_s64";
	case ARM64_INTRIN_VCLTZ_F32:
		return "vcltz_f32";
	case ARM64_INTRIN_VCLTZQ_F32:
		return "vcltzq_f32";
	case ARM64_INTRIN_VCLTZ_F64:
		return "vcltz_f64";
	case ARM64_INTRIN_VCLTZQ_F64:
		return "vcltzq_f64";
	case ARM64_INTRIN_VCLTZD_S64:
		return "vcltzd_s64";
	case ARM64_INTRIN_VCLTZS_F32:
		return "vcltzs_f32";
	case ARM64_INTRIN_VCLTZD_F64:
		return "vcltzd_f64";
	case ARM64_INTRIN_VCAGE_F32:
		return "vcage_f32";
	case ARM64_INTRIN_VCAGEQ_F32:
		return "vcageq_f32";
	case ARM64_INTRIN_VCAGE_F64:
		return "vcage_f64";
	case ARM64_INTRIN_VCAGEQ_F64:
		return "vcageq_f64";
	case ARM64_INTRIN_VCAGES_F32:
		return "vcages_f32";
	case ARM64_INTRIN_VCAGED_F64:
		return "vcaged_f64";
	case ARM64_INTRIN_VCALE_F32:
		return "vcale_f32";
	case ARM64_INTRIN_VCALEQ_F32:
		return "vcaleq_f32";
	case ARM64_INTRIN_VCALE_F64:
		return "vcale_f64";
	case ARM64_INTRIN_VCALEQ_F64:
		return "vcaleq_f64";
	case ARM64_INTRIN_VCALES_F32:
		return "vcales_f32";
	case ARM64_INTRIN_VCALED_F64:
		return "vcaled_f64";
	case ARM64_INTRIN_VCAGT_F32:
		return "vcagt_f32";
	case ARM64_INTRIN_VCAGTQ_F32:
		return "vcagtq_f32";
	case ARM64_INTRIN_VCAGT_F64:
		return "vcagt_f64";
	case ARM64_INTRIN_VCAGTQ_F64:
		return "vcagtq_f64";
	case ARM64_INTRIN_VCAGTS_F32:
		return "vcagts_f32";
	case ARM64_INTRIN_VCAGTD_F64:
		return "vcagtd_f64";
	case ARM64_INTRIN_VCALT_F32:
		return "vcalt_f32";
	case ARM64_INTRIN_VCALTQ_F32:
		return "vcaltq_f32";
	case ARM64_INTRIN_VCALT_F64:
		return "vcalt_f64";
	case ARM64_INTRIN_VCALTQ_F64:
		return "vcaltq_f64";
	case ARM64_INTRIN_VCALTS_F32:
		return "vcalts_f32";
	case ARM64_INTRIN_VCALTD_F64:
		return "vcaltd_f64";
	case ARM64_INTRIN_VTST_S8:
		return "vtst_s8";
	case ARM64_INTRIN_VTSTQ_S8:
		return "vtstq_s8";
	case ARM64_INTRIN_VTST_S16:
		return "vtst_s16";
	case ARM64_INTRIN_VTSTQ_S16:
		return "vtstq_s16";
	case ARM64_INTRIN_VTST_S32:
		return "vtst_s32";
	case ARM64_INTRIN_VTSTQ_S32:
		return "vtstq_s32";
	case ARM64_INTRIN_VTST_U8:
		return "vtst_u8";
	case ARM64_INTRIN_VTSTQ_U8:
		return "vtstq_u8";
	case ARM64_INTRIN_VTST_U16:
		return "vtst_u16";
	case ARM64_INTRIN_VTSTQ_U16:
		return "vtstq_u16";
	case ARM64_INTRIN_VTST_U32:
		return "vtst_u32";
	case ARM64_INTRIN_VTSTQ_U32:
		return "vtstq_u32";
	case ARM64_INTRIN_VTST_P8:
		return "vtst_p8";
	case ARM64_INTRIN_VTSTQ_P8:
		return "vtstq_p8";
	case ARM64_INTRIN_VTST_S64:
		return "vtst_s64";
	case ARM64_INTRIN_VTSTQ_S64:
		return "vtstq_s64";
	case ARM64_INTRIN_VTST_U64:
		return "vtst_u64";
	case ARM64_INTRIN_VTSTQ_U64:
		return "vtstq_u64";
	case ARM64_INTRIN_VTST_P64:
		return "vtst_p64";
	case ARM64_INTRIN_VTSTQ_P64:
		return "vtstq_p64";
	case ARM64_INTRIN_VTSTD_S64:
		return "vtstd_s64";
	case ARM64_INTRIN_VTSTD_U64:
		return "vtstd_u64";
	case ARM64_INTRIN_VABD_S8:
		return "vabd_s8";
	case ARM64_INTRIN_VABDQ_S8:
		return "vabdq_s8";
	case ARM64_INTRIN_VABD_S16:
		return "vabd_s16";
	case ARM64_INTRIN_VABDQ_S16:
		return "vabdq_s16";
	case ARM64_INTRIN_VABD_S32:
		return "vabd_s32";
	case ARM64_INTRIN_VABDQ_S32:
		return "vabdq_s32";
	case ARM64_INTRIN_VABD_U8:
		return "vabd_u8";
	case ARM64_INTRIN_VABDQ_U8:
		return "vabdq_u8";
	case ARM64_INTRIN_VABD_U16:
		return "vabd_u16";
	case ARM64_INTRIN_VABDQ_U16:
		return "vabdq_u16";
	case ARM64_INTRIN_VABD_U32:
		return "vabd_u32";
	case ARM64_INTRIN_VABDQ_U32:
		return "vabdq_u32";
	case ARM64_INTRIN_VABD_F32:
		return "vabd_f32";
	case ARM64_INTRIN_VABDQ_F32:
		return "vabdq_f32";
	case ARM64_INTRIN_VABD_F64:
		return "vabd_f64";
	case ARM64_INTRIN_VABDQ_F64:
		return "vabdq_f64";
	case ARM64_INTRIN_VABDS_F32:
		return "vabds_f32";
	case ARM64_INTRIN_VABDD_F64:
		return "vabdd_f64";
	case ARM64_INTRIN_VABDL_S8:
		return "vabdl_s8";
	case ARM64_INTRIN_VABDL_S16:
		return "vabdl_s16";
	case ARM64_INTRIN_VABDL_S32:
		return "vabdl_s32";
	case ARM64_INTRIN_VABDL_U8:
		return "vabdl_u8";
	case ARM64_INTRIN_VABDL_U16:
		return "vabdl_u16";
	case ARM64_INTRIN_VABDL_U32:
		return "vabdl_u32";
	case ARM64_INTRIN_VABDL_HIGH_S8:
		return "vabdl_high_s8";
	case ARM64_INTRIN_VABDL_HIGH_S16:
		return "vabdl_high_s16";
	case ARM64_INTRIN_VABDL_HIGH_S32:
		return "vabdl_high_s32";
	case ARM64_INTRIN_VABDL_HIGH_U8:
		return "vabdl_high_u8";
	case ARM64_INTRIN_VABDL_HIGH_U16:
		return "vabdl_high_u16";
	case ARM64_INTRIN_VABDL_HIGH_U32:
		return "vabdl_high_u32";
	case ARM64_INTRIN_VABA_S8:
		return "vaba_s8";
	case ARM64_INTRIN_VABAQ_S8:
		return "vabaq_s8";
	case ARM64_INTRIN_VABA_S16:
		return "vaba_s16";
	case ARM64_INTRIN_VABAQ_S16:
		return "vabaq_s16";
	case ARM64_INTRIN_VABA_S32:
		return "vaba_s32";
	case ARM64_INTRIN_VABAQ_S32:
		return "vabaq_s32";
	case ARM64_INTRIN_VABA_U8:
		return "vaba_u8";
	case ARM64_INTRIN_VABAQ_U8:
		return "vabaq_u8";
	case ARM64_INTRIN_VABA_U16:
		return "vaba_u16";
	case ARM64_INTRIN_VABAQ_U16:
		return "vabaq_u16";
	case ARM64_INTRIN_VABA_U32:
		return "vaba_u32";
	case ARM64_INTRIN_VABAQ_U32:
		return "vabaq_u32";
	case ARM64_INTRIN_VABAL_S8:
		return "vabal_s8";
	case ARM64_INTRIN_VABAL_S16:
		return "vabal_s16";
	case ARM64_INTRIN_VABAL_S32:
		return "vabal_s32";
	case ARM64_INTRIN_VABAL_U8:
		return "vabal_u8";
	case ARM64_INTRIN_VABAL_U16:
		return "vabal_u16";
	case ARM64_INTRIN_VABAL_U32:
		return "vabal_u32";
	case ARM64_INTRIN_VABAL_HIGH_S8:
		return "vabal_high_s8";
	case ARM64_INTRIN_VABAL_HIGH_S16:
		return "vabal_high_s16";
	case ARM64_INTRIN_VABAL_HIGH_S32:
		return "vabal_high_s32";
	case ARM64_INTRIN_VABAL_HIGH_U8:
		return "vabal_high_u8";
	case ARM64_INTRIN_VABAL_HIGH_U16:
		return "vabal_high_u16";
	case ARM64_INTRIN_VABAL_HIGH_U32:
		return "vabal_high_u32";
	case ARM64_INTRIN_VMAX_S8:
		return "vmax_s8";
	case ARM64_INTRIN_VMAXQ_S8:
		return "vmaxq_s8";
	case ARM64_INTRIN_VMAX_S16:
		return "vmax_s16";
	case ARM64_INTRIN_VMAXQ_S16:
		return "vmaxq_s16";
	case ARM64_INTRIN_VMAX_S32:
		return "vmax_s32";
	case ARM64_INTRIN_VMAXQ_S32:
		return "vmaxq_s32";
	case ARM64_INTRIN_VMAX_U8:
		return "vmax_u8";
	case ARM64_INTRIN_VMAXQ_U8:
		return "vmaxq_u8";
	case ARM64_INTRIN_VMAX_U16:
		return "vmax_u16";
	case ARM64_INTRIN_VMAXQ_U16:
		return "vmaxq_u16";
	case ARM64_INTRIN_VMAX_U32:
		return "vmax_u32";
	case ARM64_INTRIN_VMAXQ_U32:
		return "vmaxq_u32";
	case ARM64_INTRIN_VMAX_F32:
		return "vmax_f32";
	case ARM64_INTRIN_VMAXQ_F32:
		return "vmaxq_f32";
	case ARM64_INTRIN_VMAX_F64:
		return "vmax_f64";
	case ARM64_INTRIN_VMAXQ_F64:
		return "vmaxq_f64";
	case ARM64_INTRIN_VMIN_S8:
		return "vmin_s8";
	case ARM64_INTRIN_VMINQ_S8:
		return "vminq_s8";
	case ARM64_INTRIN_VMIN_S16:
		return "vmin_s16";
	case ARM64_INTRIN_VMINQ_S16:
		return "vminq_s16";
	case ARM64_INTRIN_VMIN_S32:
		return "vmin_s32";
	case ARM64_INTRIN_VMINQ_S32:
		return "vminq_s32";
	case ARM64_INTRIN_VMIN_U8:
		return "vmin_u8";
	case ARM64_INTRIN_VMINQ_U8:
		return "vminq_u8";
	case ARM64_INTRIN_VMIN_U16:
		return "vmin_u16";
	case ARM64_INTRIN_VMINQ_U16:
		return "vminq_u16";
	case ARM64_INTRIN_VMIN_U32:
		return "vmin_u32";
	case ARM64_INTRIN_VMINQ_U32:
		return "vminq_u32";
	case ARM64_INTRIN_VMIN_F32:
		return "vmin_f32";
	case ARM64_INTRIN_VMINQ_F32:
		return "vminq_f32";
	case ARM64_INTRIN_VMIN_F64:
		return "vmin_f64";
	case ARM64_INTRIN_VMINQ_F64:
		return "vminq_f64";
	case ARM64_INTRIN_VMAXNM_F32:
		return "vmaxnm_f32";
	case ARM64_INTRIN_VMAXNMQ_F32:
		return "vmaxnmq_f32";
	case ARM64_INTRIN_VMAXNM_F64:
		return "vmaxnm_f64";
	case ARM64_INTRIN_VMAXNMQ_F64:
		return "vmaxnmq_f64";
	case ARM64_INTRIN_VMINNM_F32:
		return "vminnm_f32";
	case ARM64_INTRIN_VMINNMQ_F32:
		return "vminnmq_f32";
	case ARM64_INTRIN_VMINNM_F64:
		return "vminnm_f64";
	case ARM64_INTRIN_VMINNMQ_F64:
		return "vminnmq_f64";
	case ARM64_INTRIN_VSHL_S8:
		return "vshl_s8";
	case ARM64_INTRIN_VSHLQ_S8:
		return "vshlq_s8";
	case ARM64_INTRIN_VSHL_S16:
		return "vshl_s16";
	case ARM64_INTRIN_VSHLQ_S16:
		return "vshlq_s16";
	case ARM64_INTRIN_VSHL_S32:
		return "vshl_s32";
	case ARM64_INTRIN_VSHLQ_S32:
		return "vshlq_s32";
	case ARM64_INTRIN_VSHL_S64:
		return "vshl_s64";
	case ARM64_INTRIN_VSHLQ_S64:
		return "vshlq_s64";
	case ARM64_INTRIN_VSHL_U8:
		return "vshl_u8";
	case ARM64_INTRIN_VSHLQ_U8:
		return "vshlq_u8";
	case ARM64_INTRIN_VSHL_U16:
		return "vshl_u16";
	case ARM64_INTRIN_VSHLQ_U16:
		return "vshlq_u16";
	case ARM64_INTRIN_VSHL_U32:
		return "vshl_u32";
	case ARM64_INTRIN_VSHLQ_U32:
		return "vshlq_u32";
	case ARM64_INTRIN_VSHL_U64:
		return "vshl_u64";
	case ARM64_INTRIN_VSHLQ_U64:
		return "vshlq_u64";
	case ARM64_INTRIN_VSHLD_S64:
		return "vshld_s64";
	case ARM64_INTRIN_VSHLD_U64:
		return "vshld_u64";
	case ARM64_INTRIN_VQSHL_S8:
		return "vqshl_s8";
	case ARM64_INTRIN_VQSHLQ_S8:
		return "vqshlq_s8";
	case ARM64_INTRIN_VQSHL_S16:
		return "vqshl_s16";
	case ARM64_INTRIN_VQSHLQ_S16:
		return "vqshlq_s16";
	case ARM64_INTRIN_VQSHL_S32:
		return "vqshl_s32";
	case ARM64_INTRIN_VQSHLQ_S32:
		return "vqshlq_s32";
	case ARM64_INTRIN_VQSHL_S64:
		return "vqshl_s64";
	case ARM64_INTRIN_VQSHLQ_S64:
		return "vqshlq_s64";
	case ARM64_INTRIN_VQSHL_U8:
		return "vqshl_u8";
	case ARM64_INTRIN_VQSHLQ_U8:
		return "vqshlq_u8";
	case ARM64_INTRIN_VQSHL_U16:
		return "vqshl_u16";
	case ARM64_INTRIN_VQSHLQ_U16:
		return "vqshlq_u16";
	case ARM64_INTRIN_VQSHL_U32:
		return "vqshl_u32";
	case ARM64_INTRIN_VQSHLQ_U32:
		return "vqshlq_u32";
	case ARM64_INTRIN_VQSHL_U64:
		return "vqshl_u64";
	case ARM64_INTRIN_VQSHLQ_U64:
		return "vqshlq_u64";
	case ARM64_INTRIN_VQSHLB_S8:
		return "vqshlb_s8";
	case ARM64_INTRIN_VQSHLH_S16:
		return "vqshlh_s16";
	case ARM64_INTRIN_VQSHLS_S32:
		return "vqshls_s32";
	case ARM64_INTRIN_VQSHLD_S64:
		return "vqshld_s64";
	case ARM64_INTRIN_VQSHLB_U8:
		return "vqshlb_u8";
	case ARM64_INTRIN_VQSHLH_U16:
		return "vqshlh_u16";
	case ARM64_INTRIN_VQSHLS_U32:
		return "vqshls_u32";
	case ARM64_INTRIN_VQSHLD_U64:
		return "vqshld_u64";
	case ARM64_INTRIN_VRSHL_S8:
		return "vrshl_s8";
	case ARM64_INTRIN_VRSHLQ_S8:
		return "vrshlq_s8";
	case ARM64_INTRIN_VRSHL_S16:
		return "vrshl_s16";
	case ARM64_INTRIN_VRSHLQ_S16:
		return "vrshlq_s16";
	case ARM64_INTRIN_VRSHL_S32:
		return "vrshl_s32";
	case ARM64_INTRIN_VRSHLQ_S32:
		return "vrshlq_s32";
	case ARM64_INTRIN_VRSHL_S64:
		return "vrshl_s64";
	case ARM64_INTRIN_VRSHLQ_S64:
		return "vrshlq_s64";
	case ARM64_INTRIN_VRSHL_U8:
		return "vrshl_u8";
	case ARM64_INTRIN_VRSHLQ_U8:
		return "vrshlq_u8";
	case ARM64_INTRIN_VRSHL_U16:
		return "vrshl_u16";
	case ARM64_INTRIN_VRSHLQ_U16:
		return "vrshlq_u16";
	case ARM64_INTRIN_VRSHL_U32:
		return "vrshl_u32";
	case ARM64_INTRIN_VRSHLQ_U32:
		return "vrshlq_u32";
	case ARM64_INTRIN_VRSHL_U64:
		return "vrshl_u64";
	case ARM64_INTRIN_VRSHLQ_U64:
		return "vrshlq_u64";
	case ARM64_INTRIN_VRSHLD_S64:
		return "vrshld_s64";
	case ARM64_INTRIN_VRSHLD_U64:
		return "vrshld_u64";
	case ARM64_INTRIN_VQRSHL_S8:
		return "vqrshl_s8";
	case ARM64_INTRIN_VQRSHLQ_S8:
		return "vqrshlq_s8";
	case ARM64_INTRIN_VQRSHL_S16:
		return "vqrshl_s16";
	case ARM64_INTRIN_VQRSHLQ_S16:
		return "vqrshlq_s16";
	case ARM64_INTRIN_VQRSHL_S32:
		return "vqrshl_s32";
	case ARM64_INTRIN_VQRSHLQ_S32:
		return "vqrshlq_s32";
	case ARM64_INTRIN_VQRSHL_S64:
		return "vqrshl_s64";
	case ARM64_INTRIN_VQRSHLQ_S64:
		return "vqrshlq_s64";
	case ARM64_INTRIN_VQRSHL_U8:
		return "vqrshl_u8";
	case ARM64_INTRIN_VQRSHLQ_U8:
		return "vqrshlq_u8";
	case ARM64_INTRIN_VQRSHL_U16:
		return "vqrshl_u16";
	case ARM64_INTRIN_VQRSHLQ_U16:
		return "vqrshlq_u16";
	case ARM64_INTRIN_VQRSHL_U32:
		return "vqrshl_u32";
	case ARM64_INTRIN_VQRSHLQ_U32:
		return "vqrshlq_u32";
	case ARM64_INTRIN_VQRSHL_U64:
		return "vqrshl_u64";
	case ARM64_INTRIN_VQRSHLQ_U64:
		return "vqrshlq_u64";
	case ARM64_INTRIN_VQRSHLB_S8:
		return "vqrshlb_s8";
	case ARM64_INTRIN_VQRSHLH_S16:
		return "vqrshlh_s16";
	case ARM64_INTRIN_VQRSHLS_S32:
		return "vqrshls_s32";
	case ARM64_INTRIN_VQRSHLD_S64:
		return "vqrshld_s64";
	case ARM64_INTRIN_VQRSHLB_U8:
		return "vqrshlb_u8";
	case ARM64_INTRIN_VQRSHLH_U16:
		return "vqrshlh_u16";
	case ARM64_INTRIN_VQRSHLS_U32:
		return "vqrshls_u32";
	case ARM64_INTRIN_VQRSHLD_U64:
		return "vqrshld_u64";
	case ARM64_INTRIN_VSHR_N_S8:
		return "vshr_n_s8";
	case ARM64_INTRIN_VSHRQ_N_S8:
		return "vshrq_n_s8";
	case ARM64_INTRIN_VSHR_N_S16:
		return "vshr_n_s16";
	case ARM64_INTRIN_VSHRQ_N_S16:
		return "vshrq_n_s16";
	case ARM64_INTRIN_VSHR_N_S32:
		return "vshr_n_s32";
	case ARM64_INTRIN_VSHRQ_N_S32:
		return "vshrq_n_s32";
	case ARM64_INTRIN_VSHR_N_S64:
		return "vshr_n_s64";
	case ARM64_INTRIN_VSHRQ_N_S64:
		return "vshrq_n_s64";
	case ARM64_INTRIN_VSHR_N_U8:
		return "vshr_n_u8";
	case ARM64_INTRIN_VSHRQ_N_U8:
		return "vshrq_n_u8";
	case ARM64_INTRIN_VSHR_N_U16:
		return "vshr_n_u16";
	case ARM64_INTRIN_VSHRQ_N_U16:
		return "vshrq_n_u16";
	case ARM64_INTRIN_VSHR_N_U32:
		return "vshr_n_u32";
	case ARM64_INTRIN_VSHRQ_N_U32:
		return "vshrq_n_u32";
	case ARM64_INTRIN_VSHR_N_U64:
		return "vshr_n_u64";
	case ARM64_INTRIN_VSHRQ_N_U64:
		return "vshrq_n_u64";
	case ARM64_INTRIN_VSHRD_N_S64:
		return "vshrd_n_s64";
	case ARM64_INTRIN_VSHRD_N_U64:
		return "vshrd_n_u64";
	case ARM64_INTRIN_VSHL_N_S8:
		return "vshl_n_s8";
	case ARM64_INTRIN_VSHLQ_N_S8:
		return "vshlq_n_s8";
	case ARM64_INTRIN_VSHL_N_S16:
		return "vshl_n_s16";
	case ARM64_INTRIN_VSHLQ_N_S16:
		return "vshlq_n_s16";
	case ARM64_INTRIN_VSHL_N_S32:
		return "vshl_n_s32";
	case ARM64_INTRIN_VSHLQ_N_S32:
		return "vshlq_n_s32";
	case ARM64_INTRIN_VSHL_N_S64:
		return "vshl_n_s64";
	case ARM64_INTRIN_VSHLQ_N_S64:
		return "vshlq_n_s64";
	case ARM64_INTRIN_VSHL_N_U8:
		return "vshl_n_u8";
	case ARM64_INTRIN_VSHLQ_N_U8:
		return "vshlq_n_u8";
	case ARM64_INTRIN_VSHL_N_U16:
		return "vshl_n_u16";
	case ARM64_INTRIN_VSHLQ_N_U16:
		return "vshlq_n_u16";
	case ARM64_INTRIN_VSHL_N_U32:
		return "vshl_n_u32";
	case ARM64_INTRIN_VSHLQ_N_U32:
		return "vshlq_n_u32";
	case ARM64_INTRIN_VSHL_N_U64:
		return "vshl_n_u64";
	case ARM64_INTRIN_VSHLQ_N_U64:
		return "vshlq_n_u64";
	case ARM64_INTRIN_VSHLD_N_S64:
		return "vshld_n_s64";
	case ARM64_INTRIN_VSHLD_N_U64:
		return "vshld_n_u64";
	case ARM64_INTRIN_VRSHR_N_S8:
		return "vrshr_n_s8";
	case ARM64_INTRIN_VRSHRQ_N_S8:
		return "vrshrq_n_s8";
	case ARM64_INTRIN_VRSHR_N_S16:
		return "vrshr_n_s16";
	case ARM64_INTRIN_VRSHRQ_N_S16:
		return "vrshrq_n_s16";
	case ARM64_INTRIN_VRSHR_N_S32:
		return "vrshr_n_s32";
	case ARM64_INTRIN_VRSHRQ_N_S32:
		return "vrshrq_n_s32";
	case ARM64_INTRIN_VRSHR_N_S64:
		return "vrshr_n_s64";
	case ARM64_INTRIN_VRSHRQ_N_S64:
		return "vrshrq_n_s64";
	case ARM64_INTRIN_VRSHR_N_U8:
		return "vrshr_n_u8";
	case ARM64_INTRIN_VRSHRQ_N_U8:
		return "vrshrq_n_u8";
	case ARM64_INTRIN_VRSHR_N_U16:
		return "vrshr_n_u16";
	case ARM64_INTRIN_VRSHRQ_N_U16:
		return "vrshrq_n_u16";
	case ARM64_INTRIN_VRSHR_N_U32:
		return "vrshr_n_u32";
	case ARM64_INTRIN_VRSHRQ_N_U32:
		return "vrshrq_n_u32";
	case ARM64_INTRIN_VRSHR_N_U64:
		return "vrshr_n_u64";
	case ARM64_INTRIN_VRSHRQ_N_U64:
		return "vrshrq_n_u64";
	case ARM64_INTRIN_VRSHRD_N_S64:
		return "vrshrd_n_s64";
	case ARM64_INTRIN_VRSHRD_N_U64:
		return "vrshrd_n_u64";
	case ARM64_INTRIN_VSRA_N_S8:
		return "vsra_n_s8";
	case ARM64_INTRIN_VSRAQ_N_S8:
		return "vsraq_n_s8";
	case ARM64_INTRIN_VSRA_N_S16:
		return "vsra_n_s16";
	case ARM64_INTRIN_VSRAQ_N_S16:
		return "vsraq_n_s16";
	case ARM64_INTRIN_VSRA_N_S32:
		return "vsra_n_s32";
	case ARM64_INTRIN_VSRAQ_N_S32:
		return "vsraq_n_s32";
	case ARM64_INTRIN_VSRA_N_S64:
		return "vsra_n_s64";
	case ARM64_INTRIN_VSRAQ_N_S64:
		return "vsraq_n_s64";
	case ARM64_INTRIN_VSRA_N_U8:
		return "vsra_n_u8";
	case ARM64_INTRIN_VSRAQ_N_U8:
		return "vsraq_n_u8";
	case ARM64_INTRIN_VSRA_N_U16:
		return "vsra_n_u16";
	case ARM64_INTRIN_VSRAQ_N_U16:
		return "vsraq_n_u16";
	case ARM64_INTRIN_VSRA_N_U32:
		return "vsra_n_u32";
	case ARM64_INTRIN_VSRAQ_N_U32:
		return "vsraq_n_u32";
	case ARM64_INTRIN_VSRA_N_U64:
		return "vsra_n_u64";
	case ARM64_INTRIN_VSRAQ_N_U64:
		return "vsraq_n_u64";
	case ARM64_INTRIN_VSRAD_N_S64:
		return "vsrad_n_s64";
	case ARM64_INTRIN_VSRAD_N_U64:
		return "vsrad_n_u64";
	case ARM64_INTRIN_VRSRA_N_S8:
		return "vrsra_n_s8";
	case ARM64_INTRIN_VRSRAQ_N_S8:
		return "vrsraq_n_s8";
	case ARM64_INTRIN_VRSRA_N_S16:
		return "vrsra_n_s16";
	case ARM64_INTRIN_VRSRAQ_N_S16:
		return "vrsraq_n_s16";
	case ARM64_INTRIN_VRSRA_N_S32:
		return "vrsra_n_s32";
	case ARM64_INTRIN_VRSRAQ_N_S32:
		return "vrsraq_n_s32";
	case ARM64_INTRIN_VRSRA_N_S64:
		return "vrsra_n_s64";
	case ARM64_INTRIN_VRSRAQ_N_S64:
		return "vrsraq_n_s64";
	case ARM64_INTRIN_VRSRA_N_U8:
		return "vrsra_n_u8";
	case ARM64_INTRIN_VRSRAQ_N_U8:
		return "vrsraq_n_u8";
	case ARM64_INTRIN_VRSRA_N_U16:
		return "vrsra_n_u16";
	case ARM64_INTRIN_VRSRAQ_N_U16:
		return "vrsraq_n_u16";
	case ARM64_INTRIN_VRSRA_N_U32:
		return "vrsra_n_u32";
	case ARM64_INTRIN_VRSRAQ_N_U32:
		return "vrsraq_n_u32";
	case ARM64_INTRIN_VRSRA_N_U64:
		return "vrsra_n_u64";
	case ARM64_INTRIN_VRSRAQ_N_U64:
		return "vrsraq_n_u64";
	case ARM64_INTRIN_VRSRAD_N_S64:
		return "vrsrad_n_s64";
	case ARM64_INTRIN_VRSRAD_N_U64:
		return "vrsrad_n_u64";
	case ARM64_INTRIN_VQSHL_N_S8:
		return "vqshl_n_s8";
	case ARM64_INTRIN_VQSHLQ_N_S8:
		return "vqshlq_n_s8";
	case ARM64_INTRIN_VQSHL_N_S16:
		return "vqshl_n_s16";
	case ARM64_INTRIN_VQSHLQ_N_S16:
		return "vqshlq_n_s16";
	case ARM64_INTRIN_VQSHL_N_S32:
		return "vqshl_n_s32";
	case ARM64_INTRIN_VQSHLQ_N_S32:
		return "vqshlq_n_s32";
	case ARM64_INTRIN_VQSHL_N_S64:
		return "vqshl_n_s64";
	case ARM64_INTRIN_VQSHLQ_N_S64:
		return "vqshlq_n_s64";
	case ARM64_INTRIN_VQSHL_N_U8:
		return "vqshl_n_u8";
	case ARM64_INTRIN_VQSHLQ_N_U8:
		return "vqshlq_n_u8";
	case ARM64_INTRIN_VQSHL_N_U16:
		return "vqshl_n_u16";
	case ARM64_INTRIN_VQSHLQ_N_U16:
		return "vqshlq_n_u16";
	case ARM64_INTRIN_VQSHL_N_U32:
		return "vqshl_n_u32";
	case ARM64_INTRIN_VQSHLQ_N_U32:
		return "vqshlq_n_u32";
	case ARM64_INTRIN_VQSHL_N_U64:
		return "vqshl_n_u64";
	case ARM64_INTRIN_VQSHLQ_N_U64:
		return "vqshlq_n_u64";
	case ARM64_INTRIN_VQSHLB_N_S8:
		return "vqshlb_n_s8";
	case ARM64_INTRIN_VQSHLH_N_S16:
		return "vqshlh_n_s16";
	case ARM64_INTRIN_VQSHLS_N_S32:
		return "vqshls_n_s32";
	case ARM64_INTRIN_VQSHLD_N_S64:
		return "vqshld_n_s64";
	case ARM64_INTRIN_VQSHLB_N_U8:
		return "vqshlb_n_u8";
	case ARM64_INTRIN_VQSHLH_N_U16:
		return "vqshlh_n_u16";
	case ARM64_INTRIN_VQSHLS_N_U32:
		return "vqshls_n_u32";
	case ARM64_INTRIN_VQSHLD_N_U64:
		return "vqshld_n_u64";
	case ARM64_INTRIN_VQSHLU_N_S8:
		return "vqshlu_n_s8";
	case ARM64_INTRIN_VQSHLUQ_N_S8:
		return "vqshluq_n_s8";
	case ARM64_INTRIN_VQSHLU_N_S16:
		return "vqshlu_n_s16";
	case ARM64_INTRIN_VQSHLUQ_N_S16:
		return "vqshluq_n_s16";
	case ARM64_INTRIN_VQSHLU_N_S32:
		return "vqshlu_n_s32";
	case ARM64_INTRIN_VQSHLUQ_N_S32:
		return "vqshluq_n_s32";
	case ARM64_INTRIN_VQSHLU_N_S64:
		return "vqshlu_n_s64";
	case ARM64_INTRIN_VQSHLUQ_N_S64:
		return "vqshluq_n_s64";
	case ARM64_INTRIN_VQSHLUB_N_S8:
		return "vqshlub_n_s8";
	case ARM64_INTRIN_VQSHLUH_N_S16:
		return "vqshluh_n_s16";
	case ARM64_INTRIN_VQSHLUS_N_S32:
		return "vqshlus_n_s32";
	case ARM64_INTRIN_VQSHLUD_N_S64:
		return "vqshlud_n_s64";
	case ARM64_INTRIN_VSHRN_N_S16:
		return "vshrn_n_s16";
	case ARM64_INTRIN_VSHRN_N_S32:
		return "vshrn_n_s32";
	case ARM64_INTRIN_VSHRN_N_S64:
		return "vshrn_n_s64";
	case ARM64_INTRIN_VSHRN_N_U16:
		return "vshrn_n_u16";
	case ARM64_INTRIN_VSHRN_N_U32:
		return "vshrn_n_u32";
	case ARM64_INTRIN_VSHRN_N_U64:
		return "vshrn_n_u64";
	case ARM64_INTRIN_VSHRN_HIGH_N_S16:
		return "vshrn_high_n_s16";
	case ARM64_INTRIN_VSHRN_HIGH_N_S32:
		return "vshrn_high_n_s32";
	case ARM64_INTRIN_VSHRN_HIGH_N_S64:
		return "vshrn_high_n_s64";
	case ARM64_INTRIN_VSHRN_HIGH_N_U16:
		return "vshrn_high_n_u16";
	case ARM64_INTRIN_VSHRN_HIGH_N_U32:
		return "vshrn_high_n_u32";
	case ARM64_INTRIN_VSHRN_HIGH_N_U64:
		return "vshrn_high_n_u64";
	case ARM64_INTRIN_VQSHRUN_N_S16:
		return "vqshrun_n_s16";
	case ARM64_INTRIN_VQSHRUN_N_S32:
		return "vqshrun_n_s32";
	case ARM64_INTRIN_VQSHRUN_N_S64:
		return "vqshrun_n_s64";
	case ARM64_INTRIN_VQSHRUNH_N_S16:
		return "vqshrunh_n_s16";
	case ARM64_INTRIN_VQSHRUNS_N_S32:
		return "vqshruns_n_s32";
	case ARM64_INTRIN_VQSHRUND_N_S64:
		return "vqshrund_n_s64";
	case ARM64_INTRIN_VQSHRUN_HIGH_N_S16:
		return "vqshrun_high_n_s16";
	case ARM64_INTRIN_VQSHRUN_HIGH_N_S32:
		return "vqshrun_high_n_s32";
	case ARM64_INTRIN_VQSHRUN_HIGH_N_S64:
		return "vqshrun_high_n_s64";
	case ARM64_INTRIN_VQRSHRUN_N_S16:
		return "vqrshrun_n_s16";
	case ARM64_INTRIN_VQRSHRUN_N_S32:
		return "vqrshrun_n_s32";
	case ARM64_INTRIN_VQRSHRUN_N_S64:
		return "vqrshrun_n_s64";
	case ARM64_INTRIN_VQRSHRUNH_N_S16:
		return "vqrshrunh_n_s16";
	case ARM64_INTRIN_VQRSHRUNS_N_S32:
		return "vqrshruns_n_s32";
	case ARM64_INTRIN_VQRSHRUND_N_S64:
		return "vqrshrund_n_s64";
	case ARM64_INTRIN_VQRSHRUN_HIGH_N_S16:
		return "vqrshrun_high_n_s16";
	case ARM64_INTRIN_VQRSHRUN_HIGH_N_S32:
		return "vqrshrun_high_n_s32";
	case ARM64_INTRIN_VQRSHRUN_HIGH_N_S64:
		return "vqrshrun_high_n_s64";
	case ARM64_INTRIN_VQSHRN_N_S16:
		return "vqshrn_n_s16";
	case ARM64_INTRIN_VQSHRN_N_S32:
		return "vqshrn_n_s32";
	case ARM64_INTRIN_VQSHRN_N_S64:
		return "vqshrn_n_s64";
	case ARM64_INTRIN_VQSHRN_N_U16:
		return "vqshrn_n_u16";
	case ARM64_INTRIN_VQSHRN_N_U32:
		return "vqshrn_n_u32";
	case ARM64_INTRIN_VQSHRN_N_U64:
		return "vqshrn_n_u64";
	case ARM64_INTRIN_VQSHRNH_N_S16:
		return "vqshrnh_n_s16";
	case ARM64_INTRIN_VQSHRNS_N_S32:
		return "vqshrns_n_s32";
	case ARM64_INTRIN_VQSHRND_N_S64:
		return "vqshrnd_n_s64";
	case ARM64_INTRIN_VQSHRNH_N_U16:
		return "vqshrnh_n_u16";
	case ARM64_INTRIN_VQSHRNS_N_U32:
		return "vqshrns_n_u32";
	case ARM64_INTRIN_VQSHRND_N_U64:
		return "vqshrnd_n_u64";
	case ARM64_INTRIN_VQSHRN_HIGH_N_S16:
		return "vqshrn_high_n_s16";
	case ARM64_INTRIN_VQSHRN_HIGH_N_S32:
		return "vqshrn_high_n_s32";
	case ARM64_INTRIN_VQSHRN_HIGH_N_S64:
		return "vqshrn_high_n_s64";
	case ARM64_INTRIN_VQSHRN_HIGH_N_U16:
		return "vqshrn_high_n_u16";
	case ARM64_INTRIN_VQSHRN_HIGH_N_U32:
		return "vqshrn_high_n_u32";
	case ARM64_INTRIN_VQSHRN_HIGH_N_U64:
		return "vqshrn_high_n_u64";
	case ARM64_INTRIN_VRSHRN_N_S16:
		return "vrshrn_n_s16";
	case ARM64_INTRIN_VRSHRN_N_S32:
		return "vrshrn_n_s32";
	case ARM64_INTRIN_VRSHRN_N_S64:
		return "vrshrn_n_s64";
	case ARM64_INTRIN_VRSHRN_N_U16:
		return "vrshrn_n_u16";
	case ARM64_INTRIN_VRSHRN_N_U32:
		return "vrshrn_n_u32";
	case ARM64_INTRIN_VRSHRN_N_U64:
		return "vrshrn_n_u64";
	case ARM64_INTRIN_VRSHRN_HIGH_N_S16:
		return "vrshrn_high_n_s16";
	case ARM64_INTRIN_VRSHRN_HIGH_N_S32:
		return "vrshrn_high_n_s32";
	case ARM64_INTRIN_VRSHRN_HIGH_N_S64:
		return "vrshrn_high_n_s64";
	case ARM64_INTRIN_VRSHRN_HIGH_N_U16:
		return "vrshrn_high_n_u16";
	case ARM64_INTRIN_VRSHRN_HIGH_N_U32:
		return "vrshrn_high_n_u32";
	case ARM64_INTRIN_VRSHRN_HIGH_N_U64:
		return "vrshrn_high_n_u64";
	case ARM64_INTRIN_VQRSHRN_N_S16:
		return "vqrshrn_n_s16";
	case ARM64_INTRIN_VQRSHRN_N_S32:
		return "vqrshrn_n_s32";
	case ARM64_INTRIN_VQRSHRN_N_S64:
		return "vqrshrn_n_s64";
	case ARM64_INTRIN_VQRSHRN_N_U16:
		return "vqrshrn_n_u16";
	case ARM64_INTRIN_VQRSHRN_N_U32:
		return "vqrshrn_n_u32";
	case ARM64_INTRIN_VQRSHRN_N_U64:
		return "vqrshrn_n_u64";
	case ARM64_INTRIN_VQRSHRNH_N_S16:
		return "vqrshrnh_n_s16";
	case ARM64_INTRIN_VQRSHRNS_N_S32:
		return "vqrshrns_n_s32";
	case ARM64_INTRIN_VQRSHRND_N_S64:
		return "vqrshrnd_n_s64";
	case ARM64_INTRIN_VQRSHRNH_N_U16:
		return "vqrshrnh_n_u16";
	case ARM64_INTRIN_VQRSHRNS_N_U32:
		return "vqrshrns_n_u32";
	case ARM64_INTRIN_VQRSHRND_N_U64:
		return "vqrshrnd_n_u64";
	case ARM64_INTRIN_VQRSHRN_HIGH_N_S16:
		return "vqrshrn_high_n_s16";
	case ARM64_INTRIN_VQRSHRN_HIGH_N_S32:
		return "vqrshrn_high_n_s32";
	case ARM64_INTRIN_VQRSHRN_HIGH_N_S64:
		return "vqrshrn_high_n_s64";
	case ARM64_INTRIN_VQRSHRN_HIGH_N_U16:
		return "vqrshrn_high_n_u16";
	case ARM64_INTRIN_VQRSHRN_HIGH_N_U32:
		return "vqrshrn_high_n_u32";
	case ARM64_INTRIN_VQRSHRN_HIGH_N_U64:
		return "vqrshrn_high_n_u64";
	case ARM64_INTRIN_VSHLL_N_S8:
		return "vshll_n_s8";
	case ARM64_INTRIN_VSHLL_N_S16:
		return "vshll_n_s16";
	case ARM64_INTRIN_VSHLL_N_S32:
		return "vshll_n_s32";
	case ARM64_INTRIN_VSHLL_N_U8:
		return "vshll_n_u8";
	case ARM64_INTRIN_VSHLL_N_U16:
		return "vshll_n_u16";
	case ARM64_INTRIN_VSHLL_N_U32:
		return "vshll_n_u32";
	case ARM64_INTRIN_VSHLL_HIGH_N_S8:
		return "vshll_high_n_s8";
	case ARM64_INTRIN_VSHLL_HIGH_N_S16:
		return "vshll_high_n_s16";
	case ARM64_INTRIN_VSHLL_HIGH_N_S32:
		return "vshll_high_n_s32";
	case ARM64_INTRIN_VSHLL_HIGH_N_U8:
		return "vshll_high_n_u8";
	case ARM64_INTRIN_VSHLL_HIGH_N_U16:
		return "vshll_high_n_u16";
	case ARM64_INTRIN_VSHLL_HIGH_N_U32:
		return "vshll_high_n_u32";
	case ARM64_INTRIN_VSRI_N_S8:
		return "vsri_n_s8";
	case ARM64_INTRIN_VSRIQ_N_S8:
		return "vsriq_n_s8";
	case ARM64_INTRIN_VSRI_N_S16:
		return "vsri_n_s16";
	case ARM64_INTRIN_VSRIQ_N_S16:
		return "vsriq_n_s16";
	case ARM64_INTRIN_VSRI_N_S32:
		return "vsri_n_s32";
	case ARM64_INTRIN_VSRIQ_N_S32:
		return "vsriq_n_s32";
	case ARM64_INTRIN_VSRI_N_S64:
		return "vsri_n_s64";
	case ARM64_INTRIN_VSRIQ_N_S64:
		return "vsriq_n_s64";
	case ARM64_INTRIN_VSRI_N_U8:
		return "vsri_n_u8";
	case ARM64_INTRIN_VSRIQ_N_U8:
		return "vsriq_n_u8";
	case ARM64_INTRIN_VSRI_N_U16:
		return "vsri_n_u16";
	case ARM64_INTRIN_VSRIQ_N_U16:
		return "vsriq_n_u16";
	case ARM64_INTRIN_VSRI_N_U32:
		return "vsri_n_u32";
	case ARM64_INTRIN_VSRIQ_N_U32:
		return "vsriq_n_u32";
	case ARM64_INTRIN_VSRI_N_U64:
		return "vsri_n_u64";
	case ARM64_INTRIN_VSRIQ_N_U64:
		return "vsriq_n_u64";
	case ARM64_INTRIN_VSRI_N_P64:
		return "vsri_n_p64";
	case ARM64_INTRIN_VSRIQ_N_P64:
		return "vsriq_n_p64";
	case ARM64_INTRIN_VSRI_N_P8:
		return "vsri_n_p8";
	case ARM64_INTRIN_VSRIQ_N_P8:
		return "vsriq_n_p8";
	case ARM64_INTRIN_VSRI_N_P16:
		return "vsri_n_p16";
	case ARM64_INTRIN_VSRIQ_N_P16:
		return "vsriq_n_p16";
	case ARM64_INTRIN_VSRID_N_S64:
		return "vsrid_n_s64";
	case ARM64_INTRIN_VSRID_N_U64:
		return "vsrid_n_u64";
	case ARM64_INTRIN_VSLI_N_S8:
		return "vsli_n_s8";
	case ARM64_INTRIN_VSLIQ_N_S8:
		return "vsliq_n_s8";
	case ARM64_INTRIN_VSLI_N_S16:
		return "vsli_n_s16";
	case ARM64_INTRIN_VSLIQ_N_S16:
		return "vsliq_n_s16";
	case ARM64_INTRIN_VSLI_N_S32:
		return "vsli_n_s32";
	case ARM64_INTRIN_VSLIQ_N_S32:
		return "vsliq_n_s32";
	case ARM64_INTRIN_VSLI_N_S64:
		return "vsli_n_s64";
	case ARM64_INTRIN_VSLIQ_N_S64:
		return "vsliq_n_s64";
	case ARM64_INTRIN_VSLI_N_U8:
		return "vsli_n_u8";
	case ARM64_INTRIN_VSLIQ_N_U8:
		return "vsliq_n_u8";
	case ARM64_INTRIN_VSLI_N_U16:
		return "vsli_n_u16";
	case ARM64_INTRIN_VSLIQ_N_U16:
		return "vsliq_n_u16";
	case ARM64_INTRIN_VSLI_N_U32:
		return "vsli_n_u32";
	case ARM64_INTRIN_VSLIQ_N_U32:
		return "vsliq_n_u32";
	case ARM64_INTRIN_VSLI_N_U64:
		return "vsli_n_u64";
	case ARM64_INTRIN_VSLIQ_N_U64:
		return "vsliq_n_u64";
	case ARM64_INTRIN_VSLI_N_P64:
		return "vsli_n_p64";
	case ARM64_INTRIN_VSLIQ_N_P64:
		return "vsliq_n_p64";
	case ARM64_INTRIN_VSLI_N_P8:
		return "vsli_n_p8";
	case ARM64_INTRIN_VSLIQ_N_P8:
		return "vsliq_n_p8";
	case ARM64_INTRIN_VSLI_N_P16:
		return "vsli_n_p16";
	case ARM64_INTRIN_VSLIQ_N_P16:
		return "vsliq_n_p16";
	case ARM64_INTRIN_VSLID_N_S64:
		return "vslid_n_s64";
	case ARM64_INTRIN_VSLID_N_U64:
		return "vslid_n_u64";
	case ARM64_INTRIN_VCVT_S32_F32:
		return "vcvt_s32_f32";
	case ARM64_INTRIN_VCVTQ_S32_F32:
		return "vcvtq_s32_f32";
	case ARM64_INTRIN_VCVT_U32_F32:
		return "vcvt_u32_f32";
	case ARM64_INTRIN_VCVTQ_U32_F32:
		return "vcvtq_u32_f32";
	case ARM64_INTRIN_VCVTN_S32_F32:
		return "vcvtn_s32_f32";
	case ARM64_INTRIN_VCVTNQ_S32_F32:
		return "vcvtnq_s32_f32";
	case ARM64_INTRIN_VCVTN_U32_F32:
		return "vcvtn_u32_f32";
	case ARM64_INTRIN_VCVTNQ_U32_F32:
		return "vcvtnq_u32_f32";
	case ARM64_INTRIN_VCVTM_S32_F32:
		return "vcvtm_s32_f32";
	case ARM64_INTRIN_VCVTMQ_S32_F32:
		return "vcvtmq_s32_f32";
	case ARM64_INTRIN_VCVTM_U32_F32:
		return "vcvtm_u32_f32";
	case ARM64_INTRIN_VCVTMQ_U32_F32:
		return "vcvtmq_u32_f32";
	case ARM64_INTRIN_VCVTP_S32_F32:
		return "vcvtp_s32_f32";
	case ARM64_INTRIN_VCVTPQ_S32_F32:
		return "vcvtpq_s32_f32";
	case ARM64_INTRIN_VCVTP_U32_F32:
		return "vcvtp_u32_f32";
	case ARM64_INTRIN_VCVTPQ_U32_F32:
		return "vcvtpq_u32_f32";
	case ARM64_INTRIN_VCVTA_S32_F32:
		return "vcvta_s32_f32";
	case ARM64_INTRIN_VCVTAQ_S32_F32:
		return "vcvtaq_s32_f32";
	case ARM64_INTRIN_VCVTA_U32_F32:
		return "vcvta_u32_f32";
	case ARM64_INTRIN_VCVTAQ_U32_F32:
		return "vcvtaq_u32_f32";
	case ARM64_INTRIN_VCVTS_S32_F32:
		return "vcvts_s32_f32";
	case ARM64_INTRIN_VCVTS_U32_F32:
		return "vcvts_u32_f32";
	case ARM64_INTRIN_VCVTNS_S32_F32:
		return "vcvtns_s32_f32";
	case ARM64_INTRIN_VCVTNS_U32_F32:
		return "vcvtns_u32_f32";
	case ARM64_INTRIN_VCVTMS_S32_F32:
		return "vcvtms_s32_f32";
	case ARM64_INTRIN_VCVTMS_U32_F32:
		return "vcvtms_u32_f32";
	case ARM64_INTRIN_VCVTPS_S32_F32:
		return "vcvtps_s32_f32";
	case ARM64_INTRIN_VCVTPS_U32_F32:
		return "vcvtps_u32_f32";
	case ARM64_INTRIN_VCVTAS_S32_F32:
		return "vcvtas_s32_f32";
	case ARM64_INTRIN_VCVTAS_U32_F32:
		return "vcvtas_u32_f32";
	case ARM64_INTRIN_VCVT_S64_F64:
		return "vcvt_s64_f64";
	case ARM64_INTRIN_VCVTQ_S64_F64:
		return "vcvtq_s64_f64";
	case ARM64_INTRIN_VCVT_U64_F64:
		return "vcvt_u64_f64";
	case ARM64_INTRIN_VCVTQ_U64_F64:
		return "vcvtq_u64_f64";
	case ARM64_INTRIN_VCVTN_S64_F64:
		return "vcvtn_s64_f64";
	case ARM64_INTRIN_VCVTNQ_S64_F64:
		return "vcvtnq_s64_f64";
	case ARM64_INTRIN_VCVTN_U64_F64:
		return "vcvtn_u64_f64";
	case ARM64_INTRIN_VCVTNQ_U64_F64:
		return "vcvtnq_u64_f64";
	case ARM64_INTRIN_VCVTM_S64_F64:
		return "vcvtm_s64_f64";
	case ARM64_INTRIN_VCVTMQ_S64_F64:
		return "vcvtmq_s64_f64";
	case ARM64_INTRIN_VCVTM_U64_F64:
		return "vcvtm_u64_f64";
	case ARM64_INTRIN_VCVTMQ_U64_F64:
		return "vcvtmq_u64_f64";
	case ARM64_INTRIN_VCVTP_S64_F64:
		return "vcvtp_s64_f64";
	case ARM64_INTRIN_VCVTPQ_S64_F64:
		return "vcvtpq_s64_f64";
	case ARM64_INTRIN_VCVTP_U64_F64:
		return "vcvtp_u64_f64";
	case ARM64_INTRIN_VCVTPQ_U64_F64:
		return "vcvtpq_u64_f64";
	case ARM64_INTRIN_VCVTA_S64_F64:
		return "vcvta_s64_f64";
	case ARM64_INTRIN_VCVTAQ_S64_F64:
		return "vcvtaq_s64_f64";
	case ARM64_INTRIN_VCVTA_U64_F64:
		return "vcvta_u64_f64";
	case ARM64_INTRIN_VCVTAQ_U64_F64:
		return "vcvtaq_u64_f64";
	case ARM64_INTRIN_VCVTD_S64_F64:
		return "vcvtd_s64_f64";
	case ARM64_INTRIN_VCVTD_U64_F64:
		return "vcvtd_u64_f64";
	case ARM64_INTRIN_VCVTND_S64_F64:
		return "vcvtnd_s64_f64";
	case ARM64_INTRIN_VCVTND_U64_F64:
		return "vcvtnd_u64_f64";
	case ARM64_INTRIN_VCVTMD_S64_F64:
		return "vcvtmd_s64_f64";
	case ARM64_INTRIN_VCVTMD_U64_F64:
		return "vcvtmd_u64_f64";
	case ARM64_INTRIN_VCVTPD_S64_F64:
		return "vcvtpd_s64_f64";
	case ARM64_INTRIN_VCVTPD_U64_F64:
		return "vcvtpd_u64_f64";
	case ARM64_INTRIN_VCVTAD_S64_F64:
		return "vcvtad_s64_f64";
	case ARM64_INTRIN_VCVTAD_U64_F64:
		return "vcvtad_u64_f64";
	case ARM64_INTRIN_VCVT_N_S32_F32:
		return "vcvt_n_s32_f32";
	case ARM64_INTRIN_VCVTQ_N_S32_F32:
		return "vcvtq_n_s32_f32";
	case ARM64_INTRIN_VCVT_N_U32_F32:
		return "vcvt_n_u32_f32";
	case ARM64_INTRIN_VCVTQ_N_U32_F32:
		return "vcvtq_n_u32_f32";
	case ARM64_INTRIN_VCVTS_N_S32_F32:
		return "vcvts_n_s32_f32";
	case ARM64_INTRIN_VCVTS_N_U32_F32:
		return "vcvts_n_u32_f32";
	case ARM64_INTRIN_VCVT_N_S64_F64:
		return "vcvt_n_s64_f64";
	case ARM64_INTRIN_VCVTQ_N_S64_F64:
		return "vcvtq_n_s64_f64";
	case ARM64_INTRIN_VCVT_N_U64_F64:
		return "vcvt_n_u64_f64";
	case ARM64_INTRIN_VCVTQ_N_U64_F64:
		return "vcvtq_n_u64_f64";
	case ARM64_INTRIN_VCVTD_N_S64_F64:
		return "vcvtd_n_s64_f64";
	case ARM64_INTRIN_VCVTD_N_U64_F64:
		return "vcvtd_n_u64_f64";
	case ARM64_INTRIN_VCVT_F32_S32:
		return "vcvt_f32_s32";
	case ARM64_INTRIN_VCVTQ_F32_S32:
		return "vcvtq_f32_s32";
	case ARM64_INTRIN_VCVT_F32_U32:
		return "vcvt_f32_u32";
	case ARM64_INTRIN_VCVTQ_F32_U32:
		return "vcvtq_f32_u32";
	case ARM64_INTRIN_VCVTS_F32_S32:
		return "vcvts_f32_s32";
	case ARM64_INTRIN_VCVTS_F32_U32:
		return "vcvts_f32_u32";
	case ARM64_INTRIN_VCVT_F64_S64:
		return "vcvt_f64_s64";
	case ARM64_INTRIN_VCVTQ_F64_S64:
		return "vcvtq_f64_s64";
	case ARM64_INTRIN_VCVT_F64_U64:
		return "vcvt_f64_u64";
	case ARM64_INTRIN_VCVT_F64_U32:
		return "vcvt_f64_u32";
	case ARM64_INTRIN_VCVT_F32_U64:
		return "vcvt_f32_u64";
	case ARM64_INTRIN_VCVTQ_F64_U64:
		return "vcvtq_f64_u64";
	case ARM64_INTRIN_VCVTD_F64_S64:
		return "vcvtd_f64_s64";
	case ARM64_INTRIN_VCVTD_F64_U64:
		return "vcvtd_f64_u64";
	case ARM64_INTRIN_VCVT_N_F32_S32:
		return "vcvt_n_f32_s32";
	case ARM64_INTRIN_VCVTQ_N_F32_S32:
		return "vcvtq_n_f32_s32";
	case ARM64_INTRIN_VCVT_N_F32_U32:
		return "vcvt_n_f32_u32";
	case ARM64_INTRIN_VCVTQ_N_F32_U32:
		return "vcvtq_n_f32_u32";
	case ARM64_INTRIN_VCVTS_N_F32_S32:
		return "vcvts_n_f32_s32";
	case ARM64_INTRIN_VCVTS_N_F32_U32:
		return "vcvts_n_f32_u32";
	case ARM64_INTRIN_VCVTS_N_F32_U64:
		return "vcvts_n_f32_u64";
	case ARM64_INTRIN_VCVT_N_F64_S64:
		return "vcvt_n_f64_s64";
	case ARM64_INTRIN_VCVTQ_N_F64_S64:
		return "vcvtq_n_f64_s64";
	case ARM64_INTRIN_VCVT_N_F64_U64:
		return "vcvt_n_f64_u64";
	case ARM64_INTRIN_VCVTQ_N_F64_U64:
		return "vcvtq_n_f64_u64";
	case ARM64_INTRIN_VCVTD_N_F64_S64:
		return "vcvtd_n_f64_s64";
	case ARM64_INTRIN_VCVTD_N_F64_U32:
		return "vcvtd_n_f64_u32";
	case ARM64_INTRIN_VCVTD_N_F64_U64:
		return "vcvtd_n_f64_u64";
	case ARM64_INTRIN_VCVT_F16_F32:
		return "vcvt_f16_f32";
	case ARM64_INTRIN_VCVT_HIGH_F16_F32:
		return "vcvt_high_f16_f32";
	case ARM64_INTRIN_VCVT_F32_F64:
		return "vcvt_f32_f64";
	case ARM64_INTRIN_VCVT_HIGH_F32_F64:
		return "vcvt_high_f32_f64";
	case ARM64_INTRIN_VCVT_F32_F16:
		return "vcvt_f32_f16";
	case ARM64_INTRIN_VCVT_HIGH_F32_F16:
		return "vcvt_high_f32_f16";
	case ARM64_INTRIN_VCVT_F64_F32:
		return "vcvt_f64_f32";
	case ARM64_INTRIN_VCVT_HIGH_F64_F32:
		return "vcvt_high_f64_f32";
	case ARM64_INTRIN_VCVTX_F32_F64:
		return "vcvtx_f32_f64";
	case ARM64_INTRIN_VCVTXD_F32_F64:
		return "vcvtxd_f32_f64";
	case ARM64_INTRIN_VCVTX_HIGH_F32_F64:
		return "vcvtx_high_f32_f64";
	case ARM64_INTRIN_VRND_F32:
		return "vrnd_f32";
	case ARM64_INTRIN_VRNDQ_F32:
		return "vrndq_f32";
	case ARM64_INTRIN_VRND_F64:
		return "vrnd_f64";
	case ARM64_INTRIN_VRNDQ_F64:
		return "vrndq_f64";
	case ARM64_INTRIN_VRNDN_F32:
		return "vrndn_f32";
	case ARM64_INTRIN_VRNDNQ_F32:
		return "vrndnq_f32";
	case ARM64_INTRIN_VRNDN_F64:
		return "vrndn_f64";
	case ARM64_INTRIN_VRNDNQ_F64:
		return "vrndnq_f64";
	case ARM64_INTRIN_VRNDNS_F32:
		return "vrndns_f32";
	case ARM64_INTRIN_VRNDM_F32:
		return "vrndm_f32";
	case ARM64_INTRIN_VRNDMQ_F32:
		return "vrndmq_f32";
	case ARM64_INTRIN_VRNDM_F64:
		return "vrndm_f64";
	case ARM64_INTRIN_VRNDMQ_F64:
		return "vrndmq_f64";
	case ARM64_INTRIN_VRNDP_F32:
		return "vrndp_f32";
	case ARM64_INTRIN_VRNDPQ_F32:
		return "vrndpq_f32";
	case ARM64_INTRIN_VRNDP_F64:
		return "vrndp_f64";
	case ARM64_INTRIN_VRNDPQ_F64:
		return "vrndpq_f64";
	case ARM64_INTRIN_VRNDA_F32:
		return "vrnda_f32";
	case ARM64_INTRIN_VRNDAQ_F32:
		return "vrndaq_f32";
	case ARM64_INTRIN_VRNDA_F64:
		return "vrnda_f64";
	case ARM64_INTRIN_VRNDAQ_F64:
		return "vrndaq_f64";
	case ARM64_INTRIN_VRNDI_F32:
		return "vrndi_f32";
	case ARM64_INTRIN_VRNDIQ_F32:
		return "vrndiq_f32";
	case ARM64_INTRIN_VRNDI_F64:
		return "vrndi_f64";
	case ARM64_INTRIN_VRNDIQ_F64:
		return "vrndiq_f64";
	case ARM64_INTRIN_VRNDX_F32:
		return "vrndx_f32";
	case ARM64_INTRIN_VRNDXQ_F32:
		return "vrndxq_f32";
	case ARM64_INTRIN_VRNDX_F64:
		return "vrndx_f64";
	case ARM64_INTRIN_VRNDXQ_F64:
		return "vrndxq_f64";
	case ARM64_INTRIN_VMOVN_S16:
		return "vmovn_s16";
	case ARM64_INTRIN_VMOVN_S32:
		return "vmovn_s32";
	case ARM64_INTRIN_VMOVN_S64:
		return "vmovn_s64";
	case ARM64_INTRIN_VMOVN_U16:
		return "vmovn_u16";
	case ARM64_INTRIN_VMOVN_U32:
		return "vmovn_u32";
	case ARM64_INTRIN_VMOVN_U64:
		return "vmovn_u64";
	case ARM64_INTRIN_VMOVN_HIGH_S16:
		return "vmovn_high_s16";
	case ARM64_INTRIN_VMOVN_HIGH_S32:
		return "vmovn_high_s32";
	case ARM64_INTRIN_VMOVN_HIGH_S64:
		return "vmovn_high_s64";
	case ARM64_INTRIN_VMOVN_HIGH_U16:
		return "vmovn_high_u16";
	case ARM64_INTRIN_VMOVN_HIGH_U32:
		return "vmovn_high_u32";
	case ARM64_INTRIN_VMOVN_HIGH_U64:
		return "vmovn_high_u64";
	case ARM64_INTRIN_VMOVL_S8:
		return "vmovl_s8";
	case ARM64_INTRIN_VMOVL_S16:
		return "vmovl_s16";
	case ARM64_INTRIN_VMOVL_S32:
		return "vmovl_s32";
	case ARM64_INTRIN_VMOVL_U8:
		return "vmovl_u8";
	case ARM64_INTRIN_VMOVL_U16:
		return "vmovl_u16";
	case ARM64_INTRIN_VMOVL_U32:
		return "vmovl_u32";
	case ARM64_INTRIN_VMOVL_HIGH_S8:
		return "vmovl_high_s8";
	case ARM64_INTRIN_VMOVL_HIGH_S16:
		return "vmovl_high_s16";
	case ARM64_INTRIN_VMOVL_HIGH_S32:
		return "vmovl_high_s32";
	case ARM64_INTRIN_VMOVL_HIGH_U8:
		return "vmovl_high_u8";
	case ARM64_INTRIN_VMOVL_HIGH_U16:
		return "vmovl_high_u16";
	case ARM64_INTRIN_VMOVL_HIGH_U32:
		return "vmovl_high_u32";
	case ARM64_INTRIN_VQMOVN_S16:
		return "vqmovn_s16";
	case ARM64_INTRIN_VQMOVN_S32:
		return "vqmovn_s32";
	case ARM64_INTRIN_VQMOVN_S64:
		return "vqmovn_s64";
	case ARM64_INTRIN_VQMOVN_U16:
		return "vqmovn_u16";
	case ARM64_INTRIN_VQMOVN_U32:
		return "vqmovn_u32";
	case ARM64_INTRIN_VQMOVN_U64:
		return "vqmovn_u64";
	case ARM64_INTRIN_VQMOVNH_S16:
		return "vqmovnh_s16";
	case ARM64_INTRIN_VQMOVNS_S32:
		return "vqmovns_s32";
	case ARM64_INTRIN_VQMOVND_S64:
		return "vqmovnd_s64";
	case ARM64_INTRIN_VQMOVNH_U16:
		return "vqmovnh_u16";
	case ARM64_INTRIN_VQMOVNS_U32:
		return "vqmovns_u32";
	case ARM64_INTRIN_VQMOVND_U64:
		return "vqmovnd_u64";
	case ARM64_INTRIN_VQMOVN_HIGH_S16:
		return "vqmovn_high_s16";
	case ARM64_INTRIN_VQMOVN_HIGH_S32:
		return "vqmovn_high_s32";
	case ARM64_INTRIN_VQMOVN_HIGH_S64:
		return "vqmovn_high_s64";
	case ARM64_INTRIN_VQMOVN_HIGH_U16:
		return "vqmovn_high_u16";
	case ARM64_INTRIN_VQMOVN_HIGH_U32:
		return "vqmovn_high_u32";
	case ARM64_INTRIN_VQMOVN_HIGH_U64:
		return "vqmovn_high_u64";
	case ARM64_INTRIN_VQMOVUN_S16:
		return "vqmovun_s16";
	case ARM64_INTRIN_VQMOVUN_S32:
		return "vqmovun_s32";
	case ARM64_INTRIN_VQMOVUN_S64:
		return "vqmovun_s64";
	case ARM64_INTRIN_VQMOVUNH_S16:
		return "vqmovunh_s16";
	case ARM64_INTRIN_VQMOVUNS_S32:
		return "vqmovuns_s32";
	case ARM64_INTRIN_VQMOVUND_S64:
		return "vqmovund_s64";
	case ARM64_INTRIN_VQMOVUN_HIGH_S16:
		return "vqmovun_high_s16";
	case ARM64_INTRIN_VQMOVUN_HIGH_S32:
		return "vqmovun_high_s32";
	case ARM64_INTRIN_VQMOVUN_HIGH_S64:
		return "vqmovun_high_s64";
	case ARM64_INTRIN_VMLA_LANE_S16:
		return "vmla_lane_s16";
	case ARM64_INTRIN_VMLAQ_LANE_S16:
		return "vmlaq_lane_s16";
	case ARM64_INTRIN_VMLA_LANE_S32:
		return "vmla_lane_s32";
	case ARM64_INTRIN_VMLAQ_LANE_S32:
		return "vmlaq_lane_s32";
	case ARM64_INTRIN_VMLA_LANE_U16:
		return "vmla_lane_u16";
	case ARM64_INTRIN_VMLAQ_LANE_U16:
		return "vmlaq_lane_u16";
	case ARM64_INTRIN_VMLA_LANE_U32:
		return "vmla_lane_u32";
	case ARM64_INTRIN_VMLAQ_LANE_U32:
		return "vmlaq_lane_u32";
	case ARM64_INTRIN_VMLA_LANE_F32:
		return "vmla_lane_f32";
	case ARM64_INTRIN_VMLAQ_LANE_F32:
		return "vmlaq_lane_f32";
	case ARM64_INTRIN_VMLA_LANEQ_S16:
		return "vmla_laneq_s16";
	case ARM64_INTRIN_VMLAQ_LANEQ_S16:
		return "vmlaq_laneq_s16";
	case ARM64_INTRIN_VMLA_LANEQ_S32:
		return "vmla_laneq_s32";
	case ARM64_INTRIN_VMLAQ_LANEQ_S32:
		return "vmlaq_laneq_s32";
	case ARM64_INTRIN_VMLA_LANEQ_U16:
		return "vmla_laneq_u16";
	case ARM64_INTRIN_VMLAQ_LANEQ_U16:
		return "vmlaq_laneq_u16";
	case ARM64_INTRIN_VMLA_LANEQ_U32:
		return "vmla_laneq_u32";
	case ARM64_INTRIN_VMLAQ_LANEQ_U32:
		return "vmlaq_laneq_u32";
	case ARM64_INTRIN_VMLA_LANEQ_F32:
		return "vmla_laneq_f32";
	case ARM64_INTRIN_VMLAQ_LANEQ_F32:
		return "vmlaq_laneq_f32";
	case ARM64_INTRIN_VMLAL_LANE_S16:
		return "vmlal_lane_s16";
	case ARM64_INTRIN_VMLAL_LANE_S32:
		return "vmlal_lane_s32";
	case ARM64_INTRIN_VMLAL_LANE_U16:
		return "vmlal_lane_u16";
	case ARM64_INTRIN_VMLAL_LANE_U32:
		return "vmlal_lane_u32";
	case ARM64_INTRIN_VMLAL_HIGH_LANE_S16:
		return "vmlal_high_lane_s16";
	case ARM64_INTRIN_VMLAL_HIGH_LANE_S32:
		return "vmlal_high_lane_s32";
	case ARM64_INTRIN_VMLAL_HIGH_LANE_U16:
		return "vmlal_high_lane_u16";
	case ARM64_INTRIN_VMLAL_HIGH_LANE_U32:
		return "vmlal_high_lane_u32";
	case ARM64_INTRIN_VMLAL_LANEQ_S16:
		return "vmlal_laneq_s16";
	case ARM64_INTRIN_VMLAL_LANEQ_S32:
		return "vmlal_laneq_s32";
	case ARM64_INTRIN_VMLAL_LANEQ_U16:
		return "vmlal_laneq_u16";
	case ARM64_INTRIN_VMLAL_LANEQ_U32:
		return "vmlal_laneq_u32";
	case ARM64_INTRIN_VMLAL_HIGH_LANEQ_S16:
		return "vmlal_high_laneq_s16";
	case ARM64_INTRIN_VMLAL_HIGH_LANEQ_S32:
		return "vmlal_high_laneq_s32";
	case ARM64_INTRIN_VMLAL_HIGH_LANEQ_U16:
		return "vmlal_high_laneq_u16";
	case ARM64_INTRIN_VMLAL_HIGH_LANEQ_U32:
		return "vmlal_high_laneq_u32";
	case ARM64_INTRIN_VQDMLAL_LANE_S16:
		return "vqdmlal_lane_s16";
	case ARM64_INTRIN_VQDMLAL_LANE_S32:
		return "vqdmlal_lane_s32";
	case ARM64_INTRIN_VQDMLALH_LANE_S16:
		return "vqdmlalh_lane_s16";
	case ARM64_INTRIN_VQDMLALS_LANE_S32:
		return "vqdmlals_lane_s32";
	case ARM64_INTRIN_VQDMLAL_HIGH_LANE_S16:
		return "vqdmlal_high_lane_s16";
	case ARM64_INTRIN_VQDMLAL_HIGH_LANE_S32:
		return "vqdmlal_high_lane_s32";
	case ARM64_INTRIN_VQDMLAL_LANEQ_S16:
		return "vqdmlal_laneq_s16";
	case ARM64_INTRIN_VQDMLAL_LANEQ_S32:
		return "vqdmlal_laneq_s32";
	case ARM64_INTRIN_VQDMLALH_LANEQ_S16:
		return "vqdmlalh_laneq_s16";
	case ARM64_INTRIN_VQDMLALS_LANEQ_S32:
		return "vqdmlals_laneq_s32";
	case ARM64_INTRIN_VQDMLAL_HIGH_LANEQ_S16:
		return "vqdmlal_high_laneq_s16";
	case ARM64_INTRIN_VQDMLAL_HIGH_LANEQ_S32:
		return "vqdmlal_high_laneq_s32";
	case ARM64_INTRIN_VMLS_LANE_S16:
		return "vmls_lane_s16";
	case ARM64_INTRIN_VMLSQ_LANE_S16:
		return "vmlsq_lane_s16";
	case ARM64_INTRIN_VMLS_LANE_S32:
		return "vmls_lane_s32";
	case ARM64_INTRIN_VMLSQ_LANE_S32:
		return "vmlsq_lane_s32";
	case ARM64_INTRIN_VMLS_LANE_U16:
		return "vmls_lane_u16";
	case ARM64_INTRIN_VMLSQ_LANE_U16:
		return "vmlsq_lane_u16";
	case ARM64_INTRIN_VMLS_LANE_U32:
		return "vmls_lane_u32";
	case ARM64_INTRIN_VMLSQ_LANE_U32:
		return "vmlsq_lane_u32";
	case ARM64_INTRIN_VMLS_LANE_F32:
		return "vmls_lane_f32";
	case ARM64_INTRIN_VMLSQ_LANE_F32:
		return "vmlsq_lane_f32";
	case ARM64_INTRIN_VMLS_LANEQ_S16:
		return "vmls_laneq_s16";
	case ARM64_INTRIN_VMLSQ_LANEQ_S16:
		return "vmlsq_laneq_s16";
	case ARM64_INTRIN_VMLS_LANEQ_S32:
		return "vmls_laneq_s32";
	case ARM64_INTRIN_VMLSQ_LANEQ_S32:
		return "vmlsq_laneq_s32";
	case ARM64_INTRIN_VMLS_LANEQ_U16:
		return "vmls_laneq_u16";
	case ARM64_INTRIN_VMLSQ_LANEQ_U16:
		return "vmlsq_laneq_u16";
	case ARM64_INTRIN_VMLS_LANEQ_U32:
		return "vmls_laneq_u32";
	case ARM64_INTRIN_VMLSQ_LANEQ_U32:
		return "vmlsq_laneq_u32";
	case ARM64_INTRIN_VMLS_LANEQ_F32:
		return "vmls_laneq_f32";
	case ARM64_INTRIN_VMLSQ_LANEQ_F32:
		return "vmlsq_laneq_f32";
	case ARM64_INTRIN_VMLSL_LANE_S16:
		return "vmlsl_lane_s16";
	case ARM64_INTRIN_VMLSL_LANE_S32:
		return "vmlsl_lane_s32";
	case ARM64_INTRIN_VMLSL_LANE_U16:
		return "vmlsl_lane_u16";
	case ARM64_INTRIN_VMLSL_LANE_U32:
		return "vmlsl_lane_u32";
	case ARM64_INTRIN_VMLSL_HIGH_LANE_S16:
		return "vmlsl_high_lane_s16";
	case ARM64_INTRIN_VMLSL_HIGH_LANE_S32:
		return "vmlsl_high_lane_s32";
	case ARM64_INTRIN_VMLSL_HIGH_LANE_U16:
		return "vmlsl_high_lane_u16";
	case ARM64_INTRIN_VMLSL_HIGH_LANE_U32:
		return "vmlsl_high_lane_u32";
	case ARM64_INTRIN_VMLSL_LANEQ_S16:
		return "vmlsl_laneq_s16";
	case ARM64_INTRIN_VMLSL_LANEQ_S32:
		return "vmlsl_laneq_s32";
	case ARM64_INTRIN_VMLSL_LANEQ_U16:
		return "vmlsl_laneq_u16";
	case ARM64_INTRIN_VMLSL_LANEQ_U32:
		return "vmlsl_laneq_u32";
	case ARM64_INTRIN_VMLSL_HIGH_LANEQ_S16:
		return "vmlsl_high_laneq_s16";
	case ARM64_INTRIN_VMLSL_HIGH_LANEQ_S32:
		return "vmlsl_high_laneq_s32";
	case ARM64_INTRIN_VMLSL_HIGH_LANEQ_U16:
		return "vmlsl_high_laneq_u16";
	case ARM64_INTRIN_VMLSL_HIGH_LANEQ_U32:
		return "vmlsl_high_laneq_u32";
	case ARM64_INTRIN_VQDMLSL_LANE_S16:
		return "vqdmlsl_lane_s16";
	case ARM64_INTRIN_VQDMLSL_LANE_S32:
		return "vqdmlsl_lane_s32";
	case ARM64_INTRIN_VQDMLSLH_LANE_S16:
		return "vqdmlslh_lane_s16";
	case ARM64_INTRIN_VQDMLSLS_LANE_S32:
		return "vqdmlsls_lane_s32";
	case ARM64_INTRIN_VQDMLSL_HIGH_LANE_S16:
		return "vqdmlsl_high_lane_s16";
	case ARM64_INTRIN_VQDMLSL_HIGH_LANE_S32:
		return "vqdmlsl_high_lane_s32";
	case ARM64_INTRIN_VQDMLSL_LANEQ_S16:
		return "vqdmlsl_laneq_s16";
	case ARM64_INTRIN_VQDMLSL_LANEQ_S32:
		return "vqdmlsl_laneq_s32";
	case ARM64_INTRIN_VQDMLSLH_LANEQ_S16:
		return "vqdmlslh_laneq_s16";
	case ARM64_INTRIN_VQDMLSLS_LANEQ_S32:
		return "vqdmlsls_laneq_s32";
	case ARM64_INTRIN_VQDMLSL_HIGH_LANEQ_S16:
		return "vqdmlsl_high_laneq_s16";
	case ARM64_INTRIN_VQDMLSL_HIGH_LANEQ_S32:
		return "vqdmlsl_high_laneq_s32";
	case ARM64_INTRIN_VMUL_N_S16:
		return "vmul_n_s16";
	case ARM64_INTRIN_VMULQ_N_S16:
		return "vmulq_n_s16";
	case ARM64_INTRIN_VMUL_N_S32:
		return "vmul_n_s32";
	case ARM64_INTRIN_VMULQ_N_S32:
		return "vmulq_n_s32";
	case ARM64_INTRIN_VMUL_N_U16:
		return "vmul_n_u16";
	case ARM64_INTRIN_VMULQ_N_U16:
		return "vmulq_n_u16";
	case ARM64_INTRIN_VMUL_N_U32:
		return "vmul_n_u32";
	case ARM64_INTRIN_VMULQ_N_U32:
		return "vmulq_n_u32";
	case ARM64_INTRIN_VMUL_N_F32:
		return "vmul_n_f32";
	case ARM64_INTRIN_VMULQ_N_F32:
		return "vmulq_n_f32";
	case ARM64_INTRIN_VMUL_N_F64:
		return "vmul_n_f64";
	case ARM64_INTRIN_VMULQ_N_F64:
		return "vmulq_n_f64";
	case ARM64_INTRIN_VMUL_LANE_S16:
		return "vmul_lane_s16";
	case ARM64_INTRIN_VMULQ_LANE_S16:
		return "vmulq_lane_s16";
	case ARM64_INTRIN_VMUL_LANE_S32:
		return "vmul_lane_s32";
	case ARM64_INTRIN_VMULQ_LANE_S32:
		return "vmulq_lane_s32";
	case ARM64_INTRIN_VMUL_LANE_U16:
		return "vmul_lane_u16";
	case ARM64_INTRIN_VMULQ_LANE_U16:
		return "vmulq_lane_u16";
	case ARM64_INTRIN_VMUL_LANE_U32:
		return "vmul_lane_u32";
	case ARM64_INTRIN_VMULQ_LANE_U32:
		return "vmulq_lane_u32";
	case ARM64_INTRIN_VMUL_LANE_F32:
		return "vmul_lane_f32";
	case ARM64_INTRIN_VMULQ_LANE_F32:
		return "vmulq_lane_f32";
	case ARM64_INTRIN_VMUL_LANE_F64:
		return "vmul_lane_f64";
	case ARM64_INTRIN_VMULQ_LANE_F64:
		return "vmulq_lane_f64";
	case ARM64_INTRIN_VMULS_LANE_F32:
		return "vmuls_lane_f32";
	case ARM64_INTRIN_VMULD_LANE_F64:
		return "vmuld_lane_f64";
	case ARM64_INTRIN_VMUL_LANEQ_S16:
		return "vmul_laneq_s16";
	case ARM64_INTRIN_VMULQ_LANEQ_S16:
		return "vmulq_laneq_s16";
	case ARM64_INTRIN_VMUL_LANEQ_S32:
		return "vmul_laneq_s32";
	case ARM64_INTRIN_VMULQ_LANEQ_S32:
		return "vmulq_laneq_s32";
	case ARM64_INTRIN_VMUL_LANEQ_U16:
		return "vmul_laneq_u16";
	case ARM64_INTRIN_VMULQ_LANEQ_U16:
		return "vmulq_laneq_u16";
	case ARM64_INTRIN_VMUL_LANEQ_U32:
		return "vmul_laneq_u32";
	case ARM64_INTRIN_VMULQ_LANEQ_U32:
		return "vmulq_laneq_u32";
	case ARM64_INTRIN_VMUL_LANEQ_F32:
		return "vmul_laneq_f32";
	case ARM64_INTRIN_VMULQ_LANEQ_F32:
		return "vmulq_laneq_f32";
	case ARM64_INTRIN_VMUL_LANEQ_F64:
		return "vmul_laneq_f64";
	case ARM64_INTRIN_VMULQ_LANEQ_F64:
		return "vmulq_laneq_f64";
	case ARM64_INTRIN_VMULS_LANEQ_F32:
		return "vmuls_laneq_f32";
	case ARM64_INTRIN_VMULD_LANEQ_F64:
		return "vmuld_laneq_f64";
	case ARM64_INTRIN_VMULL_N_S16:
		return "vmull_n_s16";
	case ARM64_INTRIN_VMULL_N_S32:
		return "vmull_n_s32";
	case ARM64_INTRIN_VMULL_N_U16:
		return "vmull_n_u16";
	case ARM64_INTRIN_VMULL_N_U32:
		return "vmull_n_u32";
	case ARM64_INTRIN_VMULL_HIGH_N_S16:
		return "vmull_high_n_s16";
	case ARM64_INTRIN_VMULL_HIGH_N_S32:
		return "vmull_high_n_s32";
	case ARM64_INTRIN_VMULL_HIGH_N_U16:
		return "vmull_high_n_u16";
	case ARM64_INTRIN_VMULL_HIGH_N_U32:
		return "vmull_high_n_u32";
	case ARM64_INTRIN_VMULL_LANE_S16:
		return "vmull_lane_s16";
	case ARM64_INTRIN_VMULL_LANE_S32:
		return "vmull_lane_s32";
	case ARM64_INTRIN_VMULL_LANE_U16:
		return "vmull_lane_u16";
	case ARM64_INTRIN_VMULL_LANE_U32:
		return "vmull_lane_u32";
	case ARM64_INTRIN_VMULL_HIGH_LANE_S16:
		return "vmull_high_lane_s16";
	case ARM64_INTRIN_VMULL_HIGH_LANE_S32:
		return "vmull_high_lane_s32";
	case ARM64_INTRIN_VMULL_HIGH_LANE_U16:
		return "vmull_high_lane_u16";
	case ARM64_INTRIN_VMULL_HIGH_LANE_U32:
		return "vmull_high_lane_u32";
	case ARM64_INTRIN_VMULL_LANEQ_S16:
		return "vmull_laneq_s16";
	case ARM64_INTRIN_VMULL_LANEQ_S32:
		return "vmull_laneq_s32";
	case ARM64_INTRIN_VMULL_LANEQ_U16:
		return "vmull_laneq_u16";
	case ARM64_INTRIN_VMULL_LANEQ_U32:
		return "vmull_laneq_u32";
	case ARM64_INTRIN_VMULL_HIGH_LANEQ_S16:
		return "vmull_high_laneq_s16";
	case ARM64_INTRIN_VMULL_HIGH_LANEQ_S32:
		return "vmull_high_laneq_s32";
	case ARM64_INTRIN_VMULL_HIGH_LANEQ_U16:
		return "vmull_high_laneq_u16";
	case ARM64_INTRIN_VMULL_HIGH_LANEQ_U32:
		return "vmull_high_laneq_u32";
	case ARM64_INTRIN_VQDMULL_N_S16:
		return "vqdmull_n_s16";
	case ARM64_INTRIN_VQDMULL_N_S32:
		return "vqdmull_n_s32";
	case ARM64_INTRIN_VQDMULL_HIGH_N_S16:
		return "vqdmull_high_n_s16";
	case ARM64_INTRIN_VQDMULL_HIGH_N_S32:
		return "vqdmull_high_n_s32";
	case ARM64_INTRIN_VQDMULL_LANE_S16:
		return "vqdmull_lane_s16";
	case ARM64_INTRIN_VQDMULL_LANE_S32:
		return "vqdmull_lane_s32";
	case ARM64_INTRIN_VQDMULLH_LANE_S16:
		return "vqdmullh_lane_s16";
	case ARM64_INTRIN_VQDMULLS_LANE_S32:
		return "vqdmulls_lane_s32";
	case ARM64_INTRIN_VQDMULL_HIGH_LANE_S16:
		return "vqdmull_high_lane_s16";
	case ARM64_INTRIN_VQDMULL_HIGH_LANE_S32:
		return "vqdmull_high_lane_s32";
	case ARM64_INTRIN_VQDMULL_LANEQ_S16:
		return "vqdmull_laneq_s16";
	case ARM64_INTRIN_VQDMULL_LANEQ_S32:
		return "vqdmull_laneq_s32";
	case ARM64_INTRIN_VQDMULLH_LANEQ_S16:
		return "vqdmullh_laneq_s16";
	case ARM64_INTRIN_VQDMULLS_LANEQ_S32:
		return "vqdmulls_laneq_s32";
	case ARM64_INTRIN_VQDMULL_HIGH_LANEQ_S16:
		return "vqdmull_high_laneq_s16";
	case ARM64_INTRIN_VQDMULL_HIGH_LANEQ_S32:
		return "vqdmull_high_laneq_s32";
	case ARM64_INTRIN_VQDMULH_N_S16:
		return "vqdmulh_n_s16";
	case ARM64_INTRIN_VQDMULHQ_N_S16:
		return "vqdmulhq_n_s16";
	case ARM64_INTRIN_VQDMULH_N_S32:
		return "vqdmulh_n_s32";
	case ARM64_INTRIN_VQDMULHQ_N_S32:
		return "vqdmulhq_n_s32";
	case ARM64_INTRIN_VQDMULH_LANE_S16:
		return "vqdmulh_lane_s16";
	case ARM64_INTRIN_VQDMULHQ_LANE_S16:
		return "vqdmulhq_lane_s16";
	case ARM64_INTRIN_VQDMULH_LANE_S32:
		return "vqdmulh_lane_s32";
	case ARM64_INTRIN_VQDMULHQ_LANE_S32:
		return "vqdmulhq_lane_s32";
	case ARM64_INTRIN_VQDMULHH_LANE_S16:
		return "vqdmulhh_lane_s16";
	case ARM64_INTRIN_VQDMULHS_LANE_S32:
		return "vqdmulhs_lane_s32";
	case ARM64_INTRIN_VQDMULH_LANEQ_S16:
		return "vqdmulh_laneq_s16";
	case ARM64_INTRIN_VQDMULHQ_LANEQ_S16:
		return "vqdmulhq_laneq_s16";
	case ARM64_INTRIN_VQDMULH_LANEQ_S32:
		return "vqdmulh_laneq_s32";
	case ARM64_INTRIN_VQDMULHQ_LANEQ_S32:
		return "vqdmulhq_laneq_s32";
	case ARM64_INTRIN_VQDMULHH_LANEQ_S16:
		return "vqdmulhh_laneq_s16";
	case ARM64_INTRIN_VQDMULHS_LANEQ_S32:
		return "vqdmulhs_laneq_s32";
	case ARM64_INTRIN_VQRDMULH_N_S16:
		return "vqrdmulh_n_s16";
	case ARM64_INTRIN_VQRDMULHQ_N_S16:
		return "vqrdmulhq_n_s16";
	case ARM64_INTRIN_VQRDMULH_N_S32:
		return "vqrdmulh_n_s32";
	case ARM64_INTRIN_VQRDMULHQ_N_S32:
		return "vqrdmulhq_n_s32";
	case ARM64_INTRIN_VQRDMULH_LANE_S16:
		return "vqrdmulh_lane_s16";
	case ARM64_INTRIN_VQRDMULHQ_LANE_S16:
		return "vqrdmulhq_lane_s16";
	case ARM64_INTRIN_VQRDMULH_LANE_S32:
		return "vqrdmulh_lane_s32";
	case ARM64_INTRIN_VQRDMULHQ_LANE_S32:
		return "vqrdmulhq_lane_s32";
	case ARM64_INTRIN_VQRDMULHH_LANE_S16:
		return "vqrdmulhh_lane_s16";
	case ARM64_INTRIN_VQRDMULHS_LANE_S32:
		return "vqrdmulhs_lane_s32";
	case ARM64_INTRIN_VQRDMULH_LANEQ_S16:
		return "vqrdmulh_laneq_s16";
	case ARM64_INTRIN_VQRDMULHQ_LANEQ_S16:
		return "vqrdmulhq_laneq_s16";
	case ARM64_INTRIN_VQRDMULH_LANEQ_S32:
		return "vqrdmulh_laneq_s32";
	case ARM64_INTRIN_VQRDMULHQ_LANEQ_S32:
		return "vqrdmulhq_laneq_s32";
	case ARM64_INTRIN_VQRDMULHH_LANEQ_S16:
		return "vqrdmulhh_laneq_s16";
	case ARM64_INTRIN_VQRDMULHS_LANEQ_S32:
		return "vqrdmulhs_laneq_s32";
	case ARM64_INTRIN_VMLA_N_S16:
		return "vmla_n_s16";
	case ARM64_INTRIN_VMLAQ_N_S16:
		return "vmlaq_n_s16";
	case ARM64_INTRIN_VMLA_N_S32:
		return "vmla_n_s32";
	case ARM64_INTRIN_VMLAQ_N_S32:
		return "vmlaq_n_s32";
	case ARM64_INTRIN_VMLA_N_U16:
		return "vmla_n_u16";
	case ARM64_INTRIN_VMLAQ_N_U16:
		return "vmlaq_n_u16";
	case ARM64_INTRIN_VMLA_N_U32:
		return "vmla_n_u32";
	case ARM64_INTRIN_VMLAQ_N_U32:
		return "vmlaq_n_u32";
	case ARM64_INTRIN_VMLA_N_F32:
		return "vmla_n_f32";
	case ARM64_INTRIN_VMLAQ_N_F32:
		return "vmlaq_n_f32";
	case ARM64_INTRIN_VMLAL_N_S16:
		return "vmlal_n_s16";
	case ARM64_INTRIN_VMLAL_N_S32:
		return "vmlal_n_s32";
	case ARM64_INTRIN_VMLAL_N_U16:
		return "vmlal_n_u16";
	case ARM64_INTRIN_VMLAL_N_U32:
		return "vmlal_n_u32";
	case ARM64_INTRIN_VMLAL_HIGH_N_S16:
		return "vmlal_high_n_s16";
	case ARM64_INTRIN_VMLAL_HIGH_N_S32:
		return "vmlal_high_n_s32";
	case ARM64_INTRIN_VMLAL_HIGH_N_U16:
		return "vmlal_high_n_u16";
	case ARM64_INTRIN_VMLAL_HIGH_N_U32:
		return "vmlal_high_n_u32";
	case ARM64_INTRIN_VQDMLAL_N_S16:
		return "vqdmlal_n_s16";
	case ARM64_INTRIN_VQDMLAL_N_S32:
		return "vqdmlal_n_s32";
	case ARM64_INTRIN_VQDMLAL_HIGH_N_S16:
		return "vqdmlal_high_n_s16";
	case ARM64_INTRIN_VQDMLAL_HIGH_N_S32:
		return "vqdmlal_high_n_s32";
	case ARM64_INTRIN_VMLS_N_S16:
		return "vmls_n_s16";
	case ARM64_INTRIN_VMLSQ_N_S16:
		return "vmlsq_n_s16";
	case ARM64_INTRIN_VMLS_N_S32:
		return "vmls_n_s32";
	case ARM64_INTRIN_VMLSQ_N_S32:
		return "vmlsq_n_s32";
	case ARM64_INTRIN_VMLS_N_U16:
		return "vmls_n_u16";
	case ARM64_INTRIN_VMLSQ_N_U16:
		return "vmlsq_n_u16";
	case ARM64_INTRIN_VMLS_N_U32:
		return "vmls_n_u32";
	case ARM64_INTRIN_VMLSQ_N_U32:
		return "vmlsq_n_u32";
	case ARM64_INTRIN_VMLS_N_F32:
		return "vmls_n_f32";
	case ARM64_INTRIN_VMLSQ_N_F32:
		return "vmlsq_n_f32";
	case ARM64_INTRIN_VMLSL_N_S16:
		return "vmlsl_n_s16";
	case ARM64_INTRIN_VMLSL_N_S32:
		return "vmlsl_n_s32";
	case ARM64_INTRIN_VMLSL_N_U16:
		return "vmlsl_n_u16";
	case ARM64_INTRIN_VMLSL_N_U32:
		return "vmlsl_n_u32";
	case ARM64_INTRIN_VMLSL_HIGH_N_S16:
		return "vmlsl_high_n_s16";
	case ARM64_INTRIN_VMLSL_HIGH_N_S32:
		return "vmlsl_high_n_s32";
	case ARM64_INTRIN_VMLSL_HIGH_N_U16:
		return "vmlsl_high_n_u16";
	case ARM64_INTRIN_VMLSL_HIGH_N_U32:
		return "vmlsl_high_n_u32";
	case ARM64_INTRIN_VQDMLSL_N_S16:
		return "vqdmlsl_n_s16";
	case ARM64_INTRIN_VQDMLSL_N_S32:
		return "vqdmlsl_n_s32";
	case ARM64_INTRIN_VQDMLSL_HIGH_N_S16:
		return "vqdmlsl_high_n_s16";
	case ARM64_INTRIN_VQDMLSL_HIGH_N_S32:
		return "vqdmlsl_high_n_s32";
	case ARM64_INTRIN_VABS_S8:
		return "vabs_s8";
	case ARM64_INTRIN_VABSQ_S8:
		return "vabsq_s8";
	case ARM64_INTRIN_VABS_S16:
		return "vabs_s16";
	case ARM64_INTRIN_VABSQ_S16:
		return "vabsq_s16";
	case ARM64_INTRIN_VABS_S32:
		return "vabs_s32";
	case ARM64_INTRIN_VABSQ_S32:
		return "vabsq_s32";
	case ARM64_INTRIN_VABS_F32:
		return "vabs_f32";
	case ARM64_INTRIN_VABSQ_F32:
		return "vabsq_f32";
	case ARM64_INTRIN_VABS_S64:
		return "vabs_s64";
	case ARM64_INTRIN_VABSD_S64:
		return "vabsd_s64";
	case ARM64_INTRIN_VABSQ_S64:
		return "vabsq_s64";
	case ARM64_INTRIN_VABS_F64:
		return "vabs_f64";
	case ARM64_INTRIN_VABSQ_F64:
		return "vabsq_f64";
	case ARM64_INTRIN_VQABS_S8:
		return "vqabs_s8";
	case ARM64_INTRIN_VQABSQ_S8:
		return "vqabsq_s8";
	case ARM64_INTRIN_VQABS_S16:
		return "vqabs_s16";
	case ARM64_INTRIN_VQABSQ_S16:
		return "vqabsq_s16";
	case ARM64_INTRIN_VQABS_S32:
		return "vqabs_s32";
	case ARM64_INTRIN_VQABSQ_S32:
		return "vqabsq_s32";
	case ARM64_INTRIN_VQABS_S64:
		return "vqabs_s64";
	case ARM64_INTRIN_VQABSQ_S64:
		return "vqabsq_s64";
	case ARM64_INTRIN_VQABSB_S8:
		return "vqabsb_s8";
	case ARM64_INTRIN_VQABSH_S16:
		return "vqabsh_s16";
	case ARM64_INTRIN_VQABSS_S32:
		return "vqabss_s32";
	case ARM64_INTRIN_VQABSD_S64:
		return "vqabsd_s64";
	case ARM64_INTRIN_VNEG_S8:
		return "vneg_s8";
	case ARM64_INTRIN_VNEGQ_S8:
		return "vnegq_s8";
	case ARM64_INTRIN_VNEG_S16:
		return "vneg_s16";
	case ARM64_INTRIN_VNEGQ_S16:
		return "vnegq_s16";
	case ARM64_INTRIN_VNEG_S32:
		return "vneg_s32";
	case ARM64_INTRIN_VNEGQ_S32:
		return "vnegq_s32";
	case ARM64_INTRIN_VNEG_F32:
		return "vneg_f32";
	case ARM64_INTRIN_VNEGQ_F32:
		return "vnegq_f32";
	case ARM64_INTRIN_VNEG_S64:
		return "vneg_s64";
	case ARM64_INTRIN_VNEGD_S64:
		return "vnegd_s64";
	case ARM64_INTRIN_VNEGQ_S64:
		return "vnegq_s64";
	case ARM64_INTRIN_VNEG_F64:
		return "vneg_f64";
	case ARM64_INTRIN_VNEGQ_F64:
		return "vnegq_f64";
	case ARM64_INTRIN_VQNEG_S8:
		return "vqneg_s8";
	case ARM64_INTRIN_VQNEGQ_S8:
		return "vqnegq_s8";
	case ARM64_INTRIN_VQNEG_S16:
		return "vqneg_s16";
	case ARM64_INTRIN_VQNEGQ_S16:
		return "vqnegq_s16";
	case ARM64_INTRIN_VQNEG_S32:
		return "vqneg_s32";
	case ARM64_INTRIN_VQNEGQ_S32:
		return "vqnegq_s32";
	case ARM64_INTRIN_VQNEG_S64:
		return "vqneg_s64";
	case ARM64_INTRIN_VQNEGQ_S64:
		return "vqnegq_s64";
	case ARM64_INTRIN_VQNEGB_S8:
		return "vqnegb_s8";
	case ARM64_INTRIN_VQNEGH_S16:
		return "vqnegh_s16";
	case ARM64_INTRIN_VQNEGS_S32:
		return "vqnegs_s32";
	case ARM64_INTRIN_VQNEGD_S64:
		return "vqnegd_s64";
	case ARM64_INTRIN_VCLS_S8:
		return "vcls_s8";
	case ARM64_INTRIN_VCLSQ_S8:
		return "vclsq_s8";
	case ARM64_INTRIN_VCLS_S16:
		return "vcls_s16";
	case ARM64_INTRIN_VCLSQ_S16:
		return "vclsq_s16";
	case ARM64_INTRIN_VCLS_S32:
		return "vcls_s32";
	case ARM64_INTRIN_VCLSQ_S32:
		return "vclsq_s32";
	case ARM64_INTRIN_VCLS_U8:
		return "vcls_u8";
	case ARM64_INTRIN_VCLSQ_U8:
		return "vclsq_u8";
	case ARM64_INTRIN_VCLS_U16:
		return "vcls_u16";
	case ARM64_INTRIN_VCLSQ_U16:
		return "vclsq_u16";
	case ARM64_INTRIN_VCLS_U32:
		return "vcls_u32";
	case ARM64_INTRIN_VCLSQ_U32:
		return "vclsq_u32";
	case ARM64_INTRIN_VCLZ_S8:
		return "vclz_s8";
	case ARM64_INTRIN_VCLZQ_S8:
		return "vclzq_s8";
	case ARM64_INTRIN_VCLZ_S16:
		return "vclz_s16";
	case ARM64_INTRIN_VCLZQ_S16:
		return "vclzq_s16";
	case ARM64_INTRIN_VCLZ_S32:
		return "vclz_s32";
	case ARM64_INTRIN_VCLZQ_S32:
		return "vclzq_s32";
	case ARM64_INTRIN_VCLZ_U8:
		return "vclz_u8";
	case ARM64_INTRIN_VCLZQ_U8:
		return "vclzq_u8";
	case ARM64_INTRIN_VCLZ_U16:
		return "vclz_u16";
	case ARM64_INTRIN_VCLZQ_U16:
		return "vclzq_u16";
	case ARM64_INTRIN_VCLZ_U32:
		return "vclz_u32";
	case ARM64_INTRIN_VCLZQ_U32:
		return "vclzq_u32";
	case ARM64_INTRIN_VCNT_S8:
		return "vcnt_s8";
	case ARM64_INTRIN_VCNTQ_S8:
		return "vcntq_s8";
	case ARM64_INTRIN_VCNT_U8:
		return "vcnt_u8";
	case ARM64_INTRIN_VCNTQ_U8:
		return "vcntq_u8";
	case ARM64_INTRIN_VCNT_P8:
		return "vcnt_p8";
	case ARM64_INTRIN_VCNTQ_P8:
		return "vcntq_p8";
	case ARM64_INTRIN_VRECPE_U32:
		return "vrecpe_u32";
	case ARM64_INTRIN_VRECPEQ_U32:
		return "vrecpeq_u32";
	case ARM64_INTRIN_VRECPE_F32:
		return "vrecpe_f32";
	case ARM64_INTRIN_VRECPEQ_F32:
		return "vrecpeq_f32";
	case ARM64_INTRIN_VRECPE_F64:
		return "vrecpe_f64";
	case ARM64_INTRIN_VRECPEQ_F64:
		return "vrecpeq_f64";
	case ARM64_INTRIN_VRECPES_F32:
		return "vrecpes_f32";
	case ARM64_INTRIN_VRECPED_F64:
		return "vrecped_f64";
	case ARM64_INTRIN_VRECPS_F32:
		return "vrecps_f32";
	case ARM64_INTRIN_VRECPSQ_F32:
		return "vrecpsq_f32";
	case ARM64_INTRIN_VRECPS_F64:
		return "vrecps_f64";
	case ARM64_INTRIN_VRECPSQ_F64:
		return "vrecpsq_f64";
	case ARM64_INTRIN_VRECPSS_F32:
		return "vrecpss_f32";
	case ARM64_INTRIN_VRECPSD_F64:
		return "vrecpsd_f64";
	case ARM64_INTRIN_VSQRT_F32:
		return "vsqrt_f32";
	case ARM64_INTRIN_VSQRTQ_F32:
		return "vsqrtq_f32";
	case ARM64_INTRIN_VSQRT_F64:
		return "vsqrt_f64";
	case ARM64_INTRIN_VSQRTQ_F64:
		return "vsqrtq_f64";
	case ARM64_INTRIN_VRSQRTE_U32:
		return "vrsqrte_u32";
	case ARM64_INTRIN_VRSQRTEQ_U32:
		return "vrsqrteq_u32";
	case ARM64_INTRIN_VRSQRTE_F32:
		return "vrsqrte_f32";
	case ARM64_INTRIN_VRSQRTEQ_F32:
		return "vrsqrteq_f32";
	case ARM64_INTRIN_VRSQRTE_F64:
		return "vrsqrte_f64";
	case ARM64_INTRIN_VRSQRTEQ_F64:
		return "vrsqrteq_f64";
	case ARM64_INTRIN_VRSQRTES_F32:
		return "vrsqrtes_f32";
	case ARM64_INTRIN_VRSQRTED_F64:
		return "vrsqrted_f64";
	case ARM64_INTRIN_VRSQRTS_F32:
		return "vrsqrts_f32";
	case ARM64_INTRIN_VRSQRTSQ_F32:
		return "vrsqrtsq_f32";
	case ARM64_INTRIN_VRSQRTS_F64:
		return "vrsqrts_f64";
	case ARM64_INTRIN_VRSQRTSQ_F64:
		return "vrsqrtsq_f64";
	case ARM64_INTRIN_VRSQRTSS_F32:
		return "vrsqrtss_f32";
	case ARM64_INTRIN_VRSQRTSD_F64:
		return "vrsqrtsd_f64";
	case ARM64_INTRIN_VMVN_S8:
		return "vmvn_s8";
	case ARM64_INTRIN_VMVNQ_S8:
		return "vmvnq_s8";
	case ARM64_INTRIN_VMVN_S16:
		return "vmvn_s16";
	case ARM64_INTRIN_VMVNQ_S16:
		return "vmvnq_s16";
	case ARM64_INTRIN_VMVN_S32:
		return "vmvn_s32";
	case ARM64_INTRIN_VMVNQ_S32:
		return "vmvnq_s32";
	case ARM64_INTRIN_VMVN_U8:
		return "vmvn_u8";
	case ARM64_INTRIN_VMVNQ_U8:
		return "vmvnq_u8";
	case ARM64_INTRIN_VMVN_U16:
		return "vmvn_u16";
	case ARM64_INTRIN_VMVNQ_U16:
		return "vmvnq_u16";
	case ARM64_INTRIN_VMVN_U32:
		return "vmvn_u32";
	case ARM64_INTRIN_VMVNQ_U32:
		return "vmvnq_u32";
	case ARM64_INTRIN_VMVN_P8:
		return "vmvn_p8";
	case ARM64_INTRIN_VMVNQ_P8:
		return "vmvnq_p8";
	case ARM64_INTRIN_VAND_S8:
		return "vand_s8";
	case ARM64_INTRIN_VANDQ_S8:
		return "vandq_s8";
	case ARM64_INTRIN_VAND_S16:
		return "vand_s16";
	case ARM64_INTRIN_VANDQ_S16:
		return "vandq_s16";
	case ARM64_INTRIN_VAND_S32:
		return "vand_s32";
	case ARM64_INTRIN_VANDQ_S32:
		return "vandq_s32";
	case ARM64_INTRIN_VAND_S64:
		return "vand_s64";
	case ARM64_INTRIN_VANDQ_S64:
		return "vandq_s64";
	case ARM64_INTRIN_VAND_U8:
		return "vand_u8";
	case ARM64_INTRIN_VANDQ_U8:
		return "vandq_u8";
	case ARM64_INTRIN_VAND_U16:
		return "vand_u16";
	case ARM64_INTRIN_VANDQ_U16:
		return "vandq_u16";
	case ARM64_INTRIN_VAND_U32:
		return "vand_u32";
	case ARM64_INTRIN_VANDQ_U32:
		return "vandq_u32";
	case ARM64_INTRIN_VAND_U64:
		return "vand_u64";
	case ARM64_INTRIN_VANDQ_U64:
		return "vandq_u64";
	case ARM64_INTRIN_VORR_S8:
		return "vorr_s8";
	case ARM64_INTRIN_VORRQ_S8:
		return "vorrq_s8";
	case ARM64_INTRIN_VORR_S16:
		return "vorr_s16";
	case ARM64_INTRIN_VORRQ_S16:
		return "vorrq_s16";
	case ARM64_INTRIN_VORR_S32:
		return "vorr_s32";
	case ARM64_INTRIN_VORRQ_S32:
		return "vorrq_s32";
	case ARM64_INTRIN_VORR_S64:
		return "vorr_s64";
	case ARM64_INTRIN_VORRQ_S64:
		return "vorrq_s64";
	case ARM64_INTRIN_VORR_U8:
		return "vorr_u8";
	case ARM64_INTRIN_VORRQ_U8:
		return "vorrq_u8";
	case ARM64_INTRIN_VORR_U16:
		return "vorr_u16";
	case ARM64_INTRIN_VORRQ_U16:
		return "vorrq_u16";
	case ARM64_INTRIN_VORR_U32:
		return "vorr_u32";
	case ARM64_INTRIN_VORRQ_U32:
		return "vorrq_u32";
	case ARM64_INTRIN_VORR_U64:
		return "vorr_u64";
	case ARM64_INTRIN_VORRQ_U64:
		return "vorrq_u64";
	case ARM64_INTRIN_VEOR_S8:
		return "veor_s8";
	case ARM64_INTRIN_VEORQ_S8:
		return "veorq_s8";
	case ARM64_INTRIN_VEOR_S16:
		return "veor_s16";
	case ARM64_INTRIN_VEORQ_S16:
		return "veorq_s16";
	case ARM64_INTRIN_VEOR_S32:
		return "veor_s32";
	case ARM64_INTRIN_VEORQ_S32:
		return "veorq_s32";
	case ARM64_INTRIN_VEOR_S64:
		return "veor_s64";
	case ARM64_INTRIN_VEORQ_S64:
		return "veorq_s64";
	case ARM64_INTRIN_VEOR_U8:
		return "veor_u8";
	case ARM64_INTRIN_VEORQ_U8:
		return "veorq_u8";
	case ARM64_INTRIN_VEOR_U16:
		return "veor_u16";
	case ARM64_INTRIN_VEORQ_U16:
		return "veorq_u16";
	case ARM64_INTRIN_VEOR_U32:
		return "veor_u32";
	case ARM64_INTRIN_VEORQ_U32:
		return "veorq_u32";
	case ARM64_INTRIN_VEOR_U64:
		return "veor_u64";
	case ARM64_INTRIN_VEORQ_U64:
		return "veorq_u64";
	case ARM64_INTRIN_VBIC_S8:
		return "vbic_s8";
	case ARM64_INTRIN_VBICQ_S8:
		return "vbicq_s8";
	case ARM64_INTRIN_VBIC_S16:
		return "vbic_s16";
	case ARM64_INTRIN_VBICQ_S16:
		return "vbicq_s16";
	case ARM64_INTRIN_VBIC_S32:
		return "vbic_s32";
	case ARM64_INTRIN_VBICQ_S32:
		return "vbicq_s32";
	case ARM64_INTRIN_VBIC_S64:
		return "vbic_s64";
	case ARM64_INTRIN_VBICQ_S64:
		return "vbicq_s64";
	case ARM64_INTRIN_VBIC_U8:
		return "vbic_u8";
	case ARM64_INTRIN_VBICQ_U8:
		return "vbicq_u8";
	case ARM64_INTRIN_VBIC_U16:
		return "vbic_u16";
	case ARM64_INTRIN_VBICQ_U16:
		return "vbicq_u16";
	case ARM64_INTRIN_VBIC_U32:
		return "vbic_u32";
	case ARM64_INTRIN_VBICQ_U32:
		return "vbicq_u32";
	case ARM64_INTRIN_VBIC_U64:
		return "vbic_u64";
	case ARM64_INTRIN_VBICQ_U64:
		return "vbicq_u64";
	case ARM64_INTRIN_VORN_S8:
		return "vorn_s8";
	case ARM64_INTRIN_VORNQ_S8:
		return "vornq_s8";
	case ARM64_INTRIN_VORN_S16:
		return "vorn_s16";
	case ARM64_INTRIN_VORNQ_S16:
		return "vornq_s16";
	case ARM64_INTRIN_VORN_S32:
		return "vorn_s32";
	case ARM64_INTRIN_VORNQ_S32:
		return "vornq_s32";
	case ARM64_INTRIN_VORN_S64:
		return "vorn_s64";
	case ARM64_INTRIN_VORNQ_S64:
		return "vornq_s64";
	case ARM64_INTRIN_VORN_U8:
		return "vorn_u8";
	case ARM64_INTRIN_VORNQ_U8:
		return "vornq_u8";
	case ARM64_INTRIN_VORN_U16:
		return "vorn_u16";
	case ARM64_INTRIN_VORNQ_U16:
		return "vornq_u16";
	case ARM64_INTRIN_VORN_U32:
		return "vorn_u32";
	case ARM64_INTRIN_VORNQ_U32:
		return "vornq_u32";
	case ARM64_INTRIN_VORN_U64:
		return "vorn_u64";
	case ARM64_INTRIN_VORNQ_U64:
		return "vornq_u64";
	case ARM64_INTRIN_VBSL_S8:
		return "vbsl_s8";
	case ARM64_INTRIN_VBSLQ_S8:
		return "vbslq_s8";
	case ARM64_INTRIN_VBSL_S16:
		return "vbsl_s16";
	case ARM64_INTRIN_VBSLQ_S16:
		return "vbslq_s16";
	case ARM64_INTRIN_VBSL_S32:
		return "vbsl_s32";
	case ARM64_INTRIN_VBSLQ_S32:
		return "vbslq_s32";
	case ARM64_INTRIN_VBSL_S64:
		return "vbsl_s64";
	case ARM64_INTRIN_VBSLQ_S64:
		return "vbslq_s64";
	case ARM64_INTRIN_VBSL_U8:
		return "vbsl_u8";
	case ARM64_INTRIN_VBSLQ_U8:
		return "vbslq_u8";
	case ARM64_INTRIN_VBSL_U16:
		return "vbsl_u16";
	case ARM64_INTRIN_VBSLQ_U16:
		return "vbslq_u16";
	case ARM64_INTRIN_VBSL_U32:
		return "vbsl_u32";
	case ARM64_INTRIN_VBSLQ_U32:
		return "vbslq_u32";
	case ARM64_INTRIN_VBSL_U64:
		return "vbsl_u64";
	case ARM64_INTRIN_VBSLQ_U64:
		return "vbslq_u64";
	case ARM64_INTRIN_VBSL_P64:
		return "vbsl_p64";
	case ARM64_INTRIN_VBSLQ_P64:
		return "vbslq_p64";
	case ARM64_INTRIN_VBSL_F32:
		return "vbsl_f32";
	case ARM64_INTRIN_VBSLQ_F32:
		return "vbslq_f32";
	case ARM64_INTRIN_VBSL_P8:
		return "vbsl_p8";
	case ARM64_INTRIN_VBSLQ_P8:
		return "vbslq_p8";
	case ARM64_INTRIN_VBSL_P16:
		return "vbsl_p16";
	case ARM64_INTRIN_VBSLQ_P16:
		return "vbslq_p16";
	case ARM64_INTRIN_VBSL_F64:
		return "vbsl_f64";
	case ARM64_INTRIN_VBSLQ_F64:
		return "vbslq_f64";
	case ARM64_INTRIN_VCOPY_LANE_S8:
		return "vcopy_lane_s8";
	case ARM64_INTRIN_VCOPYQ_LANE_S8:
		return "vcopyq_lane_s8";
	case ARM64_INTRIN_VCOPY_LANE_S16:
		return "vcopy_lane_s16";
	case ARM64_INTRIN_VCOPYQ_LANE_S16:
		return "vcopyq_lane_s16";
	case ARM64_INTRIN_VCOPY_LANE_S32:
		return "vcopy_lane_s32";
	case ARM64_INTRIN_VCOPYQ_LANE_S32:
		return "vcopyq_lane_s32";
	case ARM64_INTRIN_VCOPY_LANE_S64:
		return "vcopy_lane_s64";
	case ARM64_INTRIN_VCOPYQ_LANE_S64:
		return "vcopyq_lane_s64";
	case ARM64_INTRIN_VCOPY_LANE_U8:
		return "vcopy_lane_u8";
	case ARM64_INTRIN_VCOPYQ_LANE_U8:
		return "vcopyq_lane_u8";
	case ARM64_INTRIN_VCOPY_LANE_U16:
		return "vcopy_lane_u16";
	case ARM64_INTRIN_VCOPYQ_LANE_U16:
		return "vcopyq_lane_u16";
	case ARM64_INTRIN_VCOPY_LANE_U32:
		return "vcopy_lane_u32";
	case ARM64_INTRIN_VCOPYQ_LANE_U32:
		return "vcopyq_lane_u32";
	case ARM64_INTRIN_VCOPY_LANE_U64:
		return "vcopy_lane_u64";
	case ARM64_INTRIN_VCOPYQ_LANE_U64:
		return "vcopyq_lane_u64";
	case ARM64_INTRIN_VCOPY_LANE_P64:
		return "vcopy_lane_p64";
	case ARM64_INTRIN_VCOPYQ_LANE_P64:
		return "vcopyq_lane_p64";
	case ARM64_INTRIN_VCOPY_LANE_F32:
		return "vcopy_lane_f32";
	case ARM64_INTRIN_VCOPYQ_LANE_F32:
		return "vcopyq_lane_f32";
	case ARM64_INTRIN_VCOPY_LANE_F64:
		return "vcopy_lane_f64";
	case ARM64_INTRIN_VCOPYQ_LANE_F64:
		return "vcopyq_lane_f64";
	case ARM64_INTRIN_VCOPY_LANE_P8:
		return "vcopy_lane_p8";
	case ARM64_INTRIN_VCOPYQ_LANE_P8:
		return "vcopyq_lane_p8";
	case ARM64_INTRIN_VCOPY_LANE_P16:
		return "vcopy_lane_p16";
	case ARM64_INTRIN_VCOPYQ_LANE_P16:
		return "vcopyq_lane_p16";
	case ARM64_INTRIN_VCOPY_LANEQ_S8:
		return "vcopy_laneq_s8";
	case ARM64_INTRIN_VCOPYQ_LANEQ_S8:
		return "vcopyq_laneq_s8";
	case ARM64_INTRIN_VCOPY_LANEQ_S16:
		return "vcopy_laneq_s16";
	case ARM64_INTRIN_VCOPYQ_LANEQ_S16:
		return "vcopyq_laneq_s16";
	case ARM64_INTRIN_VCOPY_LANEQ_S32:
		return "vcopy_laneq_s32";
	case ARM64_INTRIN_VCOPYQ_LANEQ_S32:
		return "vcopyq_laneq_s32";
	case ARM64_INTRIN_VCOPY_LANEQ_S64:
		return "vcopy_laneq_s64";
	case ARM64_INTRIN_VCOPYQ_LANEQ_S64:
		return "vcopyq_laneq_s64";
	case ARM64_INTRIN_VCOPY_LANEQ_U8:
		return "vcopy_laneq_u8";
	case ARM64_INTRIN_VCOPYQ_LANEQ_U8:
		return "vcopyq_laneq_u8";
	case ARM64_INTRIN_VCOPY_LANEQ_U16:
		return "vcopy_laneq_u16";
	case ARM64_INTRIN_VCOPYQ_LANEQ_U16:
		return "vcopyq_laneq_u16";
	case ARM64_INTRIN_VCOPY_LANEQ_U32:
		return "vcopy_laneq_u32";
	case ARM64_INTRIN_VCOPYQ_LANEQ_U32:
		return "vcopyq_laneq_u32";
	case ARM64_INTRIN_VCOPY_LANEQ_U64:
		return "vcopy_laneq_u64";
	case ARM64_INTRIN_VCOPYQ_LANEQ_U64:
		return "vcopyq_laneq_u64";
	case ARM64_INTRIN_VCOPY_LANEQ_P64:
		return "vcopy_laneq_p64";
	case ARM64_INTRIN_VCOPYQ_LANEQ_P64:
		return "vcopyq_laneq_p64";
	case ARM64_INTRIN_VCOPY_LANEQ_F32:
		return "vcopy_laneq_f32";
	case ARM64_INTRIN_VCOPYQ_LANEQ_F32:
		return "vcopyq_laneq_f32";
	case ARM64_INTRIN_VCOPY_LANEQ_F64:
		return "vcopy_laneq_f64";
	case ARM64_INTRIN_VCOPYQ_LANEQ_F64:
		return "vcopyq_laneq_f64";
	case ARM64_INTRIN_VCOPY_LANEQ_P8:
		return "vcopy_laneq_p8";
	case ARM64_INTRIN_VCOPYQ_LANEQ_P8:
		return "vcopyq_laneq_p8";
	case ARM64_INTRIN_VCOPY_LANEQ_P16:
		return "vcopy_laneq_p16";
	case ARM64_INTRIN_VCOPYQ_LANEQ_P16:
		return "vcopyq_laneq_p16";
	case ARM64_INTRIN_VRBIT_S8:
		return "vrbit_s8";
	case ARM64_INTRIN_VRBITQ_S8:
		return "vrbitq_s8";
	case ARM64_INTRIN_VRBIT_U8:
		return "vrbit_u8";
	case ARM64_INTRIN_VRBITQ_U8:
		return "vrbitq_u8";
	case ARM64_INTRIN_VRBIT_P8:
		return "vrbit_p8";
	case ARM64_INTRIN_VRBITQ_P8:
		return "vrbitq_p8";
	case ARM64_INTRIN_VCREATE_S8:
		return "vcreate_s8";
	case ARM64_INTRIN_VCREATE_S16:
		return "vcreate_s16";
	case ARM64_INTRIN_VCREATE_S32:
		return "vcreate_s32";
	case ARM64_INTRIN_VCREATE_S64:
		return "vcreate_s64";
	case ARM64_INTRIN_VCREATE_U8:
		return "vcreate_u8";
	case ARM64_INTRIN_VCREATE_U16:
		return "vcreate_u16";
	case ARM64_INTRIN_VCREATE_U32:
		return "vcreate_u32";
	case ARM64_INTRIN_VCREATE_U64:
		return "vcreate_u64";
	case ARM64_INTRIN_VCREATE_P64:
		return "vcreate_p64";
	case ARM64_INTRIN_VCREATE_F16:
		return "vcreate_f16";
	case ARM64_INTRIN_VCREATE_F32:
		return "vcreate_f32";
	case ARM64_INTRIN_VCREATE_P8:
		return "vcreate_p8";
	case ARM64_INTRIN_VCREATE_P16:
		return "vcreate_p16";
	case ARM64_INTRIN_VCREATE_F64:
		return "vcreate_f64";
	case ARM64_INTRIN_VDUP_N_S8:
		return "vdup_n_s8";
	case ARM64_INTRIN_VDUPQ_N_S8:
		return "vdupq_n_s8";
	case ARM64_INTRIN_VDUP_N_S16:
		return "vdup_n_s16";
	case ARM64_INTRIN_VDUPQ_N_S16:
		return "vdupq_n_s16";
	case ARM64_INTRIN_VDUP_N_S32:
		return "vdup_n_s32";
	case ARM64_INTRIN_VDUPQ_N_S32:
		return "vdupq_n_s32";
	case ARM64_INTRIN_VDUP_N_S64:
		return "vdup_n_s64";
	case ARM64_INTRIN_VDUPQ_N_S64:
		return "vdupq_n_s64";
	case ARM64_INTRIN_VDUP_N_U8:
		return "vdup_n_u8";
	case ARM64_INTRIN_VDUPQ_N_U8:
		return "vdupq_n_u8";
	case ARM64_INTRIN_VDUP_N_U16:
		return "vdup_n_u16";
	case ARM64_INTRIN_VDUPQ_N_U16:
		return "vdupq_n_u16";
	case ARM64_INTRIN_VDUP_N_U32:
		return "vdup_n_u32";
	case ARM64_INTRIN_VDUPQ_N_U32:
		return "vdupq_n_u32";
	case ARM64_INTRIN_VDUP_N_U64:
		return "vdup_n_u64";
	case ARM64_INTRIN_VDUPQ_N_U64:
		return "vdupq_n_u64";
	case ARM64_INTRIN_VDUP_N_P64:
		return "vdup_n_p64";
	case ARM64_INTRIN_VDUPQ_N_P64:
		return "vdupq_n_p64";
	case ARM64_INTRIN_VDUP_N_F32:
		return "vdup_n_f32";
	case ARM64_INTRIN_VDUPQ_N_F32:
		return "vdupq_n_f32";
	case ARM64_INTRIN_VDUP_N_P8:
		return "vdup_n_p8";
	case ARM64_INTRIN_VDUPQ_N_P8:
		return "vdupq_n_p8";
	case ARM64_INTRIN_VDUP_N_P16:
		return "vdup_n_p16";
	case ARM64_INTRIN_VDUPQ_N_P16:
		return "vdupq_n_p16";
	case ARM64_INTRIN_VDUP_N_F64:
		return "vdup_n_f64";
	case ARM64_INTRIN_VDUPQ_N_F64:
		return "vdupq_n_f64";
	case ARM64_INTRIN_VMOV_N_S8:
		return "vmov_n_s8";
	case ARM64_INTRIN_VMOVQ_N_S8:
		return "vmovq_n_s8";
	case ARM64_INTRIN_VMOV_N_S16:
		return "vmov_n_s16";
	case ARM64_INTRIN_VMOVQ_N_S16:
		return "vmovq_n_s16";
	case ARM64_INTRIN_VMOV_N_S32:
		return "vmov_n_s32";
	case ARM64_INTRIN_VMOVQ_N_S32:
		return "vmovq_n_s32";
	case ARM64_INTRIN_VMOV_N_S64:
		return "vmov_n_s64";
	case ARM64_INTRIN_VMOVQ_N_S64:
		return "vmovq_n_s64";
	case ARM64_INTRIN_VMOV_N_U8:
		return "vmov_n_u8";
	case ARM64_INTRIN_VMOVQ_N_U8:
		return "vmovq_n_u8";
	case ARM64_INTRIN_VMOV_N_U16:
		return "vmov_n_u16";
	case ARM64_INTRIN_VMOVQ_N_U16:
		return "vmovq_n_u16";
	case ARM64_INTRIN_VMOV_N_U32:
		return "vmov_n_u32";
	case ARM64_INTRIN_VMOVQ_N_U32:
		return "vmovq_n_u32";
	case ARM64_INTRIN_VMOV_N_U64:
		return "vmov_n_u64";
	case ARM64_INTRIN_VMOVQ_N_U64:
		return "vmovq_n_u64";
	case ARM64_INTRIN_VMOV_N_F32:
		return "vmov_n_f32";
	case ARM64_INTRIN_VMOVQ_N_F32:
		return "vmovq_n_f32";
	case ARM64_INTRIN_VMOV_N_P8:
		return "vmov_n_p8";
	case ARM64_INTRIN_VMOVQ_N_P8:
		return "vmovq_n_p8";
	case ARM64_INTRIN_VMOV_N_P16:
		return "vmov_n_p16";
	case ARM64_INTRIN_VMOVQ_N_P16:
		return "vmovq_n_p16";
	case ARM64_INTRIN_VMOV_N_F64:
		return "vmov_n_f64";
	case ARM64_INTRIN_VMOVQ_N_F64:
		return "vmovq_n_f64";
	case ARM64_INTRIN_VDUP_LANE_S8:
		return "vdup_lane_s8";
	case ARM64_INTRIN_VDUPQ_LANE_S8:
		return "vdupq_lane_s8";
	case ARM64_INTRIN_VDUP_LANE_S16:
		return "vdup_lane_s16";
	case ARM64_INTRIN_VDUPQ_LANE_S16:
		return "vdupq_lane_s16";
	case ARM64_INTRIN_VDUP_LANE_S32:
		return "vdup_lane_s32";
	case ARM64_INTRIN_VDUPQ_LANE_S32:
		return "vdupq_lane_s32";
	case ARM64_INTRIN_VDUP_LANE_S64:
		return "vdup_lane_s64";
	case ARM64_INTRIN_VDUPQ_LANE_S64:
		return "vdupq_lane_s64";
	case ARM64_INTRIN_VDUP_LANE_U8:
		return "vdup_lane_u8";
	case ARM64_INTRIN_VDUPQ_LANE_U8:
		return "vdupq_lane_u8";
	case ARM64_INTRIN_VDUP_LANE_U16:
		return "vdup_lane_u16";
	case ARM64_INTRIN_VDUPQ_LANE_U16:
		return "vdupq_lane_u16";
	case ARM64_INTRIN_VDUP_LANE_U32:
		return "vdup_lane_u32";
	case ARM64_INTRIN_VDUPQ_LANE_U32:
		return "vdupq_lane_u32";
	case ARM64_INTRIN_VDUP_LANE_U64:
		return "vdup_lane_u64";
	case ARM64_INTRIN_VDUPQ_LANE_U64:
		return "vdupq_lane_u64";
	case ARM64_INTRIN_VDUP_LANE_P64:
		return "vdup_lane_p64";
	case ARM64_INTRIN_VDUPQ_LANE_P64:
		return "vdupq_lane_p64";
	case ARM64_INTRIN_VDUP_LANE_F32:
		return "vdup_lane_f32";
	case ARM64_INTRIN_VDUPQ_LANE_F32:
		return "vdupq_lane_f32";
	case ARM64_INTRIN_VDUP_LANE_P8:
		return "vdup_lane_p8";
	case ARM64_INTRIN_VDUPQ_LANE_P8:
		return "vdupq_lane_p8";
	case ARM64_INTRIN_VDUP_LANE_P16:
		return "vdup_lane_p16";
	case ARM64_INTRIN_VDUPQ_LANE_P16:
		return "vdupq_lane_p16";
	case ARM64_INTRIN_VDUP_LANE_F64:
		return "vdup_lane_f64";
	case ARM64_INTRIN_VDUPQ_LANE_F64:
		return "vdupq_lane_f64";
	case ARM64_INTRIN_VDUP_LANEQ_S8:
		return "vdup_laneq_s8";
	case ARM64_INTRIN_VDUPQ_LANEQ_S8:
		return "vdupq_laneq_s8";
	case ARM64_INTRIN_VDUP_LANEQ_S16:
		return "vdup_laneq_s16";
	case ARM64_INTRIN_VDUPQ_LANEQ_S16:
		return "vdupq_laneq_s16";
	case ARM64_INTRIN_VDUP_LANEQ_S32:
		return "vdup_laneq_s32";
	case ARM64_INTRIN_VDUPQ_LANEQ_S32:
		return "vdupq_laneq_s32";
	case ARM64_INTRIN_VDUP_LANEQ_S64:
		return "vdup_laneq_s64";
	case ARM64_INTRIN_VDUPQ_LANEQ_S64:
		return "vdupq_laneq_s64";
	case ARM64_INTRIN_VDUP_LANEQ_U8:
		return "vdup_laneq_u8";
	case ARM64_INTRIN_VDUPQ_LANEQ_U8:
		return "vdupq_laneq_u8";
	case ARM64_INTRIN_VDUP_LANEQ_U16:
		return "vdup_laneq_u16";
	case ARM64_INTRIN_VDUPQ_LANEQ_U16:
		return "vdupq_laneq_u16";
	case ARM64_INTRIN_VDUP_LANEQ_U32:
		return "vdup_laneq_u32";
	case ARM64_INTRIN_VDUPQ_LANEQ_U32:
		return "vdupq_laneq_u32";
	case ARM64_INTRIN_VDUP_LANEQ_U64:
		return "vdup_laneq_u64";
	case ARM64_INTRIN_VDUPQ_LANEQ_U64:
		return "vdupq_laneq_u64";
	case ARM64_INTRIN_VDUP_LANEQ_P64:
		return "vdup_laneq_p64";
	case ARM64_INTRIN_VDUPQ_LANEQ_P64:
		return "vdupq_laneq_p64";
	case ARM64_INTRIN_VDUP_LANEQ_F32:
		return "vdup_laneq_f32";
	case ARM64_INTRIN_VDUPQ_LANEQ_F32:
		return "vdupq_laneq_f32";
	case ARM64_INTRIN_VDUP_LANEQ_P8:
		return "vdup_laneq_p8";
	case ARM64_INTRIN_VDUPQ_LANEQ_P8:
		return "vdupq_laneq_p8";
	case ARM64_INTRIN_VDUP_LANEQ_P16:
		return "vdup_laneq_p16";
	case ARM64_INTRIN_VDUPQ_LANEQ_P16:
		return "vdupq_laneq_p16";
	case ARM64_INTRIN_VDUP_LANEQ_F64:
		return "vdup_laneq_f64";
	case ARM64_INTRIN_VDUPQ_LANEQ_F64:
		return "vdupq_laneq_f64";
	case ARM64_INTRIN_VCOMBINE_S8:
		return "vcombine_s8";
	case ARM64_INTRIN_VCOMBINE_S16:
		return "vcombine_s16";
	case ARM64_INTRIN_VCOMBINE_S32:
		return "vcombine_s32";
	case ARM64_INTRIN_VCOMBINE_S64:
		return "vcombine_s64";
	case ARM64_INTRIN_VCOMBINE_U8:
		return "vcombine_u8";
	case ARM64_INTRIN_VCOMBINE_U16:
		return "vcombine_u16";
	case ARM64_INTRIN_VCOMBINE_U32:
		return "vcombine_u32";
	case ARM64_INTRIN_VCOMBINE_U64:
		return "vcombine_u64";
	case ARM64_INTRIN_VCOMBINE_P64:
		return "vcombine_p64";
	case ARM64_INTRIN_VCOMBINE_F16:
		return "vcombine_f16";
	case ARM64_INTRIN_VCOMBINE_F32:
		return "vcombine_f32";
	case ARM64_INTRIN_VCOMBINE_P8:
		return "vcombine_p8";
	case ARM64_INTRIN_VCOMBINE_P16:
		return "vcombine_p16";
	case ARM64_INTRIN_VCOMBINE_F64:
		return "vcombine_f64";
	case ARM64_INTRIN_VGET_HIGH_S8:
		return "vget_high_s8";
	case ARM64_INTRIN_VGET_HIGH_S16:
		return "vget_high_s16";
	case ARM64_INTRIN_VGET_HIGH_S32:
		return "vget_high_s32";
	case ARM64_INTRIN_VGET_HIGH_S64:
		return "vget_high_s64";
	case ARM64_INTRIN_VGET_HIGH_U8:
		return "vget_high_u8";
	case ARM64_INTRIN_VGET_HIGH_U16:
		return "vget_high_u16";
	case ARM64_INTRIN_VGET_HIGH_U32:
		return "vget_high_u32";
	case ARM64_INTRIN_VGET_HIGH_U64:
		return "vget_high_u64";
	case ARM64_INTRIN_VGET_HIGH_P64:
		return "vget_high_p64";
	case ARM64_INTRIN_VGET_HIGH_F16:
		return "vget_high_f16";
	case ARM64_INTRIN_VGET_HIGH_F32:
		return "vget_high_f32";
	case ARM64_INTRIN_VGET_HIGH_P8:
		return "vget_high_p8";
	case ARM64_INTRIN_VGET_HIGH_P16:
		return "vget_high_p16";
	case ARM64_INTRIN_VGET_HIGH_F64:
		return "vget_high_f64";
	case ARM64_INTRIN_VGET_LOW_S8:
		return "vget_low_s8";
	case ARM64_INTRIN_VGET_LOW_S16:
		return "vget_low_s16";
	case ARM64_INTRIN_VGET_LOW_S32:
		return "vget_low_s32";
	case ARM64_INTRIN_VGET_LOW_S64:
		return "vget_low_s64";
	case ARM64_INTRIN_VGET_LOW_U8:
		return "vget_low_u8";
	case ARM64_INTRIN_VGET_LOW_U16:
		return "vget_low_u16";
	case ARM64_INTRIN_VGET_LOW_U32:
		return "vget_low_u32";
	case ARM64_INTRIN_VGET_LOW_U64:
		return "vget_low_u64";
	case ARM64_INTRIN_VGET_LOW_P64:
		return "vget_low_p64";
	case ARM64_INTRIN_VGET_LOW_F16:
		return "vget_low_f16";
	case ARM64_INTRIN_VGET_LOW_F32:
		return "vget_low_f32";
	case ARM64_INTRIN_VGET_LOW_P8:
		return "vget_low_p8";
	case ARM64_INTRIN_VGET_LOW_P16:
		return "vget_low_p16";
	case ARM64_INTRIN_VGET_LOW_F64:
		return "vget_low_f64";
	case ARM64_INTRIN_VDUPB_LANE_S8:
		return "vdupb_lane_s8";
	case ARM64_INTRIN_VDUPH_LANE_S16:
		return "vduph_lane_s16";
	case ARM64_INTRIN_VDUPS_LANE_S32:
		return "vdups_lane_s32";
	case ARM64_INTRIN_VDUPD_LANE_S64:
		return "vdupd_lane_s64";
	case ARM64_INTRIN_VDUPB_LANE_U8:
		return "vdupb_lane_u8";
	case ARM64_INTRIN_VDUPH_LANE_U16:
		return "vduph_lane_u16";
	case ARM64_INTRIN_VDUPS_LANE_U32:
		return "vdups_lane_u32";
	case ARM64_INTRIN_VDUPD_LANE_U64:
		return "vdupd_lane_u64";
	case ARM64_INTRIN_VDUPS_LANE_F32:
		return "vdups_lane_f32";
	case ARM64_INTRIN_VDUPD_LANE_F64:
		return "vdupd_lane_f64";
	case ARM64_INTRIN_VDUPB_LANE_P8:
		return "vdupb_lane_p8";
	case ARM64_INTRIN_VDUPH_LANE_P16:
		return "vduph_lane_p16";
	case ARM64_INTRIN_VDUPB_LANEQ_S8:
		return "vdupb_laneq_s8";
	case ARM64_INTRIN_VDUPH_LANEQ_S16:
		return "vduph_laneq_s16";
	case ARM64_INTRIN_VDUPS_LANEQ_S32:
		return "vdups_laneq_s32";
	case ARM64_INTRIN_VDUPD_LANEQ_S64:
		return "vdupd_laneq_s64";
	case ARM64_INTRIN_VDUPB_LANEQ_U8:
		return "vdupb_laneq_u8";
	case ARM64_INTRIN_VDUPH_LANEQ_U16:
		return "vduph_laneq_u16";
	case ARM64_INTRIN_VDUPS_LANEQ_U32:
		return "vdups_laneq_u32";
	case ARM64_INTRIN_VDUPD_LANEQ_U64:
		return "vdupd_laneq_u64";
	case ARM64_INTRIN_VDUPS_LANEQ_F32:
		return "vdups_laneq_f32";
	case ARM64_INTRIN_VDUPD_LANEQ_F64:
		return "vdupd_laneq_f64";
	case ARM64_INTRIN_VDUPB_LANEQ_P8:
		return "vdupb_laneq_p8";
	case ARM64_INTRIN_VDUPH_LANEQ_P16:
		return "vduph_laneq_p16";
	case ARM64_INTRIN_VLD1_S8:
		return "vld1_s8";
	case ARM64_INTRIN_VLD1Q_S8:
		return "vld1q_s8";
	case ARM64_INTRIN_VLD1_S16:
		return "vld1_s16";
	case ARM64_INTRIN_VLD1Q_S16:
		return "vld1q_s16";
	case ARM64_INTRIN_VLD1_S32:
		return "vld1_s32";
	case ARM64_INTRIN_VLD1Q_S32:
		return "vld1q_s32";
	case ARM64_INTRIN_VLD1_S64:
		return "vld1_s64";
	case ARM64_INTRIN_VLD1Q_S64:
		return "vld1q_s64";
	case ARM64_INTRIN_VLD1_U8:
		return "vld1_u8";
	case ARM64_INTRIN_VLD1Q_U8:
		return "vld1q_u8";
	case ARM64_INTRIN_VLD1_U16:
		return "vld1_u16";
	case ARM64_INTRIN_VLD1Q_U16:
		return "vld1q_u16";
	case ARM64_INTRIN_VLD1_U32:
		return "vld1_u32";
	case ARM64_INTRIN_VLD1Q_U32:
		return "vld1q_u32";
	case ARM64_INTRIN_VLD1_U64:
		return "vld1_u64";
	case ARM64_INTRIN_VLD1Q_U64:
		return "vld1q_u64";
	case ARM64_INTRIN_VLD1_P64:
		return "vld1_p64";
	case ARM64_INTRIN_VLD1Q_P64:
		return "vld1q_p64";
	case ARM64_INTRIN_VLD1_F16:
		return "vld1_f16";
	case ARM64_INTRIN_VLD1Q_F16:
		return "vld1q_f16";
	case ARM64_INTRIN_VLD1_F32:
		return "vld1_f32";
	case ARM64_INTRIN_VLD1Q_F32:
		return "vld1q_f32";
	case ARM64_INTRIN_VLD1_P8:
		return "vld1_p8";
	case ARM64_INTRIN_VLD1Q_P8:
		return "vld1q_p8";
	case ARM64_INTRIN_VLD1_P16:
		return "vld1_p16";
	case ARM64_INTRIN_VLD1Q_P16:
		return "vld1q_p16";
	case ARM64_INTRIN_VLD1_F64:
		return "vld1_f64";
	case ARM64_INTRIN_VLD1Q_F64:
		return "vld1q_f64";
	case ARM64_INTRIN_VLD1_LANE_S8:
		return "vld1_lane_s8";
	case ARM64_INTRIN_VLD1Q_LANE_S8:
		return "vld1q_lane_s8";
	case ARM64_INTRIN_VLD1_LANE_S16:
		return "vld1_lane_s16";
	case ARM64_INTRIN_VLD1Q_LANE_S16:
		return "vld1q_lane_s16";
	case ARM64_INTRIN_VLD1_LANE_S32:
		return "vld1_lane_s32";
	case ARM64_INTRIN_VLD1Q_LANE_S32:
		return "vld1q_lane_s32";
	case ARM64_INTRIN_VLD1_LANE_S64:
		return "vld1_lane_s64";
	case ARM64_INTRIN_VLD1Q_LANE_S64:
		return "vld1q_lane_s64";
	case ARM64_INTRIN_VLD1_LANE_U8:
		return "vld1_lane_u8";
	case ARM64_INTRIN_VLD1Q_LANE_U8:
		return "vld1q_lane_u8";
	case ARM64_INTRIN_VLD1_LANE_U16:
		return "vld1_lane_u16";
	case ARM64_INTRIN_VLD1Q_LANE_U16:
		return "vld1q_lane_u16";
	case ARM64_INTRIN_VLD1_LANE_U32:
		return "vld1_lane_u32";
	case ARM64_INTRIN_VLD1Q_LANE_U32:
		return "vld1q_lane_u32";
	case ARM64_INTRIN_VLD1_LANE_U64:
		return "vld1_lane_u64";
	case ARM64_INTRIN_VLD1Q_LANE_U64:
		return "vld1q_lane_u64";
	case ARM64_INTRIN_VLD1_LANE_P64:
		return "vld1_lane_p64";
	case ARM64_INTRIN_VLD1Q_LANE_P64:
		return "vld1q_lane_p64";
	case ARM64_INTRIN_VLD1_LANE_F16:
		return "vld1_lane_f16";
	case ARM64_INTRIN_VLD1Q_LANE_F16:
		return "vld1q_lane_f16";
	case ARM64_INTRIN_VLD1_LANE_F32:
		return "vld1_lane_f32";
	case ARM64_INTRIN_VLD1Q_LANE_F32:
		return "vld1q_lane_f32";
	case ARM64_INTRIN_VLD1_LANE_P8:
		return "vld1_lane_p8";
	case ARM64_INTRIN_VLD1Q_LANE_P8:
		return "vld1q_lane_p8";
	case ARM64_INTRIN_VLD1_LANE_P16:
		return "vld1_lane_p16";
	case ARM64_INTRIN_VLD1Q_LANE_P16:
		return "vld1q_lane_p16";
	case ARM64_INTRIN_VLD1_LANE_F64:
		return "vld1_lane_f64";
	case ARM64_INTRIN_VLD1Q_LANE_F64:
		return "vld1q_lane_f64";
	case ARM64_INTRIN_VLD1_DUP_S8:
		return "vld1_dup_s8";
	case ARM64_INTRIN_VLD1Q_DUP_S8:
		return "vld1q_dup_s8";
	case ARM64_INTRIN_VLD1_DUP_S16:
		return "vld1_dup_s16";
	case ARM64_INTRIN_VLD1Q_DUP_S16:
		return "vld1q_dup_s16";
	case ARM64_INTRIN_VLD1_DUP_S32:
		return "vld1_dup_s32";
	case ARM64_INTRIN_VLD1Q_DUP_S32:
		return "vld1q_dup_s32";
	case ARM64_INTRIN_VLD1_DUP_S64:
		return "vld1_dup_s64";
	case ARM64_INTRIN_VLD1Q_DUP_S64:
		return "vld1q_dup_s64";
	case ARM64_INTRIN_VLD1_DUP_U8:
		return "vld1_dup_u8";
	case ARM64_INTRIN_VLD1Q_DUP_U8:
		return "vld1q_dup_u8";
	case ARM64_INTRIN_VLD1_DUP_U16:
		return "vld1_dup_u16";
	case ARM64_INTRIN_VLD1Q_DUP_U16:
		return "vld1q_dup_u16";
	case ARM64_INTRIN_VLD1_DUP_U32:
		return "vld1_dup_u32";
	case ARM64_INTRIN_VLD1Q_DUP_U32:
		return "vld1q_dup_u32";
	case ARM64_INTRIN_VLD1_DUP_U64:
		return "vld1_dup_u64";
	case ARM64_INTRIN_VLD1Q_DUP_U64:
		return "vld1q_dup_u64";
	case ARM64_INTRIN_VLD1_DUP_P64:
		return "vld1_dup_p64";
	case ARM64_INTRIN_VLD1Q_DUP_P64:
		return "vld1q_dup_p64";
	case ARM64_INTRIN_VLD1_DUP_F16:
		return "vld1_dup_f16";
	case ARM64_INTRIN_VLD1Q_DUP_F16:
		return "vld1q_dup_f16";
	case ARM64_INTRIN_VLD1_DUP_F32:
		return "vld1_dup_f32";
	case ARM64_INTRIN_VLD1Q_DUP_F32:
		return "vld1q_dup_f32";
	case ARM64_INTRIN_VLD1_DUP_P8:
		return "vld1_dup_p8";
	case ARM64_INTRIN_VLD1Q_DUP_P8:
		return "vld1q_dup_p8";
	case ARM64_INTRIN_VLD1_DUP_P16:
		return "vld1_dup_p16";
	case ARM64_INTRIN_VLD1Q_DUP_P16:
		return "vld1q_dup_p16";
	case ARM64_INTRIN_VLD1_DUP_F64:
		return "vld1_dup_f64";
	case ARM64_INTRIN_VLD1Q_DUP_F64:
		return "vld1q_dup_f64";
	case ARM64_INTRIN_VST1_S8:
		return "vst1_s8";
	case ARM64_INTRIN_VST1Q_S8:
		return "vst1q_s8";
	case ARM64_INTRIN_VST1_S16:
		return "vst1_s16";
	case ARM64_INTRIN_VST1Q_S16:
		return "vst1q_s16";
	case ARM64_INTRIN_VST1_S32:
		return "vst1_s32";
	case ARM64_INTRIN_VST1Q_S32:
		return "vst1q_s32";
	case ARM64_INTRIN_VST1_S64:
		return "vst1_s64";
	case ARM64_INTRIN_VST1Q_S64:
		return "vst1q_s64";
	case ARM64_INTRIN_VST1_U8:
		return "vst1_u8";
	case ARM64_INTRIN_VST1Q_U8:
		return "vst1q_u8";
	case ARM64_INTRIN_VST1_U16:
		return "vst1_u16";
	case ARM64_INTRIN_VST1Q_U16:
		return "vst1q_u16";
	case ARM64_INTRIN_VST1_U32:
		return "vst1_u32";
	case ARM64_INTRIN_VST1Q_U32:
		return "vst1q_u32";
	case ARM64_INTRIN_VST1_U64:
		return "vst1_u64";
	case ARM64_INTRIN_VST1Q_U64:
		return "vst1q_u64";
	case ARM64_INTRIN_VST1_P64:
		return "vst1_p64";
	case ARM64_INTRIN_VST1Q_P64:
		return "vst1q_p64";
	case ARM64_INTRIN_VST1_F16:
		return "vst1_f16";
	case ARM64_INTRIN_VST1Q_F16:
		return "vst1q_f16";
	case ARM64_INTRIN_VST1_F32:
		return "vst1_f32";
	case ARM64_INTRIN_VST1Q_F32:
		return "vst1q_f32";
	case ARM64_INTRIN_VST1_P8:
		return "vst1_p8";
	case ARM64_INTRIN_VST1Q_P8:
		return "vst1q_p8";
	case ARM64_INTRIN_VST1_P16:
		return "vst1_p16";
	case ARM64_INTRIN_VST1Q_P16:
		return "vst1q_p16";
	case ARM64_INTRIN_VST1_F64:
		return "vst1_f64";
	case ARM64_INTRIN_VST1Q_F64:
		return "vst1q_f64";
	case ARM64_INTRIN_VST1_LANE_S8:
		return "vst1_lane_s8";
	case ARM64_INTRIN_VST1Q_LANE_S8:
		return "vst1q_lane_s8";
	case ARM64_INTRIN_VST1_LANE_S16:
		return "vst1_lane_s16";
	case ARM64_INTRIN_VST1Q_LANE_S16:
		return "vst1q_lane_s16";
	case ARM64_INTRIN_VST1_LANE_S32:
		return "vst1_lane_s32";
	case ARM64_INTRIN_VST1Q_LANE_S32:
		return "vst1q_lane_s32";
	case ARM64_INTRIN_VST1_LANE_S64:
		return "vst1_lane_s64";
	case ARM64_INTRIN_VST1Q_LANE_S64:
		return "vst1q_lane_s64";
	case ARM64_INTRIN_VST1_LANE_U8:
		return "vst1_lane_u8";
	case ARM64_INTRIN_VST1Q_LANE_U8:
		return "vst1q_lane_u8";
	case ARM64_INTRIN_VST1_LANE_U16:
		return "vst1_lane_u16";
	case ARM64_INTRIN_VST1Q_LANE_U16:
		return "vst1q_lane_u16";
	case ARM64_INTRIN_VST1_LANE_U32:
		return "vst1_lane_u32";
	case ARM64_INTRIN_VST1Q_LANE_U32:
		return "vst1q_lane_u32";
	case ARM64_INTRIN_VST1_LANE_U64:
		return "vst1_lane_u64";
	case ARM64_INTRIN_VST1Q_LANE_U64:
		return "vst1q_lane_u64";
	case ARM64_INTRIN_VST1_LANE_P64:
		return "vst1_lane_p64";
	case ARM64_INTRIN_VST1Q_LANE_P64:
		return "vst1q_lane_p64";
	case ARM64_INTRIN_VST1_LANE_F16:
		return "vst1_lane_f16";
	case ARM64_INTRIN_VST1Q_LANE_F16:
		return "vst1q_lane_f16";
	case ARM64_INTRIN_VST1_LANE_F32:
		return "vst1_lane_f32";
	case ARM64_INTRIN_VST1Q_LANE_F32:
		return "vst1q_lane_f32";
	case ARM64_INTRIN_VST1_LANE_P8:
		return "vst1_lane_p8";
	case ARM64_INTRIN_VST1Q_LANE_P8:
		return "vst1q_lane_p8";
	case ARM64_INTRIN_VST1_LANE_P16:
		return "vst1_lane_p16";
	case ARM64_INTRIN_VST1Q_LANE_P16:
		return "vst1q_lane_p16";
	case ARM64_INTRIN_VST1_LANE_F64:
		return "vst1_lane_f64";
	case ARM64_INTRIN_VST1Q_LANE_F64:
		return "vst1q_lane_f64";
	case ARM64_INTRIN_VLD2_S8:
		return "vld2_s8";
	case ARM64_INTRIN_VLD2Q_S8:
		return "vld2q_s8";
	case ARM64_INTRIN_VLD2_S16:
		return "vld2_s16";
	case ARM64_INTRIN_VLD2Q_S16:
		return "vld2q_s16";
	case ARM64_INTRIN_VLD2_S32:
		return "vld2_s32";
	case ARM64_INTRIN_VLD2Q_S32:
		return "vld2q_s32";
	case ARM64_INTRIN_VLD2_U8:
		return "vld2_u8";
	case ARM64_INTRIN_VLD2Q_U8:
		return "vld2q_u8";
	case ARM64_INTRIN_VLD2_U16:
		return "vld2_u16";
	case ARM64_INTRIN_VLD2Q_U16:
		return "vld2q_u16";
	case ARM64_INTRIN_VLD2_U32:
		return "vld2_u32";
	case ARM64_INTRIN_VLD2Q_U32:
		return "vld2q_u32";
	case ARM64_INTRIN_VLD2_F16:
		return "vld2_f16";
	case ARM64_INTRIN_VLD2Q_F16:
		return "vld2q_f16";
	case ARM64_INTRIN_VLD2_F32:
		return "vld2_f32";
	case ARM64_INTRIN_VLD2Q_F32:
		return "vld2q_f32";
	case ARM64_INTRIN_VLD2_P8:
		return "vld2_p8";
	case ARM64_INTRIN_VLD2Q_P8:
		return "vld2q_p8";
	case ARM64_INTRIN_VLD2_P16:
		return "vld2_p16";
	case ARM64_INTRIN_VLD2Q_P16:
		return "vld2q_p16";
	case ARM64_INTRIN_VLD2_S64:
		return "vld2_s64";
	case ARM64_INTRIN_VLD2_U64:
		return "vld2_u64";
	case ARM64_INTRIN_VLD2_P64:
		return "vld2_p64";
	case ARM64_INTRIN_VLD2Q_S64:
		return "vld2q_s64";
	case ARM64_INTRIN_VLD2Q_U64:
		return "vld2q_u64";
	case ARM64_INTRIN_VLD2Q_P64:
		return "vld2q_p64";
	case ARM64_INTRIN_VLD2_F64:
		return "vld2_f64";
	case ARM64_INTRIN_VLD2Q_F64:
		return "vld2q_f64";
	case ARM64_INTRIN_VLD3_S8:
		return "vld3_s8";
	case ARM64_INTRIN_VLD3Q_S8:
		return "vld3q_s8";
	case ARM64_INTRIN_VLD3_S16:
		return "vld3_s16";
	case ARM64_INTRIN_VLD3Q_S16:
		return "vld3q_s16";
	case ARM64_INTRIN_VLD3_S32:
		return "vld3_s32";
	case ARM64_INTRIN_VLD3Q_S32:
		return "vld3q_s32";
	case ARM64_INTRIN_VLD3_U8:
		return "vld3_u8";
	case ARM64_INTRIN_VLD3Q_U8:
		return "vld3q_u8";
	case ARM64_INTRIN_VLD3_U16:
		return "vld3_u16";
	case ARM64_INTRIN_VLD3Q_U16:
		return "vld3q_u16";
	case ARM64_INTRIN_VLD3_U32:
		return "vld3_u32";
	case ARM64_INTRIN_VLD3Q_U32:
		return "vld3q_u32";
	case ARM64_INTRIN_VLD3_F16:
		return "vld3_f16";
	case ARM64_INTRIN_VLD3Q_F16:
		return "vld3q_f16";
	case ARM64_INTRIN_VLD3_F32:
		return "vld3_f32";
	case ARM64_INTRIN_VLD3Q_F32:
		return "vld3q_f32";
	case ARM64_INTRIN_VLD3_P8:
		return "vld3_p8";
	case ARM64_INTRIN_VLD3Q_P8:
		return "vld3q_p8";
	case ARM64_INTRIN_VLD3_P16:
		return "vld3_p16";
	case ARM64_INTRIN_VLD3Q_P16:
		return "vld3q_p16";
	case ARM64_INTRIN_VLD3_S64:
		return "vld3_s64";
	case ARM64_INTRIN_VLD3_U64:
		return "vld3_u64";
	case ARM64_INTRIN_VLD3_P64:
		return "vld3_p64";
	case ARM64_INTRIN_VLD3Q_S64:
		return "vld3q_s64";
	case ARM64_INTRIN_VLD3Q_U64:
		return "vld3q_u64";
	case ARM64_INTRIN_VLD3Q_P64:
		return "vld3q_p64";
	case ARM64_INTRIN_VLD3_F64:
		return "vld3_f64";
	case ARM64_INTRIN_VLD3Q_F64:
		return "vld3q_f64";
	case ARM64_INTRIN_VLD4_S8:
		return "vld4_s8";
	case ARM64_INTRIN_VLD4Q_S8:
		return "vld4q_s8";
	case ARM64_INTRIN_VLD4_S16:
		return "vld4_s16";
	case ARM64_INTRIN_VLD4Q_S16:
		return "vld4q_s16";
	case ARM64_INTRIN_VLD4_S32:
		return "vld4_s32";
	case ARM64_INTRIN_VLD4Q_S32:
		return "vld4q_s32";
	case ARM64_INTRIN_VLD4_U8:
		return "vld4_u8";
	case ARM64_INTRIN_VLD4Q_U8:
		return "vld4q_u8";
	case ARM64_INTRIN_VLD4_U16:
		return "vld4_u16";
	case ARM64_INTRIN_VLD4Q_U16:
		return "vld4q_u16";
	case ARM64_INTRIN_VLD4_U32:
		return "vld4_u32";
	case ARM64_INTRIN_VLD4Q_U32:
		return "vld4q_u32";
	case ARM64_INTRIN_VLD4_F16:
		return "vld4_f16";
	case ARM64_INTRIN_VLD4Q_F16:
		return "vld4q_f16";
	case ARM64_INTRIN_VLD4_F32:
		return "vld4_f32";
	case ARM64_INTRIN_VLD4Q_F32:
		return "vld4q_f32";
	case ARM64_INTRIN_VLD4_P8:
		return "vld4_p8";
	case ARM64_INTRIN_VLD4Q_P8:
		return "vld4q_p8";
	case ARM64_INTRIN_VLD4_P16:
		return "vld4_p16";
	case ARM64_INTRIN_VLD4Q_P16:
		return "vld4q_p16";
	case ARM64_INTRIN_VLD4_S64:
		return "vld4_s64";
	case ARM64_INTRIN_VLD4_U64:
		return "vld4_u64";
	case ARM64_INTRIN_VLD4_P64:
		return "vld4_p64";
	case ARM64_INTRIN_VLD4Q_S64:
		return "vld4q_s64";
	case ARM64_INTRIN_VLD4Q_U64:
		return "vld4q_u64";
	case ARM64_INTRIN_VLD4Q_P64:
		return "vld4q_p64";
	case ARM64_INTRIN_VLD4_F64:
		return "vld4_f64";
	case ARM64_INTRIN_VLD4Q_F64:
		return "vld4q_f64";
	case ARM64_INTRIN_VLD2_DUP_S8:
		return "vld2_dup_s8";
	case ARM64_INTRIN_VLD2Q_DUP_S8:
		return "vld2q_dup_s8";
	case ARM64_INTRIN_VLD2_DUP_S16:
		return "vld2_dup_s16";
	case ARM64_INTRIN_VLD2Q_DUP_S16:
		return "vld2q_dup_s16";
	case ARM64_INTRIN_VLD2_DUP_S32:
		return "vld2_dup_s32";
	case ARM64_INTRIN_VLD2Q_DUP_S32:
		return "vld2q_dup_s32";
	case ARM64_INTRIN_VLD2_DUP_U8:
		return "vld2_dup_u8";
	case ARM64_INTRIN_VLD2Q_DUP_U8:
		return "vld2q_dup_u8";
	case ARM64_INTRIN_VLD2_DUP_U16:
		return "vld2_dup_u16";
	case ARM64_INTRIN_VLD2Q_DUP_U16:
		return "vld2q_dup_u16";
	case ARM64_INTRIN_VLD2_DUP_U32:
		return "vld2_dup_u32";
	case ARM64_INTRIN_VLD2Q_DUP_U32:
		return "vld2q_dup_u32";
	case ARM64_INTRIN_VLD2_DUP_F16:
		return "vld2_dup_f16";
	case ARM64_INTRIN_VLD2Q_DUP_F16:
		return "vld2q_dup_f16";
	case ARM64_INTRIN_VLD2_DUP_F32:
		return "vld2_dup_f32";
	case ARM64_INTRIN_VLD2Q_DUP_F32:
		return "vld2q_dup_f32";
	case ARM64_INTRIN_VLD2_DUP_P8:
		return "vld2_dup_p8";
	case ARM64_INTRIN_VLD2Q_DUP_P8:
		return "vld2q_dup_p8";
	case ARM64_INTRIN_VLD2_DUP_P16:
		return "vld2_dup_p16";
	case ARM64_INTRIN_VLD2Q_DUP_P16:
		return "vld2q_dup_p16";
	case ARM64_INTRIN_VLD2_DUP_S64:
		return "vld2_dup_s64";
	case ARM64_INTRIN_VLD2_DUP_U64:
		return "vld2_dup_u64";
	case ARM64_INTRIN_VLD2_DUP_P64:
		return "vld2_dup_p64";
	case ARM64_INTRIN_VLD2Q_DUP_S64:
		return "vld2q_dup_s64";
	case ARM64_INTRIN_VLD2Q_DUP_U64:
		return "vld2q_dup_u64";
	case ARM64_INTRIN_VLD2Q_DUP_P64:
		return "vld2q_dup_p64";
	case ARM64_INTRIN_VLD2_DUP_F64:
		return "vld2_dup_f64";
	case ARM64_INTRIN_VLD2Q_DUP_F64:
		return "vld2q_dup_f64";
	case ARM64_INTRIN_VLD3_DUP_S8:
		return "vld3_dup_s8";
	case ARM64_INTRIN_VLD3Q_DUP_S8:
		return "vld3q_dup_s8";
	case ARM64_INTRIN_VLD3_DUP_S16:
		return "vld3_dup_s16";
	case ARM64_INTRIN_VLD3Q_DUP_S16:
		return "vld3q_dup_s16";
	case ARM64_INTRIN_VLD3_DUP_S32:
		return "vld3_dup_s32";
	case ARM64_INTRIN_VLD3Q_DUP_S32:
		return "vld3q_dup_s32";
	case ARM64_INTRIN_VLD3_DUP_U8:
		return "vld3_dup_u8";
	case ARM64_INTRIN_VLD3Q_DUP_U8:
		return "vld3q_dup_u8";
	case ARM64_INTRIN_VLD3_DUP_U16:
		return "vld3_dup_u16";
	case ARM64_INTRIN_VLD3Q_DUP_U16:
		return "vld3q_dup_u16";
	case ARM64_INTRIN_VLD3_DUP_U32:
		return "vld3_dup_u32";
	case ARM64_INTRIN_VLD3Q_DUP_U32:
		return "vld3q_dup_u32";
	case ARM64_INTRIN_VLD3_DUP_F16:
		return "vld3_dup_f16";
	case ARM64_INTRIN_VLD3Q_DUP_F16:
		return "vld3q_dup_f16";
	case ARM64_INTRIN_VLD3_DUP_F32:
		return "vld3_dup_f32";
	case ARM64_INTRIN_VLD3Q_DUP_F32:
		return "vld3q_dup_f32";
	case ARM64_INTRIN_VLD3_DUP_P8:
		return "vld3_dup_p8";
	case ARM64_INTRIN_VLD3Q_DUP_P8:
		return "vld3q_dup_p8";
	case ARM64_INTRIN_VLD3_DUP_P16:
		return "vld3_dup_p16";
	case ARM64_INTRIN_VLD3Q_DUP_P16:
		return "vld3q_dup_p16";
	case ARM64_INTRIN_VLD3_DUP_S64:
		return "vld3_dup_s64";
	case ARM64_INTRIN_VLD3_DUP_U64:
		return "vld3_dup_u64";
	case ARM64_INTRIN_VLD3_DUP_P64:
		return "vld3_dup_p64";
	case ARM64_INTRIN_VLD3Q_DUP_S64:
		return "vld3q_dup_s64";
	case ARM64_INTRIN_VLD3Q_DUP_U64:
		return "vld3q_dup_u64";
	case ARM64_INTRIN_VLD3Q_DUP_P64:
		return "vld3q_dup_p64";
	case ARM64_INTRIN_VLD3_DUP_F64:
		return "vld3_dup_f64";
	case ARM64_INTRIN_VLD3Q_DUP_F64:
		return "vld3q_dup_f64";
	case ARM64_INTRIN_VLD4_DUP_S8:
		return "vld4_dup_s8";
	case ARM64_INTRIN_VLD4Q_DUP_S8:
		return "vld4q_dup_s8";
	case ARM64_INTRIN_VLD4_DUP_S16:
		return "vld4_dup_s16";
	case ARM64_INTRIN_VLD4Q_DUP_S16:
		return "vld4q_dup_s16";
	case ARM64_INTRIN_VLD4_DUP_S32:
		return "vld4_dup_s32";
	case ARM64_INTRIN_VLD4Q_DUP_S32:
		return "vld4q_dup_s32";
	case ARM64_INTRIN_VLD4_DUP_U8:
		return "vld4_dup_u8";
	case ARM64_INTRIN_VLD4Q_DUP_U8:
		return "vld4q_dup_u8";
	case ARM64_INTRIN_VLD4_DUP_U16:
		return "vld4_dup_u16";
	case ARM64_INTRIN_VLD4Q_DUP_U16:
		return "vld4q_dup_u16";
	case ARM64_INTRIN_VLD4_DUP_U32:
		return "vld4_dup_u32";
	case ARM64_INTRIN_VLD4Q_DUP_U32:
		return "vld4q_dup_u32";
	case ARM64_INTRIN_VLD4_DUP_F16:
		return "vld4_dup_f16";
	case ARM64_INTRIN_VLD4Q_DUP_F16:
		return "vld4q_dup_f16";
	case ARM64_INTRIN_VLD4_DUP_F32:
		return "vld4_dup_f32";
	case ARM64_INTRIN_VLD4Q_DUP_F32:
		return "vld4q_dup_f32";
	case ARM64_INTRIN_VLD4_DUP_P8:
		return "vld4_dup_p8";
	case ARM64_INTRIN_VLD4Q_DUP_P8:
		return "vld4q_dup_p8";
	case ARM64_INTRIN_VLD4_DUP_P16:
		return "vld4_dup_p16";
	case ARM64_INTRIN_VLD4Q_DUP_P16:
		return "vld4q_dup_p16";
	case ARM64_INTRIN_VLD4_DUP_S64:
		return "vld4_dup_s64";
	case ARM64_INTRIN_VLD4_DUP_U64:
		return "vld4_dup_u64";
	case ARM64_INTRIN_VLD4_DUP_P64:
		return "vld4_dup_p64";
	case ARM64_INTRIN_VLD4Q_DUP_S64:
		return "vld4q_dup_s64";
	case ARM64_INTRIN_VLD4Q_DUP_U64:
		return "vld4q_dup_u64";
	case ARM64_INTRIN_VLD4Q_DUP_P64:
		return "vld4q_dup_p64";
	case ARM64_INTRIN_VLD4_DUP_F64:
		return "vld4_dup_f64";
	case ARM64_INTRIN_VLD4Q_DUP_F64:
		return "vld4q_dup_f64";
	case ARM64_INTRIN_VST2_S8:
		return "vst2_s8";
	case ARM64_INTRIN_VST2Q_S8:
		return "vst2q_s8";
	case ARM64_INTRIN_VST2_S16:
		return "vst2_s16";
	case ARM64_INTRIN_VST2Q_S16:
		return "vst2q_s16";
	case ARM64_INTRIN_VST2_S32:
		return "vst2_s32";
	case ARM64_INTRIN_VST2Q_S32:
		return "vst2q_s32";
	case ARM64_INTRIN_VST2_U8:
		return "vst2_u8";
	case ARM64_INTRIN_VST2Q_U8:
		return "vst2q_u8";
	case ARM64_INTRIN_VST2_U16:
		return "vst2_u16";
	case ARM64_INTRIN_VST2Q_U16:
		return "vst2q_u16";
	case ARM64_INTRIN_VST2_U32:
		return "vst2_u32";
	case ARM64_INTRIN_VST2Q_U32:
		return "vst2q_u32";
	case ARM64_INTRIN_VST2_F16:
		return "vst2_f16";
	case ARM64_INTRIN_VST2Q_F16:
		return "vst2q_f16";
	case ARM64_INTRIN_VST2_F32:
		return "vst2_f32";
	case ARM64_INTRIN_VST2Q_F32:
		return "vst2q_f32";
	case ARM64_INTRIN_VST2_P8:
		return "vst2_p8";
	case ARM64_INTRIN_VST2Q_P8:
		return "vst2q_p8";
	case ARM64_INTRIN_VST2_P16:
		return "vst2_p16";
	case ARM64_INTRIN_VST2Q_P16:
		return "vst2q_p16";
	case ARM64_INTRIN_VST2_S64:
		return "vst2_s64";
	case ARM64_INTRIN_VST2_U64:
		return "vst2_u64";
	case ARM64_INTRIN_VST2_P64:
		return "vst2_p64";
	case ARM64_INTRIN_VST2Q_S64:
		return "vst2q_s64";
	case ARM64_INTRIN_VST2Q_U64:
		return "vst2q_u64";
	case ARM64_INTRIN_VST2Q_P64:
		return "vst2q_p64";
	case ARM64_INTRIN_VST2_F64:
		return "vst2_f64";
	case ARM64_INTRIN_VST2Q_F64:
		return "vst2q_f64";
	case ARM64_INTRIN_VST3_S8:
		return "vst3_s8";
	case ARM64_INTRIN_VST3Q_S8:
		return "vst3q_s8";
	case ARM64_INTRIN_VST3_S16:
		return "vst3_s16";
	case ARM64_INTRIN_VST3Q_S16:
		return "vst3q_s16";
	case ARM64_INTRIN_VST3_S32:
		return "vst3_s32";
	case ARM64_INTRIN_VST3Q_S32:
		return "vst3q_s32";
	case ARM64_INTRIN_VST3_U8:
		return "vst3_u8";
	case ARM64_INTRIN_VST3Q_U8:
		return "vst3q_u8";
	case ARM64_INTRIN_VST3_U16:
		return "vst3_u16";
	case ARM64_INTRIN_VST3Q_U16:
		return "vst3q_u16";
	case ARM64_INTRIN_VST3_U32:
		return "vst3_u32";
	case ARM64_INTRIN_VST3Q_U32:
		return "vst3q_u32";
	case ARM64_INTRIN_VST3_F16:
		return "vst3_f16";
	case ARM64_INTRIN_VST3Q_F16:
		return "vst3q_f16";
	case ARM64_INTRIN_VST3_F32:
		return "vst3_f32";
	case ARM64_INTRIN_VST3Q_F32:
		return "vst3q_f32";
	case ARM64_INTRIN_VST3_P8:
		return "vst3_p8";
	case ARM64_INTRIN_VST3Q_P8:
		return "vst3q_p8";
	case ARM64_INTRIN_VST3_P16:
		return "vst3_p16";
	case ARM64_INTRIN_VST3Q_P16:
		return "vst3q_p16";
	case ARM64_INTRIN_VST3_S64:
		return "vst3_s64";
	case ARM64_INTRIN_VST3_U64:
		return "vst3_u64";
	case ARM64_INTRIN_VST3_P64:
		return "vst3_p64";
	case ARM64_INTRIN_VST3Q_S64:
		return "vst3q_s64";
	case ARM64_INTRIN_VST3Q_U64:
		return "vst3q_u64";
	case ARM64_INTRIN_VST3Q_P64:
		return "vst3q_p64";
	case ARM64_INTRIN_VST3_F64:
		return "vst3_f64";
	case ARM64_INTRIN_VST3Q_F64:
		return "vst3q_f64";
	case ARM64_INTRIN_VST4_S8:
		return "vst4_s8";
	case ARM64_INTRIN_VST4Q_S8:
		return "vst4q_s8";
	case ARM64_INTRIN_VST4_S16:
		return "vst4_s16";
	case ARM64_INTRIN_VST4Q_S16:
		return "vst4q_s16";
	case ARM64_INTRIN_VST4_S32:
		return "vst4_s32";
	case ARM64_INTRIN_VST4Q_S32:
		return "vst4q_s32";
	case ARM64_INTRIN_VST4_U8:
		return "vst4_u8";
	case ARM64_INTRIN_VST4Q_U8:
		return "vst4q_u8";
	case ARM64_INTRIN_VST4_U16:
		return "vst4_u16";
	case ARM64_INTRIN_VST4Q_U16:
		return "vst4q_u16";
	case ARM64_INTRIN_VST4_U32:
		return "vst4_u32";
	case ARM64_INTRIN_VST4Q_U32:
		return "vst4q_u32";
	case ARM64_INTRIN_VST4_F16:
		return "vst4_f16";
	case ARM64_INTRIN_VST4Q_F16:
		return "vst4q_f16";
	case ARM64_INTRIN_VST4_F32:
		return "vst4_f32";
	case ARM64_INTRIN_VST4Q_F32:
		return "vst4q_f32";
	case ARM64_INTRIN_VST4_P8:
		return "vst4_p8";
	case ARM64_INTRIN_VST4Q_P8:
		return "vst4q_p8";
	case ARM64_INTRIN_VST4_P16:
		return "vst4_p16";
	case ARM64_INTRIN_VST4Q_P16:
		return "vst4q_p16";
	case ARM64_INTRIN_VST4_S64:
		return "vst4_s64";
	case ARM64_INTRIN_VST4_U64:
		return "vst4_u64";
	case ARM64_INTRIN_VST4_P64:
		return "vst4_p64";
	case ARM64_INTRIN_VST4Q_S64:
		return "vst4q_s64";
	case ARM64_INTRIN_VST4Q_U64:
		return "vst4q_u64";
	case ARM64_INTRIN_VST4Q_P64:
		return "vst4q_p64";
	case ARM64_INTRIN_VST4_F64:
		return "vst4_f64";
	case ARM64_INTRIN_VST4Q_F64:
		return "vst4q_f64";
	case ARM64_INTRIN_VLD2_LANE_S16:
		return "vld2_lane_s16";
	case ARM64_INTRIN_VLD2Q_LANE_S16:
		return "vld2q_lane_s16";
	case ARM64_INTRIN_VLD2_LANE_S32:
		return "vld2_lane_s32";
	case ARM64_INTRIN_VLD2Q_LANE_S32:
		return "vld2q_lane_s32";
	case ARM64_INTRIN_VLD2_LANE_U16:
		return "vld2_lane_u16";
	case ARM64_INTRIN_VLD2Q_LANE_U16:
		return "vld2q_lane_u16";
	case ARM64_INTRIN_VLD2_LANE_U32:
		return "vld2_lane_u32";
	case ARM64_INTRIN_VLD2Q_LANE_U32:
		return "vld2q_lane_u32";
	case ARM64_INTRIN_VLD2_LANE_F16:
		return "vld2_lane_f16";
	case ARM64_INTRIN_VLD2Q_LANE_F16:
		return "vld2q_lane_f16";
	case ARM64_INTRIN_VLD2_LANE_F32:
		return "vld2_lane_f32";
	case ARM64_INTRIN_VLD2Q_LANE_F32:
		return "vld2q_lane_f32";
	case ARM64_INTRIN_VLD2_LANE_P16:
		return "vld2_lane_p16";
	case ARM64_INTRIN_VLD2Q_LANE_P16:
		return "vld2q_lane_p16";
	case ARM64_INTRIN_VLD2_LANE_S8:
		return "vld2_lane_s8";
	case ARM64_INTRIN_VLD2_LANE_U8:
		return "vld2_lane_u8";
	case ARM64_INTRIN_VLD2_LANE_P8:
		return "vld2_lane_p8";
	case ARM64_INTRIN_VLD2Q_LANE_S8:
		return "vld2q_lane_s8";
	case ARM64_INTRIN_VLD2Q_LANE_U8:
		return "vld2q_lane_u8";
	case ARM64_INTRIN_VLD2Q_LANE_P8:
		return "vld2q_lane_p8";
	case ARM64_INTRIN_VLD2_LANE_S64:
		return "vld2_lane_s64";
	case ARM64_INTRIN_VLD2Q_LANE_S64:
		return "vld2q_lane_s64";
	case ARM64_INTRIN_VLD2_LANE_U64:
		return "vld2_lane_u64";
	case ARM64_INTRIN_VLD2Q_LANE_U64:
		return "vld2q_lane_u64";
	case ARM64_INTRIN_VLD2_LANE_P64:
		return "vld2_lane_p64";
	case ARM64_INTRIN_VLD2Q_LANE_P64:
		return "vld2q_lane_p64";
	case ARM64_INTRIN_VLD2_LANE_F64:
		return "vld2_lane_f64";
	case ARM64_INTRIN_VLD2Q_LANE_F64:
		return "vld2q_lane_f64";
	case ARM64_INTRIN_VLD3_LANE_S16:
		return "vld3_lane_s16";
	case ARM64_INTRIN_VLD3Q_LANE_S16:
		return "vld3q_lane_s16";
	case ARM64_INTRIN_VLD3_LANE_S32:
		return "vld3_lane_s32";
	case ARM64_INTRIN_VLD3Q_LANE_S32:
		return "vld3q_lane_s32";
	case ARM64_INTRIN_VLD3_LANE_U16:
		return "vld3_lane_u16";
	case ARM64_INTRIN_VLD3Q_LANE_U16:
		return "vld3q_lane_u16";
	case ARM64_INTRIN_VLD3_LANE_U32:
		return "vld3_lane_u32";
	case ARM64_INTRIN_VLD3Q_LANE_U32:
		return "vld3q_lane_u32";
	case ARM64_INTRIN_VLD3_LANE_F16:
		return "vld3_lane_f16";
	case ARM64_INTRIN_VLD3Q_LANE_F16:
		return "vld3q_lane_f16";
	case ARM64_INTRIN_VLD3_LANE_F32:
		return "vld3_lane_f32";
	case ARM64_INTRIN_VLD3Q_LANE_F32:
		return "vld3q_lane_f32";
	case ARM64_INTRIN_VLD3_LANE_P16:
		return "vld3_lane_p16";
	case ARM64_INTRIN_VLD3Q_LANE_P16:
		return "vld3q_lane_p16";
	case ARM64_INTRIN_VLD3_LANE_S8:
		return "vld3_lane_s8";
	case ARM64_INTRIN_VLD3_LANE_U8:
		return "vld3_lane_u8";
	case ARM64_INTRIN_VLD3_LANE_P8:
		return "vld3_lane_p8";
	case ARM64_INTRIN_VLD3Q_LANE_S8:
		return "vld3q_lane_s8";
	case ARM64_INTRIN_VLD3Q_LANE_U8:
		return "vld3q_lane_u8";
	case ARM64_INTRIN_VLD3Q_LANE_P8:
		return "vld3q_lane_p8";
	case ARM64_INTRIN_VLD3_LANE_S64:
		return "vld3_lane_s64";
	case ARM64_INTRIN_VLD3Q_LANE_S64:
		return "vld3q_lane_s64";
	case ARM64_INTRIN_VLD3_LANE_U64:
		return "vld3_lane_u64";
	case ARM64_INTRIN_VLD3Q_LANE_U64:
		return "vld3q_lane_u64";
	case ARM64_INTRIN_VLD3_LANE_P64:
		return "vld3_lane_p64";
	case ARM64_INTRIN_VLD3Q_LANE_P64:
		return "vld3q_lane_p64";
	case ARM64_INTRIN_VLD3_LANE_F64:
		return "vld3_lane_f64";
	case ARM64_INTRIN_VLD3Q_LANE_F64:
		return "vld3q_lane_f64";
	case ARM64_INTRIN_VLD4_LANE_S16:
		return "vld4_lane_s16";
	case ARM64_INTRIN_VLD4Q_LANE_S16:
		return "vld4q_lane_s16";
	case ARM64_INTRIN_VLD4_LANE_S32:
		return "vld4_lane_s32";
	case ARM64_INTRIN_VLD4Q_LANE_S32:
		return "vld4q_lane_s32";
	case ARM64_INTRIN_VLD4_LANE_U16:
		return "vld4_lane_u16";
	case ARM64_INTRIN_VLD4Q_LANE_U16:
		return "vld4q_lane_u16";
	case ARM64_INTRIN_VLD4_LANE_U32:
		return "vld4_lane_u32";
	case ARM64_INTRIN_VLD4Q_LANE_U32:
		return "vld4q_lane_u32";
	case ARM64_INTRIN_VLD4_LANE_F16:
		return "vld4_lane_f16";
	case ARM64_INTRIN_VLD4Q_LANE_F16:
		return "vld4q_lane_f16";
	case ARM64_INTRIN_VLD4_LANE_F32:
		return "vld4_lane_f32";
	case ARM64_INTRIN_VLD4Q_LANE_F32:
		return "vld4q_lane_f32";
	case ARM64_INTRIN_VLD4_LANE_P16:
		return "vld4_lane_p16";
	case ARM64_INTRIN_VLD4Q_LANE_P16:
		return "vld4q_lane_p16";
	case ARM64_INTRIN_VLD4_LANE_S8:
		return "vld4_lane_s8";
	case ARM64_INTRIN_VLD4_LANE_U8:
		return "vld4_lane_u8";
	case ARM64_INTRIN_VLD4_LANE_P8:
		return "vld4_lane_p8";
	case ARM64_INTRIN_VLD4Q_LANE_S8:
		return "vld4q_lane_s8";
	case ARM64_INTRIN_VLD4Q_LANE_U8:
		return "vld4q_lane_u8";
	case ARM64_INTRIN_VLD4Q_LANE_P8:
		return "vld4q_lane_p8";
	case ARM64_INTRIN_VLD4_LANE_S64:
		return "vld4_lane_s64";
	case ARM64_INTRIN_VLD4Q_LANE_S64:
		return "vld4q_lane_s64";
	case ARM64_INTRIN_VLD4_LANE_U64:
		return "vld4_lane_u64";
	case ARM64_INTRIN_VLD4Q_LANE_U64:
		return "vld4q_lane_u64";
	case ARM64_INTRIN_VLD4_LANE_P64:
		return "vld4_lane_p64";
	case ARM64_INTRIN_VLD4Q_LANE_P64:
		return "vld4q_lane_p64";
	case ARM64_INTRIN_VLD4_LANE_F64:
		return "vld4_lane_f64";
	case ARM64_INTRIN_VLD4Q_LANE_F64:
		return "vld4q_lane_f64";
	case ARM64_INTRIN_VST2_LANE_S8:
		return "vst2_lane_s8";
	case ARM64_INTRIN_VST2_LANE_U8:
		return "vst2_lane_u8";
	case ARM64_INTRIN_VST2_LANE_P8:
		return "vst2_lane_p8";
	case ARM64_INTRIN_VST3_LANE_S8:
		return "vst3_lane_s8";
	case ARM64_INTRIN_VST3_LANE_U8:
		return "vst3_lane_u8";
	case ARM64_INTRIN_VST3_LANE_P8:
		return "vst3_lane_p8";
	case ARM64_INTRIN_VST4_LANE_S8:
		return "vst4_lane_s8";
	case ARM64_INTRIN_VST4_LANE_U8:
		return "vst4_lane_u8";
	case ARM64_INTRIN_VST4_LANE_P8:
		return "vst4_lane_p8";
	case ARM64_INTRIN_VST2_LANE_S16:
		return "vst2_lane_s16";
	case ARM64_INTRIN_VST2Q_LANE_S16:
		return "vst2q_lane_s16";
	case ARM64_INTRIN_VST2_LANE_S32:
		return "vst2_lane_s32";
	case ARM64_INTRIN_VST2Q_LANE_S32:
		return "vst2q_lane_s32";
	case ARM64_INTRIN_VST2_LANE_U16:
		return "vst2_lane_u16";
	case ARM64_INTRIN_VST2Q_LANE_U16:
		return "vst2q_lane_u16";
	case ARM64_INTRIN_VST2_LANE_U32:
		return "vst2_lane_u32";
	case ARM64_INTRIN_VST2Q_LANE_U32:
		return "vst2q_lane_u32";
	case ARM64_INTRIN_VST2_LANE_F16:
		return "vst2_lane_f16";
	case ARM64_INTRIN_VST2Q_LANE_F16:
		return "vst2q_lane_f16";
	case ARM64_INTRIN_VST2_LANE_F32:
		return "vst2_lane_f32";
	case ARM64_INTRIN_VST2Q_LANE_F32:
		return "vst2q_lane_f32";
	case ARM64_INTRIN_VST2_LANE_P16:
		return "vst2_lane_p16";
	case ARM64_INTRIN_VST2Q_LANE_P16:
		return "vst2q_lane_p16";
	case ARM64_INTRIN_VST2Q_LANE_S8:
		return "vst2q_lane_s8";
	case ARM64_INTRIN_VST2Q_LANE_U8:
		return "vst2q_lane_u8";
	case ARM64_INTRIN_VST2Q_LANE_P8:
		return "vst2q_lane_p8";
	case ARM64_INTRIN_VST2_LANE_S64:
		return "vst2_lane_s64";
	case ARM64_INTRIN_VST2Q_LANE_S64:
		return "vst2q_lane_s64";
	case ARM64_INTRIN_VST2_LANE_U64:
		return "vst2_lane_u64";
	case ARM64_INTRIN_VST2Q_LANE_U64:
		return "vst2q_lane_u64";
	case ARM64_INTRIN_VST2_LANE_P64:
		return "vst2_lane_p64";
	case ARM64_INTRIN_VST2Q_LANE_P64:
		return "vst2q_lane_p64";
	case ARM64_INTRIN_VST2_LANE_F64:
		return "vst2_lane_f64";
	case ARM64_INTRIN_VST2Q_LANE_F64:
		return "vst2q_lane_f64";
	case ARM64_INTRIN_VST3_LANE_S16:
		return "vst3_lane_s16";
	case ARM64_INTRIN_VST3Q_LANE_S16:
		return "vst3q_lane_s16";
	case ARM64_INTRIN_VST3_LANE_S32:
		return "vst3_lane_s32";
	case ARM64_INTRIN_VST3Q_LANE_S32:
		return "vst3q_lane_s32";
	case ARM64_INTRIN_VST3_LANE_U16:
		return "vst3_lane_u16";
	case ARM64_INTRIN_VST3Q_LANE_U16:
		return "vst3q_lane_u16";
	case ARM64_INTRIN_VST3_LANE_U32:
		return "vst3_lane_u32";
	case ARM64_INTRIN_VST3Q_LANE_U32:
		return "vst3q_lane_u32";
	case ARM64_INTRIN_VST3_LANE_F16:
		return "vst3_lane_f16";
	case ARM64_INTRIN_VST3Q_LANE_F16:
		return "vst3q_lane_f16";
	case ARM64_INTRIN_VST3_LANE_F32:
		return "vst3_lane_f32";
	case ARM64_INTRIN_VST3Q_LANE_F32:
		return "vst3q_lane_f32";
	case ARM64_INTRIN_VST3_LANE_P16:
		return "vst3_lane_p16";
	case ARM64_INTRIN_VST3Q_LANE_P16:
		return "vst3q_lane_p16";
	case ARM64_INTRIN_VST3Q_LANE_S8:
		return "vst3q_lane_s8";
	case ARM64_INTRIN_VST3Q_LANE_U8:
		return "vst3q_lane_u8";
	case ARM64_INTRIN_VST3Q_LANE_P8:
		return "vst3q_lane_p8";
	case ARM64_INTRIN_VST3_LANE_S64:
		return "vst3_lane_s64";
	case ARM64_INTRIN_VST3Q_LANE_S64:
		return "vst3q_lane_s64";
	case ARM64_INTRIN_VST3_LANE_U64:
		return "vst3_lane_u64";
	case ARM64_INTRIN_VST3Q_LANE_U64:
		return "vst3q_lane_u64";
	case ARM64_INTRIN_VST3_LANE_P64:
		return "vst3_lane_p64";
	case ARM64_INTRIN_VST3Q_LANE_P64:
		return "vst3q_lane_p64";
	case ARM64_INTRIN_VST3_LANE_F64:
		return "vst3_lane_f64";
	case ARM64_INTRIN_VST3Q_LANE_F64:
		return "vst3q_lane_f64";
	case ARM64_INTRIN_VST4_LANE_S16:
		return "vst4_lane_s16";
	case ARM64_INTRIN_VST4Q_LANE_S16:
		return "vst4q_lane_s16";
	case ARM64_INTRIN_VST4_LANE_S32:
		return "vst4_lane_s32";
	case ARM64_INTRIN_VST4Q_LANE_S32:
		return "vst4q_lane_s32";
	case ARM64_INTRIN_VST4_LANE_U16:
		return "vst4_lane_u16";
	case ARM64_INTRIN_VST4Q_LANE_U16:
		return "vst4q_lane_u16";
	case ARM64_INTRIN_VST4_LANE_U32:
		return "vst4_lane_u32";
	case ARM64_INTRIN_VST4Q_LANE_U32:
		return "vst4q_lane_u32";
	case ARM64_INTRIN_VST4_LANE_F16:
		return "vst4_lane_f16";
	case ARM64_INTRIN_VST4Q_LANE_F16:
		return "vst4q_lane_f16";
	case ARM64_INTRIN_VST4_LANE_F32:
		return "vst4_lane_f32";
	case ARM64_INTRIN_VST4Q_LANE_F32:
		return "vst4q_lane_f32";
	case ARM64_INTRIN_VST4_LANE_P16:
		return "vst4_lane_p16";
	case ARM64_INTRIN_VST4Q_LANE_P16:
		return "vst4q_lane_p16";
	case ARM64_INTRIN_VST4Q_LANE_S8:
		return "vst4q_lane_s8";
	case ARM64_INTRIN_VST4Q_LANE_U8:
		return "vst4q_lane_u8";
	case ARM64_INTRIN_VST4Q_LANE_P8:
		return "vst4q_lane_p8";
	case ARM64_INTRIN_VST4_LANE_S64:
		return "vst4_lane_s64";
	case ARM64_INTRIN_VST4Q_LANE_S64:
		return "vst4q_lane_s64";
	case ARM64_INTRIN_VST4_LANE_U64:
		return "vst4_lane_u64";
	case ARM64_INTRIN_VST4Q_LANE_U64:
		return "vst4q_lane_u64";
	case ARM64_INTRIN_VST4_LANE_P64:
		return "vst4_lane_p64";
	case ARM64_INTRIN_VST4Q_LANE_P64:
		return "vst4q_lane_p64";
	case ARM64_INTRIN_VST4_LANE_F64:
		return "vst4_lane_f64";
	case ARM64_INTRIN_VST4Q_LANE_F64:
		return "vst4q_lane_f64";
	case ARM64_INTRIN_VST1_S8_X2:
		return "vst1_s8_x2";
	case ARM64_INTRIN_VST1Q_S8_X2:
		return "vst1q_s8_x2";
	case ARM64_INTRIN_VST1_S16_X2:
		return "vst1_s16_x2";
	case ARM64_INTRIN_VST1Q_S16_X2:
		return "vst1q_s16_x2";
	case ARM64_INTRIN_VST1_S32_X2:
		return "vst1_s32_x2";
	case ARM64_INTRIN_VST1Q_S32_X2:
		return "vst1q_s32_x2";
	case ARM64_INTRIN_VST1_U8_X2:
		return "vst1_u8_x2";
	case ARM64_INTRIN_VST1Q_U8_X2:
		return "vst1q_u8_x2";
	case ARM64_INTRIN_VST1_U16_X2:
		return "vst1_u16_x2";
	case ARM64_INTRIN_VST1Q_U16_X2:
		return "vst1q_u16_x2";
	case ARM64_INTRIN_VST1_U32_X2:
		return "vst1_u32_x2";
	case ARM64_INTRIN_VST1Q_U32_X2:
		return "vst1q_u32_x2";
	case ARM64_INTRIN_VST1_F16_X2:
		return "vst1_f16_x2";
	case ARM64_INTRIN_VST1Q_F16_X2:
		return "vst1q_f16_x2";
	case ARM64_INTRIN_VST1_F32_X2:
		return "vst1_f32_x2";
	case ARM64_INTRIN_VST1Q_F32_X2:
		return "vst1q_f32_x2";
	case ARM64_INTRIN_VST1_P8_X2:
		return "vst1_p8_x2";
	case ARM64_INTRIN_VST1Q_P8_X2:
		return "vst1q_p8_x2";
	case ARM64_INTRIN_VST1_P16_X2:
		return "vst1_p16_x2";
	case ARM64_INTRIN_VST1Q_P16_X2:
		return "vst1q_p16_x2";
	case ARM64_INTRIN_VST1_S64_X2:
		return "vst1_s64_x2";
	case ARM64_INTRIN_VST1_U64_X2:
		return "vst1_u64_x2";
	case ARM64_INTRIN_VST1_P64_X2:
		return "vst1_p64_x2";
	case ARM64_INTRIN_VST1Q_S64_X2:
		return "vst1q_s64_x2";
	case ARM64_INTRIN_VST1Q_U64_X2:
		return "vst1q_u64_x2";
	case ARM64_INTRIN_VST1Q_P64_X2:
		return "vst1q_p64_x2";
	case ARM64_INTRIN_VST1_F64_X2:
		return "vst1_f64_x2";
	case ARM64_INTRIN_VST1Q_F64_X2:
		return "vst1q_f64_x2";
	case ARM64_INTRIN_VST1_S8_X3:
		return "vst1_s8_x3";
	case ARM64_INTRIN_VST1Q_S8_X3:
		return "vst1q_s8_x3";
	case ARM64_INTRIN_VST1_S16_X3:
		return "vst1_s16_x3";
	case ARM64_INTRIN_VST1Q_S16_X3:
		return "vst1q_s16_x3";
	case ARM64_INTRIN_VST1_S32_X3:
		return "vst1_s32_x3";
	case ARM64_INTRIN_VST1Q_S32_X3:
		return "vst1q_s32_x3";
	case ARM64_INTRIN_VST1_U8_X3:
		return "vst1_u8_x3";
	case ARM64_INTRIN_VST1Q_U8_X3:
		return "vst1q_u8_x3";
	case ARM64_INTRIN_VST1_U16_X3:
		return "vst1_u16_x3";
	case ARM64_INTRIN_VST1Q_U16_X3:
		return "vst1q_u16_x3";
	case ARM64_INTRIN_VST1_U32_X3:
		return "vst1_u32_x3";
	case ARM64_INTRIN_VST1Q_U32_X3:
		return "vst1q_u32_x3";
	case ARM64_INTRIN_VST1_F16_X3:
		return "vst1_f16_x3";
	case ARM64_INTRIN_VST1Q_F16_X3:
		return "vst1q_f16_x3";
	case ARM64_INTRIN_VST1_F32_X3:
		return "vst1_f32_x3";
	case ARM64_INTRIN_VST1Q_F32_X3:
		return "vst1q_f32_x3";
	case ARM64_INTRIN_VST1_P8_X3:
		return "vst1_p8_x3";
	case ARM64_INTRIN_VST1Q_P8_X3:
		return "vst1q_p8_x3";
	case ARM64_INTRIN_VST1_P16_X3:
		return "vst1_p16_x3";
	case ARM64_INTRIN_VST1Q_P16_X3:
		return "vst1q_p16_x3";
	case ARM64_INTRIN_VST1_S64_X3:
		return "vst1_s64_x3";
	case ARM64_INTRIN_VST1_U64_X3:
		return "vst1_u64_x3";
	case ARM64_INTRIN_VST1_P64_X3:
		return "vst1_p64_x3";
	case ARM64_INTRIN_VST1Q_S64_X3:
		return "vst1q_s64_x3";
	case ARM64_INTRIN_VST1Q_U64_X3:
		return "vst1q_u64_x3";
	case ARM64_INTRIN_VST1Q_P64_X3:
		return "vst1q_p64_x3";
	case ARM64_INTRIN_VST1_F64_X3:
		return "vst1_f64_x3";
	case ARM64_INTRIN_VST1Q_F64_X3:
		return "vst1q_f64_x3";
	case ARM64_INTRIN_VST1_S8_X4:
		return "vst1_s8_x4";
	case ARM64_INTRIN_VST1Q_S8_X4:
		return "vst1q_s8_x4";
	case ARM64_INTRIN_VST1_S16_X4:
		return "vst1_s16_x4";
	case ARM64_INTRIN_VST1Q_S16_X4:
		return "vst1q_s16_x4";
	case ARM64_INTRIN_VST1_S32_X4:
		return "vst1_s32_x4";
	case ARM64_INTRIN_VST1Q_S32_X4:
		return "vst1q_s32_x4";
	case ARM64_INTRIN_VST1_U8_X4:
		return "vst1_u8_x4";
	case ARM64_INTRIN_VST1Q_U8_X4:
		return "vst1q_u8_x4";
	case ARM64_INTRIN_VST1_U16_X4:
		return "vst1_u16_x4";
	case ARM64_INTRIN_VST1Q_U16_X4:
		return "vst1q_u16_x4";
	case ARM64_INTRIN_VST1_U32_X4:
		return "vst1_u32_x4";
	case ARM64_INTRIN_VST1Q_U32_X4:
		return "vst1q_u32_x4";
	case ARM64_INTRIN_VST1_F16_X4:
		return "vst1_f16_x4";
	case ARM64_INTRIN_VST1Q_F16_X4:
		return "vst1q_f16_x4";
	case ARM64_INTRIN_VST1_F32_X4:
		return "vst1_f32_x4";
	case ARM64_INTRIN_VST1Q_F32_X4:
		return "vst1q_f32_x4";
	case ARM64_INTRIN_VST1_P8_X4:
		return "vst1_p8_x4";
	case ARM64_INTRIN_VST1Q_P8_X4:
		return "vst1q_p8_x4";
	case ARM64_INTRIN_VST1_P16_X4:
		return "vst1_p16_x4";
	case ARM64_INTRIN_VST1Q_P16_X4:
		return "vst1q_p16_x4";
	case ARM64_INTRIN_VST1_S64_X4:
		return "vst1_s64_x4";
	case ARM64_INTRIN_VST1_U64_X4:
		return "vst1_u64_x4";
	case ARM64_INTRIN_VST1_P64_X4:
		return "vst1_p64_x4";
	case ARM64_INTRIN_VST1Q_S64_X4:
		return "vst1q_s64_x4";
	case ARM64_INTRIN_VST1Q_U64_X4:
		return "vst1q_u64_x4";
	case ARM64_INTRIN_VST1Q_P64_X4:
		return "vst1q_p64_x4";
	case ARM64_INTRIN_VST1_F64_X4:
		return "vst1_f64_x4";
	case ARM64_INTRIN_VST1Q_F64_X4:
		return "vst1q_f64_x4";
	case ARM64_INTRIN_VLD1_S8_X2:
		return "vld1_s8_x2";
	case ARM64_INTRIN_VLD1Q_S8_X2:
		return "vld1q_s8_x2";
	case ARM64_INTRIN_VLD1_S16_X2:
		return "vld1_s16_x2";
	case ARM64_INTRIN_VLD1Q_S16_X2:
		return "vld1q_s16_x2";
	case ARM64_INTRIN_VLD1_S32_X2:
		return "vld1_s32_x2";
	case ARM64_INTRIN_VLD1Q_S32_X2:
		return "vld1q_s32_x2";
	case ARM64_INTRIN_VLD1_U8_X2:
		return "vld1_u8_x2";
	case ARM64_INTRIN_VLD1Q_U8_X2:
		return "vld1q_u8_x2";
	case ARM64_INTRIN_VLD1_U16_X2:
		return "vld1_u16_x2";
	case ARM64_INTRIN_VLD1Q_U16_X2:
		return "vld1q_u16_x2";
	case ARM64_INTRIN_VLD1_U32_X2:
		return "vld1_u32_x2";
	case ARM64_INTRIN_VLD1Q_U32_X2:
		return "vld1q_u32_x2";
	case ARM64_INTRIN_VLD1_F16_X2:
		return "vld1_f16_x2";
	case ARM64_INTRIN_VLD1Q_F16_X2:
		return "vld1q_f16_x2";
	case ARM64_INTRIN_VLD1_F32_X2:
		return "vld1_f32_x2";
	case ARM64_INTRIN_VLD1Q_F32_X2:
		return "vld1q_f32_x2";
	case ARM64_INTRIN_VLD1_P8_X2:
		return "vld1_p8_x2";
	case ARM64_INTRIN_VLD1Q_P8_X2:
		return "vld1q_p8_x2";
	case ARM64_INTRIN_VLD1_P16_X2:
		return "vld1_p16_x2";
	case ARM64_INTRIN_VLD1Q_P16_X2:
		return "vld1q_p16_x2";
	case ARM64_INTRIN_VLD1_S64_X2:
		return "vld1_s64_x2";
	case ARM64_INTRIN_VLD1_U64_X2:
		return "vld1_u64_x2";
	case ARM64_INTRIN_VLD1_P64_X2:
		return "vld1_p64_x2";
	case ARM64_INTRIN_VLD1Q_S64_X2:
		return "vld1q_s64_x2";
	case ARM64_INTRIN_VLD1Q_U64_X2:
		return "vld1q_u64_x2";
	case ARM64_INTRIN_VLD1Q_P64_X2:
		return "vld1q_p64_x2";
	case ARM64_INTRIN_VLD1_F64_X2:
		return "vld1_f64_x2";
	case ARM64_INTRIN_VLD1Q_F64_X2:
		return "vld1q_f64_x2";
	case ARM64_INTRIN_VLD1_S8_X3:
		return "vld1_s8_x3";
	case ARM64_INTRIN_VLD1Q_S8_X3:
		return "vld1q_s8_x3";
	case ARM64_INTRIN_VLD1_S16_X3:
		return "vld1_s16_x3";
	case ARM64_INTRIN_VLD1Q_S16_X3:
		return "vld1q_s16_x3";
	case ARM64_INTRIN_VLD1_S32_X3:
		return "vld1_s32_x3";
	case ARM64_INTRIN_VLD1Q_S32_X3:
		return "vld1q_s32_x3";
	case ARM64_INTRIN_VLD1_U8_X3:
		return "vld1_u8_x3";
	case ARM64_INTRIN_VLD1Q_U8_X3:
		return "vld1q_u8_x3";
	case ARM64_INTRIN_VLD1_U16_X3:
		return "vld1_u16_x3";
	case ARM64_INTRIN_VLD1Q_U16_X3:
		return "vld1q_u16_x3";
	case ARM64_INTRIN_VLD1_U32_X3:
		return "vld1_u32_x3";
	case ARM64_INTRIN_VLD1Q_U32_X3:
		return "vld1q_u32_x3";
	case ARM64_INTRIN_VLD1_F16_X3:
		return "vld1_f16_x3";
	case ARM64_INTRIN_VLD1Q_F16_X3:
		return "vld1q_f16_x3";
	case ARM64_INTRIN_VLD1_F32_X3:
		return "vld1_f32_x3";
	case ARM64_INTRIN_VLD1Q_F32_X3:
		return "vld1q_f32_x3";
	case ARM64_INTRIN_VLD1_P8_X3:
		return "vld1_p8_x3";
	case ARM64_INTRIN_VLD1Q_P8_X3:
		return "vld1q_p8_x3";
	case ARM64_INTRIN_VLD1_P16_X3:
		return "vld1_p16_x3";
	case ARM64_INTRIN_VLD1Q_P16_X3:
		return "vld1q_p16_x3";
	case ARM64_INTRIN_VLD1_S64_X3:
		return "vld1_s64_x3";
	case ARM64_INTRIN_VLD1_U64_X3:
		return "vld1_u64_x3";
	case ARM64_INTRIN_VLD1_P64_X3:
		return "vld1_p64_x3";
	case ARM64_INTRIN_VLD1Q_S64_X3:
		return "vld1q_s64_x3";
	case ARM64_INTRIN_VLD1Q_U64_X3:
		return "vld1q_u64_x3";
	case ARM64_INTRIN_VLD1Q_P64_X3:
		return "vld1q_p64_x3";
	case ARM64_INTRIN_VLD1_F64_X3:
		return "vld1_f64_x3";
	case ARM64_INTRIN_VLD1Q_F64_X3:
		return "vld1q_f64_x3";
	case ARM64_INTRIN_VLD1_S8_X4:
		return "vld1_s8_x4";
	case ARM64_INTRIN_VLD1Q_S8_X4:
		return "vld1q_s8_x4";
	case ARM64_INTRIN_VLD1_S16_X4:
		return "vld1_s16_x4";
	case ARM64_INTRIN_VLD1Q_S16_X4:
		return "vld1q_s16_x4";
	case ARM64_INTRIN_VLD1_S32_X4:
		return "vld1_s32_x4";
	case ARM64_INTRIN_VLD1Q_S32_X4:
		return "vld1q_s32_x4";
	case ARM64_INTRIN_VLD1_U8_X4:
		return "vld1_u8_x4";
	case ARM64_INTRIN_VLD1Q_U8_X4:
		return "vld1q_u8_x4";
	case ARM64_INTRIN_VLD1_U16_X4:
		return "vld1_u16_x4";
	case ARM64_INTRIN_VLD1Q_U16_X4:
		return "vld1q_u16_x4";
	case ARM64_INTRIN_VLD1_U32_X4:
		return "vld1_u32_x4";
	case ARM64_INTRIN_VLD1Q_U32_X4:
		return "vld1q_u32_x4";
	case ARM64_INTRIN_VLD1_F16_X4:
		return "vld1_f16_x4";
	case ARM64_INTRIN_VLD1Q_F16_X4:
		return "vld1q_f16_x4";
	case ARM64_INTRIN_VLD1_F32_X4:
		return "vld1_f32_x4";
	case ARM64_INTRIN_VLD1Q_F32_X4:
		return "vld1q_f32_x4";
	case ARM64_INTRIN_VLD1_P8_X4:
		return "vld1_p8_x4";
	case ARM64_INTRIN_VLD1Q_P8_X4:
		return "vld1q_p8_x4";
	case ARM64_INTRIN_VLD1_P16_X4:
		return "vld1_p16_x4";
	case ARM64_INTRIN_VLD1Q_P16_X4:
		return "vld1q_p16_x4";
	case ARM64_INTRIN_VLD1_S64_X4:
		return "vld1_s64_x4";
	case ARM64_INTRIN_VLD1_U64_X4:
		return "vld1_u64_x4";
	case ARM64_INTRIN_VLD1_P64_X4:
		return "vld1_p64_x4";
	case ARM64_INTRIN_VLD1Q_S64_X4:
		return "vld1q_s64_x4";
	case ARM64_INTRIN_VLD1Q_U64_X4:
		return "vld1q_u64_x4";
	case ARM64_INTRIN_VLD1Q_P64_X4:
		return "vld1q_p64_x4";
	case ARM64_INTRIN_VLD1_F64_X4:
		return "vld1_f64_x4";
	case ARM64_INTRIN_VLD1Q_F64_X4:
		return "vld1q_f64_x4";
	case ARM64_INTRIN_VPADD_S8:
		return "vpadd_s8";
	case ARM64_INTRIN_VPADD_S16:
		return "vpadd_s16";
	case ARM64_INTRIN_VPADD_S32:
		return "vpadd_s32";
	case ARM64_INTRIN_VPADD_U8:
		return "vpadd_u8";
	case ARM64_INTRIN_VPADD_U16:
		return "vpadd_u16";
	case ARM64_INTRIN_VPADD_U32:
		return "vpadd_u32";
	case ARM64_INTRIN_VPADD_F32:
		return "vpadd_f32";
	case ARM64_INTRIN_VPADDQ_S8:
		return "vpaddq_s8";
	case ARM64_INTRIN_VPADDQ_S16:
		return "vpaddq_s16";
	case ARM64_INTRIN_VPADDQ_S32:
		return "vpaddq_s32";
	case ARM64_INTRIN_VPADDQ_S64:
		return "vpaddq_s64";
	case ARM64_INTRIN_VPADDQ_U8:
		return "vpaddq_u8";
	case ARM64_INTRIN_VPADDQ_U16:
		return "vpaddq_u16";
	case ARM64_INTRIN_VPADDQ_U32:
		return "vpaddq_u32";
	case ARM64_INTRIN_VPADDQ_U64:
		return "vpaddq_u64";
	case ARM64_INTRIN_VPADDQ_F32:
		return "vpaddq_f32";
	case ARM64_INTRIN_VPADDQ_F64:
		return "vpaddq_f64";
	case ARM64_INTRIN_VPADDL_S8:
		return "vpaddl_s8";
	case ARM64_INTRIN_VPADDLQ_S8:
		return "vpaddlq_s8";
	case ARM64_INTRIN_VPADDL_S16:
		return "vpaddl_s16";
	case ARM64_INTRIN_VPADDLQ_S16:
		return "vpaddlq_s16";
	case ARM64_INTRIN_VPADDL_S32:
		return "vpaddl_s32";
	case ARM64_INTRIN_VPADDLQ_S32:
		return "vpaddlq_s32";
	case ARM64_INTRIN_VPADDL_U8:
		return "vpaddl_u8";
	case ARM64_INTRIN_VPADDLQ_U8:
		return "vpaddlq_u8";
	case ARM64_INTRIN_VPADDL_U16:
		return "vpaddl_u16";
	case ARM64_INTRIN_VPADDLQ_U16:
		return "vpaddlq_u16";
	case ARM64_INTRIN_VPADDL_U32:
		return "vpaddl_u32";
	case ARM64_INTRIN_VPADDLQ_U32:
		return "vpaddlq_u32";
	case ARM64_INTRIN_VPADAL_S8:
		return "vpadal_s8";
	case ARM64_INTRIN_VPADALQ_S8:
		return "vpadalq_s8";
	case ARM64_INTRIN_VPADAL_S16:
		return "vpadal_s16";
	case ARM64_INTRIN_VPADALQ_S16:
		return "vpadalq_s16";
	case ARM64_INTRIN_VPADAL_S32:
		return "vpadal_s32";
	case ARM64_INTRIN_VPADALQ_S32:
		return "vpadalq_s32";
	case ARM64_INTRIN_VPADAL_U8:
		return "vpadal_u8";
	case ARM64_INTRIN_VPADALQ_U8:
		return "vpadalq_u8";
	case ARM64_INTRIN_VPADAL_U16:
		return "vpadal_u16";
	case ARM64_INTRIN_VPADALQ_U16:
		return "vpadalq_u16";
	case ARM64_INTRIN_VPADAL_U32:
		return "vpadal_u32";
	case ARM64_INTRIN_VPADALQ_U32:
		return "vpadalq_u32";
	case ARM64_INTRIN_VPMAX_S8:
		return "vpmax_s8";
	case ARM64_INTRIN_VPMAX_S16:
		return "vpmax_s16";
	case ARM64_INTRIN_VPMAX_S32:
		return "vpmax_s32";
	case ARM64_INTRIN_VPMAX_U8:
		return "vpmax_u8";
	case ARM64_INTRIN_VPMAX_U16:
		return "vpmax_u16";
	case ARM64_INTRIN_VPMAX_U32:
		return "vpmax_u32";
	case ARM64_INTRIN_VPMAX_F32:
		return "vpmax_f32";
	case ARM64_INTRIN_VPMAXQ_S8:
		return "vpmaxq_s8";
	case ARM64_INTRIN_VPMAXQ_S16:
		return "vpmaxq_s16";
	case ARM64_INTRIN_VPMAXQ_S32:
		return "vpmaxq_s32";
	case ARM64_INTRIN_VPMAXQ_U8:
		return "vpmaxq_u8";
	case ARM64_INTRIN_VPMAXQ_U16:
		return "vpmaxq_u16";
	case ARM64_INTRIN_VPMAXQ_U32:
		return "vpmaxq_u32";
	case ARM64_INTRIN_VPMAXQ_F32:
		return "vpmaxq_f32";
	case ARM64_INTRIN_VPMAXQ_F64:
		return "vpmaxq_f64";
	case ARM64_INTRIN_VPMIN_S8:
		return "vpmin_s8";
	case ARM64_INTRIN_VPMIN_S16:
		return "vpmin_s16";
	case ARM64_INTRIN_VPMIN_S32:
		return "vpmin_s32";
	case ARM64_INTRIN_VPMIN_U8:
		return "vpmin_u8";
	case ARM64_INTRIN_VPMIN_U16:
		return "vpmin_u16";
	case ARM64_INTRIN_VPMIN_U32:
		return "vpmin_u32";
	case ARM64_INTRIN_VPMIN_F32:
		return "vpmin_f32";
	case ARM64_INTRIN_VPMINQ_S8:
		return "vpminq_s8";
	case ARM64_INTRIN_VPMINQ_S16:
		return "vpminq_s16";
	case ARM64_INTRIN_VPMINQ_S32:
		return "vpminq_s32";
	case ARM64_INTRIN_VPMINQ_U8:
		return "vpminq_u8";
	case ARM64_INTRIN_VPMINQ_U16:
		return "vpminq_u16";
	case ARM64_INTRIN_VPMINQ_U32:
		return "vpminq_u32";
	case ARM64_INTRIN_VPMINQ_F32:
		return "vpminq_f32";
	case ARM64_INTRIN_VPMINQ_F64:
		return "vpminq_f64";
	case ARM64_INTRIN_VPMAXNM_F32:
		return "vpmaxnm_f32";
	case ARM64_INTRIN_VPMAXNMQ_F32:
		return "vpmaxnmq_f32";
	case ARM64_INTRIN_VPMAXNMQ_F64:
		return "vpmaxnmq_f64";
	case ARM64_INTRIN_VPMINNM_F32:
		return "vpminnm_f32";
	case ARM64_INTRIN_VPMINNMQ_F32:
		return "vpminnmq_f32";
	case ARM64_INTRIN_VPMINNMQ_F64:
		return "vpminnmq_f64";
	case ARM64_INTRIN_VPADDD_S64:
		return "vpaddd_s64";
	case ARM64_INTRIN_VPADDD_U64:
		return "vpaddd_u64";
	case ARM64_INTRIN_VPADDS_F32:
		return "vpadds_f32";
	case ARM64_INTRIN_VPADDD_F64:
		return "vpaddd_f64";
	case ARM64_INTRIN_VPMAXS_F32:
		return "vpmaxs_f32";
	case ARM64_INTRIN_VPMAXQD_F64:
		return "vpmaxqd_f64";
	case ARM64_INTRIN_VPMINS_F32:
		return "vpmins_f32";
	case ARM64_INTRIN_VPMINQD_F64:
		return "vpminqd_f64";
	case ARM64_INTRIN_VPMAXNMS_F32:
		return "vpmaxnms_f32";
	case ARM64_INTRIN_VPMAXNMQD_F64:
		return "vpmaxnmqd_f64";
	case ARM64_INTRIN_VPMINNMS_F32:
		return "vpminnms_f32";
	case ARM64_INTRIN_VPMINNMQD_F64:
		return "vpminnmqd_f64";
	case ARM64_INTRIN_VADDV_S8:
		return "vaddv_s8";
	case ARM64_INTRIN_VADDVQ_S8:
		return "vaddvq_s8";
	case ARM64_INTRIN_VADDV_S16:
		return "vaddv_s16";
	case ARM64_INTRIN_VADDVQ_S16:
		return "vaddvq_s16";
	case ARM64_INTRIN_VADDV_S32:
		return "vaddv_s32";
	case ARM64_INTRIN_VADDVQ_S32:
		return "vaddvq_s32";
	case ARM64_INTRIN_VADDVQ_S64:
		return "vaddvq_s64";
	case ARM64_INTRIN_VADDV_U8:
		return "vaddv_u8";
	case ARM64_INTRIN_VADDVQ_U8:
		return "vaddvq_u8";
	case ARM64_INTRIN_VADDV_U16:
		return "vaddv_u16";
	case ARM64_INTRIN_VADDVQ_U16:
		return "vaddvq_u16";
	case ARM64_INTRIN_VADDV_U32:
		return "vaddv_u32";
	case ARM64_INTRIN_VADDVQ_U32:
		return "vaddvq_u32";
	case ARM64_INTRIN_VADDVQ_U64:
		return "vaddvq_u64";
	case ARM64_INTRIN_VADDV_F32:
		return "vaddv_f32";
	case ARM64_INTRIN_VADDVQ_F32:
		return "vaddvq_f32";
	case ARM64_INTRIN_VADDVQ_F64:
		return "vaddvq_f64";
	case ARM64_INTRIN_VADDLV_S8:
		return "vaddlv_s8";
	case ARM64_INTRIN_VADDLVQ_S8:
		return "vaddlvq_s8";
	case ARM64_INTRIN_VADDLV_S16:
		return "vaddlv_s16";
	case ARM64_INTRIN_VADDLVQ_S16:
		return "vaddlvq_s16";
	case ARM64_INTRIN_VADDLV_S32:
		return "vaddlv_s32";
	case ARM64_INTRIN_VADDLVQ_S32:
		return "vaddlvq_s32";
	case ARM64_INTRIN_VADDLV_U8:
		return "vaddlv_u8";
	case ARM64_INTRIN_VADDLVQ_U8:
		return "vaddlvq_u8";
	case ARM64_INTRIN_VADDLV_U16:
		return "vaddlv_u16";
	case ARM64_INTRIN_VADDLVQ_U16:
		return "vaddlvq_u16";
	case ARM64_INTRIN_VADDLV_U32:
		return "vaddlv_u32";
	case ARM64_INTRIN_VADDLVQ_U32:
		return "vaddlvq_u32";
	case ARM64_INTRIN_VMAXV_S8:
		return "vmaxv_s8";
	case ARM64_INTRIN_VMAXVQ_S8:
		return "vmaxvq_s8";
	case ARM64_INTRIN_VMAXV_S16:
		return "vmaxv_s16";
	case ARM64_INTRIN_VMAXVQ_S16:
		return "vmaxvq_s16";
	case ARM64_INTRIN_VMAXV_S32:
		return "vmaxv_s32";
	case ARM64_INTRIN_VMAXVQ_S32:
		return "vmaxvq_s32";
	case ARM64_INTRIN_VMAXV_U8:
		return "vmaxv_u8";
	case ARM64_INTRIN_VMAXVQ_U8:
		return "vmaxvq_u8";
	case ARM64_INTRIN_VMAXV_U16:
		return "vmaxv_u16";
	case ARM64_INTRIN_VMAXVQ_U16:
		return "vmaxvq_u16";
	case ARM64_INTRIN_VMAXV_U32:
		return "vmaxv_u32";
	case ARM64_INTRIN_VMAXVQ_U32:
		return "vmaxvq_u32";
	case ARM64_INTRIN_VMAXV_F32:
		return "vmaxv_f32";
	case ARM64_INTRIN_VMAXVQ_F32:
		return "vmaxvq_f32";
	case ARM64_INTRIN_VMAXVQ_F64:
		return "vmaxvq_f64";
	case ARM64_INTRIN_VMINV_S8:
		return "vminv_s8";
	case ARM64_INTRIN_VMINVQ_S8:
		return "vminvq_s8";
	case ARM64_INTRIN_VMINV_S16:
		return "vminv_s16";
	case ARM64_INTRIN_VMINVQ_S16:
		return "vminvq_s16";
	case ARM64_INTRIN_VMINV_S32:
		return "vminv_s32";
	case ARM64_INTRIN_VMINVQ_S32:
		return "vminvq_s32";
	case ARM64_INTRIN_VMINV_U8:
		return "vminv_u8";
	case ARM64_INTRIN_VMINVQ_U8:
		return "vminvq_u8";
	case ARM64_INTRIN_VMINV_U16:
		return "vminv_u16";
	case ARM64_INTRIN_VMINVQ_U16:
		return "vminvq_u16";
	case ARM64_INTRIN_VMINV_U32:
		return "vminv_u32";
	case ARM64_INTRIN_VMINVQ_U32:
		return "vminvq_u32";
	case ARM64_INTRIN_VMINV_F32:
		return "vminv_f32";
	case ARM64_INTRIN_VMINVQ_F32:
		return "vminvq_f32";
	case ARM64_INTRIN_VMINVQ_F64:
		return "vminvq_f64";
	case ARM64_INTRIN_VMAXNMV_F32:
		return "vmaxnmv_f32";
	case ARM64_INTRIN_VMAXNMVQ_F32:
		return "vmaxnmvq_f32";
	case ARM64_INTRIN_VMAXNMVQ_F64:
		return "vmaxnmvq_f64";
	case ARM64_INTRIN_VMINNMV_F32:
		return "vminnmv_f32";
	case ARM64_INTRIN_VMINNMVQ_F32:
		return "vminnmvq_f32";
	case ARM64_INTRIN_VMINNMVQ_F64:
		return "vminnmvq_f64";
	case ARM64_INTRIN_VEXT_S8:
		return "vext_s8";
	case ARM64_INTRIN_VEXTQ_S8:
		return "vextq_s8";
	case ARM64_INTRIN_VEXT_S16:
		return "vext_s16";
	case ARM64_INTRIN_VEXTQ_S16:
		return "vextq_s16";
	case ARM64_INTRIN_VEXT_S32:
		return "vext_s32";
	case ARM64_INTRIN_VEXTQ_S32:
		return "vextq_s32";
	case ARM64_INTRIN_VEXT_S64:
		return "vext_s64";
	case ARM64_INTRIN_VEXTQ_S64:
		return "vextq_s64";
	case ARM64_INTRIN_VEXT_U8:
		return "vext_u8";
	case ARM64_INTRIN_VEXTQ_U8:
		return "vextq_u8";
	case ARM64_INTRIN_VEXT_U16:
		return "vext_u16";
	case ARM64_INTRIN_VEXTQ_U16:
		return "vextq_u16";
	case ARM64_INTRIN_VEXT_U32:
		return "vext_u32";
	case ARM64_INTRIN_VEXTQ_U32:
		return "vextq_u32";
	case ARM64_INTRIN_VEXT_U64:
		return "vext_u64";
	case ARM64_INTRIN_VEXTQ_U64:
		return "vextq_u64";
	case ARM64_INTRIN_VEXT_P64:
		return "vext_p64";
	case ARM64_INTRIN_VEXTQ_P64:
		return "vextq_p64";
	case ARM64_INTRIN_VEXT_F32:
		return "vext_f32";
	case ARM64_INTRIN_VEXTQ_F32:
		return "vextq_f32";
	case ARM64_INTRIN_VEXT_F64:
		return "vext_f64";
	case ARM64_INTRIN_VEXTQ_F64:
		return "vextq_f64";
	case ARM64_INTRIN_VEXT_P8:
		return "vext_p8";
	case ARM64_INTRIN_VEXTQ_P8:
		return "vextq_p8";
	case ARM64_INTRIN_VEXT_P16:
		return "vext_p16";
	case ARM64_INTRIN_VEXTQ_P16:
		return "vextq_p16";
	case ARM64_INTRIN_VREV64_S8:
		return "vrev64_s8";
	case ARM64_INTRIN_VREV64Q_S8:
		return "vrev64q_s8";
	case ARM64_INTRIN_VREV64_S16:
		return "vrev64_s16";
	case ARM64_INTRIN_VREV64Q_S16:
		return "vrev64q_s16";
	case ARM64_INTRIN_VREV64_S32:
		return "vrev64_s32";
	case ARM64_INTRIN_VREV64Q_S32:
		return "vrev64q_s32";
	case ARM64_INTRIN_VREV64_U8:
		return "vrev64_u8";
	case ARM64_INTRIN_VREV64Q_U8:
		return "vrev64q_u8";
	case ARM64_INTRIN_VREV64_U16:
		return "vrev64_u16";
	case ARM64_INTRIN_VREV64Q_U16:
		return "vrev64q_u16";
	case ARM64_INTRIN_VREV64_U32:
		return "vrev64_u32";
	case ARM64_INTRIN_VREV64Q_U32:
		return "vrev64q_u32";
	case ARM64_INTRIN_VREV64_F32:
		return "vrev64_f32";
	case ARM64_INTRIN_VREV64Q_F32:
		return "vrev64q_f32";
	case ARM64_INTRIN_VREV64_P8:
		return "vrev64_p8";
	case ARM64_INTRIN_VREV64Q_P8:
		return "vrev64q_p8";
	case ARM64_INTRIN_VREV64_P16:
		return "vrev64_p16";
	case ARM64_INTRIN_VREV64Q_P16:
		return "vrev64q_p16";
	case ARM64_INTRIN_VREV32_S8:
		return "vrev32_s8";
	case ARM64_INTRIN_VREV32Q_S8:
		return "vrev32q_s8";
	case ARM64_INTRIN_VREV32_S16:
		return "vrev32_s16";
	case ARM64_INTRIN_VREV32Q_S16:
		return "vrev32q_s16";
	case ARM64_INTRIN_VREV32_U8:
		return "vrev32_u8";
	case ARM64_INTRIN_VREV32Q_U8:
		return "vrev32q_u8";
	case ARM64_INTRIN_VREV32_U16:
		return "vrev32_u16";
	case ARM64_INTRIN_VREV32Q_U16:
		return "vrev32q_u16";
	case ARM64_INTRIN_VREV32_P8:
		return "vrev32_p8";
	case ARM64_INTRIN_VREV32Q_P8:
		return "vrev32q_p8";
	case ARM64_INTRIN_VREV32_P16:
		return "vrev32_p16";
	case ARM64_INTRIN_VREV32Q_P16:
		return "vrev32q_p16";
	case ARM64_INTRIN_VREV16_S8:
		return "vrev16_s8";
	case ARM64_INTRIN_VREV16Q_S8:
		return "vrev16q_s8";
	case ARM64_INTRIN_VREV16_U8:
		return "vrev16_u8";
	case ARM64_INTRIN_VREV16Q_U8:
		return "vrev16q_u8";
	case ARM64_INTRIN_VREV16_P8:
		return "vrev16_p8";
	case ARM64_INTRIN_VREV16Q_P8:
		return "vrev16q_p8";
	case ARM64_INTRIN_VZIP1_S8:
		return "vzip1_s8";
	case ARM64_INTRIN_VZIP1Q_S8:
		return "vzip1q_s8";
	case ARM64_INTRIN_VZIP1_S16:
		return "vzip1_s16";
	case ARM64_INTRIN_VZIP1Q_S16:
		return "vzip1q_s16";
	case ARM64_INTRIN_VZIP1_S32:
		return "vzip1_s32";
	case ARM64_INTRIN_VZIP1Q_S32:
		return "vzip1q_s32";
	case ARM64_INTRIN_VZIP1Q_S64:
		return "vzip1q_s64";
	case ARM64_INTRIN_VZIP1_U8:
		return "vzip1_u8";
	case ARM64_INTRIN_VZIP1Q_U8:
		return "vzip1q_u8";
	case ARM64_INTRIN_VZIP1_U16:
		return "vzip1_u16";
	case ARM64_INTRIN_VZIP1Q_U16:
		return "vzip1q_u16";
	case ARM64_INTRIN_VZIP1_U32:
		return "vzip1_u32";
	case ARM64_INTRIN_VZIP1Q_U32:
		return "vzip1q_u32";
	case ARM64_INTRIN_VZIP1Q_U64:
		return "vzip1q_u64";
	case ARM64_INTRIN_VZIP1Q_P64:
		return "vzip1q_p64";
	case ARM64_INTRIN_VZIP1_F32:
		return "vzip1_f32";
	case ARM64_INTRIN_VZIP1Q_F32:
		return "vzip1q_f32";
	case ARM64_INTRIN_VZIP1Q_F64:
		return "vzip1q_f64";
	case ARM64_INTRIN_VZIP1_P8:
		return "vzip1_p8";
	case ARM64_INTRIN_VZIP1Q_P8:
		return "vzip1q_p8";
	case ARM64_INTRIN_VZIP1_P16:
		return "vzip1_p16";
	case ARM64_INTRIN_VZIP1Q_P16:
		return "vzip1q_p16";
	case ARM64_INTRIN_VZIP2_S8:
		return "vzip2_s8";
	case ARM64_INTRIN_VZIP2Q_S8:
		return "vzip2q_s8";
	case ARM64_INTRIN_VZIP2_S16:
		return "vzip2_s16";
	case ARM64_INTRIN_VZIP2Q_S16:
		return "vzip2q_s16";
	case ARM64_INTRIN_VZIP2_S32:
		return "vzip2_s32";
	case ARM64_INTRIN_VZIP2Q_S32:
		return "vzip2q_s32";
	case ARM64_INTRIN_VZIP2Q_S64:
		return "vzip2q_s64";
	case ARM64_INTRIN_VZIP2_U8:
		return "vzip2_u8";
	case ARM64_INTRIN_VZIP2Q_U8:
		return "vzip2q_u8";
	case ARM64_INTRIN_VZIP2_U16:
		return "vzip2_u16";
	case ARM64_INTRIN_VZIP2Q_U16:
		return "vzip2q_u16";
	case ARM64_INTRIN_VZIP2_U32:
		return "vzip2_u32";
	case ARM64_INTRIN_VZIP2Q_U32:
		return "vzip2q_u32";
	case ARM64_INTRIN_VZIP2Q_U64:
		return "vzip2q_u64";
	case ARM64_INTRIN_VZIP2Q_P64:
		return "vzip2q_p64";
	case ARM64_INTRIN_VZIP2_F32:
		return "vzip2_f32";
	case ARM64_INTRIN_VZIP2Q_F32:
		return "vzip2q_f32";
	case ARM64_INTRIN_VZIP2Q_F64:
		return "vzip2q_f64";
	case ARM64_INTRIN_VZIP2_P8:
		return "vzip2_p8";
	case ARM64_INTRIN_VZIP2Q_P8:
		return "vzip2q_p8";
	case ARM64_INTRIN_VZIP2_P16:
		return "vzip2_p16";
	case ARM64_INTRIN_VZIP2Q_P16:
		return "vzip2q_p16";
	case ARM64_INTRIN_VUZP1_S8:
		return "vuzp1_s8";
	case ARM64_INTRIN_VUZP1Q_S8:
		return "vuzp1q_s8";
	case ARM64_INTRIN_VUZP1_S16:
		return "vuzp1_s16";
	case ARM64_INTRIN_VUZP1Q_S16:
		return "vuzp1q_s16";
	case ARM64_INTRIN_VUZP1_S32:
		return "vuzp1_s32";
	case ARM64_INTRIN_VUZP1Q_S32:
		return "vuzp1q_s32";
	case ARM64_INTRIN_VUZP1Q_S64:
		return "vuzp1q_s64";
	case ARM64_INTRIN_VUZP1_U8:
		return "vuzp1_u8";
	case ARM64_INTRIN_VUZP1Q_U8:
		return "vuzp1q_u8";
	case ARM64_INTRIN_VUZP1_U16:
		return "vuzp1_u16";
	case ARM64_INTRIN_VUZP1Q_U16:
		return "vuzp1q_u16";
	case ARM64_INTRIN_VUZP1_U32:
		return "vuzp1_u32";
	case ARM64_INTRIN_VUZP1Q_U32:
		return "vuzp1q_u32";
	case ARM64_INTRIN_VUZP1Q_U64:
		return "vuzp1q_u64";
	case ARM64_INTRIN_VUZP1Q_P64:
		return "vuzp1q_p64";
	case ARM64_INTRIN_VUZP1_F32:
		return "vuzp1_f32";
	case ARM64_INTRIN_VUZP1Q_F32:
		return "vuzp1q_f32";
	case ARM64_INTRIN_VUZP1Q_F64:
		return "vuzp1q_f64";
	case ARM64_INTRIN_VUZP1_P8:
		return "vuzp1_p8";
	case ARM64_INTRIN_VUZP1Q_P8:
		return "vuzp1q_p8";
	case ARM64_INTRIN_VUZP1_P16:
		return "vuzp1_p16";
	case ARM64_INTRIN_VUZP1Q_P16:
		return "vuzp1q_p16";
	case ARM64_INTRIN_VUZP2_S8:
		return "vuzp2_s8";
	case ARM64_INTRIN_VUZP2Q_S8:
		return "vuzp2q_s8";
	case ARM64_INTRIN_VUZP2_S16:
		return "vuzp2_s16";
	case ARM64_INTRIN_VUZP2Q_S16:
		return "vuzp2q_s16";
	case ARM64_INTRIN_VUZP2_S32:
		return "vuzp2_s32";
	case ARM64_INTRIN_VUZP2Q_S32:
		return "vuzp2q_s32";
	case ARM64_INTRIN_VUZP2Q_S64:
		return "vuzp2q_s64";
	case ARM64_INTRIN_VUZP2_U8:
		return "vuzp2_u8";
	case ARM64_INTRIN_VUZP2Q_U8:
		return "vuzp2q_u8";
	case ARM64_INTRIN_VUZP2_U16:
		return "vuzp2_u16";
	case ARM64_INTRIN_VUZP2Q_U16:
		return "vuzp2q_u16";
	case ARM64_INTRIN_VUZP2_U32:
		return "vuzp2_u32";
	case ARM64_INTRIN_VUZP2Q_U32:
		return "vuzp2q_u32";
	case ARM64_INTRIN_VUZP2Q_U64:
		return "vuzp2q_u64";
	case ARM64_INTRIN_VUZP2Q_P64:
		return "vuzp2q_p64";
	case ARM64_INTRIN_VUZP2_F32:
		return "vuzp2_f32";
	case ARM64_INTRIN_VUZP2Q_F32:
		return "vuzp2q_f32";
	case ARM64_INTRIN_VUZP2Q_F64:
		return "vuzp2q_f64";
	case ARM64_INTRIN_VUZP2_P8:
		return "vuzp2_p8";
	case ARM64_INTRIN_VUZP2Q_P8:
		return "vuzp2q_p8";
	case ARM64_INTRIN_VUZP2_P16:
		return "vuzp2_p16";
	case ARM64_INTRIN_VUZP2Q_P16:
		return "vuzp2q_p16";
	case ARM64_INTRIN_VTRN1_S8:
		return "vtrn1_s8";
	case ARM64_INTRIN_VTRN1Q_S8:
		return "vtrn1q_s8";
	case ARM64_INTRIN_VTRN1_S16:
		return "vtrn1_s16";
	case ARM64_INTRIN_VTRN1Q_S16:
		return "vtrn1q_s16";
	case ARM64_INTRIN_VTRN1_S32:
		return "vtrn1_s32";
	case ARM64_INTRIN_VTRN1Q_S32:
		return "vtrn1q_s32";
	case ARM64_INTRIN_VTRN1Q_S64:
		return "vtrn1q_s64";
	case ARM64_INTRIN_VTRN1_U8:
		return "vtrn1_u8";
	case ARM64_INTRIN_VTRN1Q_U8:
		return "vtrn1q_u8";
	case ARM64_INTRIN_VTRN1_U16:
		return "vtrn1_u16";
	case ARM64_INTRIN_VTRN1Q_U16:
		return "vtrn1q_u16";
	case ARM64_INTRIN_VTRN1_U32:
		return "vtrn1_u32";
	case ARM64_INTRIN_VTRN1Q_U32:
		return "vtrn1q_u32";
	case ARM64_INTRIN_VTRN1Q_U64:
		return "vtrn1q_u64";
	case ARM64_INTRIN_VTRN1Q_P64:
		return "vtrn1q_p64";
	case ARM64_INTRIN_VTRN1_F32:
		return "vtrn1_f32";
	case ARM64_INTRIN_VTRN1Q_F32:
		return "vtrn1q_f32";
	case ARM64_INTRIN_VTRN1Q_F64:
		return "vtrn1q_f64";
	case ARM64_INTRIN_VTRN1_P8:
		return "vtrn1_p8";
	case ARM64_INTRIN_VTRN1Q_P8:
		return "vtrn1q_p8";
	case ARM64_INTRIN_VTRN1_P16:
		return "vtrn1_p16";
	case ARM64_INTRIN_VTRN1Q_P16:
		return "vtrn1q_p16";
	case ARM64_INTRIN_VTRN2_S8:
		return "vtrn2_s8";
	case ARM64_INTRIN_VTRN2Q_S8:
		return "vtrn2q_s8";
	case ARM64_INTRIN_VTRN2_S16:
		return "vtrn2_s16";
	case ARM64_INTRIN_VTRN2Q_S16:
		return "vtrn2q_s16";
	case ARM64_INTRIN_VTRN2_S32:
		return "vtrn2_s32";
	case ARM64_INTRIN_VTRN2Q_S32:
		return "vtrn2q_s32";
	case ARM64_INTRIN_VTRN2Q_S64:
		return "vtrn2q_s64";
	case ARM64_INTRIN_VTRN2_U8:
		return "vtrn2_u8";
	case ARM64_INTRIN_VTRN2Q_U8:
		return "vtrn2q_u8";
	case ARM64_INTRIN_VTRN2_U16:
		return "vtrn2_u16";
	case ARM64_INTRIN_VTRN2Q_U16:
		return "vtrn2q_u16";
	case ARM64_INTRIN_VTRN2_U32:
		return "vtrn2_u32";
	case ARM64_INTRIN_VTRN2Q_U32:
		return "vtrn2q_u32";
	case ARM64_INTRIN_VTRN2Q_U64:
		return "vtrn2q_u64";
	case ARM64_INTRIN_VTRN2Q_P64:
		return "vtrn2q_p64";
	case ARM64_INTRIN_VTRN2_F32:
		return "vtrn2_f32";
	case ARM64_INTRIN_VTRN2Q_F32:
		return "vtrn2q_f32";
	case ARM64_INTRIN_VTRN2Q_F64:
		return "vtrn2q_f64";
	case ARM64_INTRIN_VTRN2_P8:
		return "vtrn2_p8";
	case ARM64_INTRIN_VTRN2Q_P8:
		return "vtrn2q_p8";
	case ARM64_INTRIN_VTRN2_P16:
		return "vtrn2_p16";
	case ARM64_INTRIN_VTRN2Q_P16:
		return "vtrn2q_p16";
	case ARM64_INTRIN_VTBL1_S8:
		return "vtbl1_s8";
	case ARM64_INTRIN_VTBL1_U8:
		return "vtbl1_u8";
	case ARM64_INTRIN_VTBL1_P8:
		return "vtbl1_p8";
	case ARM64_INTRIN_VTBX1_S8:
		return "vtbx1_s8";
	case ARM64_INTRIN_VTBX1_U8:
		return "vtbx1_u8";
	case ARM64_INTRIN_VTBX1_P8:
		return "vtbx1_p8";
	case ARM64_INTRIN_VTBL2_S8:
		return "vtbl2_s8";
	case ARM64_INTRIN_VTBL2_U8:
		return "vtbl2_u8";
	case ARM64_INTRIN_VTBL2_P8:
		return "vtbl2_p8";
	case ARM64_INTRIN_VTBL3_S8:
		return "vtbl3_s8";
	case ARM64_INTRIN_VTBL3_U8:
		return "vtbl3_u8";
	case ARM64_INTRIN_VTBL3_P8:
		return "vtbl3_p8";
	case ARM64_INTRIN_VTBL4_S8:
		return "vtbl4_s8";
	case ARM64_INTRIN_VTBL4_U8:
		return "vtbl4_u8";
	case ARM64_INTRIN_VTBL4_P8:
		return "vtbl4_p8";
	case ARM64_INTRIN_VTBX2_S8:
		return "vtbx2_s8";
	case ARM64_INTRIN_VTBX2_U8:
		return "vtbx2_u8";
	case ARM64_INTRIN_VTBX2_P8:
		return "vtbx2_p8";
	case ARM64_INTRIN_VTBX3_S8:
		return "vtbx3_s8";
	case ARM64_INTRIN_VTBX3_U8:
		return "vtbx3_u8";
	case ARM64_INTRIN_VTBX3_P8:
		return "vtbx3_p8";
	case ARM64_INTRIN_VTBX4_S8:
		return "vtbx4_s8";
	case ARM64_INTRIN_VTBX4_U8:
		return "vtbx4_u8";
	case ARM64_INTRIN_VTBX4_P8:
		return "vtbx4_p8";
	case ARM64_INTRIN_VQTBL1_S8:
		return "vqtbl1_s8";
	case ARM64_INTRIN_VQTBL1Q_S8:
		return "vqtbl1q_s8";
	case ARM64_INTRIN_VQTBL1_U8:
		return "vqtbl1_u8";
	case ARM64_INTRIN_VQTBL1Q_U8:
		return "vqtbl1q_u8";
	case ARM64_INTRIN_VQTBL1_P8:
		return "vqtbl1_p8";
	case ARM64_INTRIN_VQTBL1Q_P8:
		return "vqtbl1q_p8";
	case ARM64_INTRIN_VQTBX1_S8:
		return "vqtbx1_s8";
	case ARM64_INTRIN_VQTBX1Q_S8:
		return "vqtbx1q_s8";
	case ARM64_INTRIN_VQTBX1_U8:
		return "vqtbx1_u8";
	case ARM64_INTRIN_VQTBX1Q_U8:
		return "vqtbx1q_u8";
	case ARM64_INTRIN_VQTBX1_P8:
		return "vqtbx1_p8";
	case ARM64_INTRIN_VQTBX1Q_P8:
		return "vqtbx1q_p8";
	case ARM64_INTRIN_VQTBL2_S8:
		return "vqtbl2_s8";
	case ARM64_INTRIN_VQTBL2Q_S8:
		return "vqtbl2q_s8";
	case ARM64_INTRIN_VQTBL2_U8:
		return "vqtbl2_u8";
	case ARM64_INTRIN_VQTBL2Q_U8:
		return "vqtbl2q_u8";
	case ARM64_INTRIN_VQTBL2_P8:
		return "vqtbl2_p8";
	case ARM64_INTRIN_VQTBL2Q_P8:
		return "vqtbl2q_p8";
	case ARM64_INTRIN_VQTBL3_S8:
		return "vqtbl3_s8";
	case ARM64_INTRIN_VQTBL3Q_S8:
		return "vqtbl3q_s8";
	case ARM64_INTRIN_VQTBL3_U8:
		return "vqtbl3_u8";
	case ARM64_INTRIN_VQTBL3Q_U8:
		return "vqtbl3q_u8";
	case ARM64_INTRIN_VQTBL3_P8:
		return "vqtbl3_p8";
	case ARM64_INTRIN_VQTBL3Q_P8:
		return "vqtbl3q_p8";
	case ARM64_INTRIN_VQTBL4_S8:
		return "vqtbl4_s8";
	case ARM64_INTRIN_VQTBL4Q_S8:
		return "vqtbl4q_s8";
	case ARM64_INTRIN_VQTBL4_U8:
		return "vqtbl4_u8";
	case ARM64_INTRIN_VQTBL4Q_U8:
		return "vqtbl4q_u8";
	case ARM64_INTRIN_VQTBL4_P8:
		return "vqtbl4_p8";
	case ARM64_INTRIN_VQTBL4Q_P8:
		return "vqtbl4q_p8";
	case ARM64_INTRIN_VQTBX2_S8:
		return "vqtbx2_s8";
	case ARM64_INTRIN_VQTBX2Q_S8:
		return "vqtbx2q_s8";
	case ARM64_INTRIN_VQTBX2_U8:
		return "vqtbx2_u8";
	case ARM64_INTRIN_VQTBX2Q_U8:
		return "vqtbx2q_u8";
	case ARM64_INTRIN_VQTBX2_P8:
		return "vqtbx2_p8";
	case ARM64_INTRIN_VQTBX2Q_P8:
		return "vqtbx2q_p8";
	case ARM64_INTRIN_VQTBX3_S8:
		return "vqtbx3_s8";
	case ARM64_INTRIN_VQTBX3Q_S8:
		return "vqtbx3q_s8";
	case ARM64_INTRIN_VQTBX3_U8:
		return "vqtbx3_u8";
	case ARM64_INTRIN_VQTBX3Q_U8:
		return "vqtbx3q_u8";
	case ARM64_INTRIN_VQTBX3_P8:
		return "vqtbx3_p8";
	case ARM64_INTRIN_VQTBX3Q_P8:
		return "vqtbx3q_p8";
	case ARM64_INTRIN_VQTBX4_S8:
		return "vqtbx4_s8";
	case ARM64_INTRIN_VQTBX4Q_S8:
		return "vqtbx4q_s8";
	case ARM64_INTRIN_VQTBX4_U8:
		return "vqtbx4_u8";
	case ARM64_INTRIN_VQTBX4Q_U8:
		return "vqtbx4q_u8";
	case ARM64_INTRIN_VQTBX4_P8:
		return "vqtbx4_p8";
	case ARM64_INTRIN_VQTBX4Q_P8:
		return "vqtbx4q_p8";
	case ARM64_INTRIN_VGET_LANE_U8:
		return "vget_lane_u8";
	case ARM64_INTRIN_VGET_LANE_U16:
		return "vget_lane_u16";
	case ARM64_INTRIN_VGET_LANE_U32:
		return "vget_lane_u32";
	case ARM64_INTRIN_VGET_LANE_U64:
		return "vget_lane_u64";
	case ARM64_INTRIN_VGET_LANE_P64:
		return "vget_lane_p64";
	case ARM64_INTRIN_VGET_LANE_S8:
		return "vget_lane_s8";
	case ARM64_INTRIN_VGET_LANE_S16:
		return "vget_lane_s16";
	case ARM64_INTRIN_VGET_LANE_S32:
		return "vget_lane_s32";
	case ARM64_INTRIN_VGET_LANE_S64:
		return "vget_lane_s64";
	case ARM64_INTRIN_VGET_LANE_P8:
		return "vget_lane_p8";
	case ARM64_INTRIN_VGET_LANE_P16:
		return "vget_lane_p16";
	case ARM64_INTRIN_VGET_LANE_F32:
		return "vget_lane_f32";
	case ARM64_INTRIN_VGET_LANE_F64:
		return "vget_lane_f64";
	case ARM64_INTRIN_VGETQ_LANE_U8:
		return "vgetq_lane_u8";
	case ARM64_INTRIN_VGETQ_LANE_U16:
		return "vgetq_lane_u16";
	case ARM64_INTRIN_VGETQ_LANE_U32:
		return "vgetq_lane_u32";
	case ARM64_INTRIN_VGETQ_LANE_U64:
		return "vgetq_lane_u64";
	case ARM64_INTRIN_VGETQ_LANE_P64:
		return "vgetq_lane_p64";
	case ARM64_INTRIN_VGETQ_LANE_S8:
		return "vgetq_lane_s8";
	case ARM64_INTRIN_VGETQ_LANE_S16:
		return "vgetq_lane_s16";
	case ARM64_INTRIN_VGETQ_LANE_S32:
		return "vgetq_lane_s32";
	case ARM64_INTRIN_VGETQ_LANE_S64:
		return "vgetq_lane_s64";
	case ARM64_INTRIN_VGETQ_LANE_P8:
		return "vgetq_lane_p8";
	case ARM64_INTRIN_VGETQ_LANE_P16:
		return "vgetq_lane_p16";
	case ARM64_INTRIN_VGET_LANE_F16:
		return "vget_lane_f16";
	case ARM64_INTRIN_VGETQ_LANE_F16:
		return "vgetq_lane_f16";
	case ARM64_INTRIN_VGETQ_LANE_F32:
		return "vgetq_lane_f32";
	case ARM64_INTRIN_VGETQ_LANE_F64:
		return "vgetq_lane_f64";
	case ARM64_INTRIN_VSET_LANE_U8:
		return "vset_lane_u8";
	case ARM64_INTRIN_VSET_LANE_U16:
		return "vset_lane_u16";
	case ARM64_INTRIN_VSET_LANE_U32:
		return "vset_lane_u32";
	case ARM64_INTRIN_VSET_LANE_U64:
		return "vset_lane_u64";
	case ARM64_INTRIN_VSET_LANE_P64:
		return "vset_lane_p64";
	case ARM64_INTRIN_VSET_LANE_S8:
		return "vset_lane_s8";
	case ARM64_INTRIN_VSET_LANE_S16:
		return "vset_lane_s16";
	case ARM64_INTRIN_VSET_LANE_S32:
		return "vset_lane_s32";
	case ARM64_INTRIN_VSET_LANE_S64:
		return "vset_lane_s64";
	case ARM64_INTRIN_VSET_LANE_P8:
		return "vset_lane_p8";
	case ARM64_INTRIN_VSET_LANE_P16:
		return "vset_lane_p16";
	case ARM64_INTRIN_VSET_LANE_F16:
		return "vset_lane_f16";
	case ARM64_INTRIN_VSETQ_LANE_F16:
		return "vsetq_lane_f16";
	case ARM64_INTRIN_VSET_LANE_F32:
		return "vset_lane_f32";
	case ARM64_INTRIN_VSET_LANE_F64:
		return "vset_lane_f64";
	case ARM64_INTRIN_VSETQ_LANE_U8:
		return "vsetq_lane_u8";
	case ARM64_INTRIN_VSETQ_LANE_U16:
		return "vsetq_lane_u16";
	case ARM64_INTRIN_VSETQ_LANE_U32:
		return "vsetq_lane_u32";
	case ARM64_INTRIN_VSETQ_LANE_U64:
		return "vsetq_lane_u64";
	case ARM64_INTRIN_VSETQ_LANE_P64:
		return "vsetq_lane_p64";
	case ARM64_INTRIN_VSETQ_LANE_S8:
		return "vsetq_lane_s8";
	case ARM64_INTRIN_VSETQ_LANE_S16:
		return "vsetq_lane_s16";
	case ARM64_INTRIN_VSETQ_LANE_S32:
		return "vsetq_lane_s32";
	case ARM64_INTRIN_VSETQ_LANE_S64:
		return "vsetq_lane_s64";
	case ARM64_INTRIN_VSETQ_LANE_P8:
		return "vsetq_lane_p8";
	case ARM64_INTRIN_VSETQ_LANE_P16:
		return "vsetq_lane_p16";
	case ARM64_INTRIN_VSETQ_LANE_F32:
		return "vsetq_lane_f32";
	case ARM64_INTRIN_VSETQ_LANE_F64:
		return "vsetq_lane_f64";
	case ARM64_INTRIN_VRECPXS_F32:
		return "vrecpxs_f32";
	case ARM64_INTRIN_VRECPXD_F64:
		return "vrecpxd_f64";
	case ARM64_INTRIN_VFMA_N_F32:
		return "vfma_n_f32";
	case ARM64_INTRIN_VFMAQ_N_F32:
		return "vfmaq_n_f32";
	case ARM64_INTRIN_VFMS_N_F32:
		return "vfms_n_f32";
	case ARM64_INTRIN_VFMSQ_N_F32:
		return "vfmsq_n_f32";
	case ARM64_INTRIN_VFMA_N_F64:
		return "vfma_n_f64";
	case ARM64_INTRIN_VFMAQ_N_F64:
		return "vfmaq_n_f64";
	case ARM64_INTRIN_VFMS_N_F64:
		return "vfms_n_f64";
	case ARM64_INTRIN_VFMSQ_N_F64:
		return "vfmsq_n_f64";
	case ARM64_INTRIN_VTRN_S8:
		return "vtrn_s8";
	case ARM64_INTRIN_VTRN_S16:
		return "vtrn_s16";
	case ARM64_INTRIN_VTRN_U8:
		return "vtrn_u8";
	case ARM64_INTRIN_VTRN_U16:
		return "vtrn_u16";
	case ARM64_INTRIN_VTRN_P8:
		return "vtrn_p8";
	case ARM64_INTRIN_VTRN_P16:
		return "vtrn_p16";
	case ARM64_INTRIN_VTRN_S32:
		return "vtrn_s32";
	case ARM64_INTRIN_VTRN_F32:
		return "vtrn_f32";
	case ARM64_INTRIN_VTRN_U32:
		return "vtrn_u32";
	case ARM64_INTRIN_VTRNQ_S8:
		return "vtrnq_s8";
	case ARM64_INTRIN_VTRNQ_S16:
		return "vtrnq_s16";
	case ARM64_INTRIN_VTRNQ_S32:
		return "vtrnq_s32";
	case ARM64_INTRIN_VTRNQ_F32:
		return "vtrnq_f32";
	case ARM64_INTRIN_VTRNQ_U8:
		return "vtrnq_u8";
	case ARM64_INTRIN_VTRNQ_U16:
		return "vtrnq_u16";
	case ARM64_INTRIN_VTRNQ_U32:
		return "vtrnq_u32";
	case ARM64_INTRIN_VTRNQ_P8:
		return "vtrnq_p8";
	case ARM64_INTRIN_VTRNQ_P16:
		return "vtrnq_p16";
	case ARM64_INTRIN_VZIP_S8:
		return "vzip_s8";
	case ARM64_INTRIN_VZIP_S16:
		return "vzip_s16";
	case ARM64_INTRIN_VZIP_U8:
		return "vzip_u8";
	case ARM64_INTRIN_VZIP_U16:
		return "vzip_u16";
	case ARM64_INTRIN_VZIP_P8:
		return "vzip_p8";
	case ARM64_INTRIN_VZIP_P16:
		return "vzip_p16";
	case ARM64_INTRIN_VZIP_S32:
		return "vzip_s32";
	case ARM64_INTRIN_VZIP_F32:
		return "vzip_f32";
	case ARM64_INTRIN_VZIP_U32:
		return "vzip_u32";
	case ARM64_INTRIN_VZIPQ_S8:
		return "vzipq_s8";
	case ARM64_INTRIN_VZIPQ_S16:
		return "vzipq_s16";
	case ARM64_INTRIN_VZIPQ_S32:
		return "vzipq_s32";
	case ARM64_INTRIN_VZIPQ_F32:
		return "vzipq_f32";
	case ARM64_INTRIN_VZIPQ_U8:
		return "vzipq_u8";
	case ARM64_INTRIN_VZIPQ_U16:
		return "vzipq_u16";
	case ARM64_INTRIN_VZIPQ_U32:
		return "vzipq_u32";
	case ARM64_INTRIN_VZIPQ_P8:
		return "vzipq_p8";
	case ARM64_INTRIN_VZIPQ_P16:
		return "vzipq_p16";
	case ARM64_INTRIN_VUZP_S8:
		return "vuzp_s8";
	case ARM64_INTRIN_VUZP_S16:
		return "vuzp_s16";
	case ARM64_INTRIN_VUZP_S32:
		return "vuzp_s32";
	case ARM64_INTRIN_VUZP_F32:
		return "vuzp_f32";
	case ARM64_INTRIN_VUZP_U8:
		return "vuzp_u8";
	case ARM64_INTRIN_VUZP_U16:
		return "vuzp_u16";
	case ARM64_INTRIN_VUZP_U32:
		return "vuzp_u32";
	case ARM64_INTRIN_VUZP_P8:
		return "vuzp_p8";
	case ARM64_INTRIN_VUZP_P16:
		return "vuzp_p16";
	case ARM64_INTRIN_VUZPQ_S8:
		return "vuzpq_s8";
	case ARM64_INTRIN_VUZPQ_S16:
		return "vuzpq_s16";
	case ARM64_INTRIN_VUZPQ_S32:
		return "vuzpq_s32";
	case ARM64_INTRIN_VUZPQ_F32:
		return "vuzpq_f32";
	case ARM64_INTRIN_VUZPQ_U8:
		return "vuzpq_u8";
	case ARM64_INTRIN_VUZPQ_U16:
		return "vuzpq_u16";
	case ARM64_INTRIN_VUZPQ_U32:
		return "vuzpq_u32";
	case ARM64_INTRIN_VUZPQ_P8:
		return "vuzpq_p8";
	case ARM64_INTRIN_VUZPQ_P16:
		return "vuzpq_p16";
	case ARM64_INTRIN_VLDRQ_P128:
		return "vldrq_p128";
	case ARM64_INTRIN_VSTRQ_P128:
		return "vstrq_p128";
	case ARM64_INTRIN_VAESEQ_U8:
		return "vaeseq_u8";
	case ARM64_INTRIN_VAESDQ_U8:
		return "vaesdq_u8";
	case ARM64_INTRIN_VAESMCQ_U8:
		return "vaesmcq_u8";
	case ARM64_INTRIN_VAESIMCQ_U8:
		return "vaesimcq_u8";
	case ARM64_INTRIN_VSHA1CQ_U32:
		return "vsha1cq_u32";
	case ARM64_INTRIN_VSHA1PQ_U32:
		return "vsha1pq_u32";
	case ARM64_INTRIN_VSHA1MQ_U32:
		return "vsha1mq_u32";
	case ARM64_INTRIN_VSHA1H_U32:
		return "vsha1h_u32";
	case ARM64_INTRIN_VSHA1SU0Q_U32:
		return "vsha1su0q_u32";
	case ARM64_INTRIN_VSHA1SU1Q_U32:
		return "vsha1su1q_u32";
	case ARM64_INTRIN_VSHA256HQ_U32:
		return "vsha256hq_u32";
	case ARM64_INTRIN_VSHA256H2Q_U32:
		return "vsha256h2q_u32";
	case ARM64_INTRIN_VSHA256SU0Q_U32:
		return "vsha256su0q_u32";
	case ARM64_INTRIN_VSHA256SU1Q_U32:
		return "vsha256su1q_u32";
	case ARM64_INTRIN_VMULL_P64:
		return "vmull_p64";
	case ARM64_INTRIN_VMULL_HIGH_P64:
		return "vmull_high_p64";
	case ARM64_INTRIN_VADD_P8:
		return "vadd_p8";
	case ARM64_INTRIN_VADD_P16:
		return "vadd_p16";
	case ARM64_INTRIN_VADD_P64:
		return "vadd_p64";
	case ARM64_INTRIN_VADDQ_P8:
		return "vaddq_p8";
	case ARM64_INTRIN_VADDQ_P16:
		return "vaddq_p16";
	case ARM64_INTRIN_VADDQ_P64:
		return "vaddq_p64";
	case ARM64_INTRIN_VADDQ_P128:
		return "vaddq_p128";
	case ARM64_INTRIN___CRC32B:
		return "__crc32b";
	case ARM64_INTRIN___CRC32H:
		return "__crc32h";
	case ARM64_INTRIN___CRC32W:
		return "__crc32w";
	case ARM64_INTRIN___CRC32D:
		return "__crc32d";
	case ARM64_INTRIN___CRC32CB:
		return "__crc32cb";
	case ARM64_INTRIN___CRC32CH:
		return "__crc32ch";
	case ARM64_INTRIN___CRC32CW:
		return "__crc32cw";
	case ARM64_INTRIN___CRC32CD:
		return "__crc32cd";
	case ARM64_INTRIN_VQRDMLAH_S16:
		return "vqrdmlah_s16";
	case ARM64_INTRIN_VQRDMLAH_S32:
		return "vqrdmlah_s32";
	case ARM64_INTRIN_VQRDMLAHQ_S16:
		return "vqrdmlahq_s16";
	case ARM64_INTRIN_VQRDMLAHQ_S32:
		return "vqrdmlahq_s32";
	case ARM64_INTRIN_VQRDMLSH_S16:
		return "vqrdmlsh_s16";
	case ARM64_INTRIN_VQRDMLSH_S32:
		return "vqrdmlsh_s32";
	case ARM64_INTRIN_VQRDMLSHQ_S16:
		return "vqrdmlshq_s16";
	case ARM64_INTRIN_VQRDMLSHQ_S32:
		return "vqrdmlshq_s32";
	case ARM64_INTRIN_VQRDMLAH_LANE_S16:
		return "vqrdmlah_lane_s16";
	case ARM64_INTRIN_VQRDMLAHQ_LANE_S16:
		return "vqrdmlahq_lane_s16";
	case ARM64_INTRIN_VQRDMLAH_LANEQ_S16:
		return "vqrdmlah_laneq_s16";
	case ARM64_INTRIN_VQRDMLAHQ_LANEQ_S16:
		return "vqrdmlahq_laneq_s16";
	case ARM64_INTRIN_VQRDMLAH_LANE_S32:
		return "vqrdmlah_lane_s32";
	case ARM64_INTRIN_VQRDMLAHQ_LANE_S32:
		return "vqrdmlahq_lane_s32";
	case ARM64_INTRIN_VQRDMLAH_LANEQ_S32:
		return "vqrdmlah_laneq_s32";
	case ARM64_INTRIN_VQRDMLAHQ_LANEQ_S32:
		return "vqrdmlahq_laneq_s32";
	case ARM64_INTRIN_VQRDMLSH_LANE_S16:
		return "vqrdmlsh_lane_s16";
	case ARM64_INTRIN_VQRDMLSHQ_LANE_S16:
		return "vqrdmlshq_lane_s16";
	case ARM64_INTRIN_VQRDMLSH_LANEQ_S16:
		return "vqrdmlsh_laneq_s16";
	case ARM64_INTRIN_VQRDMLSHQ_LANEQ_S16:
		return "vqrdmlshq_laneq_s16";
	case ARM64_INTRIN_VQRDMLSH_LANE_S32:
		return "vqrdmlsh_lane_s32";
	case ARM64_INTRIN_VQRDMLSHQ_LANE_S32:
		return "vqrdmlshq_lane_s32";
	case ARM64_INTRIN_VQRDMLSH_LANEQ_S32:
		return "vqrdmlsh_laneq_s32";
	case ARM64_INTRIN_VQRDMLSHQ_LANEQ_S32:
		return "vqrdmlshq_laneq_s32";
	case ARM64_INTRIN_VQRDMLAHH_S16:
		return "vqrdmlahh_s16";
	case ARM64_INTRIN_VQRDMLAHS_S32:
		return "vqrdmlahs_s32";
	case ARM64_INTRIN_VQRDMLSHH_S16:
		return "vqrdmlshh_s16";
	case ARM64_INTRIN_VQRDMLSHS_S32:
		return "vqrdmlshs_s32";
	case ARM64_INTRIN_VQRDMLAHH_LANE_S16:
		return "vqrdmlahh_lane_s16";
	case ARM64_INTRIN_VQRDMLAHH_LANEQ_S16:
		return "vqrdmlahh_laneq_s16";
	case ARM64_INTRIN_VQRDMLAHS_LANE_S32:
		return "vqrdmlahs_lane_s32";
	case ARM64_INTRIN_VQRDMLAHS_LANEQ_S32:
		return "vqrdmlahs_laneq_s32";
	case ARM64_INTRIN_VQRDMLSHH_LANE_S16:
		return "vqrdmlshh_lane_s16";
	case ARM64_INTRIN_VQRDMLSHH_LANEQ_S16:
		return "vqrdmlshh_laneq_s16";
	case ARM64_INTRIN_VQRDMLSHS_LANE_S32:
		return "vqrdmlshs_lane_s32";
	case ARM64_INTRIN_VQRDMLSHS_LANEQ_S32:
		return "vqrdmlshs_laneq_s32";
	case ARM64_INTRIN_VABSH_F16:
		return "vabsh_f16";
	case ARM64_INTRIN_VCEQZH_F16:
		return "vceqzh_f16";
	case ARM64_INTRIN_VCGEZH_F16:
		return "vcgezh_f16";
	case ARM64_INTRIN_VCGTZH_F16:
		return "vcgtzh_f16";
	case ARM64_INTRIN_VCLEZH_F16:
		return "vclezh_f16";
	case ARM64_INTRIN_VCLTZH_F16:
		return "vcltzh_f16";
	case ARM64_INTRIN_VCVTH_F16_S16:
		return "vcvth_f16_s16";
	case ARM64_INTRIN_VCVTH_F16_S32:
		return "vcvth_f16_s32";
	case ARM64_INTRIN_VCVTH_F16_S64:
		return "vcvth_f16_s64";
	case ARM64_INTRIN_VCVTH_F16_U16:
		return "vcvth_f16_u16";
	case ARM64_INTRIN_VCVTH_F16_U32:
		return "vcvth_f16_u32";
	case ARM64_INTRIN_VCVTH_F16_U64:
		return "vcvth_f16_u64";
	case ARM64_INTRIN_VCVTH_S16_F16:
		return "vcvth_s16_f16";
	case ARM64_INTRIN_VCVTH_S32_F16:
		return "vcvth_s32_f16";
	case ARM64_INTRIN_VCVTH_S64_F16:
		return "vcvth_s64_f16";
	case ARM64_INTRIN_VCVTH_U16_F16:
		return "vcvth_u16_f16";
	case ARM64_INTRIN_VCVTH_U32_F16:
		return "vcvth_u32_f16";
	case ARM64_INTRIN_VCVTH_U64_F16:
		return "vcvth_u64_f16";
	case ARM64_INTRIN_VCVTAH_S16_F16:
		return "vcvtah_s16_f16";
	case ARM64_INTRIN_VCVTAH_S32_F16:
		return "vcvtah_s32_f16";
	case ARM64_INTRIN_VCVTAH_S64_F16:
		return "vcvtah_s64_f16";
	case ARM64_INTRIN_VCVTAH_U16_F16:
		return "vcvtah_u16_f16";
	case ARM64_INTRIN_VCVTAH_U32_F16:
		return "vcvtah_u32_f16";
	case ARM64_INTRIN_VCVTAH_U64_F16:
		return "vcvtah_u64_f16";
	case ARM64_INTRIN_VCVTMH_S16_F16:
		return "vcvtmh_s16_f16";
	case ARM64_INTRIN_VCVTMH_S32_F16:
		return "vcvtmh_s32_f16";
	case ARM64_INTRIN_VCVTMH_S64_F16:
		return "vcvtmh_s64_f16";
	case ARM64_INTRIN_VCVTMH_U16_F16:
		return "vcvtmh_u16_f16";
	case ARM64_INTRIN_VCVTMH_U32_F16:
		return "vcvtmh_u32_f16";
	case ARM64_INTRIN_VCVTMH_U64_F16:
		return "vcvtmh_u64_f16";
	case ARM64_INTRIN_VCVTNH_S16_F16:
		return "vcvtnh_s16_f16";
	case ARM64_INTRIN_VCVTNH_S32_F16:
		return "vcvtnh_s32_f16";
	case ARM64_INTRIN_VCVTNH_S64_F16:
		return "vcvtnh_s64_f16";
	case ARM64_INTRIN_VCVTNH_U16_F16:
		return "vcvtnh_u16_f16";
	case ARM64_INTRIN_VCVTNH_U32_F16:
		return "vcvtnh_u32_f16";
	case ARM64_INTRIN_VCVTNH_U64_F16:
		return "vcvtnh_u64_f16";
	case ARM64_INTRIN_VCVTPH_S16_F16:
		return "vcvtph_s16_f16";
	case ARM64_INTRIN_VCVTPH_S32_F16:
		return "vcvtph_s32_f16";
	case ARM64_INTRIN_VCVTPH_S64_F16:
		return "vcvtph_s64_f16";
	case ARM64_INTRIN_VCVTPH_U16_F16:
		return "vcvtph_u16_f16";
	case ARM64_INTRIN_VCVTPH_U32_F16:
		return "vcvtph_u32_f16";
	case ARM64_INTRIN_VCVTPH_U64_F16:
		return "vcvtph_u64_f16";
	case ARM64_INTRIN_VNEGH_F16:
		return "vnegh_f16";
	case ARM64_INTRIN_VRECPEH_F16:
		return "vrecpeh_f16";
	case ARM64_INTRIN_VRECPXH_F16:
		return "vrecpxh_f16";
	case ARM64_INTRIN_VRNDH_F16:
		return "vrndh_f16";
	case ARM64_INTRIN_VRNDAH_F16:
		return "vrndah_f16";
	case ARM64_INTRIN_VRNDIH_F16:
		return "vrndih_f16";
	case ARM64_INTRIN_VRNDMH_F16:
		return "vrndmh_f16";
	case ARM64_INTRIN_VRNDNH_F16:
		return "vrndnh_f16";
	case ARM64_INTRIN_VRNDPH_F16:
		return "vrndph_f16";
	case ARM64_INTRIN_VRNDXH_F16:
		return "vrndxh_f16";
	case ARM64_INTRIN_VRSQRTEH_F16:
		return "vrsqrteh_f16";
	case ARM64_INTRIN_VSQRTH_F16:
		return "vsqrth_f16";
	case ARM64_INTRIN_VADDH_F16:
		return "vaddh_f16";
	case ARM64_INTRIN_VABDH_F16:
		return "vabdh_f16";
	case ARM64_INTRIN_VCAGEH_F16:
		return "vcageh_f16";
	case ARM64_INTRIN_VCAGTH_F16:
		return "vcagth_f16";
	case ARM64_INTRIN_VCALEH_F16:
		return "vcaleh_f16";
	case ARM64_INTRIN_VCALTH_F16:
		return "vcalth_f16";
	case ARM64_INTRIN_VCEQH_F16:
		return "vceqh_f16";
	case ARM64_INTRIN_VCGEH_F16:
		return "vcgeh_f16";
	case ARM64_INTRIN_VCGTH_F16:
		return "vcgth_f16";
	case ARM64_INTRIN_VCLEH_F16:
		return "vcleh_f16";
	case ARM64_INTRIN_VCLTH_F16:
		return "vclth_f16";
	case ARM64_INTRIN_VCVTH_N_F16_S16:
		return "vcvth_n_f16_s16";
	case ARM64_INTRIN_VCVTH_N_F16_S32:
		return "vcvth_n_f16_s32";
	case ARM64_INTRIN_VCVTH_N_F16_S64:
		return "vcvth_n_f16_s64";
	case ARM64_INTRIN_VCVTH_N_F16_U16:
		return "vcvth_n_f16_u16";
	case ARM64_INTRIN_VCVTH_N_F16_U32:
		return "vcvth_n_f16_u32";
	case ARM64_INTRIN_VCVTH_N_F16_U64:
		return "vcvth_n_f16_u64";
	case ARM64_INTRIN_VCVTH_N_S16_F16:
		return "vcvth_n_s16_f16";
	case ARM64_INTRIN_VCVTH_N_S32_F16:
		return "vcvth_n_s32_f16";
	case ARM64_INTRIN_VCVTH_N_S64_F16:
		return "vcvth_n_s64_f16";
	case ARM64_INTRIN_VCVTH_N_U16_F16:
		return "vcvth_n_u16_f16";
	case ARM64_INTRIN_VCVTH_N_U32_F16:
		return "vcvth_n_u32_f16";
	case ARM64_INTRIN_VCVTH_N_U64_F16:
		return "vcvth_n_u64_f16";
	case ARM64_INTRIN_VDIVH_F16:
		return "vdivh_f16";
	case ARM64_INTRIN_VMAXH_F16:
		return "vmaxh_f16";
	case ARM64_INTRIN_VMAXNMH_F16:
		return "vmaxnmh_f16";
	case ARM64_INTRIN_VMINH_F16:
		return "vminh_f16";
	case ARM64_INTRIN_VMINNMH_F16:
		return "vminnmh_f16";
	case ARM64_INTRIN_VMULH_F16:
		return "vmulh_f16";
	case ARM64_INTRIN_VMULXH_F16:
		return "vmulxh_f16";
	case ARM64_INTRIN_VRECPSH_F16:
		return "vrecpsh_f16";
	case ARM64_INTRIN_VRSQRTSH_F16:
		return "vrsqrtsh_f16";
	case ARM64_INTRIN_VSUBH_F16:
		return "vsubh_f16";
	case ARM64_INTRIN_VFMAH_F16:
		return "vfmah_f16";
	case ARM64_INTRIN_VFMSH_F16:
		return "vfmsh_f16";
	case ARM64_INTRIN_VABS_F16:
		return "vabs_f16";
	case ARM64_INTRIN_VABSQ_F16:
		return "vabsq_f16";
	case ARM64_INTRIN_VCEQZ_F16:
		return "vceqz_f16";
	case ARM64_INTRIN_VCEQZQ_F16:
		return "vceqzq_f16";
	case ARM64_INTRIN_VCGEZ_F16:
		return "vcgez_f16";
	case ARM64_INTRIN_VCGEZQ_F16:
		return "vcgezq_f16";
	case ARM64_INTRIN_VCGTZ_F16:
		return "vcgtz_f16";
	case ARM64_INTRIN_VCGTZQ_F16:
		return "vcgtzq_f16";
	case ARM64_INTRIN_VCLEZ_F16:
		return "vclez_f16";
	case ARM64_INTRIN_VCLEZQ_F16:
		return "vclezq_f16";
	case ARM64_INTRIN_VCLTZ_F16:
		return "vcltz_f16";
	case ARM64_INTRIN_VCLTZQ_F16:
		return "vcltzq_f16";
	case ARM64_INTRIN_VCVT_F16_S16:
		return "vcvt_f16_s16";
	case ARM64_INTRIN_VCVTQ_F16_S16:
		return "vcvtq_f16_s16";
	case ARM64_INTRIN_VCVT_F16_U16:
		return "vcvt_f16_u16";
	case ARM64_INTRIN_VCVTQ_F16_U16:
		return "vcvtq_f16_u16";
	case ARM64_INTRIN_VCVT_S16_F16:
		return "vcvt_s16_f16";
	case ARM64_INTRIN_VCVTQ_S16_F16:
		return "vcvtq_s16_f16";
	case ARM64_INTRIN_VCVT_U16_F16:
		return "vcvt_u16_f16";
	case ARM64_INTRIN_VCVTQ_U16_F16:
		return "vcvtq_u16_f16";
	case ARM64_INTRIN_VCVTA_S16_F16:
		return "vcvta_s16_f16";
	case ARM64_INTRIN_VCVTAQ_S16_F16:
		return "vcvtaq_s16_f16";
	case ARM64_INTRIN_VCVTA_U16_F16:
		return "vcvta_u16_f16";
	case ARM64_INTRIN_VCVTAQ_U16_F16:
		return "vcvtaq_u16_f16";
	case ARM64_INTRIN_VCVTM_S16_F16:
		return "vcvtm_s16_f16";
	case ARM64_INTRIN_VCVTMQ_S16_F16:
		return "vcvtmq_s16_f16";
	case ARM64_INTRIN_VCVTM_U16_F16:
		return "vcvtm_u16_f16";
	case ARM64_INTRIN_VCVTMQ_U16_F16:
		return "vcvtmq_u16_f16";
	case ARM64_INTRIN_VCVTN_S16_F16:
		return "vcvtn_s16_f16";
	case ARM64_INTRIN_VCVTNQ_S16_F16:
		return "vcvtnq_s16_f16";
	case ARM64_INTRIN_VCVTN_U16_F16:
		return "vcvtn_u16_f16";
	case ARM64_INTRIN_VCVTNQ_U16_F16:
		return "vcvtnq_u16_f16";
	case ARM64_INTRIN_VCVTP_S16_F16:
		return "vcvtp_s16_f16";
	case ARM64_INTRIN_VCVTPQ_S16_F16:
		return "vcvtpq_s16_f16";
	case ARM64_INTRIN_VCVTP_U16_F16:
		return "vcvtp_u16_f16";
	case ARM64_INTRIN_VCVTPQ_U16_F16:
		return "vcvtpq_u16_f16";
	case ARM64_INTRIN_VNEG_F16:
		return "vneg_f16";
	case ARM64_INTRIN_VNEGQ_F16:
		return "vnegq_f16";
	case ARM64_INTRIN_VRECPE_F16:
		return "vrecpe_f16";
	case ARM64_INTRIN_VRECPEQ_F16:
		return "vrecpeq_f16";
	case ARM64_INTRIN_VRND_F16:
		return "vrnd_f16";
	case ARM64_INTRIN_VRNDQ_F16:
		return "vrndq_f16";
	case ARM64_INTRIN_VRNDA_F16:
		return "vrnda_f16";
	case ARM64_INTRIN_VRNDAQ_F16:
		return "vrndaq_f16";
	case ARM64_INTRIN_VRNDI_F16:
		return "vrndi_f16";
	case ARM64_INTRIN_VRNDIQ_F16:
		return "vrndiq_f16";
	case ARM64_INTRIN_VRNDM_F16:
		return "vrndm_f16";
	case ARM64_INTRIN_VRNDMQ_F16:
		return "vrndmq_f16";
	case ARM64_INTRIN_VRNDN_F16:
		return "vrndn_f16";
	case ARM64_INTRIN_VRNDNQ_F16:
		return "vrndnq_f16";
	case ARM64_INTRIN_VRNDP_F16:
		return "vrndp_f16";
	case ARM64_INTRIN_VRNDPQ_F16:
		return "vrndpq_f16";
	case ARM64_INTRIN_VRNDX_F16:
		return "vrndx_f16";
	case ARM64_INTRIN_VRNDXQ_F16:
		return "vrndxq_f16";
	case ARM64_INTRIN_VRSQRTE_F16:
		return "vrsqrte_f16";
	case ARM64_INTRIN_VRSQRTEQ_F16:
		return "vrsqrteq_f16";
	case ARM64_INTRIN_VSQRT_F16:
		return "vsqrt_f16";
	case ARM64_INTRIN_VSQRTQ_F16:
		return "vsqrtq_f16";
	case ARM64_INTRIN_VADD_F16:
		return "vadd_f16";
	case ARM64_INTRIN_VADDQ_F16:
		return "vaddq_f16";
	case ARM64_INTRIN_VABD_F16:
		return "vabd_f16";
	case ARM64_INTRIN_VABDQ_F16:
		return "vabdq_f16";
	case ARM64_INTRIN_VCAGE_F16:
		return "vcage_f16";
	case ARM64_INTRIN_VCAGEQ_F16:
		return "vcageq_f16";
	case ARM64_INTRIN_VCAGT_F16:
		return "vcagt_f16";
	case ARM64_INTRIN_VCAGTQ_F16:
		return "vcagtq_f16";
	case ARM64_INTRIN_VCALE_F16:
		return "vcale_f16";
	case ARM64_INTRIN_VCALEQ_F16:
		return "vcaleq_f16";
	case ARM64_INTRIN_VCALT_F16:
		return "vcalt_f16";
	case ARM64_INTRIN_VCALTQ_F16:
		return "vcaltq_f16";
	case ARM64_INTRIN_VCEQ_F16:
		return "vceq_f16";
	case ARM64_INTRIN_VCEQQ_F16:
		return "vceqq_f16";
	case ARM64_INTRIN_VCGE_F16:
		return "vcge_f16";
	case ARM64_INTRIN_VCGEQ_F16:
		return "vcgeq_f16";
	case ARM64_INTRIN_VCGT_F16:
		return "vcgt_f16";
	case ARM64_INTRIN_VCGTQ_F16:
		return "vcgtq_f16";
	case ARM64_INTRIN_VCLE_F16:
		return "vcle_f16";
	case ARM64_INTRIN_VCLEQ_F16:
		return "vcleq_f16";
	case ARM64_INTRIN_VCLT_F16:
		return "vclt_f16";
	case ARM64_INTRIN_VCLTQ_F16:
		return "vcltq_f16";
	case ARM64_INTRIN_VCVT_N_F16_S16:
		return "vcvt_n_f16_s16";
	case ARM64_INTRIN_VCVTQ_N_F16_S16:
		return "vcvtq_n_f16_s16";
	case ARM64_INTRIN_VCVT_N_F16_U16:
		return "vcvt_n_f16_u16";
	case ARM64_INTRIN_VCVTQ_N_F16_U16:
		return "vcvtq_n_f16_u16";
	case ARM64_INTRIN_VCVT_N_S16_F16:
		return "vcvt_n_s16_f16";
	case ARM64_INTRIN_VCVTQ_N_S16_F16:
		return "vcvtq_n_s16_f16";
	case ARM64_INTRIN_VCVT_N_U16_F16:
		return "vcvt_n_u16_f16";
	case ARM64_INTRIN_VCVTQ_N_U16_F16:
		return "vcvtq_n_u16_f16";
	case ARM64_INTRIN_VDIV_F16:
		return "vdiv_f16";
	case ARM64_INTRIN_VDIVQ_F16:
		return "vdivq_f16";
	case ARM64_INTRIN_VMAX_F16:
		return "vmax_f16";
	case ARM64_INTRIN_VMAXQ_F16:
		return "vmaxq_f16";
	case ARM64_INTRIN_VMAXNM_F16:
		return "vmaxnm_f16";
	case ARM64_INTRIN_VMAXNMQ_F16:
		return "vmaxnmq_f16";
	case ARM64_INTRIN_VMIN_F16:
		return "vmin_f16";
	case ARM64_INTRIN_VMINQ_F16:
		return "vminq_f16";
	case ARM64_INTRIN_VMINNM_F16:
		return "vminnm_f16";
	case ARM64_INTRIN_VMINNMQ_F16:
		return "vminnmq_f16";
	case ARM64_INTRIN_VMUL_F16:
		return "vmul_f16";
	case ARM64_INTRIN_VMULQ_F16:
		return "vmulq_f16";
	case ARM64_INTRIN_VMULX_F16:
		return "vmulx_f16";
	case ARM64_INTRIN_VMULXQ_F16:
		return "vmulxq_f16";
	case ARM64_INTRIN_VPADD_F16:
		return "vpadd_f16";
	case ARM64_INTRIN_VPADDQ_F16:
		return "vpaddq_f16";
	case ARM64_INTRIN_VPMAX_F16:
		return "vpmax_f16";
	case ARM64_INTRIN_VPMAXQ_F16:
		return "vpmaxq_f16";
	case ARM64_INTRIN_VPMAXNM_F16:
		return "vpmaxnm_f16";
	case ARM64_INTRIN_VPMAXNMQ_F16:
		return "vpmaxnmq_f16";
	case ARM64_INTRIN_VPMIN_F16:
		return "vpmin_f16";
	case ARM64_INTRIN_VPMINQ_F16:
		return "vpminq_f16";
	case ARM64_INTRIN_VPMINNM_F16:
		return "vpminnm_f16";
	case ARM64_INTRIN_VPMINNMQ_F16:
		return "vpminnmq_f16";
	case ARM64_INTRIN_VRECPS_F16:
		return "vrecps_f16";
	case ARM64_INTRIN_VRECPSQ_F16:
		return "vrecpsq_f16";
	case ARM64_INTRIN_VRSQRTS_F16:
		return "vrsqrts_f16";
	case ARM64_INTRIN_VRSQRTSQ_F16:
		return "vrsqrtsq_f16";
	case ARM64_INTRIN_VSUB_F16:
		return "vsub_f16";
	case ARM64_INTRIN_VSUBQ_F16:
		return "vsubq_f16";
	case ARM64_INTRIN_VFMA_F16:
		return "vfma_f16";
	case ARM64_INTRIN_VFMAQ_F16:
		return "vfmaq_f16";
	case ARM64_INTRIN_VFMS_F16:
		return "vfms_f16";
	case ARM64_INTRIN_VFMSQ_F16:
		return "vfmsq_f16";
	case ARM64_INTRIN_VFMA_LANE_F16:
		return "vfma_lane_f16";
	case ARM64_INTRIN_VFMAQ_LANE_F16:
		return "vfmaq_lane_f16";
	case ARM64_INTRIN_VFMA_LANEQ_F16:
		return "vfma_laneq_f16";
	case ARM64_INTRIN_VFMAQ_LANEQ_F16:
		return "vfmaq_laneq_f16";
	case ARM64_INTRIN_VFMA_N_F16:
		return "vfma_n_f16";
	case ARM64_INTRIN_VFMAQ_N_F16:
		return "vfmaq_n_f16";
	case ARM64_INTRIN_VFMAH_LANE_F16:
		return "vfmah_lane_f16";
	case ARM64_INTRIN_VFMAH_LANEQ_F16:
		return "vfmah_laneq_f16";
	case ARM64_INTRIN_VFMS_LANE_F16:
		return "vfms_lane_f16";
	case ARM64_INTRIN_VFMSQ_LANE_F16:
		return "vfmsq_lane_f16";
	case ARM64_INTRIN_VFMS_LANEQ_F16:
		return "vfms_laneq_f16";
	case ARM64_INTRIN_VFMSQ_LANEQ_F16:
		return "vfmsq_laneq_f16";
	case ARM64_INTRIN_VFMS_N_F16:
		return "vfms_n_f16";
	case ARM64_INTRIN_VFMSQ_N_F16:
		return "vfmsq_n_f16";
	case ARM64_INTRIN_VFMSH_LANE_F16:
		return "vfmsh_lane_f16";
	case ARM64_INTRIN_VFMSH_LANEQ_F16:
		return "vfmsh_laneq_f16";
	case ARM64_INTRIN_VMUL_LANE_F16:
		return "vmul_lane_f16";
	case ARM64_INTRIN_VMULQ_LANE_F16:
		return "vmulq_lane_f16";
	case ARM64_INTRIN_VMUL_LANEQ_F16:
		return "vmul_laneq_f16";
	case ARM64_INTRIN_VMULQ_LANEQ_F16:
		return "vmulq_laneq_f16";
	case ARM64_INTRIN_VMUL_N_F16:
		return "vmul_n_f16";
	case ARM64_INTRIN_VMULQ_N_F16:
		return "vmulq_n_f16";
	case ARM64_INTRIN_VMULH_LANE_F16:
		return "vmulh_lane_f16";
	case ARM64_INTRIN_VMULH_LANEQ_F16:
		return "vmulh_laneq_f16";
	case ARM64_INTRIN_VMULX_LANE_F16:
		return "vmulx_lane_f16";
	case ARM64_INTRIN_VMULXQ_LANE_F16:
		return "vmulxq_lane_f16";
	case ARM64_INTRIN_VMULX_LANEQ_F16:
		return "vmulx_laneq_f16";
	case ARM64_INTRIN_VMULXQ_LANEQ_F16:
		return "vmulxq_laneq_f16";
	case ARM64_INTRIN_VMULX_N_F16:
		return "vmulx_n_f16";
	case ARM64_INTRIN_VMULXQ_N_F16:
		return "vmulxq_n_f16";
	case ARM64_INTRIN_VMULXH_LANE_F16:
		return "vmulxh_lane_f16";
	case ARM64_INTRIN_VMULXH_LANEQ_F16:
		return "vmulxh_laneq_f16";
	case ARM64_INTRIN_VMAXV_F16:
		return "vmaxv_f16";
	case ARM64_INTRIN_VMAXVQ_F16:
		return "vmaxvq_f16";
	case ARM64_INTRIN_VMINV_F16:
		return "vminv_f16";
	case ARM64_INTRIN_VMINVQ_F16:
		return "vminvq_f16";
	case ARM64_INTRIN_VMAXNMV_F16:
		return "vmaxnmv_f16";
	case ARM64_INTRIN_VMAXNMVQ_F16:
		return "vmaxnmvq_f16";
	case ARM64_INTRIN_VMINNMV_F16:
		return "vminnmv_f16";
	case ARM64_INTRIN_VMINNMVQ_F16:
		return "vminnmvq_f16";
	case ARM64_INTRIN_VBSL_F16:
		return "vbsl_f16";
	case ARM64_INTRIN_VBSLQ_F16:
		return "vbslq_f16";
	case ARM64_INTRIN_VZIP_F16:
		return "vzip_f16";
	case ARM64_INTRIN_VZIPQ_F16:
		return "vzipq_f16";
	case ARM64_INTRIN_VUZP_F16:
		return "vuzp_f16";
	case ARM64_INTRIN_VUZPQ_F16:
		return "vuzpq_f16";
	case ARM64_INTRIN_VTRN_F16:
		return "vtrn_f16";
	case ARM64_INTRIN_VTRNQ_F16:
		return "vtrnq_f16";
	case ARM64_INTRIN_VMOV_N_F16:
		return "vmov_n_f16";
	case ARM64_INTRIN_VMOVQ_N_F16:
		return "vmovq_n_f16";
	case ARM64_INTRIN_VDUP_N_F16:
		return "vdup_n_f16";
	case ARM64_INTRIN_VDUPQ_N_F16:
		return "vdupq_n_f16";
	case ARM64_INTRIN_VDUP_LANE_F16:
		return "vdup_lane_f16";
	case ARM64_INTRIN_VDUPQ_LANE_F16:
		return "vdupq_lane_f16";
	case ARM64_INTRIN_VEXT_F16:
		return "vext_f16";
	case ARM64_INTRIN_VEXTQ_F16:
		return "vextq_f16";
	case ARM64_INTRIN_VREV64_F16:
		return "vrev64_f16";
	case ARM64_INTRIN_VREV64Q_F16:
		return "vrev64q_f16";
	case ARM64_INTRIN_VZIP1_F16:
		return "vzip1_f16";
	case ARM64_INTRIN_VZIP1Q_F16:
		return "vzip1q_f16";
	case ARM64_INTRIN_VZIP2_F16:
		return "vzip2_f16";
	case ARM64_INTRIN_VZIP2Q_F16:
		return "vzip2q_f16";
	case ARM64_INTRIN_VUZP1_F16:
		return "vuzp1_f16";
	case ARM64_INTRIN_VUZP1Q_F16:
		return "vuzp1q_f16";
	case ARM64_INTRIN_VUZP2_F16:
		return "vuzp2_f16";
	case ARM64_INTRIN_VUZP2Q_F16:
		return "vuzp2q_f16";
	case ARM64_INTRIN_VTRN1_F16:
		return "vtrn1_f16";
	case ARM64_INTRIN_VTRN1Q_F16:
		return "vtrn1q_f16";
	case ARM64_INTRIN_VTRN2_F16:
		return "vtrn2_f16";
	case ARM64_INTRIN_VTRN2Q_F16:
		return "vtrn2q_f16";
	case ARM64_INTRIN_VDUP_LANEQ_F16:
		return "vdup_laneq_f16";
	case ARM64_INTRIN_VDUPQ_LANEQ_F16:
		return "vdupq_laneq_f16";
	case ARM64_INTRIN_VDUPH_LANE_F16:
		return "vduph_lane_f16";
	case ARM64_INTRIN_VDUPH_LANEQ_F16:
		return "vduph_laneq_f16";
	case ARM64_INTRIN_VDOT_U32:
		return "vdot_u32";
	case ARM64_INTRIN_VDOT_S32:
		return "vdot_s32";
	case ARM64_INTRIN_VDOTQ_U32:
		return "vdotq_u32";
	case ARM64_INTRIN_VDOTQ_S32:
		return "vdotq_s32";
	case ARM64_INTRIN_VDOT_LANE_U32:
		return "vdot_lane_u32";
	case ARM64_INTRIN_VDOT_LANE_S32:
		return "vdot_lane_s32";
	case ARM64_INTRIN_VDOTQ_LANEQ_U32:
		return "vdotq_laneq_u32";
	case ARM64_INTRIN_VDOTQ_LANEQ_S32:
		return "vdotq_laneq_s32";
	case ARM64_INTRIN_VDOT_LANEQ_U32:
		return "vdot_laneq_u32";
	case ARM64_INTRIN_VDOT_LANEQ_S32:
		return "vdot_laneq_s32";
	case ARM64_INTRIN_VDOTQ_LANE_U32:
		return "vdotq_lane_u32";
	case ARM64_INTRIN_VDOTQ_LANE_S32:
		return "vdotq_lane_s32";
	case ARM64_INTRIN_VSHA512HQ_U64:
		return "vsha512hq_u64";
	case ARM64_INTRIN_VSHA512H2Q_U64:
		return "vsha512h2q_u64";
	case ARM64_INTRIN_VSHA512SU0Q_U64:
		return "vsha512su0q_u64";
	case ARM64_INTRIN_VSHA512SU1Q_U64:
		return "vsha512su1q_u64";
	case ARM64_INTRIN_VEOR3Q_U8:
		return "veor3q_u8";
	case ARM64_INTRIN_VEOR3Q_U16:
		return "veor3q_u16";
	case ARM64_INTRIN_VEOR3Q_U32:
		return "veor3q_u32";
	case ARM64_INTRIN_VEOR3Q_U64:
		return "veor3q_u64";
	case ARM64_INTRIN_VEOR3Q_S8:
		return "veor3q_s8";
	case ARM64_INTRIN_VEOR3Q_S16:
		return "veor3q_s16";
	case ARM64_INTRIN_VEOR3Q_S32:
		return "veor3q_s32";
	case ARM64_INTRIN_VEOR3Q_S64:
		return "veor3q_s64";
	case ARM64_INTRIN_VRAX1Q_U64:
		return "vrax1q_u64";
	case ARM64_INTRIN_VXARQ_U64:
		return "vxarq_u64";
	case ARM64_INTRIN_VBCAXQ_U8:
		return "vbcaxq_u8";
	case ARM64_INTRIN_VBCAXQ_U16:
		return "vbcaxq_u16";
	case ARM64_INTRIN_VBCAXQ_U32:
		return "vbcaxq_u32";
	case ARM64_INTRIN_VBCAXQ_U64:
		return "vbcaxq_u64";
	case ARM64_INTRIN_VBCAXQ_S8:
		return "vbcaxq_s8";
	case ARM64_INTRIN_VBCAXQ_S16:
		return "vbcaxq_s16";
	case ARM64_INTRIN_VBCAXQ_S32:
		return "vbcaxq_s32";
	case ARM64_INTRIN_VBCAXQ_S64:
		return "vbcaxq_s64";
	case ARM64_INTRIN_VSM3SS1Q_U32:
		return "vsm3ss1q_u32";
	case ARM64_INTRIN_VSM3TT1AQ_U32:
		return "vsm3tt1aq_u32";
	case ARM64_INTRIN_VSM3TT1BQ_U32:
		return "vsm3tt1bq_u32";
	case ARM64_INTRIN_VSM3TT2AQ_U32:
		return "vsm3tt2aq_u32";
	case ARM64_INTRIN_VSM3TT2BQ_U32:
		return "vsm3tt2bq_u32";
	case ARM64_INTRIN_VSM3PARTW1Q_U32:
		return "vsm3partw1q_u32";
	case ARM64_INTRIN_VSM3PARTW2Q_U32:
		return "vsm3partw2q_u32";
	case ARM64_INTRIN_VSM4EQ_U32:
		return "vsm4eq_u32";
	case ARM64_INTRIN_VSM4EKEYQ_U32:
		return "vsm4ekeyq_u32";
	case ARM64_INTRIN_VFMLAL_LOW_F16:
		return "vfmlal_low_f16";
	case ARM64_INTRIN_VFMLSL_LOW_F16:
		return "vfmlsl_low_f16";
	case ARM64_INTRIN_VFMLALQ_LOW_F16:
		return "vfmlalq_low_f16";
	case ARM64_INTRIN_VFMLSLQ_LOW_F16:
		return "vfmlslq_low_f16";
	case ARM64_INTRIN_VFMLAL_HIGH_F16:
		return "vfmlal_high_f16";
	case ARM64_INTRIN_VFMLSL_HIGH_F16:
		return "vfmlsl_high_f16";
	case ARM64_INTRIN_VFMLALQ_HIGH_F16:
		return "vfmlalq_high_f16";
	case ARM64_INTRIN_VFMLSLQ_HIGH_F16:
		return "vfmlslq_high_f16";
	case ARM64_INTRIN_VFMLAL_LANE_LOW_F16:
		return "vfmlal_lane_low_f16";
	case ARM64_INTRIN_VFMLAL_LANEQ_LOW_F16:
		return "vfmlal_laneq_low_f16";
	case ARM64_INTRIN_VFMLALQ_LANE_LOW_F16:
		return "vfmlalq_lane_low_f16";
	case ARM64_INTRIN_VFMLALQ_LANEQ_LOW_F16:
		return "vfmlalq_laneq_low_f16";
	case ARM64_INTRIN_VFMLSL_LANE_LOW_F16:
		return "vfmlsl_lane_low_f16";
	case ARM64_INTRIN_VFMLSL_LANEQ_LOW_F16:
		return "vfmlsl_laneq_low_f16";
	case ARM64_INTRIN_VFMLSLQ_LANE_LOW_F16:
		return "vfmlslq_lane_low_f16";
	case ARM64_INTRIN_VFMLSLQ_LANEQ_LOW_F16:
		return "vfmlslq_laneq_low_f16";
	case ARM64_INTRIN_VFMLAL_LANE_HIGH_F16:
		return "vfmlal_lane_high_f16";
	case ARM64_INTRIN_VFMLSL_LANE_HIGH_F16:
		return "vfmlsl_lane_high_f16";
	case ARM64_INTRIN_VFMLALQ_LANE_HIGH_F16:
		return "vfmlalq_lane_high_f16";
	case ARM64_INTRIN_VFMLSLQ_LANE_HIGH_F16:
		return "vfmlslq_lane_high_f16";
	case ARM64_INTRIN_VFMLAL_LANEQ_HIGH_F16:
		return "vfmlal_laneq_high_f16";
	case ARM64_INTRIN_VFMLSL_LANEQ_HIGH_F16:
		return "vfmlsl_laneq_high_f16";
	case ARM64_INTRIN_VFMLALQ_LANEQ_HIGH_F16:
		return "vfmlalq_laneq_high_f16";
	case ARM64_INTRIN_VFMLSLQ_LANEQ_HIGH_F16:
		return "vfmlslq_laneq_high_f16";
	case ARM64_INTRIN_VCADD_ROT90_F16:
		return "vcadd_rot90_f16";
	case ARM64_INTRIN_VCADD_ROT90_F32:
		return "vcadd_rot90_f32";
	case ARM64_INTRIN_VCADDQ_ROT90_F16:
		return "vcaddq_rot90_f16";
	case ARM64_INTRIN_VCADDQ_ROT90_F32:
		return "vcaddq_rot90_f32";
	case ARM64_INTRIN_VCADDQ_ROT90_F64:
		return "vcaddq_rot90_f64";
	case ARM64_INTRIN_VCADD_ROT270_F16:
		return "vcadd_rot270_f16";
	case ARM64_INTRIN_VCADD_ROT270_F32:
		return "vcadd_rot270_f32";
	case ARM64_INTRIN_VCADDQ_ROT270_F16:
		return "vcaddq_rot270_f16";
	case ARM64_INTRIN_VCADDQ_ROT270_F32:
		return "vcaddq_rot270_f32";
	case ARM64_INTRIN_VCADDQ_ROT270_F64:
		return "vcaddq_rot270_f64";
	case ARM64_INTRIN_VCMLA_F16:
		return "vcmla_f16";
	case ARM64_INTRIN_VCMLA_F32:
		return "vcmla_f32";
	case ARM64_INTRIN_VCMLA_LANE_F16:
		return "vcmla_lane_f16";
	case ARM64_INTRIN_VCMLA_LANE_F32:
		return "vcmla_lane_f32";
	case ARM64_INTRIN_VCMLA_LANEQ_F16:
		return "vcmla_laneq_f16";
	case ARM64_INTRIN_VCMLA_LANEQ_F32:
		return "vcmla_laneq_f32";
	case ARM64_INTRIN_VCMLAQ_F16:
		return "vcmlaq_f16";
	case ARM64_INTRIN_VCMLAQ_F32:
		return "vcmlaq_f32";
	case ARM64_INTRIN_VCMLAQ_F64:
		return "vcmlaq_f64";
	case ARM64_INTRIN_VCMLAQ_LANE_F16:
		return "vcmlaq_lane_f16";
	case ARM64_INTRIN_VCMLAQ_LANE_F32:
		return "vcmlaq_lane_f32";
	case ARM64_INTRIN_VCMLAQ_LANEQ_F16:
		return "vcmlaq_laneq_f16";
	case ARM64_INTRIN_VCMLAQ_LANEQ_F32:
		return "vcmlaq_laneq_f32";
	case ARM64_INTRIN_VCMLA_ROT90_F16:
		return "vcmla_rot90_f16";
	case ARM64_INTRIN_VCMLA_ROT90_F32:
		return "vcmla_rot90_f32";
	case ARM64_INTRIN_VCMLA_ROT90_LANE_F16:
		return "vcmla_rot90_lane_f16";
	case ARM64_INTRIN_VCMLA_ROT90_LANE_F32:
		return "vcmla_rot90_lane_f32";
	case ARM64_INTRIN_VCMLA_ROT90_LANEQ_F16:
		return "vcmla_rot90_laneq_f16";
	case ARM64_INTRIN_VCMLA_ROT90_LANEQ_F32:
		return "vcmla_rot90_laneq_f32";
	case ARM64_INTRIN_VCMLAQ_ROT90_F16:
		return "vcmlaq_rot90_f16";
	case ARM64_INTRIN_VCMLAQ_ROT90_F32:
		return "vcmlaq_rot90_f32";
	case ARM64_INTRIN_VCMLAQ_ROT90_F64:
		return "vcmlaq_rot90_f64";
	case ARM64_INTRIN_VCMLAQ_ROT90_LANE_F16:
		return "vcmlaq_rot90_lane_f16";
	case ARM64_INTRIN_VCMLAQ_ROT90_LANE_F32:
		return "vcmlaq_rot90_lane_f32";
	case ARM64_INTRIN_VCMLAQ_ROT90_LANEQ_F16:
		return "vcmlaq_rot90_laneq_f16";
	case ARM64_INTRIN_VCMLAQ_ROT90_LANEQ_F32:
		return "vcmlaq_rot90_laneq_f32";
	case ARM64_INTRIN_VCMLA_ROT180_F16:
		return "vcmla_rot180_f16";
	case ARM64_INTRIN_VCMLA_ROT180_F32:
		return "vcmla_rot180_f32";
	case ARM64_INTRIN_VCMLA_ROT180_LANE_F16:
		return "vcmla_rot180_lane_f16";
	case ARM64_INTRIN_VCMLA_ROT180_LANE_F32:
		return "vcmla_rot180_lane_f32";
	case ARM64_INTRIN_VCMLA_ROT180_LANEQ_F16:
		return "vcmla_rot180_laneq_f16";
	case ARM64_INTRIN_VCMLA_ROT180_LANEQ_F32:
		return "vcmla_rot180_laneq_f32";
	case ARM64_INTRIN_VCMLAQ_ROT180_F16:
		return "vcmlaq_rot180_f16";
	case ARM64_INTRIN_VCMLAQ_ROT180_F32:
		return "vcmlaq_rot180_f32";
	case ARM64_INTRIN_VCMLAQ_ROT180_F64:
		return "vcmlaq_rot180_f64";
	case ARM64_INTRIN_VCMLAQ_ROT180_LANE_F16:
		return "vcmlaq_rot180_lane_f16";
	case ARM64_INTRIN_VCMLAQ_ROT180_LANE_F32:
		return "vcmlaq_rot180_lane_f32";
	case ARM64_INTRIN_VCMLAQ_ROT180_LANEQ_F16:
		return "vcmlaq_rot180_laneq_f16";
	case ARM64_INTRIN_VCMLAQ_ROT180_LANEQ_F32:
		return "vcmlaq_rot180_laneq_f32";
	case ARM64_INTRIN_VCMLA_ROT270_F16:
		return "vcmla_rot270_f16";
	case ARM64_INTRIN_VCMLA_ROT270_F32:
		return "vcmla_rot270_f32";
	case ARM64_INTRIN_VCMLA_ROT270_LANE_F16:
		return "vcmla_rot270_lane_f16";
	case ARM64_INTRIN_VCMLA_ROT270_LANE_F32:
		return "vcmla_rot270_lane_f32";
	case ARM64_INTRIN_VCMLA_ROT270_LANEQ_F16:
		return "vcmla_rot270_laneq_f16";
	case ARM64_INTRIN_VCMLA_ROT270_LANEQ_F32:
		return "vcmla_rot270_laneq_f32";
	case ARM64_INTRIN_VCMLAQ_ROT270_F16:
		return "vcmlaq_rot270_f16";
	case ARM64_INTRIN_VCMLAQ_ROT270_F32:
		return "vcmlaq_rot270_f32";
	case ARM64_INTRIN_VCMLAQ_ROT270_F64:
		return "vcmlaq_rot270_f64";
	case ARM64_INTRIN_VCMLAQ_ROT270_LANE_F16:
		return "vcmlaq_rot270_lane_f16";
	case ARM64_INTRIN_VCMLAQ_ROT270_LANE_F32:
		return "vcmlaq_rot270_lane_f32";
	case ARM64_INTRIN_VCMLAQ_ROT270_LANEQ_F16:
		return "vcmlaq_rot270_laneq_f16";
	case ARM64_INTRIN_VCMLAQ_ROT270_LANEQ_F32:
		return "vcmlaq_rot270_laneq_f32";
	case ARM64_INTRIN_VRND32Z_F32:
		return "vrnd32z_f32";
	case ARM64_INTRIN_VRND32ZQ_F32:
		return "vrnd32zq_f32";
	case ARM64_INTRIN_VRND32Z_F64:
		return "vrnd32z_f64";
	case ARM64_INTRIN_VRND32ZQ_F64:
		return "vrnd32zq_f64";
	case ARM64_INTRIN_VRND64Z_F32:
		return "vrnd64z_f32";
	case ARM64_INTRIN_VRND64ZQ_F32:
		return "vrnd64zq_f32";
	case ARM64_INTRIN_VRND64Z_F64:
		return "vrnd64z_f64";
	case ARM64_INTRIN_VRND64ZQ_F64:
		return "vrnd64zq_f64";
	case ARM64_INTRIN_VRND32X_F32:
		return "vrnd32x_f32";
	case ARM64_INTRIN_VRND32XQ_F32:
		return "vrnd32xq_f32";
	case ARM64_INTRIN_VRND32X_F64:
		return "vrnd32x_f64";
	case ARM64_INTRIN_VRND32XQ_F64:
		return "vrnd32xq_f64";
	case ARM64_INTRIN_VRND64X_F32:
		return "vrnd64x_f32";
	case ARM64_INTRIN_VRND64XQ_F32:
		return "vrnd64xq_f32";
	case ARM64_INTRIN_VRND64X_F64:
		return "vrnd64x_f64";
	case ARM64_INTRIN_VRND64XQ_F64:
		return "vrnd64xq_f64";
	case ARM64_INTRIN_VMMLAQ_S32:
		return "vmmlaq_s32";
	case ARM64_INTRIN_VMMLAQ_U32:
		return "vmmlaq_u32";
	case ARM64_INTRIN_VUSMMLAQ_S32:
		return "vusmmlaq_s32";
	case ARM64_INTRIN_VUSDOT_S32:
		return "vusdot_s32";
	case ARM64_INTRIN_VUSDOT_LANE_S32:
		return "vusdot_lane_s32";
	case ARM64_INTRIN_VSUDOT_LANE_S32:
		return "vsudot_lane_s32";
	case ARM64_INTRIN_VUSDOT_LANEQ_S32:
		return "vusdot_laneq_s32";
	case ARM64_INTRIN_VSUDOT_LANEQ_S32:
		return "vsudot_laneq_s32";
	case ARM64_INTRIN_VUSDOTQ_S32:
		return "vusdotq_s32";
	case ARM64_INTRIN_VUSDOTQ_LANE_S32:
		return "vusdotq_lane_s32";
	case ARM64_INTRIN_VSUDOTQ_LANE_S32:
		return "vsudotq_lane_s32";
	case ARM64_INTRIN_VUSDOTQ_LANEQ_S32:
		return "vusdotq_laneq_s32";
	case ARM64_INTRIN_VSUDOTQ_LANEQ_S32:
		return "vsudotq_laneq_s32";
	case ARM64_INTRIN_VCREATE_BF16:
		return "vcreate_bf16";
	case ARM64_INTRIN_VDUP_N_BF16:
		return "vdup_n_bf16";
	case ARM64_INTRIN_VDUPQ_N_BF16:
		return "vdupq_n_bf16";
	case ARM64_INTRIN_VDUP_LANE_BF16:
		return "vdup_lane_bf16";
	case ARM64_INTRIN_VDUPQ_LANE_BF16:
		return "vdupq_lane_bf16";
	case ARM64_INTRIN_VDUP_LANEQ_BF16:
		return "vdup_laneq_bf16";
	case ARM64_INTRIN_VDUPQ_LANEQ_BF16:
		return "vdupq_laneq_bf16";
	case ARM64_INTRIN_VCOMBINE_BF16:
		return "vcombine_bf16";
	case ARM64_INTRIN_VGET_HIGH_BF16:
		return "vget_high_bf16";
	case ARM64_INTRIN_VGET_LOW_BF16:
		return "vget_low_bf16";
	case ARM64_INTRIN_VGET_LANE_BF16:
		return "vget_lane_bf16";
	case ARM64_INTRIN_VGETQ_LANE_BF16:
		return "vgetq_lane_bf16";
	case ARM64_INTRIN_VSET_LANE_BF16:
		return "vset_lane_bf16";
	case ARM64_INTRIN_VSETQ_LANE_BF16:
		return "vsetq_lane_bf16";
	case ARM64_INTRIN_VDUPH_LANE_BF16:
		return "vduph_lane_bf16";
	case ARM64_INTRIN_VDUPH_LANEQ_BF16:
		return "vduph_laneq_bf16";
	case ARM64_INTRIN_VLD1_BF16:
		return "vld1_bf16";
	case ARM64_INTRIN_VLD1Q_BF16:
		return "vld1q_bf16";
	case ARM64_INTRIN_VLD1_LANE_BF16:
		return "vld1_lane_bf16";
	case ARM64_INTRIN_VLD1Q_LANE_BF16:
		return "vld1q_lane_bf16";
	case ARM64_INTRIN_VLD1_DUP_BF16:
		return "vld1_dup_bf16";
	case ARM64_INTRIN_VLD1Q_DUP_BF16:
		return "vld1q_dup_bf16";
	case ARM64_INTRIN_VST1_BF16:
		return "vst1_bf16";
	case ARM64_INTRIN_VST1Q_BF16:
		return "vst1q_bf16";
	case ARM64_INTRIN_VST1_LANE_BF16:
		return "vst1_lane_bf16";
	case ARM64_INTRIN_VST1Q_LANE_BF16:
		return "vst1q_lane_bf16";
	case ARM64_INTRIN_VLD2_BF16:
		return "vld2_bf16";
	case ARM64_INTRIN_VLD2Q_BF16:
		return "vld2q_bf16";
	case ARM64_INTRIN_VLD3_BF16:
		return "vld3_bf16";
	case ARM64_INTRIN_VLD3Q_BF16:
		return "vld3q_bf16";
	case ARM64_INTRIN_VLD4_BF16:
		return "vld4_bf16";
	case ARM64_INTRIN_VLD4Q_BF16:
		return "vld4q_bf16";
	case ARM64_INTRIN_VLD2_DUP_BF16:
		return "vld2_dup_bf16";
	case ARM64_INTRIN_VLD2Q_DUP_BF16:
		return "vld2q_dup_bf16";
	case ARM64_INTRIN_VLD3_DUP_BF16:
		return "vld3_dup_bf16";
	case ARM64_INTRIN_VLD3Q_DUP_BF16:
		return "vld3q_dup_bf16";
	case ARM64_INTRIN_VLD4_DUP_BF16:
		return "vld4_dup_bf16";
	case ARM64_INTRIN_VLD4Q_DUP_BF16:
		return "vld4q_dup_bf16";
	case ARM64_INTRIN_VST2_BF16:
		return "vst2_bf16";
	case ARM64_INTRIN_VST2Q_BF16:
		return "vst2q_bf16";
	case ARM64_INTRIN_VST3_BF16:
		return "vst3_bf16";
	case ARM64_INTRIN_VST3Q_BF16:
		return "vst3q_bf16";
	case ARM64_INTRIN_VST4_BF16:
		return "vst4_bf16";
	case ARM64_INTRIN_VST4Q_BF16:
		return "vst4q_bf16";
	case ARM64_INTRIN_VLD2_LANE_BF16:
		return "vld2_lane_bf16";
	case ARM64_INTRIN_VLD2Q_LANE_BF16:
		return "vld2q_lane_bf16";
	case ARM64_INTRIN_VLD3_LANE_BF16:
		return "vld3_lane_bf16";
	case ARM64_INTRIN_VLD3Q_LANE_BF16:
		return "vld3q_lane_bf16";
	case ARM64_INTRIN_VLD4_LANE_BF16:
		return "vld4_lane_bf16";
	case ARM64_INTRIN_VLD4Q_LANE_BF16:
		return "vld4q_lane_bf16";
	case ARM64_INTRIN_VST2_LANE_BF16:
		return "vst2_lane_bf16";
	case ARM64_INTRIN_VST2Q_LANE_BF16:
		return "vst2q_lane_bf16";
	case ARM64_INTRIN_VST3_LANE_BF16:
		return "vst3_lane_bf16";
	case ARM64_INTRIN_VST3Q_LANE_BF16:
		return "vst3q_lane_bf16";
	case ARM64_INTRIN_VST4_LANE_BF16:
		return "vst4_lane_bf16";
	case ARM64_INTRIN_VST4Q_LANE_BF16:
		return "vst4q_lane_bf16";
	case ARM64_INTRIN_VST1_BF16_X2:
		return "vst1_bf16_x2";
	case ARM64_INTRIN_VST1Q_BF16_X2:
		return "vst1q_bf16_x2";
	case ARM64_INTRIN_VST1_BF16_X3:
		return "vst1_bf16_x3";
	case ARM64_INTRIN_VST1Q_BF16_X3:
		return "vst1q_bf16_x3";
	case ARM64_INTRIN_VST1_BF16_X4:
		return "vst1_bf16_x4";
	case ARM64_INTRIN_VST1Q_BF16_X4:
		return "vst1q_bf16_x4";
	case ARM64_INTRIN_VLD1_BF16_X2:
		return "vld1_bf16_x2";
	case ARM64_INTRIN_VLD1Q_BF16_X2:
		return "vld1q_bf16_x2";
	case ARM64_INTRIN_VLD1_BF16_X3:
		return "vld1_bf16_x3";
	case ARM64_INTRIN_VLD1Q_BF16_X3:
		return "vld1q_bf16_x3";
	case ARM64_INTRIN_VLD1_BF16_X4:
		return "vld1_bf16_x4";
	case ARM64_INTRIN_VLD1Q_BF16_X4:
		return "vld1q_bf16_x4";
	case ARM64_INTRIN_VCVT_F32_BF16:
		return "vcvt_f32_bf16";
	case ARM64_INTRIN_VCVTQ_LOW_F32_BF16:
		return "vcvtq_low_f32_bf16";
	case ARM64_INTRIN_VCVTQ_HIGH_F32_BF16:
		return "vcvtq_high_f32_bf16";
	case ARM64_INTRIN_VCVT_BF16_F32:
		return "vcvt_bf16_f32";
	case ARM64_INTRIN_VCVTQ_LOW_BF16_F32:
		return "vcvtq_low_bf16_f32";
	case ARM64_INTRIN_VCVTQ_HIGH_BF16_F32:
		return "vcvtq_high_bf16_f32";
	case ARM64_INTRIN_VCVTH_BF16_F32:
		return "vcvth_bf16_f32";
	case ARM64_INTRIN_VCVTAH_F32_BF16:
		return "vcvtah_f32_bf16";
	case ARM64_INTRIN_VCOPY_LANE_BF16:
		return "vcopy_lane_bf16";
	case ARM64_INTRIN_VCOPYQ_LANE_BF16:
		return "vcopyq_lane_bf16";
	case ARM64_INTRIN_VCOPY_LANEQ_BF16:
		return "vcopy_laneq_bf16";
	case ARM64_INTRIN_VCOPYQ_LANEQ_BF16:
		return "vcopyq_laneq_bf16";
	case ARM64_INTRIN_VBFDOT_F32:
		return "vbfdot_f32";
	case ARM64_INTRIN_VBFDOTQ_F32:
		return "vbfdotq_f32";
	case ARM64_INTRIN_VBFDOT_LANE_F32:
		return "vbfdot_lane_f32";
	case ARM64_INTRIN_VBFDOTQ_LANEQ_F32:
		return "vbfdotq_laneq_f32";
	case ARM64_INTRIN_VBFDOT_LANEQ_F32:
		return "vbfdot_laneq_f32";
	case ARM64_INTRIN_VBFDOTQ_LANE_F32:
		return "vbfdotq_lane_f32";
	case ARM64_INTRIN_VBFMMLAQ_F32:
		return "vbfmmlaq_f32";
	case ARM64_INTRIN_VBFMLALBQ_F32:
		return "vbfmlalbq_f32";
	case ARM64_INTRIN_VBFMLALTQ_F32:
		return "vbfmlaltq_f32";
	case ARM64_INTRIN_VBFMLALBQ_LANE_F32:
		return "vbfmlalbq_lane_f32";
	case ARM64_INTRIN_VBFMLALBQ_LANEQ_F32:
		return "vbfmlalbq_laneq_f32";
	case ARM64_INTRIN_VBFMLALTQ_LANE_F32:
		return "vbfmlaltq_lane_f32";
	case ARM64_INTRIN_VBFMLALTQ_LANEQ_F32:
		return "vbfmlaltq_laneq_f32";
	default:
		return "";
	}
}

vector<NameAndType> NeonGetIntrinsicInputs(uint32_t intrinsic)
{
	switch (intrinsic)
	{
	case ARM64_INTRIN_VABSQ_F16:
	case ARM64_INTRIN_VABSQ_F32:
	case ARM64_INTRIN_VABSQ_F64:
	case ARM64_INTRIN_VADDVQ_F64:
	case ARM64_INTRIN_VCEQZQ_F16:
	case ARM64_INTRIN_VCEQZQ_F32:
	case ARM64_INTRIN_VCEQZQ_F64:
	case ARM64_INTRIN_VCGEZQ_F16:
	case ARM64_INTRIN_VCGEZQ_F32:
	case ARM64_INTRIN_VCGEZQ_F64:
	case ARM64_INTRIN_VCGTZQ_F16:
	case ARM64_INTRIN_VCGTZQ_F32:
	case ARM64_INTRIN_VCGTZQ_F64:
	case ARM64_INTRIN_VCLEZQ_F16:
	case ARM64_INTRIN_VCLEZQ_F32:
	case ARM64_INTRIN_VCLEZQ_F64:
	case ARM64_INTRIN_VCLTZQ_F16:
	case ARM64_INTRIN_VCLTZQ_F32:
	case ARM64_INTRIN_VCLTZQ_F64:
	case ARM64_INTRIN_VCVT_BF16_F32:
	case ARM64_INTRIN_VCVT_F16_F32:
	case ARM64_INTRIN_VCVT_F32_F64:
	case ARM64_INTRIN_VCVT_HIGH_F32_F16:
	case ARM64_INTRIN_VCVT_HIGH_F64_F32:
	case ARM64_INTRIN_VCVTAQ_S16_F16:
	case ARM64_INTRIN_VCVTAQ_S32_F32:
	case ARM64_INTRIN_VCVTAQ_S64_F64:
	case ARM64_INTRIN_VCVTAQ_U16_F16:
	case ARM64_INTRIN_VCVTAQ_U32_F32:
	case ARM64_INTRIN_VCVTAQ_U64_F64:
	case ARM64_INTRIN_VCVTMQ_S16_F16:
	case ARM64_INTRIN_VCVTMQ_S32_F32:
	case ARM64_INTRIN_VCVTMQ_S64_F64:
	case ARM64_INTRIN_VCVTMQ_U16_F16:
	case ARM64_INTRIN_VCVTMQ_U32_F32:
	case ARM64_INTRIN_VCVTMQ_U64_F64:
	case ARM64_INTRIN_VCVTNQ_S16_F16:
	case ARM64_INTRIN_VCVTNQ_S32_F32:
	case ARM64_INTRIN_VCVTNQ_S64_F64:
	case ARM64_INTRIN_VCVTNQ_U16_F16:
	case ARM64_INTRIN_VCVTNQ_U32_F32:
	case ARM64_INTRIN_VCVTNQ_U64_F64:
	case ARM64_INTRIN_VCVTPQ_S16_F16:
	case ARM64_INTRIN_VCVTPQ_S32_F32:
	case ARM64_INTRIN_VCVTPQ_S64_F64:
	case ARM64_INTRIN_VCVTPQ_U16_F16:
	case ARM64_INTRIN_VCVTPQ_U32_F32:
	case ARM64_INTRIN_VCVTPQ_U64_F64:
	case ARM64_INTRIN_VCVTQ_HIGH_F32_BF16:
	case ARM64_INTRIN_VCVTQ_LOW_BF16_F32:
	case ARM64_INTRIN_VCVTQ_LOW_F32_BF16:
	case ARM64_INTRIN_VCVTQ_S16_F16:
	case ARM64_INTRIN_VCVTQ_S32_F32:
	case ARM64_INTRIN_VCVTQ_S64_F64:
	case ARM64_INTRIN_VCVTQ_U16_F16:
	case ARM64_INTRIN_VCVTQ_U32_F32:
	case ARM64_INTRIN_VCVTQ_U64_F64:
	case ARM64_INTRIN_VCVTX_F32_F64:
	case ARM64_INTRIN_VGET_HIGH_BF16:
	case ARM64_INTRIN_VGET_HIGH_F16:
	case ARM64_INTRIN_VGET_HIGH_F32:
	case ARM64_INTRIN_VGET_HIGH_F64:
	case ARM64_INTRIN_VGET_LOW_BF16:
	case ARM64_INTRIN_VGET_LOW_F16:
	case ARM64_INTRIN_VGET_LOW_F32:
	case ARM64_INTRIN_VGET_LOW_F64:
	case ARM64_INTRIN_VMAXNMVQ_F16:
	case ARM64_INTRIN_VMAXNMVQ_F32:
	case ARM64_INTRIN_VMAXNMVQ_F64:
	case ARM64_INTRIN_VMAXVQ_F16:
	case ARM64_INTRIN_VMAXVQ_F32:
	case ARM64_INTRIN_VMAXVQ_F64:
	case ARM64_INTRIN_VMINNMVQ_F16:
	case ARM64_INTRIN_VMINNMVQ_F32:
	case ARM64_INTRIN_VMINNMVQ_F64:
	case ARM64_INTRIN_VMINVQ_F16:
	case ARM64_INTRIN_VMINVQ_F32:
	case ARM64_INTRIN_VMINVQ_F64:
	case ARM64_INTRIN_VNEGQ_F16:
	case ARM64_INTRIN_VNEGQ_F32:
	case ARM64_INTRIN_VNEGQ_F64:
	case ARM64_INTRIN_VPADDD_F64:
	case ARM64_INTRIN_VPMAXNMQD_F64:
	case ARM64_INTRIN_VPMAXQD_F64:
	case ARM64_INTRIN_VPMINNMQD_F64:
	case ARM64_INTRIN_VPMINQD_F64:
	case ARM64_INTRIN_VRECPEQ_F16:
	case ARM64_INTRIN_VRECPEQ_F32:
	case ARM64_INTRIN_VRECPEQ_F64:
	case ARM64_INTRIN_VREV64Q_F16:
	case ARM64_INTRIN_VREV64Q_F32:
	case ARM64_INTRIN_VRND32XQ_F32:
	case ARM64_INTRIN_VRND32XQ_F64:
	case ARM64_INTRIN_VRND32ZQ_F32:
	case ARM64_INTRIN_VRND32ZQ_F64:
	case ARM64_INTRIN_VRND64XQ_F32:
	case ARM64_INTRIN_VRND64XQ_F64:
	case ARM64_INTRIN_VRND64ZQ_F32:
	case ARM64_INTRIN_VRND64ZQ_F64:
	case ARM64_INTRIN_VRNDAQ_F16:
	case ARM64_INTRIN_VRNDAQ_F32:
	case ARM64_INTRIN_VRNDAQ_F64:
	case ARM64_INTRIN_VRNDIQ_F16:
	case ARM64_INTRIN_VRNDIQ_F32:
	case ARM64_INTRIN_VRNDIQ_F64:
	case ARM64_INTRIN_VRNDMQ_F16:
	case ARM64_INTRIN_VRNDMQ_F32:
	case ARM64_INTRIN_VRNDMQ_F64:
	case ARM64_INTRIN_VRNDNQ_F16:
	case ARM64_INTRIN_VRNDNQ_F32:
	case ARM64_INTRIN_VRNDNQ_F64:
	case ARM64_INTRIN_VRNDPQ_F16:
	case ARM64_INTRIN_VRNDPQ_F32:
	case ARM64_INTRIN_VRNDPQ_F64:
	case ARM64_INTRIN_VRNDQ_F16:
	case ARM64_INTRIN_VRNDQ_F32:
	case ARM64_INTRIN_VRNDQ_F64:
	case ARM64_INTRIN_VRNDXQ_F16:
	case ARM64_INTRIN_VRNDXQ_F32:
	case ARM64_INTRIN_VRNDXQ_F64:
	case ARM64_INTRIN_VRSQRTEQ_F16:
	case ARM64_INTRIN_VRSQRTEQ_F32:
	case ARM64_INTRIN_VRSQRTEQ_F64:
	case ARM64_INTRIN_VSQRTQ_F16:
	case ARM64_INTRIN_VSQRTQ_F32:
	case ARM64_INTRIN_VSQRTQ_F64:
		return {NameAndType(Type::FloatType(16))};
	case ARM64_INTRIN_VABDQ_F16:
	case ARM64_INTRIN_VABDQ_F32:
	case ARM64_INTRIN_VABDQ_F64:
	case ARM64_INTRIN_VADDQ_F16:
	case ARM64_INTRIN_VADDQ_F32:
	case ARM64_INTRIN_VADDQ_F64:
	case ARM64_INTRIN_VCADDQ_ROT270_F16:
	case ARM64_INTRIN_VCADDQ_ROT270_F32:
	case ARM64_INTRIN_VCADDQ_ROT270_F64:
	case ARM64_INTRIN_VCADDQ_ROT90_F16:
	case ARM64_INTRIN_VCADDQ_ROT90_F32:
	case ARM64_INTRIN_VCADDQ_ROT90_F64:
	case ARM64_INTRIN_VCAGEQ_F16:
	case ARM64_INTRIN_VCAGEQ_F32:
	case ARM64_INTRIN_VCAGEQ_F64:
	case ARM64_INTRIN_VCAGTQ_F16:
	case ARM64_INTRIN_VCAGTQ_F32:
	case ARM64_INTRIN_VCAGTQ_F64:
	case ARM64_INTRIN_VCALEQ_F16:
	case ARM64_INTRIN_VCALEQ_F32:
	case ARM64_INTRIN_VCALEQ_F64:
	case ARM64_INTRIN_VCALTQ_F16:
	case ARM64_INTRIN_VCALTQ_F32:
	case ARM64_INTRIN_VCALTQ_F64:
	case ARM64_INTRIN_VCEQQ_F16:
	case ARM64_INTRIN_VCEQQ_F32:
	case ARM64_INTRIN_VCEQQ_F64:
	case ARM64_INTRIN_VCGEQ_F16:
	case ARM64_INTRIN_VCGEQ_F32:
	case ARM64_INTRIN_VCGEQ_F64:
	case ARM64_INTRIN_VCGTQ_F16:
	case ARM64_INTRIN_VCGTQ_F32:
	case ARM64_INTRIN_VCGTQ_F64:
	case ARM64_INTRIN_VCLEQ_F16:
	case ARM64_INTRIN_VCLEQ_F32:
	case ARM64_INTRIN_VCLEQ_F64:
	case ARM64_INTRIN_VCLTQ_F16:
	case ARM64_INTRIN_VCLTQ_F32:
	case ARM64_INTRIN_VCLTQ_F64:
	case ARM64_INTRIN_VCVTQ_HIGH_BF16_F32:
	case ARM64_INTRIN_VDIVQ_F16:
	case ARM64_INTRIN_VDIVQ_F32:
	case ARM64_INTRIN_VDIVQ_F64:
	case ARM64_INTRIN_VMAXNMQ_F16:
	case ARM64_INTRIN_VMAXNMQ_F32:
	case ARM64_INTRIN_VMAXNMQ_F64:
	case ARM64_INTRIN_VMAXQ_F16:
	case ARM64_INTRIN_VMAXQ_F32:
	case ARM64_INTRIN_VMAXQ_F64:
	case ARM64_INTRIN_VMINNMQ_F16:
	case ARM64_INTRIN_VMINNMQ_F32:
	case ARM64_INTRIN_VMINNMQ_F64:
	case ARM64_INTRIN_VMINQ_F16:
	case ARM64_INTRIN_VMINQ_F32:
	case ARM64_INTRIN_VMINQ_F64:
	case ARM64_INTRIN_VMULQ_F16:
	case ARM64_INTRIN_VMULQ_F32:
	case ARM64_INTRIN_VMULQ_F64:
	case ARM64_INTRIN_VMULXQ_F16:
	case ARM64_INTRIN_VMULXQ_F32:
	case ARM64_INTRIN_VMULXQ_F64:
	case ARM64_INTRIN_VPADDQ_F16:
	case ARM64_INTRIN_VPADDQ_F32:
	case ARM64_INTRIN_VPADDQ_F64:
	case ARM64_INTRIN_VPMAXNMQ_F16:
	case ARM64_INTRIN_VPMAXNMQ_F32:
	case ARM64_INTRIN_VPMAXNMQ_F64:
	case ARM64_INTRIN_VPMAXQ_F16:
	case ARM64_INTRIN_VPMAXQ_F32:
	case ARM64_INTRIN_VPMAXQ_F64:
	case ARM64_INTRIN_VPMINNMQ_F16:
	case ARM64_INTRIN_VPMINNMQ_F32:
	case ARM64_INTRIN_VPMINNMQ_F64:
	case ARM64_INTRIN_VPMINQ_F16:
	case ARM64_INTRIN_VPMINQ_F32:
	case ARM64_INTRIN_VPMINQ_F64:
	case ARM64_INTRIN_VRECPSQ_F16:
	case ARM64_INTRIN_VRECPSQ_F32:
	case ARM64_INTRIN_VRECPSQ_F64:
	case ARM64_INTRIN_VRSQRTSQ_F16:
	case ARM64_INTRIN_VRSQRTSQ_F32:
	case ARM64_INTRIN_VRSQRTSQ_F64:
	case ARM64_INTRIN_VSUBQ_F16:
	case ARM64_INTRIN_VSUBQ_F32:
	case ARM64_INTRIN_VSUBQ_F64:
	case ARM64_INTRIN_VTRN1Q_F16:
	case ARM64_INTRIN_VTRN1Q_F32:
	case ARM64_INTRIN_VTRN1Q_F64:
	case ARM64_INTRIN_VTRN2Q_F16:
	case ARM64_INTRIN_VTRN2Q_F32:
	case ARM64_INTRIN_VTRN2Q_F64:
	case ARM64_INTRIN_VUZP1Q_F16:
	case ARM64_INTRIN_VUZP1Q_F32:
	case ARM64_INTRIN_VUZP1Q_F64:
	case ARM64_INTRIN_VUZP2Q_F16:
	case ARM64_INTRIN_VUZP2Q_F32:
	case ARM64_INTRIN_VUZP2Q_F64:
	case ARM64_INTRIN_VZIP1Q_F16:
	case ARM64_INTRIN_VZIP1Q_F32:
	case ARM64_INTRIN_VZIP1Q_F64:
	case ARM64_INTRIN_VZIP2Q_F16:
	case ARM64_INTRIN_VZIP2Q_F32:
	case ARM64_INTRIN_VZIP2Q_F64:
		return {NameAndType(Type::FloatType(16)), NameAndType(Type::FloatType(16))};
	case ARM64_INTRIN_VBFDOTQ_F32:
	case ARM64_INTRIN_VBFMLALBQ_F32:
	case ARM64_INTRIN_VBFMLALTQ_F32:
	case ARM64_INTRIN_VBFMMLAQ_F32:
	case ARM64_INTRIN_VCMLAQ_F16:
	case ARM64_INTRIN_VCMLAQ_F32:
	case ARM64_INTRIN_VCMLAQ_F64:
	case ARM64_INTRIN_VCMLAQ_ROT180_F16:
	case ARM64_INTRIN_VCMLAQ_ROT180_F32:
	case ARM64_INTRIN_VCMLAQ_ROT180_F64:
	case ARM64_INTRIN_VCMLAQ_ROT270_F16:
	case ARM64_INTRIN_VCMLAQ_ROT270_F32:
	case ARM64_INTRIN_VCMLAQ_ROT270_F64:
	case ARM64_INTRIN_VCMLAQ_ROT90_F16:
	case ARM64_INTRIN_VCMLAQ_ROT90_F32:
	case ARM64_INTRIN_VCMLAQ_ROT90_F64:
	case ARM64_INTRIN_VFMAQ_F16:
	case ARM64_INTRIN_VFMAQ_F32:
	case ARM64_INTRIN_VFMAQ_F64:
	case ARM64_INTRIN_VFMLALQ_HIGH_F16:
	case ARM64_INTRIN_VFMLALQ_LOW_F16:
	case ARM64_INTRIN_VFMLSLQ_HIGH_F16:
	case ARM64_INTRIN_VFMLSLQ_LOW_F16:
	case ARM64_INTRIN_VFMSQ_F16:
	case ARM64_INTRIN_VFMSQ_F32:
	case ARM64_INTRIN_VFMSQ_F64:
		return {NameAndType(Type::FloatType(16)), NameAndType(Type::FloatType(16)),
		    NameAndType(Type::FloatType(16))};
	case ARM64_INTRIN_VBFDOTQ_LANEQ_F32:
	case ARM64_INTRIN_VBFMLALBQ_LANEQ_F32:
	case ARM64_INTRIN_VBFMLALTQ_LANEQ_F32:
	case ARM64_INTRIN_VCMLAQ_LANEQ_F16:
	case ARM64_INTRIN_VCMLAQ_LANEQ_F32:
	case ARM64_INTRIN_VCMLAQ_ROT180_LANEQ_F16:
	case ARM64_INTRIN_VCMLAQ_ROT180_LANEQ_F32:
	case ARM64_INTRIN_VCMLAQ_ROT270_LANEQ_F16:
	case ARM64_INTRIN_VCMLAQ_ROT270_LANEQ_F32:
	case ARM64_INTRIN_VCMLAQ_ROT90_LANEQ_F16:
	case ARM64_INTRIN_VCMLAQ_ROT90_LANEQ_F32:
	case ARM64_INTRIN_VFMAQ_LANEQ_F16:
	case ARM64_INTRIN_VFMAQ_LANEQ_F32:
	case ARM64_INTRIN_VFMAQ_LANEQ_F64:
	case ARM64_INTRIN_VFMLALQ_LANEQ_HIGH_F16:
	case ARM64_INTRIN_VFMLALQ_LANEQ_LOW_F16:
	case ARM64_INTRIN_VFMLSLQ_LANEQ_HIGH_F16:
	case ARM64_INTRIN_VFMLSLQ_LANEQ_LOW_F16:
	case ARM64_INTRIN_VFMSQ_LANEQ_F16:
	case ARM64_INTRIN_VFMSQ_LANEQ_F32:
	case ARM64_INTRIN_VFMSQ_LANEQ_F64:
		return {NameAndType(Type::FloatType(16)), NameAndType(Type::FloatType(16)),
		    NameAndType(Type::FloatType(16)), NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VFMAQ_N_F16:
	case ARM64_INTRIN_VFMSQ_N_F16:
		return {NameAndType(Type::FloatType(16)), NameAndType(Type::FloatType(16)),
		    NameAndType(Type::FloatType(2))};
	case ARM64_INTRIN_VFMAQ_N_F32:
	case ARM64_INTRIN_VFMSQ_N_F32:
		return {NameAndType(Type::FloatType(16)), NameAndType(Type::FloatType(16)),
		    NameAndType(Type::FloatType(4))};
	case ARM64_INTRIN_VFMAQ_N_F64:
	case ARM64_INTRIN_VFMSQ_N_F64:
		return {NameAndType(Type::FloatType(16)), NameAndType(Type::FloatType(16)),
		    NameAndType(Type::FloatType(8))};
	case ARM64_INTRIN_VBFDOTQ_LANE_F32:
	case ARM64_INTRIN_VBFMLALBQ_LANE_F32:
	case ARM64_INTRIN_VBFMLALTQ_LANE_F32:
	case ARM64_INTRIN_VCMLAQ_LANE_F16:
	case ARM64_INTRIN_VCMLAQ_LANE_F32:
	case ARM64_INTRIN_VCMLAQ_ROT180_LANE_F16:
	case ARM64_INTRIN_VCMLAQ_ROT180_LANE_F32:
	case ARM64_INTRIN_VCMLAQ_ROT270_LANE_F16:
	case ARM64_INTRIN_VCMLAQ_ROT270_LANE_F32:
	case ARM64_INTRIN_VCMLAQ_ROT90_LANE_F16:
	case ARM64_INTRIN_VCMLAQ_ROT90_LANE_F32:
	case ARM64_INTRIN_VFMAQ_LANE_F16:
	case ARM64_INTRIN_VFMAQ_LANE_F32:
	case ARM64_INTRIN_VFMAQ_LANE_F64:
	case ARM64_INTRIN_VFMLALQ_LANE_HIGH_F16:
	case ARM64_INTRIN_VFMLALQ_LANE_LOW_F16:
	case ARM64_INTRIN_VFMLSLQ_LANE_HIGH_F16:
	case ARM64_INTRIN_VFMLSLQ_LANE_LOW_F16:
	case ARM64_INTRIN_VFMSQ_LANE_F16:
	case ARM64_INTRIN_VFMSQ_LANE_F32:
	case ARM64_INTRIN_VFMSQ_LANE_F64:
		return {NameAndType(Type::FloatType(16)), NameAndType(Type::FloatType(16)),
		    NameAndType(Type::FloatType(8)), NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VEXTQ_F16:
	case ARM64_INTRIN_VEXTQ_F32:
	case ARM64_INTRIN_VEXTQ_F64:
	case ARM64_INTRIN_VMULQ_LANEQ_F16:
	case ARM64_INTRIN_VMULQ_LANEQ_F32:
	case ARM64_INTRIN_VMULQ_LANEQ_F64:
	case ARM64_INTRIN_VMULXQ_LANEQ_F16:
	case ARM64_INTRIN_VMULXQ_LANEQ_F32:
	case ARM64_INTRIN_VMULXQ_LANEQ_F64:
		return {NameAndType(Type::FloatType(16)), NameAndType(Type::FloatType(16)),
		    NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VMULQ_N_F16:
	case ARM64_INTRIN_VMULXQ_N_F16:
		return {NameAndType(Type::FloatType(16)), NameAndType(Type::FloatType(2))};
	case ARM64_INTRIN_VMULQ_N_F32:
		return {NameAndType(Type::FloatType(16)), NameAndType(Type::FloatType(4))};
	case ARM64_INTRIN_VMULQ_N_F64:
		return {NameAndType(Type::FloatType(16)), NameAndType(Type::FloatType(8))};
	case ARM64_INTRIN_VMULQ_LANE_F16:
	case ARM64_INTRIN_VMULQ_LANE_F32:
	case ARM64_INTRIN_VMULQ_LANE_F64:
	case ARM64_INTRIN_VMULXQ_LANE_F16:
	case ARM64_INTRIN_VMULXQ_LANE_F32:
	case ARM64_INTRIN_VMULXQ_LANE_F64:
		return {NameAndType(Type::FloatType(16)), NameAndType(Type::FloatType(8)),
		    NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VCVTQ_N_S16_F16:
	case ARM64_INTRIN_VCVTQ_N_S32_F32:
	case ARM64_INTRIN_VCVTQ_N_S64_F64:
	case ARM64_INTRIN_VCVTQ_N_U16_F16:
	case ARM64_INTRIN_VCVTQ_N_U32_F32:
	case ARM64_INTRIN_VCVTQ_N_U64_F64:
	case ARM64_INTRIN_VDUP_LANEQ_BF16:
	case ARM64_INTRIN_VDUP_LANEQ_F16:
	case ARM64_INTRIN_VDUP_LANEQ_F32:
	case ARM64_INTRIN_VDUP_LANEQ_F64:
	case ARM64_INTRIN_VDUPD_LANEQ_F64:
	case ARM64_INTRIN_VDUPH_LANEQ_BF16:
	case ARM64_INTRIN_VDUPH_LANEQ_F16:
	case ARM64_INTRIN_VDUPQ_LANEQ_BF16:
	case ARM64_INTRIN_VDUPQ_LANEQ_F16:
	case ARM64_INTRIN_VDUPQ_LANEQ_F32:
	case ARM64_INTRIN_VDUPQ_LANEQ_F64:
	case ARM64_INTRIN_VDUPS_LANEQ_F32:
	case ARM64_INTRIN_VGETQ_LANE_BF16:
	case ARM64_INTRIN_VGETQ_LANE_F16:
	case ARM64_INTRIN_VGETQ_LANE_F32:
	case ARM64_INTRIN_VGETQ_LANE_F64:
		return {NameAndType(Type::FloatType(16)), NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VABSH_F16:
	case ARM64_INTRIN_VCEQZH_F16:
	case ARM64_INTRIN_VCGEZH_F16:
	case ARM64_INTRIN_VCGTZH_F16:
	case ARM64_INTRIN_VCLEZH_F16:
	case ARM64_INTRIN_VCLTZH_F16:
	case ARM64_INTRIN_VCVTAH_F32_BF16:
	case ARM64_INTRIN_VCVTAH_S16_F16:
	case ARM64_INTRIN_VCVTAH_S32_F16:
	case ARM64_INTRIN_VCVTAH_S64_F16:
	case ARM64_INTRIN_VCVTAH_U16_F16:
	case ARM64_INTRIN_VCVTAH_U32_F16:
	case ARM64_INTRIN_VCVTAH_U64_F16:
	case ARM64_INTRIN_VCVTH_S16_F16:
	case ARM64_INTRIN_VCVTH_S32_F16:
	case ARM64_INTRIN_VCVTH_S64_F16:
	case ARM64_INTRIN_VCVTH_U16_F16:
	case ARM64_INTRIN_VCVTH_U32_F16:
	case ARM64_INTRIN_VCVTH_U64_F16:
	case ARM64_INTRIN_VCVTMH_S16_F16:
	case ARM64_INTRIN_VCVTMH_S32_F16:
	case ARM64_INTRIN_VCVTMH_S64_F16:
	case ARM64_INTRIN_VCVTMH_U16_F16:
	case ARM64_INTRIN_VCVTMH_U32_F16:
	case ARM64_INTRIN_VCVTMH_U64_F16:
	case ARM64_INTRIN_VCVTNH_S16_F16:
	case ARM64_INTRIN_VCVTNH_S32_F16:
	case ARM64_INTRIN_VCVTNH_S64_F16:
	case ARM64_INTRIN_VCVTNH_U16_F16:
	case ARM64_INTRIN_VCVTNH_U32_F16:
	case ARM64_INTRIN_VCVTNH_U64_F16:
	case ARM64_INTRIN_VCVTPH_S16_F16:
	case ARM64_INTRIN_VCVTPH_S32_F16:
	case ARM64_INTRIN_VCVTPH_S64_F16:
	case ARM64_INTRIN_VCVTPH_U16_F16:
	case ARM64_INTRIN_VCVTPH_U32_F16:
	case ARM64_INTRIN_VCVTPH_U64_F16:
	case ARM64_INTRIN_VDUP_N_BF16:
	case ARM64_INTRIN_VDUP_N_F16:
	case ARM64_INTRIN_VDUPQ_N_BF16:
	case ARM64_INTRIN_VDUPQ_N_F16:
	case ARM64_INTRIN_VMOV_N_F16:
	case ARM64_INTRIN_VMOVQ_N_F16:
	case ARM64_INTRIN_VNEGH_F16:
	case ARM64_INTRIN_VRECPEH_F16:
	case ARM64_INTRIN_VRECPXH_F16:
	case ARM64_INTRIN_VRNDAH_F16:
	case ARM64_INTRIN_VRNDH_F16:
	case ARM64_INTRIN_VRNDIH_F16:
	case ARM64_INTRIN_VRNDMH_F16:
	case ARM64_INTRIN_VRNDNH_F16:
	case ARM64_INTRIN_VRNDPH_F16:
	case ARM64_INTRIN_VRNDXH_F16:
	case ARM64_INTRIN_VRSQRTEH_F16:
	case ARM64_INTRIN_VSQRTH_F16:
		return {NameAndType(Type::FloatType(2))};
	case ARM64_INTRIN_VMULH_LANEQ_F16:
	case ARM64_INTRIN_VMULXH_LANEQ_F16:
	case ARM64_INTRIN_VSETQ_LANE_BF16:
	case ARM64_INTRIN_VSETQ_LANE_F16:
		return {NameAndType(Type::FloatType(2)), NameAndType(Type::FloatType(16)),
		    NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VABDH_F16:
	case ARM64_INTRIN_VADDH_F16:
	case ARM64_INTRIN_VCAGEH_F16:
	case ARM64_INTRIN_VCAGTH_F16:
	case ARM64_INTRIN_VCALEH_F16:
	case ARM64_INTRIN_VCALTH_F16:
	case ARM64_INTRIN_VCEQH_F16:
	case ARM64_INTRIN_VCGEH_F16:
	case ARM64_INTRIN_VCGTH_F16:
	case ARM64_INTRIN_VCLEH_F16:
	case ARM64_INTRIN_VCLTH_F16:
	case ARM64_INTRIN_VDIVH_F16:
	case ARM64_INTRIN_VMAXH_F16:
	case ARM64_INTRIN_VMAXNMH_F16:
	case ARM64_INTRIN_VMINH_F16:
	case ARM64_INTRIN_VMINNMH_F16:
	case ARM64_INTRIN_VMULH_F16:
	case ARM64_INTRIN_VMULXH_F16:
	case ARM64_INTRIN_VRECPSH_F16:
	case ARM64_INTRIN_VRSQRTSH_F16:
	case ARM64_INTRIN_VSUBH_F16:
		return {NameAndType(Type::FloatType(2)), NameAndType(Type::FloatType(2))};
	case ARM64_INTRIN_VFMAH_LANEQ_F16:
	case ARM64_INTRIN_VFMSH_LANEQ_F16:
		return {NameAndType(Type::FloatType(2)), NameAndType(Type::FloatType(2)),
		    NameAndType(Type::FloatType(16)), NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VFMAH_F16:
	case ARM64_INTRIN_VFMSH_F16:
		return {NameAndType(Type::FloatType(2)), NameAndType(Type::FloatType(2)),
		    NameAndType(Type::FloatType(2))};
	case ARM64_INTRIN_VFMAH_LANE_F16:
	case ARM64_INTRIN_VFMSH_LANE_F16:
		return {NameAndType(Type::FloatType(2)), NameAndType(Type::FloatType(2)),
		    NameAndType(Type::FloatType(8)), NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VMULH_LANE_F16:
	case ARM64_INTRIN_VMULXH_LANE_F16:
	case ARM64_INTRIN_VSET_LANE_BF16:
	case ARM64_INTRIN_VSET_LANE_F16:
		return {NameAndType(Type::FloatType(2)), NameAndType(Type::FloatType(8)),
		    NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VCVTH_N_S16_F16:
	case ARM64_INTRIN_VCVTH_N_S32_F16:
	case ARM64_INTRIN_VCVTH_N_S64_F16:
	case ARM64_INTRIN_VCVTH_N_U16_F16:
	case ARM64_INTRIN_VCVTH_N_U32_F16:
	case ARM64_INTRIN_VCVTH_N_U64_F16:
		return {NameAndType(Type::FloatType(2)), NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VCEQZS_F32:
	case ARM64_INTRIN_VCGEZS_F32:
	case ARM64_INTRIN_VCGTZS_F32:
	case ARM64_INTRIN_VCLEZS_F32:
	case ARM64_INTRIN_VCLTZS_F32:
	case ARM64_INTRIN_VCVTAS_S32_F32:
	case ARM64_INTRIN_VCVTAS_U32_F32:
	case ARM64_INTRIN_VCVTH_BF16_F32:
	case ARM64_INTRIN_VCVTMS_S32_F32:
	case ARM64_INTRIN_VCVTMS_U32_F32:
	case ARM64_INTRIN_VCVTNS_S32_F32:
	case ARM64_INTRIN_VCVTNS_U32_F32:
	case ARM64_INTRIN_VCVTPS_S32_F32:
	case ARM64_INTRIN_VCVTPS_U32_F32:
	case ARM64_INTRIN_VCVTS_S32_F32:
	case ARM64_INTRIN_VCVTS_U32_F32:
	case ARM64_INTRIN_VDUP_N_F32:
	case ARM64_INTRIN_VDUPQ_N_F32:
	case ARM64_INTRIN_VMOV_N_F32:
	case ARM64_INTRIN_VMOVQ_N_F32:
	case ARM64_INTRIN_VRECPES_F32:
	case ARM64_INTRIN_VRECPXS_F32:
	case ARM64_INTRIN_VRNDNS_F32:
	case ARM64_INTRIN_VRSQRTES_F32:
		return {NameAndType(Type::FloatType(4))};
	case ARM64_INTRIN_VMULS_LANEQ_F32:
	case ARM64_INTRIN_VMULXS_LANEQ_F32:
	case ARM64_INTRIN_VSETQ_LANE_F32:
		return {NameAndType(Type::FloatType(4)), NameAndType(Type::FloatType(16)),
		    NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VABDS_F32:
	case ARM64_INTRIN_VCAGES_F32:
	case ARM64_INTRIN_VCAGTS_F32:
	case ARM64_INTRIN_VCALES_F32:
	case ARM64_INTRIN_VCALTS_F32:
	case ARM64_INTRIN_VCEQS_F32:
	case ARM64_INTRIN_VCGES_F32:
	case ARM64_INTRIN_VCGTS_F32:
	case ARM64_INTRIN_VCLES_F32:
	case ARM64_INTRIN_VCLTS_F32:
	case ARM64_INTRIN_VMULXS_F32:
	case ARM64_INTRIN_VRECPSS_F32:
	case ARM64_INTRIN_VRSQRTSS_F32:
		return {NameAndType(Type::FloatType(4)), NameAndType(Type::FloatType(4))};
	case ARM64_INTRIN_VFMAS_LANEQ_F32:
	case ARM64_INTRIN_VFMSS_LANEQ_F32:
		return {NameAndType(Type::FloatType(4)), NameAndType(Type::FloatType(4)),
		    NameAndType(Type::FloatType(16)), NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VFMAS_LANE_F32:
	case ARM64_INTRIN_VFMSS_LANE_F32:
		return {NameAndType(Type::FloatType(4)), NameAndType(Type::FloatType(4)),
		    NameAndType(Type::FloatType(8)), NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VMULS_LANE_F32:
	case ARM64_INTRIN_VMULXS_LANE_F32:
	case ARM64_INTRIN_VSET_LANE_F32:
		return {NameAndType(Type::FloatType(4)), NameAndType(Type::FloatType(8)),
		    NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VCVTS_N_S32_F32:
	case ARM64_INTRIN_VCVTS_N_U32_F32:
		return {NameAndType(Type::FloatType(4)), NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VABS_F16:
	case ARM64_INTRIN_VABS_F32:
	case ARM64_INTRIN_VABS_F64:
	case ARM64_INTRIN_VADDV_F32:
	case ARM64_INTRIN_VCEQZ_F16:
	case ARM64_INTRIN_VCEQZ_F32:
	case ARM64_INTRIN_VCEQZ_F64:
	case ARM64_INTRIN_VCEQZD_F64:
	case ARM64_INTRIN_VCGEZ_F16:
	case ARM64_INTRIN_VCGEZ_F32:
	case ARM64_INTRIN_VCGEZ_F64:
	case ARM64_INTRIN_VCGEZD_F64:
	case ARM64_INTRIN_VCGTZ_F16:
	case ARM64_INTRIN_VCGTZ_F32:
	case ARM64_INTRIN_VCGTZ_F64:
	case ARM64_INTRIN_VCGTZD_F64:
	case ARM64_INTRIN_VCLEZ_F16:
	case ARM64_INTRIN_VCLEZ_F32:
	case ARM64_INTRIN_VCLEZ_F64:
	case ARM64_INTRIN_VCLEZD_F64:
	case ARM64_INTRIN_VCLTZ_F16:
	case ARM64_INTRIN_VCLTZ_F32:
	case ARM64_INTRIN_VCLTZ_F64:
	case ARM64_INTRIN_VCLTZD_F64:
	case ARM64_INTRIN_VCVT_F32_BF16:
	case ARM64_INTRIN_VCVT_F32_F16:
	case ARM64_INTRIN_VCVT_F64_F32:
	case ARM64_INTRIN_VCVT_S16_F16:
	case ARM64_INTRIN_VCVT_S32_F32:
	case ARM64_INTRIN_VCVT_S64_F64:
	case ARM64_INTRIN_VCVT_U16_F16:
	case ARM64_INTRIN_VCVT_U32_F32:
	case ARM64_INTRIN_VCVT_U64_F64:
	case ARM64_INTRIN_VCVTA_S16_F16:
	case ARM64_INTRIN_VCVTA_S32_F32:
	case ARM64_INTRIN_VCVTA_S64_F64:
	case ARM64_INTRIN_VCVTA_U16_F16:
	case ARM64_INTRIN_VCVTA_U32_F32:
	case ARM64_INTRIN_VCVTA_U64_F64:
	case ARM64_INTRIN_VCVTAD_S64_F64:
	case ARM64_INTRIN_VCVTAD_U64_F64:
	case ARM64_INTRIN_VCVTD_S64_F64:
	case ARM64_INTRIN_VCVTD_U64_F64:
	case ARM64_INTRIN_VCVTM_S16_F16:
	case ARM64_INTRIN_VCVTM_S32_F32:
	case ARM64_INTRIN_VCVTM_S64_F64:
	case ARM64_INTRIN_VCVTM_U16_F16:
	case ARM64_INTRIN_VCVTM_U32_F32:
	case ARM64_INTRIN_VCVTM_U64_F64:
	case ARM64_INTRIN_VCVTMD_S64_F64:
	case ARM64_INTRIN_VCVTMD_U64_F64:
	case ARM64_INTRIN_VCVTN_S16_F16:
	case ARM64_INTRIN_VCVTN_S32_F32:
	case ARM64_INTRIN_VCVTN_S64_F64:
	case ARM64_INTRIN_VCVTN_U16_F16:
	case ARM64_INTRIN_VCVTN_U32_F32:
	case ARM64_INTRIN_VCVTN_U64_F64:
	case ARM64_INTRIN_VCVTND_S64_F64:
	case ARM64_INTRIN_VCVTND_U64_F64:
	case ARM64_INTRIN_VCVTP_S16_F16:
	case ARM64_INTRIN_VCVTP_S32_F32:
	case ARM64_INTRIN_VCVTP_S64_F64:
	case ARM64_INTRIN_VCVTP_U16_F16:
	case ARM64_INTRIN_VCVTP_U32_F32:
	case ARM64_INTRIN_VCVTP_U64_F64:
	case ARM64_INTRIN_VCVTPD_S64_F64:
	case ARM64_INTRIN_VCVTPD_U64_F64:
	case ARM64_INTRIN_VCVTXD_F32_F64:
	case ARM64_INTRIN_VDUP_N_F64:
	case ARM64_INTRIN_VDUPQ_N_F64:
	case ARM64_INTRIN_VMAXNMV_F16:
	case ARM64_INTRIN_VMAXNMV_F32:
	case ARM64_INTRIN_VMAXV_F16:
	case ARM64_INTRIN_VMAXV_F32:
	case ARM64_INTRIN_VMINNMV_F16:
	case ARM64_INTRIN_VMINNMV_F32:
	case ARM64_INTRIN_VMINV_F16:
	case ARM64_INTRIN_VMINV_F32:
	case ARM64_INTRIN_VMOV_N_F64:
	case ARM64_INTRIN_VMOVQ_N_F64:
	case ARM64_INTRIN_VNEG_F16:
	case ARM64_INTRIN_VNEG_F32:
	case ARM64_INTRIN_VNEG_F64:
	case ARM64_INTRIN_VPADDS_F32:
	case ARM64_INTRIN_VPMAXNMS_F32:
	case ARM64_INTRIN_VPMAXS_F32:
	case ARM64_INTRIN_VPMINNMS_F32:
	case ARM64_INTRIN_VPMINS_F32:
	case ARM64_INTRIN_VRECPE_F16:
	case ARM64_INTRIN_VRECPE_F32:
	case ARM64_INTRIN_VRECPE_F64:
	case ARM64_INTRIN_VRECPED_F64:
	case ARM64_INTRIN_VRECPXD_F64:
	case ARM64_INTRIN_VREV64_F16:
	case ARM64_INTRIN_VREV64_F32:
	case ARM64_INTRIN_VRND32X_F32:
	case ARM64_INTRIN_VRND32X_F64:
	case ARM64_INTRIN_VRND32Z_F32:
	case ARM64_INTRIN_VRND32Z_F64:
	case ARM64_INTRIN_VRND64X_F32:
	case ARM64_INTRIN_VRND64X_F64:
	case ARM64_INTRIN_VRND64Z_F32:
	case ARM64_INTRIN_VRND64Z_F64:
	case ARM64_INTRIN_VRND_F16:
	case ARM64_INTRIN_VRND_F32:
	case ARM64_INTRIN_VRND_F64:
	case ARM64_INTRIN_VRNDA_F16:
	case ARM64_INTRIN_VRNDA_F32:
	case ARM64_INTRIN_VRNDA_F64:
	case ARM64_INTRIN_VRNDI_F16:
	case ARM64_INTRIN_VRNDI_F32:
	case ARM64_INTRIN_VRNDI_F64:
	case ARM64_INTRIN_VRNDM_F16:
	case ARM64_INTRIN_VRNDM_F32:
	case ARM64_INTRIN_VRNDM_F64:
	case ARM64_INTRIN_VRNDN_F16:
	case ARM64_INTRIN_VRNDN_F32:
	case ARM64_INTRIN_VRNDN_F64:
	case ARM64_INTRIN_VRNDP_F16:
	case ARM64_INTRIN_VRNDP_F32:
	case ARM64_INTRIN_VRNDP_F64:
	case ARM64_INTRIN_VRNDX_F16:
	case ARM64_INTRIN_VRNDX_F32:
	case ARM64_INTRIN_VRNDX_F64:
	case ARM64_INTRIN_VRSQRTE_F16:
	case ARM64_INTRIN_VRSQRTE_F32:
	case ARM64_INTRIN_VRSQRTE_F64:
	case ARM64_INTRIN_VRSQRTED_F64:
	case ARM64_INTRIN_VSQRT_F16:
	case ARM64_INTRIN_VSQRT_F32:
	case ARM64_INTRIN_VSQRT_F64:
		return {NameAndType(Type::FloatType(8))};
	case ARM64_INTRIN_VCVT_HIGH_F16_F32:
	case ARM64_INTRIN_VCVT_HIGH_F32_F64:
	case ARM64_INTRIN_VCVTX_HIGH_F32_F64:
		return {NameAndType(Type::FloatType(8)), NameAndType(Type::FloatType(16))};
	case ARM64_INTRIN_VMUL_LANEQ_F16:
	case ARM64_INTRIN_VMUL_LANEQ_F32:
	case ARM64_INTRIN_VMUL_LANEQ_F64:
	case ARM64_INTRIN_VMULD_LANEQ_F64:
	case ARM64_INTRIN_VMULX_LANEQ_F16:
	case ARM64_INTRIN_VMULX_LANEQ_F32:
	case ARM64_INTRIN_VMULX_LANEQ_F64:
	case ARM64_INTRIN_VMULXD_LANEQ_F64:
	case ARM64_INTRIN_VSETQ_LANE_F64:
		return {NameAndType(Type::FloatType(8)), NameAndType(Type::FloatType(16)),
		    NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VMUL_N_F16:
	case ARM64_INTRIN_VMULX_N_F16:
		return {NameAndType(Type::FloatType(8)), NameAndType(Type::FloatType(2))};
	case ARM64_INTRIN_VMUL_N_F32:
		return {NameAndType(Type::FloatType(8)), NameAndType(Type::FloatType(4))};
	case ARM64_INTRIN_VABD_F16:
	case ARM64_INTRIN_VABD_F32:
	case ARM64_INTRIN_VABD_F64:
	case ARM64_INTRIN_VABDD_F64:
	case ARM64_INTRIN_VADD_F16:
	case ARM64_INTRIN_VADD_F32:
	case ARM64_INTRIN_VADD_F64:
	case ARM64_INTRIN_VCADD_ROT270_F16:
	case ARM64_INTRIN_VCADD_ROT270_F32:
	case ARM64_INTRIN_VCADD_ROT90_F16:
	case ARM64_INTRIN_VCADD_ROT90_F32:
	case ARM64_INTRIN_VCAGE_F16:
	case ARM64_INTRIN_VCAGE_F32:
	case ARM64_INTRIN_VCAGE_F64:
	case ARM64_INTRIN_VCAGED_F64:
	case ARM64_INTRIN_VCAGT_F16:
	case ARM64_INTRIN_VCAGT_F32:
	case ARM64_INTRIN_VCAGT_F64:
	case ARM64_INTRIN_VCAGTD_F64:
	case ARM64_INTRIN_VCALE_F16:
	case ARM64_INTRIN_VCALE_F32:
	case ARM64_INTRIN_VCALE_F64:
	case ARM64_INTRIN_VCALED_F64:
	case ARM64_INTRIN_VCALT_F16:
	case ARM64_INTRIN_VCALT_F32:
	case ARM64_INTRIN_VCALT_F64:
	case ARM64_INTRIN_VCALTD_F64:
	case ARM64_INTRIN_VCEQ_F16:
	case ARM64_INTRIN_VCEQ_F32:
	case ARM64_INTRIN_VCEQ_F64:
	case ARM64_INTRIN_VCEQD_F64:
	case ARM64_INTRIN_VCGE_F16:
	case ARM64_INTRIN_VCGE_F32:
	case ARM64_INTRIN_VCGE_F64:
	case ARM64_INTRIN_VCGED_F64:
	case ARM64_INTRIN_VCGT_F16:
	case ARM64_INTRIN_VCGT_F32:
	case ARM64_INTRIN_VCGT_F64:
	case ARM64_INTRIN_VCGTD_F64:
	case ARM64_INTRIN_VCLE_F16:
	case ARM64_INTRIN_VCLE_F32:
	case ARM64_INTRIN_VCLE_F64:
	case ARM64_INTRIN_VCLED_F64:
	case ARM64_INTRIN_VCLT_F16:
	case ARM64_INTRIN_VCLT_F32:
	case ARM64_INTRIN_VCLT_F64:
	case ARM64_INTRIN_VCLTD_F64:
	case ARM64_INTRIN_VDIV_F16:
	case ARM64_INTRIN_VDIV_F32:
	case ARM64_INTRIN_VDIV_F64:
	case ARM64_INTRIN_VMAX_F16:
	case ARM64_INTRIN_VMAX_F32:
	case ARM64_INTRIN_VMAX_F64:
	case ARM64_INTRIN_VMAXNM_F16:
	case ARM64_INTRIN_VMAXNM_F32:
	case ARM64_INTRIN_VMAXNM_F64:
	case ARM64_INTRIN_VMIN_F16:
	case ARM64_INTRIN_VMIN_F32:
	case ARM64_INTRIN_VMIN_F64:
	case ARM64_INTRIN_VMINNM_F16:
	case ARM64_INTRIN_VMINNM_F32:
	case ARM64_INTRIN_VMINNM_F64:
	case ARM64_INTRIN_VMUL_F16:
	case ARM64_INTRIN_VMUL_F32:
	case ARM64_INTRIN_VMUL_F64:
	case ARM64_INTRIN_VMUL_N_F64:
	case ARM64_INTRIN_VMULX_F16:
	case ARM64_INTRIN_VMULX_F32:
	case ARM64_INTRIN_VMULX_F64:
	case ARM64_INTRIN_VMULXD_F64:
	case ARM64_INTRIN_VPADD_F16:
	case ARM64_INTRIN_VPADD_F32:
	case ARM64_INTRIN_VPMAX_F16:
	case ARM64_INTRIN_VPMAX_F32:
	case ARM64_INTRIN_VPMAXNM_F16:
	case ARM64_INTRIN_VPMAXNM_F32:
	case ARM64_INTRIN_VPMIN_F16:
	case ARM64_INTRIN_VPMIN_F32:
	case ARM64_INTRIN_VPMINNM_F16:
	case ARM64_INTRIN_VPMINNM_F32:
	case ARM64_INTRIN_VRECPS_F16:
	case ARM64_INTRIN_VRECPS_F32:
	case ARM64_INTRIN_VRECPS_F64:
	case ARM64_INTRIN_VRECPSD_F64:
	case ARM64_INTRIN_VRSQRTS_F16:
	case ARM64_INTRIN_VRSQRTS_F32:
	case ARM64_INTRIN_VRSQRTS_F64:
	case ARM64_INTRIN_VRSQRTSD_F64:
	case ARM64_INTRIN_VSUB_F16:
	case ARM64_INTRIN_VSUB_F32:
	case ARM64_INTRIN_VSUB_F64:
	case ARM64_INTRIN_VTRN1_F16:
	case ARM64_INTRIN_VTRN1_F32:
	case ARM64_INTRIN_VTRN2_F16:
	case ARM64_INTRIN_VTRN2_F32:
	case ARM64_INTRIN_VUZP1_F16:
	case ARM64_INTRIN_VUZP1_F32:
	case ARM64_INTRIN_VUZP2_F16:
	case ARM64_INTRIN_VUZP2_F32:
	case ARM64_INTRIN_VZIP1_F16:
	case ARM64_INTRIN_VZIP1_F32:
	case ARM64_INTRIN_VZIP2_F16:
	case ARM64_INTRIN_VZIP2_F32:
		return {NameAndType(Type::FloatType(8)), NameAndType(Type::FloatType(8))};
	case ARM64_INTRIN_VBFDOT_LANEQ_F32:
	case ARM64_INTRIN_VCMLA_LANEQ_F16:
	case ARM64_INTRIN_VCMLA_ROT180_LANEQ_F16:
	case ARM64_INTRIN_VCMLA_ROT270_LANEQ_F16:
	case ARM64_INTRIN_VCMLA_ROT90_LANEQ_F16:
	case ARM64_INTRIN_VFMA_LANEQ_F16:
	case ARM64_INTRIN_VFMA_LANEQ_F32:
	case ARM64_INTRIN_VFMA_LANEQ_F64:
	case ARM64_INTRIN_VFMAD_LANEQ_F64:
	case ARM64_INTRIN_VFMLAL_LANEQ_HIGH_F16:
	case ARM64_INTRIN_VFMLAL_LANEQ_LOW_F16:
	case ARM64_INTRIN_VFMLSL_LANEQ_HIGH_F16:
	case ARM64_INTRIN_VFMLSL_LANEQ_LOW_F16:
	case ARM64_INTRIN_VFMS_LANEQ_F16:
	case ARM64_INTRIN_VFMS_LANEQ_F32:
	case ARM64_INTRIN_VFMS_LANEQ_F64:
	case ARM64_INTRIN_VFMSD_LANEQ_F64:
		return {NameAndType(Type::FloatType(8)), NameAndType(Type::FloatType(8)),
		    NameAndType(Type::FloatType(16)), NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VFMA_N_F16:
	case ARM64_INTRIN_VFMS_N_F16:
		return {NameAndType(Type::FloatType(8)), NameAndType(Type::FloatType(8)),
		    NameAndType(Type::FloatType(2))};
	case ARM64_INTRIN_VFMA_N_F32:
	case ARM64_INTRIN_VFMS_N_F32:
		return {NameAndType(Type::FloatType(8)), NameAndType(Type::FloatType(8)),
		    NameAndType(Type::FloatType(4))};
	case ARM64_INTRIN_VBFDOT_F32:
	case ARM64_INTRIN_VCMLA_F16:
	case ARM64_INTRIN_VCMLA_F32:
	case ARM64_INTRIN_VCMLA_ROT180_F16:
	case ARM64_INTRIN_VCMLA_ROT180_F32:
	case ARM64_INTRIN_VCMLA_ROT270_F16:
	case ARM64_INTRIN_VCMLA_ROT270_F32:
	case ARM64_INTRIN_VCMLA_ROT90_F16:
	case ARM64_INTRIN_VCMLA_ROT90_F32:
	case ARM64_INTRIN_VFMA_F16:
	case ARM64_INTRIN_VFMA_F32:
	case ARM64_INTRIN_VFMA_F64:
	case ARM64_INTRIN_VFMA_N_F64:
	case ARM64_INTRIN_VFMLAL_HIGH_F16:
	case ARM64_INTRIN_VFMLAL_LOW_F16:
	case ARM64_INTRIN_VFMLSL_HIGH_F16:
	case ARM64_INTRIN_VFMLSL_LOW_F16:
	case ARM64_INTRIN_VFMS_F16:
	case ARM64_INTRIN_VFMS_F32:
	case ARM64_INTRIN_VFMS_F64:
	case ARM64_INTRIN_VFMS_N_F64:
		return {NameAndType(Type::FloatType(8)), NameAndType(Type::FloatType(8)),
		    NameAndType(Type::FloatType(8))};
	case ARM64_INTRIN_VBFDOT_LANE_F32:
	case ARM64_INTRIN_VCMLA_LANE_F16:
	case ARM64_INTRIN_VCMLA_LANE_F32:
	case ARM64_INTRIN_VCMLA_ROT180_LANE_F16:
	case ARM64_INTRIN_VCMLA_ROT180_LANE_F32:
	case ARM64_INTRIN_VCMLA_ROT270_LANE_F16:
	case ARM64_INTRIN_VCMLA_ROT270_LANE_F32:
	case ARM64_INTRIN_VCMLA_ROT90_LANE_F16:
	case ARM64_INTRIN_VCMLA_ROT90_LANE_F32:
	case ARM64_INTRIN_VFMA_LANE_F16:
	case ARM64_INTRIN_VFMA_LANE_F32:
	case ARM64_INTRIN_VFMA_LANE_F64:
	case ARM64_INTRIN_VFMAD_LANE_F64:
	case ARM64_INTRIN_VFMLAL_LANE_HIGH_F16:
	case ARM64_INTRIN_VFMLAL_LANE_LOW_F16:
	case ARM64_INTRIN_VFMLSL_LANE_HIGH_F16:
	case ARM64_INTRIN_VFMLSL_LANE_LOW_F16:
	case ARM64_INTRIN_VFMS_LANE_F16:
	case ARM64_INTRIN_VFMS_LANE_F32:
	case ARM64_INTRIN_VFMS_LANE_F64:
	case ARM64_INTRIN_VFMSD_LANE_F64:
		return {NameAndType(Type::FloatType(8)), NameAndType(Type::FloatType(8)),
		    NameAndType(Type::FloatType(8)), NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VEXT_F16:
	case ARM64_INTRIN_VEXT_F32:
	case ARM64_INTRIN_VEXT_F64:
	case ARM64_INTRIN_VMUL_LANE_F16:
	case ARM64_INTRIN_VMUL_LANE_F32:
	case ARM64_INTRIN_VMUL_LANE_F64:
	case ARM64_INTRIN_VMULD_LANE_F64:
	case ARM64_INTRIN_VMULX_LANE_F16:
	case ARM64_INTRIN_VMULX_LANE_F32:
	case ARM64_INTRIN_VMULX_LANE_F64:
	case ARM64_INTRIN_VMULXD_LANE_F64:
	case ARM64_INTRIN_VSET_LANE_F64:
		return {NameAndType(Type::FloatType(8)), NameAndType(Type::FloatType(8)),
		    NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VCVT_N_S16_F16:
	case ARM64_INTRIN_VCVT_N_S32_F32:
	case ARM64_INTRIN_VCVT_N_S64_F64:
	case ARM64_INTRIN_VCVT_N_U16_F16:
	case ARM64_INTRIN_VCVT_N_U32_F32:
	case ARM64_INTRIN_VCVT_N_U64_F64:
	case ARM64_INTRIN_VCVTD_N_S64_F64:
	case ARM64_INTRIN_VCVTD_N_U64_F64:
	case ARM64_INTRIN_VDUP_LANE_BF16:
	case ARM64_INTRIN_VDUP_LANE_F16:
	case ARM64_INTRIN_VDUP_LANE_F32:
	case ARM64_INTRIN_VDUP_LANE_F64:
	case ARM64_INTRIN_VDUPD_LANE_F64:
	case ARM64_INTRIN_VDUPH_LANE_BF16:
	case ARM64_INTRIN_VDUPH_LANE_F16:
	case ARM64_INTRIN_VDUPQ_LANE_BF16:
	case ARM64_INTRIN_VDUPQ_LANE_F16:
	case ARM64_INTRIN_VDUPQ_LANE_F32:
	case ARM64_INTRIN_VDUPQ_LANE_F64:
	case ARM64_INTRIN_VDUPS_LANE_F32:
	case ARM64_INTRIN_VGET_LANE_BF16:
	case ARM64_INTRIN_VGET_LANE_F16:
	case ARM64_INTRIN_VGET_LANE_F32:
	case ARM64_INTRIN_VGET_LANE_F64:
		return {NameAndType(Type::FloatType(8)), NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VDUP_N_P8:
	case ARM64_INTRIN_VDUP_N_S8:
	case ARM64_INTRIN_VDUP_N_U8:
	case ARM64_INTRIN_VDUPQ_N_P8:
	case ARM64_INTRIN_VDUPQ_N_S8:
	case ARM64_INTRIN_VDUPQ_N_U8:
	case ARM64_INTRIN_VMOV_N_P8:
	case ARM64_INTRIN_VMOV_N_S8:
	case ARM64_INTRIN_VMOV_N_U8:
	case ARM64_INTRIN_VMOVQ_N_P8:
	case ARM64_INTRIN_VMOVQ_N_S8:
	case ARM64_INTRIN_VMOVQ_N_U8:
	case ARM64_INTRIN_VQABSB_S8:
	case ARM64_INTRIN_VQNEGB_S8:
		return {NameAndType(Type::IntegerType(1, false))};
	case ARM64_INTRIN_VQADDB_S8:
	case ARM64_INTRIN_VQADDB_U8:
	case ARM64_INTRIN_VQRSHLB_S8:
	case ARM64_INTRIN_VQRSHLB_U8:
	case ARM64_INTRIN_VQSHLB_S8:
	case ARM64_INTRIN_VQSHLB_U8:
	case ARM64_INTRIN_VQSUBB_S8:
	case ARM64_INTRIN_VQSUBB_U8:
	case ARM64_INTRIN_VSQADDB_U8:
	case ARM64_INTRIN_VUQADDB_S8:
		return {NameAndType(Type::IntegerType(1, false)), NameAndType(Type::IntegerType(1, false))};
	case ARM64_INTRIN_VSETQ_LANE_P8:
	case ARM64_INTRIN_VSETQ_LANE_S8:
	case ARM64_INTRIN_VSETQ_LANE_U8:
		return {NameAndType(Type::IntegerType(1, false)), NameAndType(Type::IntegerType(16, false)),
		    NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VQSHLB_N_S8:
	case ARM64_INTRIN_VQSHLB_N_U8:
	case ARM64_INTRIN_VQSHLUB_N_S8:
		return {NameAndType(Type::IntegerType(1, false)), NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VSET_LANE_P8:
	case ARM64_INTRIN_VSET_LANE_S8:
	case ARM64_INTRIN_VSET_LANE_U8:
		return {NameAndType(Type::IntegerType(1, false)), NameAndType(Type::IntegerType(8, false)),
		    NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VABSQ_S16:
	case ARM64_INTRIN_VABSQ_S32:
	case ARM64_INTRIN_VABSQ_S64:
	case ARM64_INTRIN_VABSQ_S8:
	case ARM64_INTRIN_VADDLVQ_S16:
	case ARM64_INTRIN_VADDLVQ_S32:
	case ARM64_INTRIN_VADDLVQ_S8:
	case ARM64_INTRIN_VADDLVQ_U16:
	case ARM64_INTRIN_VADDLVQ_U32:
	case ARM64_INTRIN_VADDLVQ_U8:
	case ARM64_INTRIN_VADDVQ_S16:
	case ARM64_INTRIN_VADDVQ_S32:
	case ARM64_INTRIN_VADDVQ_S64:
	case ARM64_INTRIN_VADDVQ_S8:
	case ARM64_INTRIN_VADDVQ_U16:
	case ARM64_INTRIN_VADDVQ_U32:
	case ARM64_INTRIN_VADDVQ_U64:
	case ARM64_INTRIN_VADDVQ_U8:
	case ARM64_INTRIN_VAESIMCQ_U8:
	case ARM64_INTRIN_VAESMCQ_U8:
	case ARM64_INTRIN_VCEQZQ_P64:
	case ARM64_INTRIN_VCEQZQ_P8:
	case ARM64_INTRIN_VCEQZQ_S16:
	case ARM64_INTRIN_VCEQZQ_S32:
	case ARM64_INTRIN_VCEQZQ_S64:
	case ARM64_INTRIN_VCEQZQ_S8:
	case ARM64_INTRIN_VCEQZQ_U16:
	case ARM64_INTRIN_VCEQZQ_U32:
	case ARM64_INTRIN_VCEQZQ_U64:
	case ARM64_INTRIN_VCEQZQ_U8:
	case ARM64_INTRIN_VCGEZQ_S16:
	case ARM64_INTRIN_VCGEZQ_S32:
	case ARM64_INTRIN_VCGEZQ_S64:
	case ARM64_INTRIN_VCGEZQ_S8:
	case ARM64_INTRIN_VCGTZQ_S16:
	case ARM64_INTRIN_VCGTZQ_S32:
	case ARM64_INTRIN_VCGTZQ_S64:
	case ARM64_INTRIN_VCGTZQ_S8:
	case ARM64_INTRIN_VCLEZQ_S16:
	case ARM64_INTRIN_VCLEZQ_S32:
	case ARM64_INTRIN_VCLEZQ_S64:
	case ARM64_INTRIN_VCLEZQ_S8:
	case ARM64_INTRIN_VCLSQ_S16:
	case ARM64_INTRIN_VCLSQ_S32:
	case ARM64_INTRIN_VCLSQ_S8:
	case ARM64_INTRIN_VCLSQ_U16:
	case ARM64_INTRIN_VCLSQ_U32:
	case ARM64_INTRIN_VCLSQ_U8:
	case ARM64_INTRIN_VCLTZQ_S16:
	case ARM64_INTRIN_VCLTZQ_S32:
	case ARM64_INTRIN_VCLTZQ_S64:
	case ARM64_INTRIN_VCLTZQ_S8:
	case ARM64_INTRIN_VCLZQ_S16:
	case ARM64_INTRIN_VCLZQ_S32:
	case ARM64_INTRIN_VCLZQ_S8:
	case ARM64_INTRIN_VCLZQ_U16:
	case ARM64_INTRIN_VCLZQ_U32:
	case ARM64_INTRIN_VCLZQ_U8:
	case ARM64_INTRIN_VCNTQ_P8:
	case ARM64_INTRIN_VCNTQ_S8:
	case ARM64_INTRIN_VCNTQ_U8:
	case ARM64_INTRIN_VCVTQ_F16_S16:
	case ARM64_INTRIN_VCVTQ_F16_U16:
	case ARM64_INTRIN_VCVTQ_F32_S32:
	case ARM64_INTRIN_VCVTQ_F32_U32:
	case ARM64_INTRIN_VCVTQ_F64_S64:
	case ARM64_INTRIN_VCVTQ_F64_U64:
	case ARM64_INTRIN_VGET_HIGH_P16:
	case ARM64_INTRIN_VGET_HIGH_P64:
	case ARM64_INTRIN_VGET_HIGH_P8:
	case ARM64_INTRIN_VGET_HIGH_S16:
	case ARM64_INTRIN_VGET_HIGH_S32:
	case ARM64_INTRIN_VGET_HIGH_S64:
	case ARM64_INTRIN_VGET_HIGH_S8:
	case ARM64_INTRIN_VGET_HIGH_U16:
	case ARM64_INTRIN_VGET_HIGH_U32:
	case ARM64_INTRIN_VGET_HIGH_U64:
	case ARM64_INTRIN_VGET_HIGH_U8:
	case ARM64_INTRIN_VGET_LOW_P16:
	case ARM64_INTRIN_VGET_LOW_P64:
	case ARM64_INTRIN_VGET_LOW_P8:
	case ARM64_INTRIN_VGET_LOW_S16:
	case ARM64_INTRIN_VGET_LOW_S32:
	case ARM64_INTRIN_VGET_LOW_S64:
	case ARM64_INTRIN_VGET_LOW_S8:
	case ARM64_INTRIN_VGET_LOW_U16:
	case ARM64_INTRIN_VGET_LOW_U32:
	case ARM64_INTRIN_VGET_LOW_U64:
	case ARM64_INTRIN_VGET_LOW_U8:
	case ARM64_INTRIN_VLDRQ_P128:
	case ARM64_INTRIN_VMAXVQ_S16:
	case ARM64_INTRIN_VMAXVQ_S32:
	case ARM64_INTRIN_VMAXVQ_S8:
	case ARM64_INTRIN_VMAXVQ_U16:
	case ARM64_INTRIN_VMAXVQ_U32:
	case ARM64_INTRIN_VMAXVQ_U8:
	case ARM64_INTRIN_VMINVQ_S16:
	case ARM64_INTRIN_VMINVQ_S32:
	case ARM64_INTRIN_VMINVQ_S8:
	case ARM64_INTRIN_VMINVQ_U16:
	case ARM64_INTRIN_VMINVQ_U32:
	case ARM64_INTRIN_VMINVQ_U8:
	case ARM64_INTRIN_VMOVL_HIGH_S16:
	case ARM64_INTRIN_VMOVL_HIGH_S32:
	case ARM64_INTRIN_VMOVL_HIGH_S8:
	case ARM64_INTRIN_VMOVL_HIGH_U16:
	case ARM64_INTRIN_VMOVL_HIGH_U32:
	case ARM64_INTRIN_VMOVL_HIGH_U8:
	case ARM64_INTRIN_VMOVN_S16:
	case ARM64_INTRIN_VMOVN_S32:
	case ARM64_INTRIN_VMOVN_S64:
	case ARM64_INTRIN_VMOVN_U16:
	case ARM64_INTRIN_VMOVN_U32:
	case ARM64_INTRIN_VMOVN_U64:
	case ARM64_INTRIN_VMVNQ_P8:
	case ARM64_INTRIN_VMVNQ_S16:
	case ARM64_INTRIN_VMVNQ_S32:
	case ARM64_INTRIN_VMVNQ_S8:
	case ARM64_INTRIN_VMVNQ_U16:
	case ARM64_INTRIN_VMVNQ_U32:
	case ARM64_INTRIN_VMVNQ_U8:
	case ARM64_INTRIN_VNEGQ_S16:
	case ARM64_INTRIN_VNEGQ_S32:
	case ARM64_INTRIN_VNEGQ_S64:
	case ARM64_INTRIN_VNEGQ_S8:
	case ARM64_INTRIN_VPADDD_S64:
	case ARM64_INTRIN_VPADDD_U64:
	case ARM64_INTRIN_VPADDLQ_S16:
	case ARM64_INTRIN_VPADDLQ_S32:
	case ARM64_INTRIN_VPADDLQ_S8:
	case ARM64_INTRIN_VPADDLQ_U16:
	case ARM64_INTRIN_VPADDLQ_U32:
	case ARM64_INTRIN_VPADDLQ_U8:
	case ARM64_INTRIN_VQABSQ_S16:
	case ARM64_INTRIN_VQABSQ_S32:
	case ARM64_INTRIN_VQABSQ_S64:
	case ARM64_INTRIN_VQABSQ_S8:
	case ARM64_INTRIN_VQMOVN_S16:
	case ARM64_INTRIN_VQMOVN_S32:
	case ARM64_INTRIN_VQMOVN_S64:
	case ARM64_INTRIN_VQMOVN_U16:
	case ARM64_INTRIN_VQMOVN_U32:
	case ARM64_INTRIN_VQMOVN_U64:
	case ARM64_INTRIN_VQMOVUN_S16:
	case ARM64_INTRIN_VQMOVUN_S32:
	case ARM64_INTRIN_VQMOVUN_S64:
	case ARM64_INTRIN_VQNEGQ_S16:
	case ARM64_INTRIN_VQNEGQ_S32:
	case ARM64_INTRIN_VQNEGQ_S64:
	case ARM64_INTRIN_VQNEGQ_S8:
	case ARM64_INTRIN_VRBITQ_P8:
	case ARM64_INTRIN_VRBITQ_S8:
	case ARM64_INTRIN_VRBITQ_U8:
	case ARM64_INTRIN_VRECPEQ_U32:
	case ARM64_INTRIN_VREV16Q_P8:
	case ARM64_INTRIN_VREV16Q_S8:
	case ARM64_INTRIN_VREV16Q_U8:
	case ARM64_INTRIN_VREV32Q_P16:
	case ARM64_INTRIN_VREV32Q_P8:
	case ARM64_INTRIN_VREV32Q_S16:
	case ARM64_INTRIN_VREV32Q_S8:
	case ARM64_INTRIN_VREV32Q_U16:
	case ARM64_INTRIN_VREV32Q_U8:
	case ARM64_INTRIN_VREV64Q_P16:
	case ARM64_INTRIN_VREV64Q_P8:
	case ARM64_INTRIN_VREV64Q_S16:
	case ARM64_INTRIN_VREV64Q_S32:
	case ARM64_INTRIN_VREV64Q_S8:
	case ARM64_INTRIN_VREV64Q_U16:
	case ARM64_INTRIN_VREV64Q_U32:
	case ARM64_INTRIN_VREV64Q_U8:
	case ARM64_INTRIN_VRSQRTEQ_U32:
		return {NameAndType(Type::IntegerType(16, false))};
	case ARM64_INTRIN_VBSLQ_F16:
	case ARM64_INTRIN_VBSLQ_F32:
	case ARM64_INTRIN_VBSLQ_F64:
		return {NameAndType(Type::IntegerType(16, false)), NameAndType(Type::FloatType(16)),
		    NameAndType(Type::FloatType(16))};
	case ARM64_INTRIN_VABDL_HIGH_S16:
	case ARM64_INTRIN_VABDL_HIGH_S32:
	case ARM64_INTRIN_VABDL_HIGH_S8:
	case ARM64_INTRIN_VABDL_HIGH_U16:
	case ARM64_INTRIN_VABDL_HIGH_U32:
	case ARM64_INTRIN_VABDL_HIGH_U8:
	case ARM64_INTRIN_VABDQ_S16:
	case ARM64_INTRIN_VABDQ_S32:
	case ARM64_INTRIN_VABDQ_S8:
	case ARM64_INTRIN_VABDQ_U16:
	case ARM64_INTRIN_VABDQ_U32:
	case ARM64_INTRIN_VABDQ_U8:
	case ARM64_INTRIN_VADDHN_S16:
	case ARM64_INTRIN_VADDHN_S32:
	case ARM64_INTRIN_VADDHN_S64:
	case ARM64_INTRIN_VADDHN_U16:
	case ARM64_INTRIN_VADDHN_U32:
	case ARM64_INTRIN_VADDHN_U64:
	case ARM64_INTRIN_VADDL_HIGH_S16:
	case ARM64_INTRIN_VADDL_HIGH_S32:
	case ARM64_INTRIN_VADDL_HIGH_S8:
	case ARM64_INTRIN_VADDL_HIGH_U16:
	case ARM64_INTRIN_VADDL_HIGH_U32:
	case ARM64_INTRIN_VADDL_HIGH_U8:
	case ARM64_INTRIN_VADDQ_P128:
	case ARM64_INTRIN_VADDQ_P16:
	case ARM64_INTRIN_VADDQ_P64:
	case ARM64_INTRIN_VADDQ_P8:
	case ARM64_INTRIN_VADDQ_S16:
	case ARM64_INTRIN_VADDQ_S32:
	case ARM64_INTRIN_VADDQ_S64:
	case ARM64_INTRIN_VADDQ_S8:
	case ARM64_INTRIN_VADDQ_U16:
	case ARM64_INTRIN_VADDQ_U32:
	case ARM64_INTRIN_VADDQ_U64:
	case ARM64_INTRIN_VADDQ_U8:
	case ARM64_INTRIN_VADDW_HIGH_S16:
	case ARM64_INTRIN_VADDW_HIGH_S32:
	case ARM64_INTRIN_VADDW_HIGH_S8:
	case ARM64_INTRIN_VADDW_HIGH_U16:
	case ARM64_INTRIN_VADDW_HIGH_U32:
	case ARM64_INTRIN_VADDW_HIGH_U8:
	case ARM64_INTRIN_VAESDQ_U8:
	case ARM64_INTRIN_VAESEQ_U8:
	case ARM64_INTRIN_VANDQ_S16:
	case ARM64_INTRIN_VANDQ_S32:
	case ARM64_INTRIN_VANDQ_S64:
	case ARM64_INTRIN_VANDQ_S8:
	case ARM64_INTRIN_VANDQ_U16:
	case ARM64_INTRIN_VANDQ_U32:
	case ARM64_INTRIN_VANDQ_U64:
	case ARM64_INTRIN_VANDQ_U8:
	case ARM64_INTRIN_VBICQ_S16:
	case ARM64_INTRIN_VBICQ_S32:
	case ARM64_INTRIN_VBICQ_S64:
	case ARM64_INTRIN_VBICQ_S8:
	case ARM64_INTRIN_VBICQ_U16:
	case ARM64_INTRIN_VBICQ_U32:
	case ARM64_INTRIN_VBICQ_U64:
	case ARM64_INTRIN_VBICQ_U8:
	case ARM64_INTRIN_VCEQQ_P64:
	case ARM64_INTRIN_VCEQQ_P8:
	case ARM64_INTRIN_VCEQQ_S16:
	case ARM64_INTRIN_VCEQQ_S32:
	case ARM64_INTRIN_VCEQQ_S64:
	case ARM64_INTRIN_VCEQQ_S8:
	case ARM64_INTRIN_VCEQQ_U16:
	case ARM64_INTRIN_VCEQQ_U32:
	case ARM64_INTRIN_VCEQQ_U64:
	case ARM64_INTRIN_VCEQQ_U8:
	case ARM64_INTRIN_VCGEQ_S16:
	case ARM64_INTRIN_VCGEQ_S32:
	case ARM64_INTRIN_VCGEQ_S64:
	case ARM64_INTRIN_VCGEQ_S8:
	case ARM64_INTRIN_VCGEQ_U16:
	case ARM64_INTRIN_VCGEQ_U32:
	case ARM64_INTRIN_VCGEQ_U64:
	case ARM64_INTRIN_VCGEQ_U8:
	case ARM64_INTRIN_VCGTQ_S16:
	case ARM64_INTRIN_VCGTQ_S32:
	case ARM64_INTRIN_VCGTQ_S64:
	case ARM64_INTRIN_VCGTQ_S8:
	case ARM64_INTRIN_VCGTQ_U16:
	case ARM64_INTRIN_VCGTQ_U32:
	case ARM64_INTRIN_VCGTQ_U64:
	case ARM64_INTRIN_VCGTQ_U8:
	case ARM64_INTRIN_VCLEQ_S16:
	case ARM64_INTRIN_VCLEQ_S32:
	case ARM64_INTRIN_VCLEQ_S64:
	case ARM64_INTRIN_VCLEQ_S8:
	case ARM64_INTRIN_VCLEQ_U16:
	case ARM64_INTRIN_VCLEQ_U32:
	case ARM64_INTRIN_VCLEQ_U64:
	case ARM64_INTRIN_VCLEQ_U8:
	case ARM64_INTRIN_VCLTQ_S16:
	case ARM64_INTRIN_VCLTQ_S32:
	case ARM64_INTRIN_VCLTQ_S64:
	case ARM64_INTRIN_VCLTQ_S8:
	case ARM64_INTRIN_VCLTQ_U16:
	case ARM64_INTRIN_VCLTQ_U32:
	case ARM64_INTRIN_VCLTQ_U64:
	case ARM64_INTRIN_VCLTQ_U8:
	case ARM64_INTRIN_VEORQ_S16:
	case ARM64_INTRIN_VEORQ_S32:
	case ARM64_INTRIN_VEORQ_S64:
	case ARM64_INTRIN_VEORQ_S8:
	case ARM64_INTRIN_VEORQ_U16:
	case ARM64_INTRIN_VEORQ_U32:
	case ARM64_INTRIN_VEORQ_U64:
	case ARM64_INTRIN_VEORQ_U8:
	case ARM64_INTRIN_VHADDQ_S16:
	case ARM64_INTRIN_VHADDQ_S32:
	case ARM64_INTRIN_VHADDQ_S8:
	case ARM64_INTRIN_VHADDQ_U16:
	case ARM64_INTRIN_VHADDQ_U32:
	case ARM64_INTRIN_VHADDQ_U8:
	case ARM64_INTRIN_VHSUBQ_S16:
	case ARM64_INTRIN_VHSUBQ_S32:
	case ARM64_INTRIN_VHSUBQ_S8:
	case ARM64_INTRIN_VHSUBQ_U16:
	case ARM64_INTRIN_VHSUBQ_U32:
	case ARM64_INTRIN_VHSUBQ_U8:
	case ARM64_INTRIN_VMAXQ_S16:
	case ARM64_INTRIN_VMAXQ_S32:
	case ARM64_INTRIN_VMAXQ_S8:
	case ARM64_INTRIN_VMAXQ_U16:
	case ARM64_INTRIN_VMAXQ_U32:
	case ARM64_INTRIN_VMAXQ_U8:
	case ARM64_INTRIN_VMINQ_S16:
	case ARM64_INTRIN_VMINQ_S32:
	case ARM64_INTRIN_VMINQ_S8:
	case ARM64_INTRIN_VMINQ_U16:
	case ARM64_INTRIN_VMINQ_U32:
	case ARM64_INTRIN_VMINQ_U8:
	case ARM64_INTRIN_VMULL_HIGH_P64:
	case ARM64_INTRIN_VMULL_HIGH_P8:
	case ARM64_INTRIN_VMULL_HIGH_S16:
	case ARM64_INTRIN_VMULL_HIGH_S32:
	case ARM64_INTRIN_VMULL_HIGH_S8:
	case ARM64_INTRIN_VMULL_HIGH_U16:
	case ARM64_INTRIN_VMULL_HIGH_U32:
	case ARM64_INTRIN_VMULL_HIGH_U8:
	case ARM64_INTRIN_VMULQ_P8:
	case ARM64_INTRIN_VMULQ_S16:
	case ARM64_INTRIN_VMULQ_S32:
	case ARM64_INTRIN_VMULQ_S8:
	case ARM64_INTRIN_VMULQ_U16:
	case ARM64_INTRIN_VMULQ_U32:
	case ARM64_INTRIN_VMULQ_U8:
	case ARM64_INTRIN_VORNQ_S16:
	case ARM64_INTRIN_VORNQ_S32:
	case ARM64_INTRIN_VORNQ_S64:
	case ARM64_INTRIN_VORNQ_S8:
	case ARM64_INTRIN_VORNQ_U16:
	case ARM64_INTRIN_VORNQ_U32:
	case ARM64_INTRIN_VORNQ_U64:
	case ARM64_INTRIN_VORNQ_U8:
	case ARM64_INTRIN_VORRQ_S16:
	case ARM64_INTRIN_VORRQ_S32:
	case ARM64_INTRIN_VORRQ_S64:
	case ARM64_INTRIN_VORRQ_S8:
	case ARM64_INTRIN_VORRQ_U16:
	case ARM64_INTRIN_VORRQ_U32:
	case ARM64_INTRIN_VORRQ_U64:
	case ARM64_INTRIN_VORRQ_U8:
	case ARM64_INTRIN_VPADALQ_S16:
	case ARM64_INTRIN_VPADALQ_S32:
	case ARM64_INTRIN_VPADALQ_S8:
	case ARM64_INTRIN_VPADALQ_U16:
	case ARM64_INTRIN_VPADALQ_U32:
	case ARM64_INTRIN_VPADALQ_U8:
	case ARM64_INTRIN_VPADDQ_S16:
	case ARM64_INTRIN_VPADDQ_S32:
	case ARM64_INTRIN_VPADDQ_S64:
	case ARM64_INTRIN_VPADDQ_S8:
	case ARM64_INTRIN_VPADDQ_U16:
	case ARM64_INTRIN_VPADDQ_U32:
	case ARM64_INTRIN_VPADDQ_U64:
	case ARM64_INTRIN_VPADDQ_U8:
	case ARM64_INTRIN_VPMAXQ_S16:
	case ARM64_INTRIN_VPMAXQ_S32:
	case ARM64_INTRIN_VPMAXQ_S8:
	case ARM64_INTRIN_VPMAXQ_U16:
	case ARM64_INTRIN_VPMAXQ_U32:
	case ARM64_INTRIN_VPMAXQ_U8:
	case ARM64_INTRIN_VPMINQ_S16:
	case ARM64_INTRIN_VPMINQ_S32:
	case ARM64_INTRIN_VPMINQ_S8:
	case ARM64_INTRIN_VPMINQ_U16:
	case ARM64_INTRIN_VPMINQ_U32:
	case ARM64_INTRIN_VPMINQ_U8:
	case ARM64_INTRIN_VQADDQ_S16:
	case ARM64_INTRIN_VQADDQ_S32:
	case ARM64_INTRIN_VQADDQ_S64:
	case ARM64_INTRIN_VQADDQ_S8:
	case ARM64_INTRIN_VQADDQ_U16:
	case ARM64_INTRIN_VQADDQ_U32:
	case ARM64_INTRIN_VQADDQ_U64:
	case ARM64_INTRIN_VQADDQ_U8:
	case ARM64_INTRIN_VQDMULHQ_S16:
	case ARM64_INTRIN_VQDMULHQ_S32:
	case ARM64_INTRIN_VQDMULL_HIGH_S16:
	case ARM64_INTRIN_VQDMULL_HIGH_S32:
	case ARM64_INTRIN_VQRDMULHQ_S16:
	case ARM64_INTRIN_VQRDMULHQ_S32:
	case ARM64_INTRIN_VQRSHLQ_S16:
	case ARM64_INTRIN_VQRSHLQ_S32:
	case ARM64_INTRIN_VQRSHLQ_S64:
	case ARM64_INTRIN_VQRSHLQ_S8:
	case ARM64_INTRIN_VQRSHLQ_U16:
	case ARM64_INTRIN_VQRSHLQ_U32:
	case ARM64_INTRIN_VQRSHLQ_U64:
	case ARM64_INTRIN_VQRSHLQ_U8:
	case ARM64_INTRIN_VQSHLQ_S16:
	case ARM64_INTRIN_VQSHLQ_S32:
	case ARM64_INTRIN_VQSHLQ_S64:
	case ARM64_INTRIN_VQSHLQ_S8:
	case ARM64_INTRIN_VQSHLQ_U16:
	case ARM64_INTRIN_VQSHLQ_U32:
	case ARM64_INTRIN_VQSHLQ_U64:
	case ARM64_INTRIN_VQSHLQ_U8:
	case ARM64_INTRIN_VQSUBQ_S16:
	case ARM64_INTRIN_VQSUBQ_S32:
	case ARM64_INTRIN_VQSUBQ_S64:
	case ARM64_INTRIN_VQSUBQ_S8:
	case ARM64_INTRIN_VQSUBQ_U16:
	case ARM64_INTRIN_VQSUBQ_U32:
	case ARM64_INTRIN_VQSUBQ_U64:
	case ARM64_INTRIN_VQSUBQ_U8:
	case ARM64_INTRIN_VRADDHN_S16:
	case ARM64_INTRIN_VRADDHN_S32:
	case ARM64_INTRIN_VRADDHN_S64:
	case ARM64_INTRIN_VRADDHN_U16:
	case ARM64_INTRIN_VRADDHN_U32:
	case ARM64_INTRIN_VRADDHN_U64:
	case ARM64_INTRIN_VRAX1Q_U64:
	case ARM64_INTRIN_VRHADDQ_S16:
	case ARM64_INTRIN_VRHADDQ_S32:
	case ARM64_INTRIN_VRHADDQ_S8:
	case ARM64_INTRIN_VRHADDQ_U16:
	case ARM64_INTRIN_VRHADDQ_U32:
	case ARM64_INTRIN_VRHADDQ_U8:
	case ARM64_INTRIN_VRSHLQ_S16:
	case ARM64_INTRIN_VRSHLQ_S32:
	case ARM64_INTRIN_VRSHLQ_S64:
	case ARM64_INTRIN_VRSHLQ_S8:
	case ARM64_INTRIN_VRSHLQ_U16:
	case ARM64_INTRIN_VRSHLQ_U32:
	case ARM64_INTRIN_VRSHLQ_U64:
	case ARM64_INTRIN_VRSHLQ_U8:
	case ARM64_INTRIN_VRSUBHN_S16:
	case ARM64_INTRIN_VRSUBHN_S32:
	case ARM64_INTRIN_VRSUBHN_S64:
	case ARM64_INTRIN_VRSUBHN_U16:
	case ARM64_INTRIN_VRSUBHN_U32:
	case ARM64_INTRIN_VRSUBHN_U64:
	case ARM64_INTRIN_VSHA1SU1Q_U32:
	case ARM64_INTRIN_VSHA256SU0Q_U32:
	case ARM64_INTRIN_VSHA512SU0Q_U64:
	case ARM64_INTRIN_VSHLQ_S16:
	case ARM64_INTRIN_VSHLQ_S32:
	case ARM64_INTRIN_VSHLQ_S64:
	case ARM64_INTRIN_VSHLQ_S8:
	case ARM64_INTRIN_VSHLQ_U16:
	case ARM64_INTRIN_VSHLQ_U32:
	case ARM64_INTRIN_VSHLQ_U64:
	case ARM64_INTRIN_VSHLQ_U8:
	case ARM64_INTRIN_VSM4EKEYQ_U32:
	case ARM64_INTRIN_VSM4EQ_U32:
	case ARM64_INTRIN_VSQADDQ_U16:
	case ARM64_INTRIN_VSQADDQ_U32:
	case ARM64_INTRIN_VSQADDQ_U64:
	case ARM64_INTRIN_VSQADDQ_U8:
	case ARM64_INTRIN_VSUBHN_S16:
	case ARM64_INTRIN_VSUBHN_S32:
	case ARM64_INTRIN_VSUBHN_S64:
	case ARM64_INTRIN_VSUBHN_U16:
	case ARM64_INTRIN_VSUBHN_U32:
	case ARM64_INTRIN_VSUBHN_U64:
	case ARM64_INTRIN_VSUBL_HIGH_S16:
	case ARM64_INTRIN_VSUBL_HIGH_S32:
	case ARM64_INTRIN_VSUBL_HIGH_S8:
	case ARM64_INTRIN_VSUBL_HIGH_U16:
	case ARM64_INTRIN_VSUBL_HIGH_U32:
	case ARM64_INTRIN_VSUBL_HIGH_U8:
	case ARM64_INTRIN_VSUBQ_S16:
	case ARM64_INTRIN_VSUBQ_S32:
	case ARM64_INTRIN_VSUBQ_S64:
	case ARM64_INTRIN_VSUBQ_S8:
	case ARM64_INTRIN_VSUBQ_U16:
	case ARM64_INTRIN_VSUBQ_U32:
	case ARM64_INTRIN_VSUBQ_U64:
	case ARM64_INTRIN_VSUBQ_U8:
	case ARM64_INTRIN_VSUBW_HIGH_S16:
	case ARM64_INTRIN_VSUBW_HIGH_S32:
	case ARM64_INTRIN_VSUBW_HIGH_S8:
	case ARM64_INTRIN_VSUBW_HIGH_U16:
	case ARM64_INTRIN_VSUBW_HIGH_U32:
	case ARM64_INTRIN_VSUBW_HIGH_U8:
	case ARM64_INTRIN_VTRN1Q_P16:
	case ARM64_INTRIN_VTRN1Q_P64:
	case ARM64_INTRIN_VTRN1Q_P8:
	case ARM64_INTRIN_VTRN1Q_S16:
	case ARM64_INTRIN_VTRN1Q_S32:
	case ARM64_INTRIN_VTRN1Q_S64:
	case ARM64_INTRIN_VTRN1Q_S8:
	case ARM64_INTRIN_VTRN1Q_U16:
	case ARM64_INTRIN_VTRN1Q_U32:
	case ARM64_INTRIN_VTRN1Q_U64:
	case ARM64_INTRIN_VTRN1Q_U8:
	case ARM64_INTRIN_VTRN2Q_P16:
	case ARM64_INTRIN_VTRN2Q_P64:
	case ARM64_INTRIN_VTRN2Q_P8:
	case ARM64_INTRIN_VTRN2Q_S16:
	case ARM64_INTRIN_VTRN2Q_S32:
	case ARM64_INTRIN_VTRN2Q_S64:
	case ARM64_INTRIN_VTRN2Q_S8:
	case ARM64_INTRIN_VTRN2Q_U16:
	case ARM64_INTRIN_VTRN2Q_U32:
	case ARM64_INTRIN_VTRN2Q_U64:
	case ARM64_INTRIN_VTRN2Q_U8:
	case ARM64_INTRIN_VTSTQ_P64:
	case ARM64_INTRIN_VTSTQ_P8:
	case ARM64_INTRIN_VTSTQ_S16:
	case ARM64_INTRIN_VTSTQ_S32:
	case ARM64_INTRIN_VTSTQ_S64:
	case ARM64_INTRIN_VTSTQ_S8:
	case ARM64_INTRIN_VTSTQ_U16:
	case ARM64_INTRIN_VTSTQ_U32:
	case ARM64_INTRIN_VTSTQ_U64:
	case ARM64_INTRIN_VTSTQ_U8:
	case ARM64_INTRIN_VUQADDQ_S16:
	case ARM64_INTRIN_VUQADDQ_S32:
	case ARM64_INTRIN_VUQADDQ_S64:
	case ARM64_INTRIN_VUQADDQ_S8:
	case ARM64_INTRIN_VUZP1Q_P16:
	case ARM64_INTRIN_VUZP1Q_P64:
	case ARM64_INTRIN_VUZP1Q_P8:
	case ARM64_INTRIN_VUZP1Q_S16:
	case ARM64_INTRIN_VUZP1Q_S32:
	case ARM64_INTRIN_VUZP1Q_S64:
	case ARM64_INTRIN_VUZP1Q_S8:
	case ARM64_INTRIN_VUZP1Q_U16:
	case ARM64_INTRIN_VUZP1Q_U32:
	case ARM64_INTRIN_VUZP1Q_U64:
	case ARM64_INTRIN_VUZP1Q_U8:
	case ARM64_INTRIN_VUZP2Q_P16:
	case ARM64_INTRIN_VUZP2Q_P64:
	case ARM64_INTRIN_VUZP2Q_P8:
	case ARM64_INTRIN_VUZP2Q_S16:
	case ARM64_INTRIN_VUZP2Q_S32:
	case ARM64_INTRIN_VUZP2Q_S64:
	case ARM64_INTRIN_VUZP2Q_S8:
	case ARM64_INTRIN_VUZP2Q_U16:
	case ARM64_INTRIN_VUZP2Q_U32:
	case ARM64_INTRIN_VUZP2Q_U64:
	case ARM64_INTRIN_VUZP2Q_U8:
	case ARM64_INTRIN_VZIP1Q_P16:
	case ARM64_INTRIN_VZIP1Q_P64:
	case ARM64_INTRIN_VZIP1Q_P8:
	case ARM64_INTRIN_VZIP1Q_S16:
	case ARM64_INTRIN_VZIP1Q_S32:
	case ARM64_INTRIN_VZIP1Q_S64:
	case ARM64_INTRIN_VZIP1Q_S8:
	case ARM64_INTRIN_VZIP1Q_U16:
	case ARM64_INTRIN_VZIP1Q_U32:
	case ARM64_INTRIN_VZIP1Q_U64:
	case ARM64_INTRIN_VZIP1Q_U8:
	case ARM64_INTRIN_VZIP2Q_P16:
	case ARM64_INTRIN_VZIP2Q_P64:
	case ARM64_INTRIN_VZIP2Q_P8:
	case ARM64_INTRIN_VZIP2Q_S16:
	case ARM64_INTRIN_VZIP2Q_S32:
	case ARM64_INTRIN_VZIP2Q_S64:
	case ARM64_INTRIN_VZIP2Q_S8:
	case ARM64_INTRIN_VZIP2Q_U16:
	case ARM64_INTRIN_VZIP2Q_U32:
	case ARM64_INTRIN_VZIP2Q_U64:
	case ARM64_INTRIN_VZIP2Q_U8:
		return {NameAndType(Type::IntegerType(16, false)), NameAndType(Type::IntegerType(16, false))};
	case ARM64_INTRIN_VABAL_HIGH_S16:
	case ARM64_INTRIN_VABAL_HIGH_S32:
	case ARM64_INTRIN_VABAL_HIGH_S8:
	case ARM64_INTRIN_VABAL_HIGH_U16:
	case ARM64_INTRIN_VABAL_HIGH_U32:
	case ARM64_INTRIN_VABAL_HIGH_U8:
	case ARM64_INTRIN_VABAQ_S16:
	case ARM64_INTRIN_VABAQ_S32:
	case ARM64_INTRIN_VABAQ_S8:
	case ARM64_INTRIN_VABAQ_U16:
	case ARM64_INTRIN_VABAQ_U32:
	case ARM64_INTRIN_VABAQ_U8:
	case ARM64_INTRIN_VBCAXQ_S16:
	case ARM64_INTRIN_VBCAXQ_S32:
	case ARM64_INTRIN_VBCAXQ_S64:
	case ARM64_INTRIN_VBCAXQ_S8:
	case ARM64_INTRIN_VBCAXQ_U16:
	case ARM64_INTRIN_VBCAXQ_U32:
	case ARM64_INTRIN_VBCAXQ_U64:
	case ARM64_INTRIN_VBCAXQ_U8:
	case ARM64_INTRIN_VBSLQ_P16:
	case ARM64_INTRIN_VBSLQ_P64:
	case ARM64_INTRIN_VBSLQ_P8:
	case ARM64_INTRIN_VBSLQ_S16:
	case ARM64_INTRIN_VBSLQ_S32:
	case ARM64_INTRIN_VBSLQ_S64:
	case ARM64_INTRIN_VBSLQ_S8:
	case ARM64_INTRIN_VBSLQ_U16:
	case ARM64_INTRIN_VBSLQ_U32:
	case ARM64_INTRIN_VBSLQ_U64:
	case ARM64_INTRIN_VBSLQ_U8:
	case ARM64_INTRIN_VDOTQ_S32:
	case ARM64_INTRIN_VDOTQ_U32:
	case ARM64_INTRIN_VEOR3Q_S16:
	case ARM64_INTRIN_VEOR3Q_S32:
	case ARM64_INTRIN_VEOR3Q_S64:
	case ARM64_INTRIN_VEOR3Q_S8:
	case ARM64_INTRIN_VEOR3Q_U16:
	case ARM64_INTRIN_VEOR3Q_U32:
	case ARM64_INTRIN_VEOR3Q_U64:
	case ARM64_INTRIN_VEOR3Q_U8:
	case ARM64_INTRIN_VMLAL_HIGH_S16:
	case ARM64_INTRIN_VMLAL_HIGH_S32:
	case ARM64_INTRIN_VMLAL_HIGH_S8:
	case ARM64_INTRIN_VMLAL_HIGH_U16:
	case ARM64_INTRIN_VMLAL_HIGH_U32:
	case ARM64_INTRIN_VMLAL_HIGH_U8:
	case ARM64_INTRIN_VMLAQ_S16:
	case ARM64_INTRIN_VMLAQ_S32:
	case ARM64_INTRIN_VMLAQ_S8:
	case ARM64_INTRIN_VMLAQ_U16:
	case ARM64_INTRIN_VMLAQ_U32:
	case ARM64_INTRIN_VMLAQ_U8:
	case ARM64_INTRIN_VMLSL_HIGH_S16:
	case ARM64_INTRIN_VMLSL_HIGH_S32:
	case ARM64_INTRIN_VMLSL_HIGH_S8:
	case ARM64_INTRIN_VMLSL_HIGH_U16:
	case ARM64_INTRIN_VMLSL_HIGH_U32:
	case ARM64_INTRIN_VMLSL_HIGH_U8:
	case ARM64_INTRIN_VMLSQ_S16:
	case ARM64_INTRIN_VMLSQ_S32:
	case ARM64_INTRIN_VMLSQ_S8:
	case ARM64_INTRIN_VMLSQ_U16:
	case ARM64_INTRIN_VMLSQ_U32:
	case ARM64_INTRIN_VMLSQ_U8:
	case ARM64_INTRIN_VMMLAQ_S32:
	case ARM64_INTRIN_VMMLAQ_U32:
	case ARM64_INTRIN_VQDMLAL_HIGH_S16:
	case ARM64_INTRIN_VQDMLAL_HIGH_S32:
	case ARM64_INTRIN_VQDMLSL_HIGH_S16:
	case ARM64_INTRIN_VQDMLSL_HIGH_S32:
	case ARM64_INTRIN_VQRDMLAHQ_S16:
	case ARM64_INTRIN_VQRDMLAHQ_S32:
	case ARM64_INTRIN_VQRDMLSHQ_S16:
	case ARM64_INTRIN_VQRDMLSHQ_S32:
	case ARM64_INTRIN_VSHA1SU0Q_U32:
	case ARM64_INTRIN_VSHA256H2Q_U32:
	case ARM64_INTRIN_VSHA256HQ_U32:
	case ARM64_INTRIN_VSHA256SU1Q_U32:
	case ARM64_INTRIN_VSHA512H2Q_U64:
	case ARM64_INTRIN_VSHA512HQ_U64:
	case ARM64_INTRIN_VSHA512SU1Q_U64:
	case ARM64_INTRIN_VSM3PARTW1Q_U32:
	case ARM64_INTRIN_VSM3PARTW2Q_U32:
	case ARM64_INTRIN_VSM3SS1Q_U32:
	case ARM64_INTRIN_VUSDOTQ_S32:
	case ARM64_INTRIN_VUSMMLAQ_S32:
		return {NameAndType(Type::IntegerType(16, false)), NameAndType(Type::IntegerType(16, false)),
		    NameAndType(Type::IntegerType(16, false))};
	case ARM64_INTRIN_VDOTQ_LANEQ_S32:
	case ARM64_INTRIN_VDOTQ_LANEQ_U32:
	case ARM64_INTRIN_VMLAL_HIGH_LANEQ_S16:
	case ARM64_INTRIN_VMLAL_HIGH_LANEQ_S32:
	case ARM64_INTRIN_VMLAL_HIGH_LANEQ_U16:
	case ARM64_INTRIN_VMLAL_HIGH_LANEQ_U32:
	case ARM64_INTRIN_VMLAQ_LANEQ_S16:
	case ARM64_INTRIN_VMLAQ_LANEQ_S32:
	case ARM64_INTRIN_VMLAQ_LANEQ_U16:
	case ARM64_INTRIN_VMLAQ_LANEQ_U32:
	case ARM64_INTRIN_VMLSL_HIGH_LANEQ_S16:
	case ARM64_INTRIN_VMLSL_HIGH_LANEQ_S32:
	case ARM64_INTRIN_VMLSL_HIGH_LANEQ_U16:
	case ARM64_INTRIN_VMLSL_HIGH_LANEQ_U32:
	case ARM64_INTRIN_VMLSQ_LANEQ_S16:
	case ARM64_INTRIN_VMLSQ_LANEQ_S32:
	case ARM64_INTRIN_VMLSQ_LANEQ_U16:
	case ARM64_INTRIN_VMLSQ_LANEQ_U32:
	case ARM64_INTRIN_VQDMLAL_HIGH_LANEQ_S16:
	case ARM64_INTRIN_VQDMLAL_HIGH_LANEQ_S32:
	case ARM64_INTRIN_VQDMLSL_HIGH_LANEQ_S16:
	case ARM64_INTRIN_VQDMLSL_HIGH_LANEQ_S32:
	case ARM64_INTRIN_VQRDMLAHQ_LANEQ_S16:
	case ARM64_INTRIN_VQRDMLAHQ_LANEQ_S32:
	case ARM64_INTRIN_VQRDMLSHQ_LANEQ_S16:
	case ARM64_INTRIN_VQRDMLSHQ_LANEQ_S32:
	case ARM64_INTRIN_VSM3TT1AQ_U32:
	case ARM64_INTRIN_VSM3TT1BQ_U32:
	case ARM64_INTRIN_VSM3TT2AQ_U32:
	case ARM64_INTRIN_VSM3TT2BQ_U32:
	case ARM64_INTRIN_VSUDOTQ_LANEQ_S32:
	case ARM64_INTRIN_VUSDOTQ_LANEQ_S32:
		return {NameAndType(Type::IntegerType(16, false)), NameAndType(Type::IntegerType(16, false)),
		    NameAndType(Type::IntegerType(16, false)), NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VMLAL_HIGH_N_S16:
	case ARM64_INTRIN_VMLAL_HIGH_N_U16:
	case ARM64_INTRIN_VMLAQ_N_S16:
	case ARM64_INTRIN_VMLAQ_N_U16:
	case ARM64_INTRIN_VMLSL_HIGH_N_S16:
	case ARM64_INTRIN_VMLSL_HIGH_N_U16:
	case ARM64_INTRIN_VMLSQ_N_S16:
	case ARM64_INTRIN_VMLSQ_N_U16:
	case ARM64_INTRIN_VQDMLAL_HIGH_N_S16:
	case ARM64_INTRIN_VQDMLSL_HIGH_N_S16:
		return {NameAndType(Type::IntegerType(16, false)), NameAndType(Type::IntegerType(16, false)),
		    NameAndType(Type::IntegerType(2, false))};
	case ARM64_INTRIN_VEXTQ_P16:
	case ARM64_INTRIN_VEXTQ_P64:
	case ARM64_INTRIN_VEXTQ_P8:
	case ARM64_INTRIN_VEXTQ_S16:
	case ARM64_INTRIN_VEXTQ_S32:
	case ARM64_INTRIN_VEXTQ_S64:
	case ARM64_INTRIN_VEXTQ_S8:
	case ARM64_INTRIN_VEXTQ_U16:
	case ARM64_INTRIN_VEXTQ_U32:
	case ARM64_INTRIN_VEXTQ_U64:
	case ARM64_INTRIN_VEXTQ_U8:
	case ARM64_INTRIN_VMLAL_HIGH_N_S32:
	case ARM64_INTRIN_VMLAL_HIGH_N_U32:
	case ARM64_INTRIN_VMLAQ_N_S32:
	case ARM64_INTRIN_VMLAQ_N_U32:
	case ARM64_INTRIN_VMLSL_HIGH_N_S32:
	case ARM64_INTRIN_VMLSL_HIGH_N_U32:
	case ARM64_INTRIN_VMLSQ_N_S32:
	case ARM64_INTRIN_VMLSQ_N_U32:
	case ARM64_INTRIN_VMULL_HIGH_LANEQ_S16:
	case ARM64_INTRIN_VMULL_HIGH_LANEQ_S32:
	case ARM64_INTRIN_VMULL_HIGH_LANEQ_U16:
	case ARM64_INTRIN_VMULL_HIGH_LANEQ_U32:
	case ARM64_INTRIN_VMULQ_LANEQ_S16:
	case ARM64_INTRIN_VMULQ_LANEQ_S32:
	case ARM64_INTRIN_VMULQ_LANEQ_U16:
	case ARM64_INTRIN_VMULQ_LANEQ_U32:
	case ARM64_INTRIN_VQDMLAL_HIGH_N_S32:
	case ARM64_INTRIN_VQDMLSL_HIGH_N_S32:
	case ARM64_INTRIN_VQDMULHQ_LANEQ_S16:
	case ARM64_INTRIN_VQDMULHQ_LANEQ_S32:
	case ARM64_INTRIN_VQDMULL_HIGH_LANEQ_S16:
	case ARM64_INTRIN_VQDMULL_HIGH_LANEQ_S32:
	case ARM64_INTRIN_VQRDMULHQ_LANEQ_S16:
	case ARM64_INTRIN_VQRDMULHQ_LANEQ_S32:
	case ARM64_INTRIN_VRSRAQ_N_S16:
	case ARM64_INTRIN_VRSRAQ_N_S32:
	case ARM64_INTRIN_VRSRAQ_N_S64:
	case ARM64_INTRIN_VRSRAQ_N_S8:
	case ARM64_INTRIN_VRSRAQ_N_U16:
	case ARM64_INTRIN_VRSRAQ_N_U32:
	case ARM64_INTRIN_VRSRAQ_N_U64:
	case ARM64_INTRIN_VRSRAQ_N_U8:
	case ARM64_INTRIN_VSLIQ_N_P16:
	case ARM64_INTRIN_VSLIQ_N_P64:
	case ARM64_INTRIN_VSLIQ_N_P8:
	case ARM64_INTRIN_VSLIQ_N_S16:
	case ARM64_INTRIN_VSLIQ_N_S32:
	case ARM64_INTRIN_VSLIQ_N_S64:
	case ARM64_INTRIN_VSLIQ_N_S8:
	case ARM64_INTRIN_VSLIQ_N_U16:
	case ARM64_INTRIN_VSLIQ_N_U32:
	case ARM64_INTRIN_VSLIQ_N_U64:
	case ARM64_INTRIN_VSLIQ_N_U8:
	case ARM64_INTRIN_VSRAQ_N_S16:
	case ARM64_INTRIN_VSRAQ_N_S32:
	case ARM64_INTRIN_VSRAQ_N_S64:
	case ARM64_INTRIN_VSRAQ_N_S8:
	case ARM64_INTRIN_VSRAQ_N_U16:
	case ARM64_INTRIN_VSRAQ_N_U32:
	case ARM64_INTRIN_VSRAQ_N_U64:
	case ARM64_INTRIN_VSRAQ_N_U8:
	case ARM64_INTRIN_VSRIQ_N_P16:
	case ARM64_INTRIN_VSRIQ_N_P64:
	case ARM64_INTRIN_VSRIQ_N_P8:
	case ARM64_INTRIN_VSRIQ_N_S16:
	case ARM64_INTRIN_VSRIQ_N_S32:
	case ARM64_INTRIN_VSRIQ_N_S64:
	case ARM64_INTRIN_VSRIQ_N_S8:
	case ARM64_INTRIN_VSRIQ_N_U16:
	case ARM64_INTRIN_VSRIQ_N_U32:
	case ARM64_INTRIN_VSRIQ_N_U64:
	case ARM64_INTRIN_VSRIQ_N_U8:
	case ARM64_INTRIN_VXARQ_U64:
		return {NameAndType(Type::IntegerType(16, false)), NameAndType(Type::IntegerType(16, false)),
		    NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VDOTQ_LANE_S32:
	case ARM64_INTRIN_VDOTQ_LANE_U32:
	case ARM64_INTRIN_VMLAL_HIGH_LANE_S16:
	case ARM64_INTRIN_VMLAL_HIGH_LANE_S32:
	case ARM64_INTRIN_VMLAL_HIGH_LANE_U16:
	case ARM64_INTRIN_VMLAL_HIGH_LANE_U32:
	case ARM64_INTRIN_VMLAQ_LANE_S16:
	case ARM64_INTRIN_VMLAQ_LANE_S32:
	case ARM64_INTRIN_VMLAQ_LANE_U16:
	case ARM64_INTRIN_VMLAQ_LANE_U32:
	case ARM64_INTRIN_VMLSL_HIGH_LANE_S16:
	case ARM64_INTRIN_VMLSL_HIGH_LANE_S32:
	case ARM64_INTRIN_VMLSL_HIGH_LANE_U16:
	case ARM64_INTRIN_VMLSL_HIGH_LANE_U32:
	case ARM64_INTRIN_VMLSQ_LANE_S16:
	case ARM64_INTRIN_VMLSQ_LANE_S32:
	case ARM64_INTRIN_VMLSQ_LANE_U16:
	case ARM64_INTRIN_VMLSQ_LANE_U32:
	case ARM64_INTRIN_VQDMLAL_HIGH_LANE_S16:
	case ARM64_INTRIN_VQDMLAL_HIGH_LANE_S32:
	case ARM64_INTRIN_VQDMLSL_HIGH_LANE_S16:
	case ARM64_INTRIN_VQDMLSL_HIGH_LANE_S32:
	case ARM64_INTRIN_VQRDMLAHQ_LANE_S16:
	case ARM64_INTRIN_VQRDMLAHQ_LANE_S32:
	case ARM64_INTRIN_VQRDMLSHQ_LANE_S16:
	case ARM64_INTRIN_VQRDMLSHQ_LANE_S32:
	case ARM64_INTRIN_VSUDOTQ_LANE_S32:
	case ARM64_INTRIN_VUSDOTQ_LANE_S32:
		return {NameAndType(Type::IntegerType(16, false)), NameAndType(Type::IntegerType(16, false)),
		    NameAndType(Type::IntegerType(8, false)), NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VMULL_HIGH_N_S16:
	case ARM64_INTRIN_VMULL_HIGH_N_U16:
	case ARM64_INTRIN_VMULQ_N_S16:
	case ARM64_INTRIN_VMULQ_N_U16:
	case ARM64_INTRIN_VQDMULHQ_N_S16:
	case ARM64_INTRIN_VQDMULL_HIGH_N_S16:
	case ARM64_INTRIN_VQRDMULHQ_N_S16:
		return {NameAndType(Type::IntegerType(16, false)), NameAndType(Type::IntegerType(2, false))};
	case ARM64_INTRIN_VCVTQ_N_F16_S16:
	case ARM64_INTRIN_VCVTQ_N_F16_U16:
	case ARM64_INTRIN_VCVTQ_N_F32_S32:
	case ARM64_INTRIN_VCVTQ_N_F32_U32:
	case ARM64_INTRIN_VCVTQ_N_F64_S64:
	case ARM64_INTRIN_VCVTQ_N_F64_U64:
	case ARM64_INTRIN_VDUP_LANEQ_P16:
	case ARM64_INTRIN_VDUP_LANEQ_P64:
	case ARM64_INTRIN_VDUP_LANEQ_P8:
	case ARM64_INTRIN_VDUP_LANEQ_S16:
	case ARM64_INTRIN_VDUP_LANEQ_S32:
	case ARM64_INTRIN_VDUP_LANEQ_S64:
	case ARM64_INTRIN_VDUP_LANEQ_S8:
	case ARM64_INTRIN_VDUP_LANEQ_U16:
	case ARM64_INTRIN_VDUP_LANEQ_U32:
	case ARM64_INTRIN_VDUP_LANEQ_U64:
	case ARM64_INTRIN_VDUP_LANEQ_U8:
	case ARM64_INTRIN_VDUPB_LANEQ_P8:
	case ARM64_INTRIN_VDUPB_LANEQ_S8:
	case ARM64_INTRIN_VDUPB_LANEQ_U8:
	case ARM64_INTRIN_VDUPD_LANEQ_S64:
	case ARM64_INTRIN_VDUPD_LANEQ_U64:
	case ARM64_INTRIN_VDUPH_LANEQ_P16:
	case ARM64_INTRIN_VDUPH_LANEQ_S16:
	case ARM64_INTRIN_VDUPH_LANEQ_U16:
	case ARM64_INTRIN_VDUPQ_LANEQ_P16:
	case ARM64_INTRIN_VDUPQ_LANEQ_P64:
	case ARM64_INTRIN_VDUPQ_LANEQ_P8:
	case ARM64_INTRIN_VDUPQ_LANEQ_S16:
	case ARM64_INTRIN_VDUPQ_LANEQ_S32:
	case ARM64_INTRIN_VDUPQ_LANEQ_S64:
	case ARM64_INTRIN_VDUPQ_LANEQ_S8:
	case ARM64_INTRIN_VDUPQ_LANEQ_U16:
	case ARM64_INTRIN_VDUPQ_LANEQ_U32:
	case ARM64_INTRIN_VDUPQ_LANEQ_U64:
	case ARM64_INTRIN_VDUPQ_LANEQ_U8:
	case ARM64_INTRIN_VDUPS_LANEQ_S32:
	case ARM64_INTRIN_VDUPS_LANEQ_U32:
	case ARM64_INTRIN_VGETQ_LANE_P16:
	case ARM64_INTRIN_VGETQ_LANE_P64:
	case ARM64_INTRIN_VGETQ_LANE_P8:
	case ARM64_INTRIN_VGETQ_LANE_S16:
	case ARM64_INTRIN_VGETQ_LANE_S32:
	case ARM64_INTRIN_VGETQ_LANE_S64:
	case ARM64_INTRIN_VGETQ_LANE_S8:
	case ARM64_INTRIN_VGETQ_LANE_U16:
	case ARM64_INTRIN_VGETQ_LANE_U32:
	case ARM64_INTRIN_VGETQ_LANE_U64:
	case ARM64_INTRIN_VGETQ_LANE_U8:
	case ARM64_INTRIN_VMULL_HIGH_N_S32:
	case ARM64_INTRIN_VMULL_HIGH_N_U32:
	case ARM64_INTRIN_VMULQ_N_S32:
	case ARM64_INTRIN_VMULQ_N_U32:
	case ARM64_INTRIN_VQDMULHQ_N_S32:
	case ARM64_INTRIN_VQDMULL_HIGH_N_S32:
	case ARM64_INTRIN_VQRDMULHQ_N_S32:
	case ARM64_INTRIN_VQRSHRN_N_S16:
	case ARM64_INTRIN_VQRSHRN_N_S32:
	case ARM64_INTRIN_VQRSHRN_N_S64:
	case ARM64_INTRIN_VQRSHRN_N_U16:
	case ARM64_INTRIN_VQRSHRN_N_U32:
	case ARM64_INTRIN_VQRSHRN_N_U64:
	case ARM64_INTRIN_VQRSHRUN_N_S16:
	case ARM64_INTRIN_VQRSHRUN_N_S32:
	case ARM64_INTRIN_VQRSHRUN_N_S64:
	case ARM64_INTRIN_VQSHLQ_N_S16:
	case ARM64_INTRIN_VQSHLQ_N_S32:
	case ARM64_INTRIN_VQSHLQ_N_S64:
	case ARM64_INTRIN_VQSHLQ_N_S8:
	case ARM64_INTRIN_VQSHLQ_N_U16:
	case ARM64_INTRIN_VQSHLQ_N_U32:
	case ARM64_INTRIN_VQSHLQ_N_U64:
	case ARM64_INTRIN_VQSHLQ_N_U8:
	case ARM64_INTRIN_VQSHLUQ_N_S16:
	case ARM64_INTRIN_VQSHLUQ_N_S32:
	case ARM64_INTRIN_VQSHLUQ_N_S64:
	case ARM64_INTRIN_VQSHLUQ_N_S8:
	case ARM64_INTRIN_VQSHRN_N_S16:
	case ARM64_INTRIN_VQSHRN_N_S32:
	case ARM64_INTRIN_VQSHRN_N_S64:
	case ARM64_INTRIN_VQSHRN_N_U16:
	case ARM64_INTRIN_VQSHRN_N_U32:
	case ARM64_INTRIN_VQSHRN_N_U64:
	case ARM64_INTRIN_VQSHRUN_N_S16:
	case ARM64_INTRIN_VQSHRUN_N_S32:
	case ARM64_INTRIN_VQSHRUN_N_S64:
	case ARM64_INTRIN_VRSHRN_N_S16:
	case ARM64_INTRIN_VRSHRN_N_S32:
	case ARM64_INTRIN_VRSHRN_N_S64:
	case ARM64_INTRIN_VRSHRN_N_U16:
	case ARM64_INTRIN_VRSHRN_N_U32:
	case ARM64_INTRIN_VRSHRN_N_U64:
	case ARM64_INTRIN_VRSHRQ_N_S16:
	case ARM64_INTRIN_VRSHRQ_N_S32:
	case ARM64_INTRIN_VRSHRQ_N_S64:
	case ARM64_INTRIN_VRSHRQ_N_S8:
	case ARM64_INTRIN_VRSHRQ_N_U16:
	case ARM64_INTRIN_VRSHRQ_N_U32:
	case ARM64_INTRIN_VRSHRQ_N_U64:
	case ARM64_INTRIN_VRSHRQ_N_U8:
	case ARM64_INTRIN_VSHLL_HIGH_N_S16:
	case ARM64_INTRIN_VSHLL_HIGH_N_S32:
	case ARM64_INTRIN_VSHLL_HIGH_N_S8:
	case ARM64_INTRIN_VSHLL_HIGH_N_U16:
	case ARM64_INTRIN_VSHLL_HIGH_N_U32:
	case ARM64_INTRIN_VSHLL_HIGH_N_U8:
	case ARM64_INTRIN_VSHLQ_N_S16:
	case ARM64_INTRIN_VSHLQ_N_S32:
	case ARM64_INTRIN_VSHLQ_N_S64:
	case ARM64_INTRIN_VSHLQ_N_S8:
	case ARM64_INTRIN_VSHLQ_N_U16:
	case ARM64_INTRIN_VSHLQ_N_U32:
	case ARM64_INTRIN_VSHLQ_N_U64:
	case ARM64_INTRIN_VSHLQ_N_U8:
	case ARM64_INTRIN_VSHRN_N_S16:
	case ARM64_INTRIN_VSHRN_N_S32:
	case ARM64_INTRIN_VSHRN_N_S64:
	case ARM64_INTRIN_VSHRN_N_U16:
	case ARM64_INTRIN_VSHRN_N_U32:
	case ARM64_INTRIN_VSHRN_N_U64:
	case ARM64_INTRIN_VSHRQ_N_S16:
	case ARM64_INTRIN_VSHRQ_N_S32:
	case ARM64_INTRIN_VSHRQ_N_S64:
	case ARM64_INTRIN_VSHRQ_N_S8:
	case ARM64_INTRIN_VSHRQ_N_U16:
	case ARM64_INTRIN_VSHRQ_N_U32:
	case ARM64_INTRIN_VSHRQ_N_U64:
	case ARM64_INTRIN_VSHRQ_N_U8:
		return {NameAndType(Type::IntegerType(16, false)), NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VSHA1CQ_U32:
	case ARM64_INTRIN_VSHA1MQ_U32:
	case ARM64_INTRIN_VSHA1PQ_U32:
		return {NameAndType(Type::IntegerType(16, false)), NameAndType(Type::IntegerType(4, false)),
		    NameAndType(Type::IntegerType(16, false))};
	case ARM64_INTRIN_VADDW_S16:
	case ARM64_INTRIN_VADDW_S32:
	case ARM64_INTRIN_VADDW_S8:
	case ARM64_INTRIN_VADDW_U16:
	case ARM64_INTRIN_VADDW_U32:
	case ARM64_INTRIN_VADDW_U8:
	case ARM64_INTRIN_VSUBW_S16:
	case ARM64_INTRIN_VSUBW_S32:
	case ARM64_INTRIN_VSUBW_S8:
	case ARM64_INTRIN_VSUBW_U16:
	case ARM64_INTRIN_VSUBW_U32:
	case ARM64_INTRIN_VSUBW_U8:
		return {NameAndType(Type::IntegerType(16, false)), NameAndType(Type::IntegerType(8, false))};
	case ARM64_INTRIN_VMLAL_LANEQ_S16:
	case ARM64_INTRIN_VMLAL_LANEQ_S32:
	case ARM64_INTRIN_VMLAL_LANEQ_U16:
	case ARM64_INTRIN_VMLAL_LANEQ_U32:
	case ARM64_INTRIN_VMLSL_LANEQ_S16:
	case ARM64_INTRIN_VMLSL_LANEQ_S32:
	case ARM64_INTRIN_VMLSL_LANEQ_U16:
	case ARM64_INTRIN_VMLSL_LANEQ_U32:
	case ARM64_INTRIN_VQDMLAL_LANEQ_S16:
	case ARM64_INTRIN_VQDMLAL_LANEQ_S32:
	case ARM64_INTRIN_VQDMLSL_LANEQ_S16:
	case ARM64_INTRIN_VQDMLSL_LANEQ_S32:
		return {NameAndType(Type::IntegerType(16, false)), NameAndType(Type::IntegerType(8, false)),
		    NameAndType(Type::IntegerType(16, false)), NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VMLAL_N_S16:
	case ARM64_INTRIN_VMLAL_N_U16:
	case ARM64_INTRIN_VMLSL_N_S16:
	case ARM64_INTRIN_VMLSL_N_U16:
	case ARM64_INTRIN_VQDMLAL_N_S16:
	case ARM64_INTRIN_VQDMLSL_N_S16:
		return {NameAndType(Type::IntegerType(16, false)), NameAndType(Type::IntegerType(8, false)),
		    NameAndType(Type::IntegerType(2, false))};
	case ARM64_INTRIN_VMLAL_N_S32:
	case ARM64_INTRIN_VMLAL_N_U32:
	case ARM64_INTRIN_VMLSL_N_S32:
	case ARM64_INTRIN_VMLSL_N_U32:
	case ARM64_INTRIN_VMULL_HIGH_LANE_S16:
	case ARM64_INTRIN_VMULL_HIGH_LANE_S32:
	case ARM64_INTRIN_VMULL_HIGH_LANE_U16:
	case ARM64_INTRIN_VMULL_HIGH_LANE_U32:
	case ARM64_INTRIN_VMULQ_LANE_S16:
	case ARM64_INTRIN_VMULQ_LANE_S32:
	case ARM64_INTRIN_VMULQ_LANE_U16:
	case ARM64_INTRIN_VMULQ_LANE_U32:
	case ARM64_INTRIN_VQDMLAL_N_S32:
	case ARM64_INTRIN_VQDMLSL_N_S32:
	case ARM64_INTRIN_VQDMULHQ_LANE_S16:
	case ARM64_INTRIN_VQDMULHQ_LANE_S32:
	case ARM64_INTRIN_VQDMULL_HIGH_LANE_S16:
	case ARM64_INTRIN_VQDMULL_HIGH_LANE_S32:
	case ARM64_INTRIN_VQRDMULHQ_LANE_S16:
	case ARM64_INTRIN_VQRDMULHQ_LANE_S32:
		return {NameAndType(Type::IntegerType(16, false)), NameAndType(Type::IntegerType(8, false)),
		    NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VABAL_S16:
	case ARM64_INTRIN_VABAL_S32:
	case ARM64_INTRIN_VABAL_S8:
	case ARM64_INTRIN_VABAL_U16:
	case ARM64_INTRIN_VABAL_U32:
	case ARM64_INTRIN_VABAL_U8:
	case ARM64_INTRIN_VMLAL_S16:
	case ARM64_INTRIN_VMLAL_S32:
	case ARM64_INTRIN_VMLAL_S8:
	case ARM64_INTRIN_VMLAL_U16:
	case ARM64_INTRIN_VMLAL_U32:
	case ARM64_INTRIN_VMLAL_U8:
	case ARM64_INTRIN_VMLSL_S16:
	case ARM64_INTRIN_VMLSL_S32:
	case ARM64_INTRIN_VMLSL_S8:
	case ARM64_INTRIN_VMLSL_U16:
	case ARM64_INTRIN_VMLSL_U32:
	case ARM64_INTRIN_VMLSL_U8:
	case ARM64_INTRIN_VQDMLAL_S16:
	case ARM64_INTRIN_VQDMLAL_S32:
	case ARM64_INTRIN_VQDMLSL_S16:
	case ARM64_INTRIN_VQDMLSL_S32:
		return {NameAndType(Type::IntegerType(16, false)), NameAndType(Type::IntegerType(8, false)),
		    NameAndType(Type::IntegerType(8, false))};
	case ARM64_INTRIN_VMLAL_LANE_S16:
	case ARM64_INTRIN_VMLAL_LANE_S32:
	case ARM64_INTRIN_VMLAL_LANE_U16:
	case ARM64_INTRIN_VMLAL_LANE_U32:
	case ARM64_INTRIN_VMLSL_LANE_S16:
	case ARM64_INTRIN_VMLSL_LANE_S32:
	case ARM64_INTRIN_VMLSL_LANE_U16:
	case ARM64_INTRIN_VMLSL_LANE_U32:
	case ARM64_INTRIN_VQDMLAL_LANE_S16:
	case ARM64_INTRIN_VQDMLAL_LANE_S32:
	case ARM64_INTRIN_VQDMLSL_LANE_S16:
	case ARM64_INTRIN_VQDMLSL_LANE_S32:
		return {NameAndType(Type::IntegerType(16, false)), NameAndType(Type::IntegerType(8, false)),
		    NameAndType(Type::IntegerType(8, false)), NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VCVTH_F16_S16:
	case ARM64_INTRIN_VCVTH_F16_U16:
	case ARM64_INTRIN_VDUP_N_P16:
	case ARM64_INTRIN_VDUP_N_S16:
	case ARM64_INTRIN_VDUP_N_U16:
	case ARM64_INTRIN_VDUPQ_N_P16:
	case ARM64_INTRIN_VDUPQ_N_S16:
	case ARM64_INTRIN_VDUPQ_N_U16:
	case ARM64_INTRIN_VMOV_N_P16:
	case ARM64_INTRIN_VMOV_N_S16:
	case ARM64_INTRIN_VMOV_N_U16:
	case ARM64_INTRIN_VMOVQ_N_P16:
	case ARM64_INTRIN_VMOVQ_N_S16:
	case ARM64_INTRIN_VMOVQ_N_U16:
	case ARM64_INTRIN_VQABSH_S16:
	case ARM64_INTRIN_VQMOVNH_S16:
	case ARM64_INTRIN_VQMOVNH_U16:
	case ARM64_INTRIN_VQMOVUNH_S16:
	case ARM64_INTRIN_VQNEGH_S16:
		return {NameAndType(Type::IntegerType(2, false))};
	case ARM64_INTRIN_VQDMULHH_LANEQ_S16:
	case ARM64_INTRIN_VQDMULLH_LANEQ_S16:
	case ARM64_INTRIN_VQRDMULHH_LANEQ_S16:
	case ARM64_INTRIN_VSETQ_LANE_P16:
	case ARM64_INTRIN_VSETQ_LANE_S16:
	case ARM64_INTRIN_VSETQ_LANE_U16:
		return {NameAndType(Type::IntegerType(2, false)), NameAndType(Type::IntegerType(16, false)),
		    NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VQADDH_S16:
	case ARM64_INTRIN_VQADDH_U16:
	case ARM64_INTRIN_VQDMULHH_S16:
	case ARM64_INTRIN_VQDMULLH_S16:
	case ARM64_INTRIN_VQRDMULHH_S16:
	case ARM64_INTRIN_VQRSHLH_S16:
	case ARM64_INTRIN_VQRSHLH_U16:
	case ARM64_INTRIN_VQSHLH_S16:
	case ARM64_INTRIN_VQSHLH_U16:
	case ARM64_INTRIN_VQSUBH_S16:
	case ARM64_INTRIN_VQSUBH_U16:
	case ARM64_INTRIN_VSQADDH_U16:
	case ARM64_INTRIN_VUQADDH_S16:
		return {NameAndType(Type::IntegerType(2, false)), NameAndType(Type::IntegerType(2, false))};
	case ARM64_INTRIN_VQRDMLAHH_LANEQ_S16:
	case ARM64_INTRIN_VQRDMLSHH_LANEQ_S16:
		return {NameAndType(Type::IntegerType(2, false)), NameAndType(Type::IntegerType(2, false)),
		    NameAndType(Type::IntegerType(16, false)), NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VQRDMLAHH_S16:
	case ARM64_INTRIN_VQRDMLSHH_S16:
		return {NameAndType(Type::IntegerType(2, false)), NameAndType(Type::IntegerType(2, false)),
		    NameAndType(Type::IntegerType(2, false))};
	case ARM64_INTRIN_VQRDMLAHH_LANE_S16:
	case ARM64_INTRIN_VQRDMLSHH_LANE_S16:
		return {NameAndType(Type::IntegerType(2, false)), NameAndType(Type::IntegerType(2, false)),
		    NameAndType(Type::IntegerType(8, false)), NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VCVTH_N_F16_S16:
	case ARM64_INTRIN_VCVTH_N_F16_U16:
	case ARM64_INTRIN_VQRSHRNH_N_S16:
	case ARM64_INTRIN_VQRSHRNH_N_U16:
	case ARM64_INTRIN_VQRSHRUNH_N_S16:
	case ARM64_INTRIN_VQSHLH_N_S16:
	case ARM64_INTRIN_VQSHLH_N_U16:
	case ARM64_INTRIN_VQSHLUH_N_S16:
	case ARM64_INTRIN_VQSHRNH_N_S16:
	case ARM64_INTRIN_VQSHRNH_N_U16:
	case ARM64_INTRIN_VQSHRUNH_N_S16:
		return {NameAndType(Type::IntegerType(2, false)), NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VQDMULHH_LANE_S16:
	case ARM64_INTRIN_VQDMULLH_LANE_S16:
	case ARM64_INTRIN_VQRDMULHH_LANE_S16:
	case ARM64_INTRIN_VSET_LANE_P16:
	case ARM64_INTRIN_VSET_LANE_S16:
	case ARM64_INTRIN_VSET_LANE_U16:
		return {NameAndType(Type::IntegerType(2, false)), NameAndType(Type::IntegerType(8, false)),
		    NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VCVTH_F16_S32:
	case ARM64_INTRIN_VCVTH_F16_U32:
	case ARM64_INTRIN_VCVTS_F32_S32:
	case ARM64_INTRIN_VCVTS_F32_U32:
	case ARM64_INTRIN_VDUP_N_S32:
	case ARM64_INTRIN_VDUP_N_U32:
	case ARM64_INTRIN_VDUPQ_N_S32:
	case ARM64_INTRIN_VDUPQ_N_U32:
	case ARM64_INTRIN_VMOV_N_S32:
	case ARM64_INTRIN_VMOV_N_U32:
	case ARM64_INTRIN_VMOVQ_N_S32:
	case ARM64_INTRIN_VMOVQ_N_U32:
	case ARM64_INTRIN_VQABSS_S32:
	case ARM64_INTRIN_VQMOVNS_S32:
	case ARM64_INTRIN_VQMOVNS_U32:
	case ARM64_INTRIN_VQMOVUNS_S32:
	case ARM64_INTRIN_VQNEGS_S32:
	case ARM64_INTRIN_VSHA1H_U32:
	case ARM64_INTRIN_VCVT_F64_U32:
		return {NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN___CRC32B:
	case ARM64_INTRIN___CRC32CB:
	case ARM64_INTRIN_VCVTH_N_F16_U32:
	case ARM64_INTRIN_VCVTS_N_F32_U32:
	case ARM64_INTRIN_VCVTD_N_F64_U32:
		return {NameAndType(Type::IntegerType(4, false)), NameAndType(Type::IntegerType(1, false))};
	case ARM64_INTRIN_VCVTH_N_F16_U64:
	case ARM64_INTRIN_VCVTD_N_F64_U64:
	case ARM64_INTRIN_VCVTS_N_F32_U64:
		return {NameAndType(Type::IntegerType(8, false)), NameAndType(Type::IntegerType(1, false))};
	case ARM64_INTRIN_VQDMULHS_LANEQ_S32:
	case ARM64_INTRIN_VQDMULLS_LANEQ_S32:
	case ARM64_INTRIN_VQRDMULHS_LANEQ_S32:
	case ARM64_INTRIN_VSETQ_LANE_S32:
	case ARM64_INTRIN_VSETQ_LANE_U32:
		return {NameAndType(Type::IntegerType(4, false)), NameAndType(Type::IntegerType(16, false)),
		    NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN___CRC32CH:
	case ARM64_INTRIN___CRC32H:
		return {NameAndType(Type::IntegerType(4, false)), NameAndType(Type::IntegerType(2, false))};
	case ARM64_INTRIN_VQDMLALH_LANEQ_S16:
	case ARM64_INTRIN_VQDMLSLH_LANEQ_S16:
		return {NameAndType(Type::IntegerType(4, false)), NameAndType(Type::IntegerType(2, false)),
		    NameAndType(Type::IntegerType(16, false)), NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VQDMLALH_S16:
	case ARM64_INTRIN_VQDMLSLH_S16:
		return {NameAndType(Type::IntegerType(4, false)), NameAndType(Type::IntegerType(2, false)),
		    NameAndType(Type::IntegerType(2, false))};
	case ARM64_INTRIN_VQDMLALH_LANE_S16:
	case ARM64_INTRIN_VQDMLSLH_LANE_S16:
		return {NameAndType(Type::IntegerType(4, false)), NameAndType(Type::IntegerType(2, false)),
		    NameAndType(Type::IntegerType(8, false)), NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN___CRC32CW:
	case ARM64_INTRIN___CRC32W:
	case ARM64_INTRIN_VCVTH_N_F16_S32:
	case ARM64_INTRIN_VCVTS_N_F32_S32:
	case ARM64_INTRIN_VQADDS_S32:
	case ARM64_INTRIN_VQADDS_U32:
	case ARM64_INTRIN_VQDMULHS_S32:
	case ARM64_INTRIN_VQDMULLS_S32:
	case ARM64_INTRIN_VQRDMULHS_S32:
	case ARM64_INTRIN_VQRSHLS_S32:
	case ARM64_INTRIN_VQRSHLS_U32:
	case ARM64_INTRIN_VQRSHRNS_N_S32:
	case ARM64_INTRIN_VQRSHRNS_N_U32:
	case ARM64_INTRIN_VQRSHRUNS_N_S32:
	case ARM64_INTRIN_VQSHLS_N_S32:
	case ARM64_INTRIN_VQSHLS_N_U32:
	case ARM64_INTRIN_VQSHLS_S32:
	case ARM64_INTRIN_VQSHLS_U32:
	case ARM64_INTRIN_VQSHLUS_N_S32:
	case ARM64_INTRIN_VQSHRNS_N_S32:
	case ARM64_INTRIN_VQSHRNS_N_U32:
	case ARM64_INTRIN_VQSHRUNS_N_S32:
	case ARM64_INTRIN_VQSUBS_S32:
	case ARM64_INTRIN_VQSUBS_U32:
	case ARM64_INTRIN_VSQADDS_U32:
	case ARM64_INTRIN_VUQADDS_S32:
		return {NameAndType(Type::IntegerType(4, false)), NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VQRDMLAHS_LANEQ_S32:
	case ARM64_INTRIN_VQRDMLSHS_LANEQ_S32:
		return {NameAndType(Type::IntegerType(4, false)), NameAndType(Type::IntegerType(4, false)),
		    NameAndType(Type::IntegerType(16, false)), NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VQRDMLAHS_S32:
	case ARM64_INTRIN_VQRDMLSHS_S32:
		return {NameAndType(Type::IntegerType(4, false)), NameAndType(Type::IntegerType(4, false)),
		    NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VQRDMLAHS_LANE_S32:
	case ARM64_INTRIN_VQRDMLSHS_LANE_S32:
		return {NameAndType(Type::IntegerType(4, false)), NameAndType(Type::IntegerType(4, false)),
		    NameAndType(Type::IntegerType(8, false)), NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN___CRC32CD:
	case ARM64_INTRIN___CRC32D:
		return {NameAndType(Type::IntegerType(4, false)), NameAndType(Type::IntegerType(8, false))};
	case ARM64_INTRIN_VQDMULHS_LANE_S32:
	case ARM64_INTRIN_VQDMULLS_LANE_S32:
	case ARM64_INTRIN_VQRDMULHS_LANE_S32:
	case ARM64_INTRIN_VSET_LANE_S32:
	case ARM64_INTRIN_VSET_LANE_U32:
		return {NameAndType(Type::IntegerType(4, false)), NameAndType(Type::IntegerType(8, false)),
		    NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VABS_S16:
	case ARM64_INTRIN_VABS_S32:
	case ARM64_INTRIN_VABS_S64:
	case ARM64_INTRIN_VABS_S8:
	case ARM64_INTRIN_VABSD_S64:
	case ARM64_INTRIN_VADDLV_S16:
	case ARM64_INTRIN_VADDLV_S32:
	case ARM64_INTRIN_VADDLV_S8:
	case ARM64_INTRIN_VADDLV_U16:
	case ARM64_INTRIN_VADDLV_U32:
	case ARM64_INTRIN_VADDLV_U8:
	case ARM64_INTRIN_VADDV_S16:
	case ARM64_INTRIN_VADDV_S32:
	case ARM64_INTRIN_VADDV_S8:
	case ARM64_INTRIN_VADDV_U16:
	case ARM64_INTRIN_VADDV_U32:
	case ARM64_INTRIN_VADDV_U8:
	case ARM64_INTRIN_VCEQZ_P64:
	case ARM64_INTRIN_VCEQZ_P8:
	case ARM64_INTRIN_VCEQZ_S16:
	case ARM64_INTRIN_VCEQZ_S32:
	case ARM64_INTRIN_VCEQZ_S64:
	case ARM64_INTRIN_VCEQZ_S8:
	case ARM64_INTRIN_VCEQZ_U16:
	case ARM64_INTRIN_VCEQZ_U32:
	case ARM64_INTRIN_VCEQZ_U64:
	case ARM64_INTRIN_VCEQZ_U8:
	case ARM64_INTRIN_VCEQZD_S64:
	case ARM64_INTRIN_VCEQZD_U64:
	case ARM64_INTRIN_VCGEZ_S16:
	case ARM64_INTRIN_VCGEZ_S32:
	case ARM64_INTRIN_VCGEZ_S64:
	case ARM64_INTRIN_VCGEZ_S8:
	case ARM64_INTRIN_VCGEZD_S64:
	case ARM64_INTRIN_VCGTZ_S16:
	case ARM64_INTRIN_VCGTZ_S32:
	case ARM64_INTRIN_VCGTZ_S64:
	case ARM64_INTRIN_VCGTZ_S8:
	case ARM64_INTRIN_VCGTZD_S64:
	case ARM64_INTRIN_VCLEZ_S16:
	case ARM64_INTRIN_VCLEZ_S32:
	case ARM64_INTRIN_VCLEZ_S64:
	case ARM64_INTRIN_VCLEZ_S8:
	case ARM64_INTRIN_VCLEZD_S64:
	case ARM64_INTRIN_VCLS_S16:
	case ARM64_INTRIN_VCLS_S32:
	case ARM64_INTRIN_VCLS_S8:
	case ARM64_INTRIN_VCLS_U16:
	case ARM64_INTRIN_VCLS_U32:
	case ARM64_INTRIN_VCLS_U8:
	case ARM64_INTRIN_VCLTZ_S16:
	case ARM64_INTRIN_VCLTZ_S32:
	case ARM64_INTRIN_VCLTZ_S64:
	case ARM64_INTRIN_VCLTZ_S8:
	case ARM64_INTRIN_VCLTZD_S64:
	case ARM64_INTRIN_VCLZ_S16:
	case ARM64_INTRIN_VCLZ_S32:
	case ARM64_INTRIN_VCLZ_S8:
	case ARM64_INTRIN_VCLZ_U16:
	case ARM64_INTRIN_VCLZ_U32:
	case ARM64_INTRIN_VCLZ_U8:
	case ARM64_INTRIN_VCNT_P8:
	case ARM64_INTRIN_VCNT_S8:
	case ARM64_INTRIN_VCNT_U8:
	case ARM64_INTRIN_VCREATE_BF16:
	case ARM64_INTRIN_VCREATE_F16:
	case ARM64_INTRIN_VCREATE_F32:
	case ARM64_INTRIN_VCREATE_F64:
	case ARM64_INTRIN_VCREATE_P16:
	case ARM64_INTRIN_VCREATE_P64:
	case ARM64_INTRIN_VCREATE_P8:
	case ARM64_INTRIN_VCREATE_S16:
	case ARM64_INTRIN_VCREATE_S32:
	case ARM64_INTRIN_VCREATE_S64:
	case ARM64_INTRIN_VCREATE_S8:
	case ARM64_INTRIN_VCREATE_U16:
	case ARM64_INTRIN_VCREATE_U32:
	case ARM64_INTRIN_VCREATE_U64:
	case ARM64_INTRIN_VCREATE_U8:
	case ARM64_INTRIN_VCVT_F16_S16:
	case ARM64_INTRIN_VCVT_F16_U16:
	case ARM64_INTRIN_VCVT_F32_S32:
	case ARM64_INTRIN_VCVT_F32_U32:
	case ARM64_INTRIN_VCVT_F64_S64:
	case ARM64_INTRIN_VCVT_F64_U64:
	case ARM64_INTRIN_VCVT_F32_U64:
	case ARM64_INTRIN_VCVTD_F64_S64:
	case ARM64_INTRIN_VCVTD_F64_U64:
	case ARM64_INTRIN_VCVTH_F16_S64:
	case ARM64_INTRIN_VCVTH_F16_U64:
	case ARM64_INTRIN_VDUP_N_P64:
	case ARM64_INTRIN_VDUP_N_S64:
	case ARM64_INTRIN_VDUP_N_U64:
	case ARM64_INTRIN_VDUPQ_N_P64:
	case ARM64_INTRIN_VDUPQ_N_S64:
	case ARM64_INTRIN_VDUPQ_N_U64:
	case ARM64_INTRIN_VMAXV_S16:
	case ARM64_INTRIN_VMAXV_S32:
	case ARM64_INTRIN_VMAXV_S8:
	case ARM64_INTRIN_VMAXV_U16:
	case ARM64_INTRIN_VMAXV_U32:
	case ARM64_INTRIN_VMAXV_U8:
	case ARM64_INTRIN_VMINV_S16:
	case ARM64_INTRIN_VMINV_S32:
	case ARM64_INTRIN_VMINV_S8:
	case ARM64_INTRIN_VMINV_U16:
	case ARM64_INTRIN_VMINV_U32:
	case ARM64_INTRIN_VMINV_U8:
	case ARM64_INTRIN_VMOV_N_S64:
	case ARM64_INTRIN_VMOV_N_U64:
	case ARM64_INTRIN_VMOVL_S16:
	case ARM64_INTRIN_VMOVL_S32:
	case ARM64_INTRIN_VMOVL_S8:
	case ARM64_INTRIN_VMOVL_U16:
	case ARM64_INTRIN_VMOVL_U32:
	case ARM64_INTRIN_VMOVL_U8:
	case ARM64_INTRIN_VMOVQ_N_S64:
	case ARM64_INTRIN_VMOVQ_N_U64:
	case ARM64_INTRIN_VMVN_P8:
	case ARM64_INTRIN_VMVN_S16:
	case ARM64_INTRIN_VMVN_S32:
	case ARM64_INTRIN_VMVN_S8:
	case ARM64_INTRIN_VMVN_U16:
	case ARM64_INTRIN_VMVN_U32:
	case ARM64_INTRIN_VMVN_U8:
	case ARM64_INTRIN_VNEG_S16:
	case ARM64_INTRIN_VNEG_S32:
	case ARM64_INTRIN_VNEG_S64:
	case ARM64_INTRIN_VNEG_S8:
	case ARM64_INTRIN_VNEGD_S64:
	case ARM64_INTRIN_VPADDL_S16:
	case ARM64_INTRIN_VPADDL_S32:
	case ARM64_INTRIN_VPADDL_S8:
	case ARM64_INTRIN_VPADDL_U16:
	case ARM64_INTRIN_VPADDL_U32:
	case ARM64_INTRIN_VPADDL_U8:
	case ARM64_INTRIN_VQABS_S16:
	case ARM64_INTRIN_VQABS_S32:
	case ARM64_INTRIN_VQABS_S64:
	case ARM64_INTRIN_VQABS_S8:
	case ARM64_INTRIN_VQABSD_S64:
	case ARM64_INTRIN_VQMOVND_S64:
	case ARM64_INTRIN_VQMOVND_U64:
	case ARM64_INTRIN_VQMOVUND_S64:
	case ARM64_INTRIN_VQNEG_S16:
	case ARM64_INTRIN_VQNEG_S32:
	case ARM64_INTRIN_VQNEG_S64:
	case ARM64_INTRIN_VQNEG_S8:
	case ARM64_INTRIN_VQNEGD_S64:
	case ARM64_INTRIN_VRBIT_P8:
	case ARM64_INTRIN_VRBIT_S8:
	case ARM64_INTRIN_VRBIT_U8:
	case ARM64_INTRIN_VRECPE_U32:
	case ARM64_INTRIN_VREV16_P8:
	case ARM64_INTRIN_VREV16_S8:
	case ARM64_INTRIN_VREV16_U8:
	case ARM64_INTRIN_VREV32_P16:
	case ARM64_INTRIN_VREV32_P8:
	case ARM64_INTRIN_VREV32_S16:
	case ARM64_INTRIN_VREV32_S8:
	case ARM64_INTRIN_VREV32_U16:
	case ARM64_INTRIN_VREV32_U8:
	case ARM64_INTRIN_VREV64_P16:
	case ARM64_INTRIN_VREV64_P8:
	case ARM64_INTRIN_VREV64_S16:
	case ARM64_INTRIN_VREV64_S32:
	case ARM64_INTRIN_VREV64_S8:
	case ARM64_INTRIN_VREV64_U16:
	case ARM64_INTRIN_VREV64_U32:
	case ARM64_INTRIN_VREV64_U8:
	case ARM64_INTRIN_VRSQRTE_U32:
		return {NameAndType(Type::IntegerType(8, false))};
	case ARM64_INTRIN_VBSL_F16:
	case ARM64_INTRIN_VBSL_F32:
	case ARM64_INTRIN_VBSL_F64:
		return {NameAndType(Type::IntegerType(8, false)), NameAndType(Type::FloatType(8)),
		    NameAndType(Type::FloatType(8))};
	case ARM64_INTRIN_VMOVN_HIGH_S16:
	case ARM64_INTRIN_VMOVN_HIGH_S32:
	case ARM64_INTRIN_VMOVN_HIGH_S64:
	case ARM64_INTRIN_VMOVN_HIGH_U16:
	case ARM64_INTRIN_VMOVN_HIGH_U32:
	case ARM64_INTRIN_VMOVN_HIGH_U64:
	case ARM64_INTRIN_VQMOVN_HIGH_S16:
	case ARM64_INTRIN_VQMOVN_HIGH_S32:
	case ARM64_INTRIN_VQMOVN_HIGH_S64:
	case ARM64_INTRIN_VQMOVN_HIGH_U16:
	case ARM64_INTRIN_VQMOVN_HIGH_U32:
	case ARM64_INTRIN_VQMOVN_HIGH_U64:
	case ARM64_INTRIN_VQMOVUN_HIGH_S16:
	case ARM64_INTRIN_VQMOVUN_HIGH_S32:
	case ARM64_INTRIN_VQMOVUN_HIGH_S64:
		return {NameAndType(Type::IntegerType(8, false)), NameAndType(Type::IntegerType(16, false))};
	case ARM64_INTRIN_VADDHN_HIGH_S16:
	case ARM64_INTRIN_VADDHN_HIGH_S32:
	case ARM64_INTRIN_VADDHN_HIGH_S64:
	case ARM64_INTRIN_VADDHN_HIGH_U16:
	case ARM64_INTRIN_VADDHN_HIGH_U32:
	case ARM64_INTRIN_VADDHN_HIGH_U64:
	case ARM64_INTRIN_VRADDHN_HIGH_S16:
	case ARM64_INTRIN_VRADDHN_HIGH_S32:
	case ARM64_INTRIN_VRADDHN_HIGH_S64:
	case ARM64_INTRIN_VRADDHN_HIGH_U16:
	case ARM64_INTRIN_VRADDHN_HIGH_U32:
	case ARM64_INTRIN_VRADDHN_HIGH_U64:
	case ARM64_INTRIN_VRSUBHN_HIGH_S16:
	case ARM64_INTRIN_VRSUBHN_HIGH_S32:
	case ARM64_INTRIN_VRSUBHN_HIGH_S64:
	case ARM64_INTRIN_VRSUBHN_HIGH_U16:
	case ARM64_INTRIN_VRSUBHN_HIGH_U32:
	case ARM64_INTRIN_VRSUBHN_HIGH_U64:
	case ARM64_INTRIN_VSUBHN_HIGH_S16:
	case ARM64_INTRIN_VSUBHN_HIGH_S32:
	case ARM64_INTRIN_VSUBHN_HIGH_S64:
	case ARM64_INTRIN_VSUBHN_HIGH_U16:
	case ARM64_INTRIN_VSUBHN_HIGH_U32:
	case ARM64_INTRIN_VSUBHN_HIGH_U64:
		return {NameAndType(Type::IntegerType(8, false)), NameAndType(Type::IntegerType(16, false)),
		    NameAndType(Type::IntegerType(16, false))};
	case ARM64_INTRIN_VMUL_LANEQ_S16:
	case ARM64_INTRIN_VMUL_LANEQ_S32:
	case ARM64_INTRIN_VMUL_LANEQ_U16:
	case ARM64_INTRIN_VMUL_LANEQ_U32:
	case ARM64_INTRIN_VMULL_LANEQ_S16:
	case ARM64_INTRIN_VMULL_LANEQ_S32:
	case ARM64_INTRIN_VMULL_LANEQ_U16:
	case ARM64_INTRIN_VMULL_LANEQ_U32:
	case ARM64_INTRIN_VQDMULH_LANEQ_S16:
	case ARM64_INTRIN_VQDMULH_LANEQ_S32:
	case ARM64_INTRIN_VQDMULL_LANEQ_S16:
	case ARM64_INTRIN_VQDMULL_LANEQ_S32:
	case ARM64_INTRIN_VQRDMULH_LANEQ_S16:
	case ARM64_INTRIN_VQRDMULH_LANEQ_S32:
	case ARM64_INTRIN_VQRSHRN_HIGH_N_S16:
	case ARM64_INTRIN_VQRSHRN_HIGH_N_S32:
	case ARM64_INTRIN_VQRSHRN_HIGH_N_S64:
	case ARM64_INTRIN_VQRSHRN_HIGH_N_U16:
	case ARM64_INTRIN_VQRSHRN_HIGH_N_U32:
	case ARM64_INTRIN_VQRSHRN_HIGH_N_U64:
	case ARM64_INTRIN_VQRSHRUN_HIGH_N_S16:
	case ARM64_INTRIN_VQRSHRUN_HIGH_N_S32:
	case ARM64_INTRIN_VQRSHRUN_HIGH_N_S64:
	case ARM64_INTRIN_VQSHRN_HIGH_N_S16:
	case ARM64_INTRIN_VQSHRN_HIGH_N_S32:
	case ARM64_INTRIN_VQSHRN_HIGH_N_S64:
	case ARM64_INTRIN_VQSHRN_HIGH_N_U16:
	case ARM64_INTRIN_VQSHRN_HIGH_N_U32:
	case ARM64_INTRIN_VQSHRN_HIGH_N_U64:
	case ARM64_INTRIN_VQSHRUN_HIGH_N_S16:
	case ARM64_INTRIN_VQSHRUN_HIGH_N_S32:
	case ARM64_INTRIN_VQSHRUN_HIGH_N_S64:
	case ARM64_INTRIN_VRSHRN_HIGH_N_S16:
	case ARM64_INTRIN_VRSHRN_HIGH_N_S32:
	case ARM64_INTRIN_VRSHRN_HIGH_N_S64:
	case ARM64_INTRIN_VRSHRN_HIGH_N_U16:
	case ARM64_INTRIN_VRSHRN_HIGH_N_U32:
	case ARM64_INTRIN_VRSHRN_HIGH_N_U64:
	case ARM64_INTRIN_VSETQ_LANE_P64:
	case ARM64_INTRIN_VSETQ_LANE_S64:
	case ARM64_INTRIN_VSETQ_LANE_U64:
	case ARM64_INTRIN_VSHRN_HIGH_N_S16:
	case ARM64_INTRIN_VSHRN_HIGH_N_S32:
	case ARM64_INTRIN_VSHRN_HIGH_N_S64:
	case ARM64_INTRIN_VSHRN_HIGH_N_U16:
	case ARM64_INTRIN_VSHRN_HIGH_N_U32:
	case ARM64_INTRIN_VSHRN_HIGH_N_U64:
		return {NameAndType(Type::IntegerType(8, false)), NameAndType(Type::IntegerType(16, false)),
		    NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VMUL_N_S16:
	case ARM64_INTRIN_VMUL_N_U16:
	case ARM64_INTRIN_VMULL_N_S16:
	case ARM64_INTRIN_VMULL_N_U16:
	case ARM64_INTRIN_VQDMULH_N_S16:
	case ARM64_INTRIN_VQDMULL_N_S16:
	case ARM64_INTRIN_VQRDMULH_N_S16:
		return {NameAndType(Type::IntegerType(8, false)), NameAndType(Type::IntegerType(2, false))};
	case ARM64_INTRIN_VCVT_N_F16_S16:
	case ARM64_INTRIN_VCVT_N_F16_U16:
	case ARM64_INTRIN_VCVT_N_F32_S32:
	case ARM64_INTRIN_VCVT_N_F32_U32:
	case ARM64_INTRIN_VCVT_N_F64_S64:
	case ARM64_INTRIN_VCVT_N_F64_U64:
	case ARM64_INTRIN_VCVTD_N_F64_S64:
	case ARM64_INTRIN_VCVTH_N_F16_S64:
	case ARM64_INTRIN_VDUP_LANE_P16:
	case ARM64_INTRIN_VDUP_LANE_P64:
	case ARM64_INTRIN_VDUP_LANE_P8:
	case ARM64_INTRIN_VDUP_LANE_S16:
	case ARM64_INTRIN_VDUP_LANE_S32:
	case ARM64_INTRIN_VDUP_LANE_S64:
	case ARM64_INTRIN_VDUP_LANE_S8:
	case ARM64_INTRIN_VDUP_LANE_U16:
	case ARM64_INTRIN_VDUP_LANE_U32:
	case ARM64_INTRIN_VDUP_LANE_U64:
	case ARM64_INTRIN_VDUP_LANE_U8:
	case ARM64_INTRIN_VDUPB_LANE_P8:
	case ARM64_INTRIN_VDUPB_LANE_S8:
	case ARM64_INTRIN_VDUPB_LANE_U8:
	case ARM64_INTRIN_VDUPD_LANE_S64:
	case ARM64_INTRIN_VDUPD_LANE_U64:
	case ARM64_INTRIN_VDUPH_LANE_P16:
	case ARM64_INTRIN_VDUPH_LANE_S16:
	case ARM64_INTRIN_VDUPH_LANE_U16:
	case ARM64_INTRIN_VDUPQ_LANE_P16:
	case ARM64_INTRIN_VDUPQ_LANE_P64:
	case ARM64_INTRIN_VDUPQ_LANE_P8:
	case ARM64_INTRIN_VDUPQ_LANE_S16:
	case ARM64_INTRIN_VDUPQ_LANE_S32:
	case ARM64_INTRIN_VDUPQ_LANE_S64:
	case ARM64_INTRIN_VDUPQ_LANE_S8:
	case ARM64_INTRIN_VDUPQ_LANE_U16:
	case ARM64_INTRIN_VDUPQ_LANE_U32:
	case ARM64_INTRIN_VDUPQ_LANE_U64:
	case ARM64_INTRIN_VDUPQ_LANE_U8:
	case ARM64_INTRIN_VDUPS_LANE_S32:
	case ARM64_INTRIN_VDUPS_LANE_U32:
	case ARM64_INTRIN_VGET_LANE_P16:
	case ARM64_INTRIN_VGET_LANE_P64:
	case ARM64_INTRIN_VGET_LANE_P8:
	case ARM64_INTRIN_VGET_LANE_S16:
	case ARM64_INTRIN_VGET_LANE_S32:
	case ARM64_INTRIN_VGET_LANE_S64:
	case ARM64_INTRIN_VGET_LANE_S8:
	case ARM64_INTRIN_VGET_LANE_U16:
	case ARM64_INTRIN_VGET_LANE_U32:
	case ARM64_INTRIN_VGET_LANE_U64:
	case ARM64_INTRIN_VGET_LANE_U8:
	case ARM64_INTRIN_VMUL_N_S32:
	case ARM64_INTRIN_VMUL_N_U32:
	case ARM64_INTRIN_VMULL_N_S32:
	case ARM64_INTRIN_VMULL_N_U32:
	case ARM64_INTRIN_VQDMULH_N_S32:
	case ARM64_INTRIN_VQDMULL_N_S32:
	case ARM64_INTRIN_VQRDMULH_N_S32:
	case ARM64_INTRIN_VQRSHRND_N_S64:
	case ARM64_INTRIN_VQRSHRND_N_U64:
	case ARM64_INTRIN_VQRSHRUND_N_S64:
	case ARM64_INTRIN_VQSHL_N_S16:
	case ARM64_INTRIN_VQSHL_N_S32:
	case ARM64_INTRIN_VQSHL_N_S64:
	case ARM64_INTRIN_VQSHL_N_S8:
	case ARM64_INTRIN_VQSHL_N_U16:
	case ARM64_INTRIN_VQSHL_N_U32:
	case ARM64_INTRIN_VQSHL_N_U64:
	case ARM64_INTRIN_VQSHL_N_U8:
	case ARM64_INTRIN_VQSHLD_N_S64:
	case ARM64_INTRIN_VQSHLD_N_U64:
	case ARM64_INTRIN_VQSHLU_N_S16:
	case ARM64_INTRIN_VQSHLU_N_S32:
	case ARM64_INTRIN_VQSHLU_N_S64:
	case ARM64_INTRIN_VQSHLU_N_S8:
	case ARM64_INTRIN_VQSHLUD_N_S64:
	case ARM64_INTRIN_VQSHRND_N_S64:
	case ARM64_INTRIN_VQSHRND_N_U64:
	case ARM64_INTRIN_VQSHRUND_N_S64:
	case ARM64_INTRIN_VRSHR_N_S16:
	case ARM64_INTRIN_VRSHR_N_S32:
	case ARM64_INTRIN_VRSHR_N_S64:
	case ARM64_INTRIN_VRSHR_N_S8:
	case ARM64_INTRIN_VRSHR_N_U16:
	case ARM64_INTRIN_VRSHR_N_U32:
	case ARM64_INTRIN_VRSHR_N_U64:
	case ARM64_INTRIN_VRSHR_N_U8:
	case ARM64_INTRIN_VRSHRD_N_S64:
	case ARM64_INTRIN_VRSHRD_N_U64:
	case ARM64_INTRIN_VSHL_N_S16:
	case ARM64_INTRIN_VSHL_N_S32:
	case ARM64_INTRIN_VSHL_N_S64:
	case ARM64_INTRIN_VSHL_N_S8:
	case ARM64_INTRIN_VSHL_N_U16:
	case ARM64_INTRIN_VSHL_N_U32:
	case ARM64_INTRIN_VSHL_N_U64:
	case ARM64_INTRIN_VSHL_N_U8:
	case ARM64_INTRIN_VSHLD_N_S64:
	case ARM64_INTRIN_VSHLD_N_U64:
	case ARM64_INTRIN_VSHLL_N_S16:
	case ARM64_INTRIN_VSHLL_N_S32:
	case ARM64_INTRIN_VSHLL_N_S8:
	case ARM64_INTRIN_VSHLL_N_U16:
	case ARM64_INTRIN_VSHLL_N_U32:
	case ARM64_INTRIN_VSHLL_N_U8:
	case ARM64_INTRIN_VSHR_N_S16:
	case ARM64_INTRIN_VSHR_N_S32:
	case ARM64_INTRIN_VSHR_N_S64:
	case ARM64_INTRIN_VSHR_N_S8:
	case ARM64_INTRIN_VSHR_N_U16:
	case ARM64_INTRIN_VSHR_N_U32:
	case ARM64_INTRIN_VSHR_N_U64:
	case ARM64_INTRIN_VSHR_N_U8:
	case ARM64_INTRIN_VSHRD_N_S64:
	case ARM64_INTRIN_VSHRD_N_U64:
		return {NameAndType(Type::IntegerType(8, false)), NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VQDMLALS_LANEQ_S32:
	case ARM64_INTRIN_VQDMLSLS_LANEQ_S32:
		return {NameAndType(Type::IntegerType(8, false)), NameAndType(Type::IntegerType(4, false)),
		    NameAndType(Type::IntegerType(16, false)), NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VQDMLALS_S32:
	case ARM64_INTRIN_VQDMLSLS_S32:
		return {NameAndType(Type::IntegerType(8, false)), NameAndType(Type::IntegerType(4, false)),
		    NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VQDMLALS_LANE_S32:
	case ARM64_INTRIN_VQDMLSLS_LANE_S32:
		return {NameAndType(Type::IntegerType(8, false)), NameAndType(Type::IntegerType(4, false)),
		    NameAndType(Type::IntegerType(8, false)), NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VABD_S16:
	case ARM64_INTRIN_VABD_S32:
	case ARM64_INTRIN_VABD_S8:
	case ARM64_INTRIN_VABD_U16:
	case ARM64_INTRIN_VABD_U32:
	case ARM64_INTRIN_VABD_U8:
	case ARM64_INTRIN_VABDL_S16:
	case ARM64_INTRIN_VABDL_S32:
	case ARM64_INTRIN_VABDL_S8:
	case ARM64_INTRIN_VABDL_U16:
	case ARM64_INTRIN_VABDL_U32:
	case ARM64_INTRIN_VABDL_U8:
	case ARM64_INTRIN_VADD_P16:
	case ARM64_INTRIN_VADD_P64:
	case ARM64_INTRIN_VADD_P8:
	case ARM64_INTRIN_VADD_S16:
	case ARM64_INTRIN_VADD_S32:
	case ARM64_INTRIN_VADD_S64:
	case ARM64_INTRIN_VADD_S8:
	case ARM64_INTRIN_VADD_U16:
	case ARM64_INTRIN_VADD_U32:
	case ARM64_INTRIN_VADD_U64:
	case ARM64_INTRIN_VADD_U8:
	case ARM64_INTRIN_VADDD_S64:
	case ARM64_INTRIN_VADDD_U64:
	case ARM64_INTRIN_VADDL_S16:
	case ARM64_INTRIN_VADDL_S32:
	case ARM64_INTRIN_VADDL_S8:
	case ARM64_INTRIN_VADDL_U16:
	case ARM64_INTRIN_VADDL_U32:
	case ARM64_INTRIN_VADDL_U8:
	case ARM64_INTRIN_VAND_S16:
	case ARM64_INTRIN_VAND_S32:
	case ARM64_INTRIN_VAND_S64:
	case ARM64_INTRIN_VAND_S8:
	case ARM64_INTRIN_VAND_U16:
	case ARM64_INTRIN_VAND_U32:
	case ARM64_INTRIN_VAND_U64:
	case ARM64_INTRIN_VAND_U8:
	case ARM64_INTRIN_VBIC_S16:
	case ARM64_INTRIN_VBIC_S32:
	case ARM64_INTRIN_VBIC_S64:
	case ARM64_INTRIN_VBIC_S8:
	case ARM64_INTRIN_VBIC_U16:
	case ARM64_INTRIN_VBIC_U32:
	case ARM64_INTRIN_VBIC_U64:
	case ARM64_INTRIN_VBIC_U8:
	case ARM64_INTRIN_VCEQ_P64:
	case ARM64_INTRIN_VCEQ_P8:
	case ARM64_INTRIN_VCEQ_S16:
	case ARM64_INTRIN_VCEQ_S32:
	case ARM64_INTRIN_VCEQ_S64:
	case ARM64_INTRIN_VCEQ_S8:
	case ARM64_INTRIN_VCEQ_U16:
	case ARM64_INTRIN_VCEQ_U32:
	case ARM64_INTRIN_VCEQ_U64:
	case ARM64_INTRIN_VCEQ_U8:
	case ARM64_INTRIN_VCEQD_S64:
	case ARM64_INTRIN_VCEQD_U64:
	case ARM64_INTRIN_VCGE_S16:
	case ARM64_INTRIN_VCGE_S32:
	case ARM64_INTRIN_VCGE_S64:
	case ARM64_INTRIN_VCGE_S8:
	case ARM64_INTRIN_VCGE_U16:
	case ARM64_INTRIN_VCGE_U32:
	case ARM64_INTRIN_VCGE_U64:
	case ARM64_INTRIN_VCGE_U8:
	case ARM64_INTRIN_VCGED_S64:
	case ARM64_INTRIN_VCGED_U64:
	case ARM64_INTRIN_VCGT_S16:
	case ARM64_INTRIN_VCGT_S32:
	case ARM64_INTRIN_VCGT_S64:
	case ARM64_INTRIN_VCGT_S8:
	case ARM64_INTRIN_VCGT_U16:
	case ARM64_INTRIN_VCGT_U32:
	case ARM64_INTRIN_VCGT_U64:
	case ARM64_INTRIN_VCGT_U8:
	case ARM64_INTRIN_VCGTD_S64:
	case ARM64_INTRIN_VCGTD_U64:
	case ARM64_INTRIN_VCLE_S16:
	case ARM64_INTRIN_VCLE_S32:
	case ARM64_INTRIN_VCLE_S64:
	case ARM64_INTRIN_VCLE_S8:
	case ARM64_INTRIN_VCLE_U16:
	case ARM64_INTRIN_VCLE_U32:
	case ARM64_INTRIN_VCLE_U64:
	case ARM64_INTRIN_VCLE_U8:
	case ARM64_INTRIN_VCLED_S64:
	case ARM64_INTRIN_VCLED_U64:
	case ARM64_INTRIN_VCLT_S16:
	case ARM64_INTRIN_VCLT_S32:
	case ARM64_INTRIN_VCLT_S64:
	case ARM64_INTRIN_VCLT_S8:
	case ARM64_INTRIN_VCLT_U16:
	case ARM64_INTRIN_VCLT_U32:
	case ARM64_INTRIN_VCLT_U64:
	case ARM64_INTRIN_VCLT_U8:
	case ARM64_INTRIN_VCLTD_S64:
	case ARM64_INTRIN_VCLTD_U64:
	case ARM64_INTRIN_VEOR_S16:
	case ARM64_INTRIN_VEOR_S32:
	case ARM64_INTRIN_VEOR_S64:
	case ARM64_INTRIN_VEOR_S8:
	case ARM64_INTRIN_VEOR_U16:
	case ARM64_INTRIN_VEOR_U32:
	case ARM64_INTRIN_VEOR_U64:
	case ARM64_INTRIN_VEOR_U8:
	case ARM64_INTRIN_VHADD_S16:
	case ARM64_INTRIN_VHADD_S32:
	case ARM64_INTRIN_VHADD_S8:
	case ARM64_INTRIN_VHADD_U16:
	case ARM64_INTRIN_VHADD_U32:
	case ARM64_INTRIN_VHADD_U8:
	case ARM64_INTRIN_VHSUB_S16:
	case ARM64_INTRIN_VHSUB_S32:
	case ARM64_INTRIN_VHSUB_S8:
	case ARM64_INTRIN_VHSUB_U16:
	case ARM64_INTRIN_VHSUB_U32:
	case ARM64_INTRIN_VHSUB_U8:
	case ARM64_INTRIN_VMAX_S16:
	case ARM64_INTRIN_VMAX_S32:
	case ARM64_INTRIN_VMAX_S8:
	case ARM64_INTRIN_VMAX_U16:
	case ARM64_INTRIN_VMAX_U32:
	case ARM64_INTRIN_VMAX_U8:
	case ARM64_INTRIN_VMIN_S16:
	case ARM64_INTRIN_VMIN_S32:
	case ARM64_INTRIN_VMIN_S8:
	case ARM64_INTRIN_VMIN_U16:
	case ARM64_INTRIN_VMIN_U32:
	case ARM64_INTRIN_VMIN_U8:
	case ARM64_INTRIN_VMUL_P8:
	case ARM64_INTRIN_VMUL_S16:
	case ARM64_INTRIN_VMUL_S32:
	case ARM64_INTRIN_VMUL_S8:
	case ARM64_INTRIN_VMUL_U16:
	case ARM64_INTRIN_VMUL_U32:
	case ARM64_INTRIN_VMUL_U8:
	case ARM64_INTRIN_VMULL_P64:
	case ARM64_INTRIN_VMULL_P8:
	case ARM64_INTRIN_VMULL_S16:
	case ARM64_INTRIN_VMULL_S32:
	case ARM64_INTRIN_VMULL_S8:
	case ARM64_INTRIN_VMULL_U16:
	case ARM64_INTRIN_VMULL_U32:
	case ARM64_INTRIN_VMULL_U8:
	case ARM64_INTRIN_VORN_S16:
	case ARM64_INTRIN_VORN_S32:
	case ARM64_INTRIN_VORN_S64:
	case ARM64_INTRIN_VORN_S8:
	case ARM64_INTRIN_VORN_U16:
	case ARM64_INTRIN_VORN_U32:
	case ARM64_INTRIN_VORN_U64:
	case ARM64_INTRIN_VORN_U8:
	case ARM64_INTRIN_VORR_S16:
	case ARM64_INTRIN_VORR_S32:
	case ARM64_INTRIN_VORR_S64:
	case ARM64_INTRIN_VORR_S8:
	case ARM64_INTRIN_VORR_U16:
	case ARM64_INTRIN_VORR_U32:
	case ARM64_INTRIN_VORR_U64:
	case ARM64_INTRIN_VORR_U8:
	case ARM64_INTRIN_VPADAL_S16:
	case ARM64_INTRIN_VPADAL_S32:
	case ARM64_INTRIN_VPADAL_S8:
	case ARM64_INTRIN_VPADAL_U16:
	case ARM64_INTRIN_VPADAL_U32:
	case ARM64_INTRIN_VPADAL_U8:
	case ARM64_INTRIN_VPADD_S16:
	case ARM64_INTRIN_VPADD_S32:
	case ARM64_INTRIN_VPADD_S8:
	case ARM64_INTRIN_VPADD_U16:
	case ARM64_INTRIN_VPADD_U32:
	case ARM64_INTRIN_VPADD_U8:
	case ARM64_INTRIN_VPMAX_S16:
	case ARM64_INTRIN_VPMAX_S32:
	case ARM64_INTRIN_VPMAX_S8:
	case ARM64_INTRIN_VPMAX_U16:
	case ARM64_INTRIN_VPMAX_U32:
	case ARM64_INTRIN_VPMAX_U8:
	case ARM64_INTRIN_VPMIN_S16:
	case ARM64_INTRIN_VPMIN_S32:
	case ARM64_INTRIN_VPMIN_S8:
	case ARM64_INTRIN_VPMIN_U16:
	case ARM64_INTRIN_VPMIN_U32:
	case ARM64_INTRIN_VPMIN_U8:
	case ARM64_INTRIN_VQADD_S16:
	case ARM64_INTRIN_VQADD_S32:
	case ARM64_INTRIN_VQADD_S64:
	case ARM64_INTRIN_VQADD_S8:
	case ARM64_INTRIN_VQADD_U16:
	case ARM64_INTRIN_VQADD_U32:
	case ARM64_INTRIN_VQADD_U64:
	case ARM64_INTRIN_VQADD_U8:
	case ARM64_INTRIN_VQADDD_S64:
	case ARM64_INTRIN_VQADDD_U64:
	case ARM64_INTRIN_VQDMULH_S16:
	case ARM64_INTRIN_VQDMULH_S32:
	case ARM64_INTRIN_VQDMULL_S16:
	case ARM64_INTRIN_VQDMULL_S32:
	case ARM64_INTRIN_VQRDMULH_S16:
	case ARM64_INTRIN_VQRDMULH_S32:
	case ARM64_INTRIN_VQRSHL_S16:
	case ARM64_INTRIN_VQRSHL_S32:
	case ARM64_INTRIN_VQRSHL_S64:
	case ARM64_INTRIN_VQRSHL_S8:
	case ARM64_INTRIN_VQRSHL_U16:
	case ARM64_INTRIN_VQRSHL_U32:
	case ARM64_INTRIN_VQRSHL_U64:
	case ARM64_INTRIN_VQRSHL_U8:
	case ARM64_INTRIN_VQRSHLD_S64:
	case ARM64_INTRIN_VQRSHLD_U64:
	case ARM64_INTRIN_VQSHL_S16:
	case ARM64_INTRIN_VQSHL_S32:
	case ARM64_INTRIN_VQSHL_S64:
	case ARM64_INTRIN_VQSHL_S8:
	case ARM64_INTRIN_VQSHL_U16:
	case ARM64_INTRIN_VQSHL_U32:
	case ARM64_INTRIN_VQSHL_U64:
	case ARM64_INTRIN_VQSHL_U8:
	case ARM64_INTRIN_VQSHLD_S64:
	case ARM64_INTRIN_VQSHLD_U64:
	case ARM64_INTRIN_VQSUB_S16:
	case ARM64_INTRIN_VQSUB_S32:
	case ARM64_INTRIN_VQSUB_S64:
	case ARM64_INTRIN_VQSUB_S8:
	case ARM64_INTRIN_VQSUB_U16:
	case ARM64_INTRIN_VQSUB_U32:
	case ARM64_INTRIN_VQSUB_U64:
	case ARM64_INTRIN_VQSUB_U8:
	case ARM64_INTRIN_VQSUBD_S64:
	case ARM64_INTRIN_VQSUBD_U64:
	case ARM64_INTRIN_VRHADD_S16:
	case ARM64_INTRIN_VRHADD_S32:
	case ARM64_INTRIN_VRHADD_S8:
	case ARM64_INTRIN_VRHADD_U16:
	case ARM64_INTRIN_VRHADD_U32:
	case ARM64_INTRIN_VRHADD_U8:
	case ARM64_INTRIN_VRSHL_S16:
	case ARM64_INTRIN_VRSHL_S32:
	case ARM64_INTRIN_VRSHL_S64:
	case ARM64_INTRIN_VRSHL_S8:
	case ARM64_INTRIN_VRSHL_U16:
	case ARM64_INTRIN_VRSHL_U32:
	case ARM64_INTRIN_VRSHL_U64:
	case ARM64_INTRIN_VRSHL_U8:
	case ARM64_INTRIN_VRSHLD_S64:
	case ARM64_INTRIN_VRSHLD_U64:
	case ARM64_INTRIN_VSHL_S16:
	case ARM64_INTRIN_VSHL_S32:
	case ARM64_INTRIN_VSHL_S64:
	case ARM64_INTRIN_VSHL_S8:
	case ARM64_INTRIN_VSHL_U16:
	case ARM64_INTRIN_VSHL_U32:
	case ARM64_INTRIN_VSHL_U64:
	case ARM64_INTRIN_VSHL_U8:
	case ARM64_INTRIN_VSHLD_S64:
	case ARM64_INTRIN_VSHLD_U64:
	case ARM64_INTRIN_VSQADD_U16:
	case ARM64_INTRIN_VSQADD_U32:
	case ARM64_INTRIN_VSQADD_U64:
	case ARM64_INTRIN_VSQADD_U8:
	case ARM64_INTRIN_VSQADDD_U64:
	case ARM64_INTRIN_VSUB_S16:
	case ARM64_INTRIN_VSUB_S32:
	case ARM64_INTRIN_VSUB_S64:
	case ARM64_INTRIN_VSUB_S8:
	case ARM64_INTRIN_VSUB_U16:
	case ARM64_INTRIN_VSUB_U32:
	case ARM64_INTRIN_VSUB_U64:
	case ARM64_INTRIN_VSUB_U8:
	case ARM64_INTRIN_VSUBD_S64:
	case ARM64_INTRIN_VSUBD_U64:
	case ARM64_INTRIN_VSUBL_S16:
	case ARM64_INTRIN_VSUBL_S32:
	case ARM64_INTRIN_VSUBL_S8:
	case ARM64_INTRIN_VSUBL_U16:
	case ARM64_INTRIN_VSUBL_U32:
	case ARM64_INTRIN_VSUBL_U8:
	case ARM64_INTRIN_VTRN1_P16:
	case ARM64_INTRIN_VTRN1_P8:
	case ARM64_INTRIN_VTRN1_S16:
	case ARM64_INTRIN_VTRN1_S32:
	case ARM64_INTRIN_VTRN1_S8:
	case ARM64_INTRIN_VTRN1_U16:
	case ARM64_INTRIN_VTRN1_U32:
	case ARM64_INTRIN_VTRN1_U8:
	case ARM64_INTRIN_VTRN2_P16:
	case ARM64_INTRIN_VTRN2_P8:
	case ARM64_INTRIN_VTRN2_S16:
	case ARM64_INTRIN_VTRN2_S32:
	case ARM64_INTRIN_VTRN2_S8:
	case ARM64_INTRIN_VTRN2_U16:
	case ARM64_INTRIN_VTRN2_U32:
	case ARM64_INTRIN_VTRN2_U8:
	case ARM64_INTRIN_VTST_P64:
	case ARM64_INTRIN_VTST_P8:
	case ARM64_INTRIN_VTST_S16:
	case ARM64_INTRIN_VTST_S32:
	case ARM64_INTRIN_VTST_S64:
	case ARM64_INTRIN_VTST_S8:
	case ARM64_INTRIN_VTST_U16:
	case ARM64_INTRIN_VTST_U32:
	case ARM64_INTRIN_VTST_U64:
	case ARM64_INTRIN_VTST_U8:
	case ARM64_INTRIN_VTSTD_S64:
	case ARM64_INTRIN_VTSTD_U64:
	case ARM64_INTRIN_VUQADD_S16:
	case ARM64_INTRIN_VUQADD_S32:
	case ARM64_INTRIN_VUQADD_S64:
	case ARM64_INTRIN_VUQADD_S8:
	case ARM64_INTRIN_VUQADDD_S64:
	case ARM64_INTRIN_VUZP1_P16:
	case ARM64_INTRIN_VUZP1_P8:
	case ARM64_INTRIN_VUZP1_S16:
	case ARM64_INTRIN_VUZP1_S32:
	case ARM64_INTRIN_VUZP1_S8:
	case ARM64_INTRIN_VUZP1_U16:
	case ARM64_INTRIN_VUZP1_U32:
	case ARM64_INTRIN_VUZP1_U8:
	case ARM64_INTRIN_VUZP2_P16:
	case ARM64_INTRIN_VUZP2_P8:
	case ARM64_INTRIN_VUZP2_S16:
	case ARM64_INTRIN_VUZP2_S32:
	case ARM64_INTRIN_VUZP2_S8:
	case ARM64_INTRIN_VUZP2_U16:
	case ARM64_INTRIN_VUZP2_U32:
	case ARM64_INTRIN_VUZP2_U8:
	case ARM64_INTRIN_VZIP1_P16:
	case ARM64_INTRIN_VZIP1_P8:
	case ARM64_INTRIN_VZIP1_S16:
	case ARM64_INTRIN_VZIP1_S32:
	case ARM64_INTRIN_VZIP1_S8:
	case ARM64_INTRIN_VZIP1_U16:
	case ARM64_INTRIN_VZIP1_U32:
	case ARM64_INTRIN_VZIP1_U8:
	case ARM64_INTRIN_VZIP2_P16:
	case ARM64_INTRIN_VZIP2_P8:
	case ARM64_INTRIN_VZIP2_S16:
	case ARM64_INTRIN_VZIP2_S32:
	case ARM64_INTRIN_VZIP2_S8:
	case ARM64_INTRIN_VZIP2_U16:
	case ARM64_INTRIN_VZIP2_U32:
	case ARM64_INTRIN_VZIP2_U8:
		return {NameAndType(Type::IntegerType(8, false)), NameAndType(Type::IntegerType(8, false))};
	case ARM64_INTRIN_VDOT_LANEQ_S32:
	case ARM64_INTRIN_VDOT_LANEQ_U32:
	case ARM64_INTRIN_VMLA_LANEQ_S16:
	case ARM64_INTRIN_VMLA_LANEQ_S32:
	case ARM64_INTRIN_VMLA_LANEQ_U16:
	case ARM64_INTRIN_VMLA_LANEQ_U32:
	case ARM64_INTRIN_VMLS_LANEQ_S16:
	case ARM64_INTRIN_VMLS_LANEQ_S32:
	case ARM64_INTRIN_VMLS_LANEQ_U16:
	case ARM64_INTRIN_VMLS_LANEQ_U32:
	case ARM64_INTRIN_VQRDMLAH_LANEQ_S16:
	case ARM64_INTRIN_VQRDMLAH_LANEQ_S32:
	case ARM64_INTRIN_VQRDMLSH_LANEQ_S16:
	case ARM64_INTRIN_VQRDMLSH_LANEQ_S32:
	case ARM64_INTRIN_VSUDOT_LANEQ_S32:
	case ARM64_INTRIN_VUSDOT_LANEQ_S32:
		return {NameAndType(Type::IntegerType(8, false)), NameAndType(Type::IntegerType(8, false)),
		    NameAndType(Type::IntegerType(16, false)), NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VMLA_N_S16:
	case ARM64_INTRIN_VMLA_N_U16:
	case ARM64_INTRIN_VMLS_N_S16:
	case ARM64_INTRIN_VMLS_N_U16:
		return {NameAndType(Type::IntegerType(8, false)), NameAndType(Type::IntegerType(8, false)),
		    NameAndType(Type::IntegerType(2, false))};
	case ARM64_INTRIN_VEXT_P16:
	case ARM64_INTRIN_VEXT_P64:
	case ARM64_INTRIN_VEXT_P8:
	case ARM64_INTRIN_VEXT_S16:
	case ARM64_INTRIN_VEXT_S32:
	case ARM64_INTRIN_VEXT_S64:
	case ARM64_INTRIN_VEXT_S8:
	case ARM64_INTRIN_VEXT_U16:
	case ARM64_INTRIN_VEXT_U32:
	case ARM64_INTRIN_VEXT_U64:
	case ARM64_INTRIN_VEXT_U8:
	case ARM64_INTRIN_VMLA_N_S32:
	case ARM64_INTRIN_VMLA_N_U32:
	case ARM64_INTRIN_VMLS_N_S32:
	case ARM64_INTRIN_VMLS_N_U32:
	case ARM64_INTRIN_VMUL_LANE_S16:
	case ARM64_INTRIN_VMUL_LANE_S32:
	case ARM64_INTRIN_VMUL_LANE_U16:
	case ARM64_INTRIN_VMUL_LANE_U32:
	case ARM64_INTRIN_VMULL_LANE_S16:
	case ARM64_INTRIN_VMULL_LANE_S32:
	case ARM64_INTRIN_VMULL_LANE_U16:
	case ARM64_INTRIN_VMULL_LANE_U32:
	case ARM64_INTRIN_VQDMULH_LANE_S16:
	case ARM64_INTRIN_VQDMULH_LANE_S32:
	case ARM64_INTRIN_VQDMULL_LANE_S16:
	case ARM64_INTRIN_VQDMULL_LANE_S32:
	case ARM64_INTRIN_VQRDMULH_LANE_S16:
	case ARM64_INTRIN_VQRDMULH_LANE_S32:
	case ARM64_INTRIN_VRSRA_N_S16:
	case ARM64_INTRIN_VRSRA_N_S32:
	case ARM64_INTRIN_VRSRA_N_S64:
	case ARM64_INTRIN_VRSRA_N_S8:
	case ARM64_INTRIN_VRSRA_N_U16:
	case ARM64_INTRIN_VRSRA_N_U32:
	case ARM64_INTRIN_VRSRA_N_U64:
	case ARM64_INTRIN_VRSRA_N_U8:
	case ARM64_INTRIN_VRSRAD_N_S64:
	case ARM64_INTRIN_VRSRAD_N_U64:
	case ARM64_INTRIN_VSET_LANE_P64:
	case ARM64_INTRIN_VSET_LANE_S64:
	case ARM64_INTRIN_VSET_LANE_U64:
	case ARM64_INTRIN_VSLI_N_P16:
	case ARM64_INTRIN_VSLI_N_P64:
	case ARM64_INTRIN_VSLI_N_P8:
	case ARM64_INTRIN_VSLI_N_S16:
	case ARM64_INTRIN_VSLI_N_S32:
	case ARM64_INTRIN_VSLI_N_S64:
	case ARM64_INTRIN_VSLI_N_S8:
	case ARM64_INTRIN_VSLI_N_U16:
	case ARM64_INTRIN_VSLI_N_U32:
	case ARM64_INTRIN_VSLI_N_U64:
	case ARM64_INTRIN_VSLI_N_U8:
	case ARM64_INTRIN_VSLID_N_S64:
	case ARM64_INTRIN_VSLID_N_U64:
	case ARM64_INTRIN_VSRA_N_S16:
	case ARM64_INTRIN_VSRA_N_S32:
	case ARM64_INTRIN_VSRA_N_S64:
	case ARM64_INTRIN_VSRA_N_S8:
	case ARM64_INTRIN_VSRA_N_U16:
	case ARM64_INTRIN_VSRA_N_U32:
	case ARM64_INTRIN_VSRA_N_U64:
	case ARM64_INTRIN_VSRA_N_U8:
	case ARM64_INTRIN_VSRAD_N_S64:
	case ARM64_INTRIN_VSRAD_N_U64:
	case ARM64_INTRIN_VSRI_N_P16:
	case ARM64_INTRIN_VSRI_N_P64:
	case ARM64_INTRIN_VSRI_N_P8:
	case ARM64_INTRIN_VSRI_N_S16:
	case ARM64_INTRIN_VSRI_N_S32:
	case ARM64_INTRIN_VSRI_N_S64:
	case ARM64_INTRIN_VSRI_N_S8:
	case ARM64_INTRIN_VSRI_N_U16:
	case ARM64_INTRIN_VSRI_N_U32:
	case ARM64_INTRIN_VSRI_N_U64:
	case ARM64_INTRIN_VSRI_N_U8:
	case ARM64_INTRIN_VSRID_N_S64:
	case ARM64_INTRIN_VSRID_N_U64:
		return {NameAndType(Type::IntegerType(8, false)), NameAndType(Type::IntegerType(8, false)),
		    NameAndType(Type::IntegerType(4, false))};
	case ARM64_INTRIN_VABA_S16:
	case ARM64_INTRIN_VABA_S32:
	case ARM64_INTRIN_VABA_S8:
	case ARM64_INTRIN_VABA_U16:
	case ARM64_INTRIN_VABA_U32:
	case ARM64_INTRIN_VABA_U8:
	case ARM64_INTRIN_VBSL_P16:
	case ARM64_INTRIN_VBSL_P64:
	case ARM64_INTRIN_VBSL_P8:
	case ARM64_INTRIN_VBSL_S16:
	case ARM64_INTRIN_VBSL_S32:
	case ARM64_INTRIN_VBSL_S64:
	case ARM64_INTRIN_VBSL_S8:
	case ARM64_INTRIN_VBSL_U16:
	case ARM64_INTRIN_VBSL_U32:
	case ARM64_INTRIN_VBSL_U64:
	case ARM64_INTRIN_VBSL_U8:
	case ARM64_INTRIN_VDOT_S32:
	case ARM64_INTRIN_VDOT_U32:
	case ARM64_INTRIN_VMLA_S16:
	case ARM64_INTRIN_VMLA_S32:
	case ARM64_INTRIN_VMLA_S8:
	case ARM64_INTRIN_VMLA_U16:
	case ARM64_INTRIN_VMLA_U32:
	case ARM64_INTRIN_VMLA_U8:
	case ARM64_INTRIN_VMLS_S16:
	case ARM64_INTRIN_VMLS_S32:
	case ARM64_INTRIN_VMLS_S8:
	case ARM64_INTRIN_VMLS_U16:
	case ARM64_INTRIN_VMLS_U32:
	case ARM64_INTRIN_VMLS_U8:
	case ARM64_INTRIN_VQRDMLAH_S16:
	case ARM64_INTRIN_VQRDMLAH_S32:
	case ARM64_INTRIN_VQRDMLSH_S16:
	case ARM64_INTRIN_VQRDMLSH_S32:
	case ARM64_INTRIN_VUSDOT_S32:
		return {NameAndType(Type::IntegerType(8, false)), NameAndType(Type::IntegerType(8, false)),
		    NameAndType(Type::IntegerType(8, false))};
	case ARM64_INTRIN_VDOT_LANE_S32:
	case ARM64_INTRIN_VDOT_LANE_U32:
	case ARM64_INTRIN_VMLA_LANE_S16:
	case ARM64_INTRIN_VMLA_LANE_S32:
	case ARM64_INTRIN_VMLA_LANE_U16:
	case ARM64_INTRIN_VMLA_LANE_U32:
	case ARM64_INTRIN_VMLS_LANE_S16:
	case ARM64_INTRIN_VMLS_LANE_S32:
	case ARM64_INTRIN_VMLS_LANE_U16:
	case ARM64_INTRIN_VMLS_LANE_U32:
	case ARM64_INTRIN_VQRDMLAH_LANE_S16:
	case ARM64_INTRIN_VQRDMLAH_LANE_S32:
	case ARM64_INTRIN_VQRDMLSH_LANE_S16:
	case ARM64_INTRIN_VQRDMLSH_LANE_S32:
	case ARM64_INTRIN_VSUDOT_LANE_S32:
	case ARM64_INTRIN_VUSDOT_LANE_S32:
		return {NameAndType(Type::IntegerType(8, false)), NameAndType(Type::IntegerType(8, false)),
		    NameAndType(Type::IntegerType(8, false)), NameAndType(Type::IntegerType(4, false))};

	default:
		return vector<NameAndType>();
	}
}

vector<Confidence<Ref<Type>>> NeonGetIntrinsicOutputs(uint32_t intrinsic)
{
	switch (intrinsic)
	{
	case ARM64_INTRIN_VABDQ_F16:
	case ARM64_INTRIN_VABDQ_F32:
	case ARM64_INTRIN_VABDQ_F64:
	case ARM64_INTRIN_VABSQ_F16:
	case ARM64_INTRIN_VABSQ_F32:
	case ARM64_INTRIN_VABSQ_F64:
	case ARM64_INTRIN_VADDQ_F16:
	case ARM64_INTRIN_VADDQ_F32:
	case ARM64_INTRIN_VADDQ_F64:
	case ARM64_INTRIN_VBFDOTQ_F32:
	case ARM64_INTRIN_VBFDOTQ_LANE_F32:
	case ARM64_INTRIN_VBFDOTQ_LANEQ_F32:
	case ARM64_INTRIN_VBFMLALBQ_F32:
	case ARM64_INTRIN_VBFMLALBQ_LANE_F32:
	case ARM64_INTRIN_VBFMLALBQ_LANEQ_F32:
	case ARM64_INTRIN_VBFMLALTQ_F32:
	case ARM64_INTRIN_VBFMLALTQ_LANE_F32:
	case ARM64_INTRIN_VBFMLALTQ_LANEQ_F32:
	case ARM64_INTRIN_VBFMMLAQ_F32:
	case ARM64_INTRIN_VBSLQ_F16:
	case ARM64_INTRIN_VBSLQ_F32:
	case ARM64_INTRIN_VBSLQ_F64:
	case ARM64_INTRIN_VCADDQ_ROT270_F16:
	case ARM64_INTRIN_VCADDQ_ROT270_F32:
	case ARM64_INTRIN_VCADDQ_ROT270_F64:
	case ARM64_INTRIN_VCADDQ_ROT90_F16:
	case ARM64_INTRIN_VCADDQ_ROT90_F32:
	case ARM64_INTRIN_VCADDQ_ROT90_F64:
	case ARM64_INTRIN_VCMLAQ_F16:
	case ARM64_INTRIN_VCMLAQ_F32:
	case ARM64_INTRIN_VCMLAQ_F64:
	case ARM64_INTRIN_VCMLAQ_LANE_F16:
	case ARM64_INTRIN_VCMLAQ_LANE_F32:
	case ARM64_INTRIN_VCMLAQ_LANEQ_F16:
	case ARM64_INTRIN_VCMLAQ_LANEQ_F32:
	case ARM64_INTRIN_VCMLAQ_ROT180_F16:
	case ARM64_INTRIN_VCMLAQ_ROT180_F32:
	case ARM64_INTRIN_VCMLAQ_ROT180_F64:
	case ARM64_INTRIN_VCMLAQ_ROT180_LANE_F16:
	case ARM64_INTRIN_VCMLAQ_ROT180_LANE_F32:
	case ARM64_INTRIN_VCMLAQ_ROT180_LANEQ_F16:
	case ARM64_INTRIN_VCMLAQ_ROT180_LANEQ_F32:
	case ARM64_INTRIN_VCMLAQ_ROT270_F16:
	case ARM64_INTRIN_VCMLAQ_ROT270_F32:
	case ARM64_INTRIN_VCMLAQ_ROT270_F64:
	case ARM64_INTRIN_VCMLAQ_ROT270_LANE_F16:
	case ARM64_INTRIN_VCMLAQ_ROT270_LANE_F32:
	case ARM64_INTRIN_VCMLAQ_ROT270_LANEQ_F16:
	case ARM64_INTRIN_VCMLAQ_ROT270_LANEQ_F32:
	case ARM64_INTRIN_VCMLAQ_ROT90_F16:
	case ARM64_INTRIN_VCMLAQ_ROT90_F32:
	case ARM64_INTRIN_VCMLAQ_ROT90_F64:
	case ARM64_INTRIN_VCMLAQ_ROT90_LANE_F16:
	case ARM64_INTRIN_VCMLAQ_ROT90_LANE_F32:
	case ARM64_INTRIN_VCMLAQ_ROT90_LANEQ_F16:
	case ARM64_INTRIN_VCMLAQ_ROT90_LANEQ_F32:
	case ARM64_INTRIN_VCVT_F32_BF16:
	case ARM64_INTRIN_VCVT_F32_F16:
	case ARM64_INTRIN_VCVT_F64_F32:
	case ARM64_INTRIN_VCVT_HIGH_F16_F32:
	case ARM64_INTRIN_VCVT_HIGH_F32_F16:
	case ARM64_INTRIN_VCVT_HIGH_F32_F64:
	case ARM64_INTRIN_VCVT_HIGH_F64_F32:
	case ARM64_INTRIN_VCVTQ_F16_S16:
	case ARM64_INTRIN_VCVTQ_F16_U16:
	case ARM64_INTRIN_VCVTQ_F32_S32:
	case ARM64_INTRIN_VCVTQ_F32_U32:
	case ARM64_INTRIN_VCVTQ_F64_S64:
	case ARM64_INTRIN_VCVTQ_F64_U64:
	case ARM64_INTRIN_VCVTQ_HIGH_BF16_F32:
	case ARM64_INTRIN_VCVTQ_HIGH_F32_BF16:
	case ARM64_INTRIN_VCVTQ_LOW_BF16_F32:
	case ARM64_INTRIN_VCVTQ_LOW_F32_BF16:
	case ARM64_INTRIN_VCVTQ_N_F16_S16:
	case ARM64_INTRIN_VCVTQ_N_F16_U16:
	case ARM64_INTRIN_VCVTQ_N_F32_S32:
	case ARM64_INTRIN_VCVTQ_N_F32_U32:
	case ARM64_INTRIN_VCVTQ_N_F64_S64:
	case ARM64_INTRIN_VCVTQ_N_F64_U64:
	case ARM64_INTRIN_VCVTX_HIGH_F32_F64:
	case ARM64_INTRIN_VDIVQ_F16:
	case ARM64_INTRIN_VDIVQ_F32:
	case ARM64_INTRIN_VDIVQ_F64:
	case ARM64_INTRIN_VDUPQ_LANE_BF16:
	case ARM64_INTRIN_VDUPQ_LANE_F16:
	case ARM64_INTRIN_VDUPQ_LANE_F32:
	case ARM64_INTRIN_VDUPQ_LANE_F64:
	case ARM64_INTRIN_VDUPQ_LANEQ_BF16:
	case ARM64_INTRIN_VDUPQ_LANEQ_F16:
	case ARM64_INTRIN_VDUPQ_LANEQ_F32:
	case ARM64_INTRIN_VDUPQ_LANEQ_F64:
	case ARM64_INTRIN_VDUPQ_N_BF16:
	case ARM64_INTRIN_VDUPQ_N_F16:
	case ARM64_INTRIN_VDUPQ_N_F32:
	case ARM64_INTRIN_VDUPQ_N_F64:
	case ARM64_INTRIN_VEXTQ_F16:
	case ARM64_INTRIN_VEXTQ_F32:
	case ARM64_INTRIN_VEXTQ_F64:
	case ARM64_INTRIN_VFMAQ_F16:
	case ARM64_INTRIN_VFMAQ_F32:
	case ARM64_INTRIN_VFMAQ_F64:
	case ARM64_INTRIN_VFMAQ_LANE_F16:
	case ARM64_INTRIN_VFMAQ_LANE_F32:
	case ARM64_INTRIN_VFMAQ_LANE_F64:
	case ARM64_INTRIN_VFMAQ_LANEQ_F16:
	case ARM64_INTRIN_VFMAQ_LANEQ_F32:
	case ARM64_INTRIN_VFMAQ_LANEQ_F64:
	case ARM64_INTRIN_VFMAQ_N_F16:
	case ARM64_INTRIN_VFMAQ_N_F32:
	case ARM64_INTRIN_VFMAQ_N_F64:
	case ARM64_INTRIN_VFMLALQ_HIGH_F16:
	case ARM64_INTRIN_VFMLALQ_LANE_HIGH_F16:
	case ARM64_INTRIN_VFMLALQ_LANE_LOW_F16:
	case ARM64_INTRIN_VFMLALQ_LANEQ_HIGH_F16:
	case ARM64_INTRIN_VFMLALQ_LANEQ_LOW_F16:
	case ARM64_INTRIN_VFMLALQ_LOW_F16:
	case ARM64_INTRIN_VFMLSLQ_HIGH_F16:
	case ARM64_INTRIN_VFMLSLQ_LANE_HIGH_F16:
	case ARM64_INTRIN_VFMLSLQ_LANE_LOW_F16:
	case ARM64_INTRIN_VFMLSLQ_LANEQ_HIGH_F16:
	case ARM64_INTRIN_VFMLSLQ_LANEQ_LOW_F16:
	case ARM64_INTRIN_VFMLSLQ_LOW_F16:
	case ARM64_INTRIN_VFMSQ_F16:
	case ARM64_INTRIN_VFMSQ_F32:
	case ARM64_INTRIN_VFMSQ_F64:
	case ARM64_INTRIN_VFMSQ_LANE_F16:
	case ARM64_INTRIN_VFMSQ_LANE_F32:
	case ARM64_INTRIN_VFMSQ_LANE_F64:
	case ARM64_INTRIN_VFMSQ_LANEQ_F16:
	case ARM64_INTRIN_VFMSQ_LANEQ_F32:
	case ARM64_INTRIN_VFMSQ_LANEQ_F64:
	case ARM64_INTRIN_VFMSQ_N_F16:
	case ARM64_INTRIN_VFMSQ_N_F32:
	case ARM64_INTRIN_VFMSQ_N_F64:
	case ARM64_INTRIN_VMAXNMQ_F16:
	case ARM64_INTRIN_VMAXNMQ_F32:
	case ARM64_INTRIN_VMAXNMQ_F64:
	case ARM64_INTRIN_VMAXQ_F16:
	case ARM64_INTRIN_VMAXQ_F32:
	case ARM64_INTRIN_VMAXQ_F64:
	case ARM64_INTRIN_VMINNMQ_F16:
	case ARM64_INTRIN_VMINNMQ_F32:
	case ARM64_INTRIN_VMINNMQ_F64:
	case ARM64_INTRIN_VMINQ_F16:
	case ARM64_INTRIN_VMINQ_F32:
	case ARM64_INTRIN_VMINQ_F64:
	case ARM64_INTRIN_VMOVQ_N_F16:
	case ARM64_INTRIN_VMOVQ_N_F32:
	case ARM64_INTRIN_VMOVQ_N_F64:
	case ARM64_INTRIN_VMULQ_F16:
	case ARM64_INTRIN_VMULQ_F32:
	case ARM64_INTRIN_VMULQ_F64:
	case ARM64_INTRIN_VMULQ_LANE_F16:
	case ARM64_INTRIN_VMULQ_LANE_F32:
	case ARM64_INTRIN_VMULQ_LANE_F64:
	case ARM64_INTRIN_VMULQ_LANEQ_F16:
	case ARM64_INTRIN_VMULQ_LANEQ_F32:
	case ARM64_INTRIN_VMULQ_LANEQ_F64:
	case ARM64_INTRIN_VMULQ_N_F16:
	case ARM64_INTRIN_VMULQ_N_F32:
	case ARM64_INTRIN_VMULQ_N_F64:
	case ARM64_INTRIN_VMULXQ_F16:
	case ARM64_INTRIN_VMULXQ_F32:
	case ARM64_INTRIN_VMULXQ_F64:
	case ARM64_INTRIN_VMULXQ_LANE_F16:
	case ARM64_INTRIN_VMULXQ_LANE_F32:
	case ARM64_INTRIN_VMULXQ_LANE_F64:
	case ARM64_INTRIN_VMULXQ_LANEQ_F16:
	case ARM64_INTRIN_VMULXQ_LANEQ_F32:
	case ARM64_INTRIN_VMULXQ_LANEQ_F64:
	case ARM64_INTRIN_VMULXQ_N_F16:
	case ARM64_INTRIN_VNEGQ_F16:
	case ARM64_INTRIN_VNEGQ_F32:
	case ARM64_INTRIN_VNEGQ_F64:
	case ARM64_INTRIN_VPADDQ_F16:
	case ARM64_INTRIN_VPADDQ_F32:
	case ARM64_INTRIN_VPADDQ_F64:
	case ARM64_INTRIN_VPMAXNMQ_F16:
	case ARM64_INTRIN_VPMAXNMQ_F32:
	case ARM64_INTRIN_VPMAXNMQ_F64:
	case ARM64_INTRIN_VPMAXQ_F16:
	case ARM64_INTRIN_VPMAXQ_F32:
	case ARM64_INTRIN_VPMAXQ_F64:
	case ARM64_INTRIN_VPMINNMQ_F16:
	case ARM64_INTRIN_VPMINNMQ_F32:
	case ARM64_INTRIN_VPMINNMQ_F64:
	case ARM64_INTRIN_VPMINQ_F16:
	case ARM64_INTRIN_VPMINQ_F32:
	case ARM64_INTRIN_VPMINQ_F64:
	case ARM64_INTRIN_VRECPEQ_F16:
	case ARM64_INTRIN_VRECPEQ_F32:
	case ARM64_INTRIN_VRECPEQ_F64:
	case ARM64_INTRIN_VRECPSQ_F16:
	case ARM64_INTRIN_VRECPSQ_F32:
	case ARM64_INTRIN_VRECPSQ_F64:
	case ARM64_INTRIN_VREV64Q_F16:
	case ARM64_INTRIN_VREV64Q_F32:
	case ARM64_INTRIN_VRND32XQ_F32:
	case ARM64_INTRIN_VRND32XQ_F64:
	case ARM64_INTRIN_VRND32ZQ_F32:
	case ARM64_INTRIN_VRND32ZQ_F64:
	case ARM64_INTRIN_VRND64XQ_F32:
	case ARM64_INTRIN_VRND64XQ_F64:
	case ARM64_INTRIN_VRND64ZQ_F32:
	case ARM64_INTRIN_VRND64ZQ_F64:
	case ARM64_INTRIN_VRNDAQ_F16:
	case ARM64_INTRIN_VRNDAQ_F32:
	case ARM64_INTRIN_VRNDAQ_F64:
	case ARM64_INTRIN_VRNDIQ_F16:
	case ARM64_INTRIN_VRNDIQ_F32:
	case ARM64_INTRIN_VRNDIQ_F64:
	case ARM64_INTRIN_VRNDMQ_F16:
	case ARM64_INTRIN_VRNDMQ_F32:
	case ARM64_INTRIN_VRNDMQ_F64:
	case ARM64_INTRIN_VRNDNQ_F16:
	case ARM64_INTRIN_VRNDNQ_F32:
	case ARM64_INTRIN_VRNDNQ_F64:
	case ARM64_INTRIN_VRNDPQ_F16:
	case ARM64_INTRIN_VRNDPQ_F32:
	case ARM64_INTRIN_VRNDPQ_F64:
	case ARM64_INTRIN_VRNDQ_F16:
	case ARM64_INTRIN_VRNDQ_F32:
	case ARM64_INTRIN_VRNDQ_F64:
	case ARM64_INTRIN_VRNDXQ_F16:
	case ARM64_INTRIN_VRNDXQ_F32:
	case ARM64_INTRIN_VRNDXQ_F64:
	case ARM64_INTRIN_VRSQRTEQ_F16:
	case ARM64_INTRIN_VRSQRTEQ_F32:
	case ARM64_INTRIN_VRSQRTEQ_F64:
	case ARM64_INTRIN_VRSQRTSQ_F16:
	case ARM64_INTRIN_VRSQRTSQ_F32:
	case ARM64_INTRIN_VRSQRTSQ_F64:
	case ARM64_INTRIN_VSETQ_LANE_BF16:
	case ARM64_INTRIN_VSETQ_LANE_F16:
	case ARM64_INTRIN_VSETQ_LANE_F32:
	case ARM64_INTRIN_VSETQ_LANE_F64:
	case ARM64_INTRIN_VSQRTQ_F16:
	case ARM64_INTRIN_VSQRTQ_F32:
	case ARM64_INTRIN_VSQRTQ_F64:
	case ARM64_INTRIN_VSUBQ_F16:
	case ARM64_INTRIN_VSUBQ_F32:
	case ARM64_INTRIN_VSUBQ_F64:
	case ARM64_INTRIN_VTRN1Q_F16:
	case ARM64_INTRIN_VTRN1Q_F32:
	case ARM64_INTRIN_VTRN1Q_F64:
	case ARM64_INTRIN_VTRN2Q_F16:
	case ARM64_INTRIN_VTRN2Q_F32:
	case ARM64_INTRIN_VTRN2Q_F64:
	case ARM64_INTRIN_VUZP1Q_F16:
	case ARM64_INTRIN_VUZP1Q_F32:
	case ARM64_INTRIN_VUZP1Q_F64:
	case ARM64_INTRIN_VUZP2Q_F16:
	case ARM64_INTRIN_VUZP2Q_F32:
	case ARM64_INTRIN_VUZP2Q_F64:
	case ARM64_INTRIN_VZIP1Q_F16:
	case ARM64_INTRIN_VZIP1Q_F32:
	case ARM64_INTRIN_VZIP1Q_F64:
	case ARM64_INTRIN_VZIP2Q_F16:
	case ARM64_INTRIN_VZIP2Q_F32:
	case ARM64_INTRIN_VZIP2Q_F64:
	case ARM64_INTRIN_VCVTH_N_F16_U32:
		return {Type::FloatType(16)};
	case ARM64_INTRIN_VABDH_F16:
	case ARM64_INTRIN_VABSH_F16:
	case ARM64_INTRIN_VADDH_F16:
	case ARM64_INTRIN_VCVTH_BF16_F32:
	case ARM64_INTRIN_VCVTH_F16_S16:
	case ARM64_INTRIN_VCVTH_F16_S32:
	case ARM64_INTRIN_VCVTH_F16_S64:
	case ARM64_INTRIN_VCVTH_F16_U16:
	case ARM64_INTRIN_VCVTH_F16_U32:
	case ARM64_INTRIN_VCVTH_F16_U64:
	case ARM64_INTRIN_VCVTH_N_F16_S16:
	case ARM64_INTRIN_VCVTH_N_F16_S32:
	case ARM64_INTRIN_VCVTH_N_F16_S64:
	case ARM64_INTRIN_VCVTH_N_F16_U16:
	case ARM64_INTRIN_VDIVH_F16:
	case ARM64_INTRIN_VDUPH_LANE_BF16:
	case ARM64_INTRIN_VDUPH_LANE_F16:
	case ARM64_INTRIN_VDUPH_LANEQ_BF16:
	case ARM64_INTRIN_VDUPH_LANEQ_F16:
	case ARM64_INTRIN_VFMAH_F16:
	case ARM64_INTRIN_VFMAH_LANE_F16:
	case ARM64_INTRIN_VFMAH_LANEQ_F16:
	case ARM64_INTRIN_VFMSH_F16:
	case ARM64_INTRIN_VFMSH_LANE_F16:
	case ARM64_INTRIN_VFMSH_LANEQ_F16:
	case ARM64_INTRIN_VGET_LANE_BF16:
	case ARM64_INTRIN_VGET_LANE_F16:
	case ARM64_INTRIN_VGETQ_LANE_BF16:
	case ARM64_INTRIN_VGETQ_LANE_F16:
	case ARM64_INTRIN_VMAXH_F16:
	case ARM64_INTRIN_VMAXNMH_F16:
	case ARM64_INTRIN_VMAXNMV_F16:
	case ARM64_INTRIN_VMAXNMVQ_F16:
	case ARM64_INTRIN_VMAXV_F16:
	case ARM64_INTRIN_VMAXVQ_F16:
	case ARM64_INTRIN_VMINH_F16:
	case ARM64_INTRIN_VMINNMH_F16:
	case ARM64_INTRIN_VMINNMV_F16:
	case ARM64_INTRIN_VMINNMVQ_F16:
	case ARM64_INTRIN_VMINV_F16:
	case ARM64_INTRIN_VMINVQ_F16:
	case ARM64_INTRIN_VMULH_F16:
	case ARM64_INTRIN_VMULH_LANE_F16:
	case ARM64_INTRIN_VMULH_LANEQ_F16:
	case ARM64_INTRIN_VMULXH_F16:
	case ARM64_INTRIN_VMULXH_LANE_F16:
	case ARM64_INTRIN_VMULXH_LANEQ_F16:
	case ARM64_INTRIN_VNEGH_F16:
	case ARM64_INTRIN_VRECPEH_F16:
	case ARM64_INTRIN_VRECPSH_F16:
	case ARM64_INTRIN_VRECPXH_F16:
	case ARM64_INTRIN_VRNDAH_F16:
	case ARM64_INTRIN_VRNDH_F16:
	case ARM64_INTRIN_VRNDIH_F16:
	case ARM64_INTRIN_VRNDMH_F16:
	case ARM64_INTRIN_VRNDNH_F16:
	case ARM64_INTRIN_VRNDPH_F16:
	case ARM64_INTRIN_VRNDXH_F16:
	case ARM64_INTRIN_VRSQRTEH_F16:
	case ARM64_INTRIN_VRSQRTSH_F16:
	case ARM64_INTRIN_VSQRTH_F16:
	case ARM64_INTRIN_VSUBH_F16:
	case ARM64_INTRIN_VCVTH_N_F16_U64:
		return {Type::FloatType(2)};
	case ARM64_INTRIN_VABDS_F32:
	case ARM64_INTRIN_VADDV_F32:
	case ARM64_INTRIN_VCVTAH_F32_BF16:
	case ARM64_INTRIN_VCVTS_F32_S32:
	case ARM64_INTRIN_VCVTS_F32_U32:
	case ARM64_INTRIN_VCVTS_N_F32_S32:
	case ARM64_INTRIN_VCVTS_N_F32_U32:
	case ARM64_INTRIN_VCVTS_N_F32_U64:
	case ARM64_INTRIN_VCVTXD_F32_F64:
	case ARM64_INTRIN_VDUPS_LANE_F32:
	case ARM64_INTRIN_VDUPS_LANEQ_F32:
	case ARM64_INTRIN_VFMAS_LANE_F32:
	case ARM64_INTRIN_VFMAS_LANEQ_F32:
	case ARM64_INTRIN_VFMSS_LANE_F32:
	case ARM64_INTRIN_VFMSS_LANEQ_F32:
	case ARM64_INTRIN_VGET_LANE_F32:
	case ARM64_INTRIN_VGETQ_LANE_F32:
	case ARM64_INTRIN_VMAXNMV_F32:
	case ARM64_INTRIN_VMAXNMVQ_F32:
	case ARM64_INTRIN_VMAXV_F32:
	case ARM64_INTRIN_VMAXVQ_F32:
	case ARM64_INTRIN_VMINNMV_F32:
	case ARM64_INTRIN_VMINNMVQ_F32:
	case ARM64_INTRIN_VMINV_F32:
	case ARM64_INTRIN_VMINVQ_F32:
	case ARM64_INTRIN_VMULS_LANE_F32:
	case ARM64_INTRIN_VMULS_LANEQ_F32:
	case ARM64_INTRIN_VMULXS_F32:
	case ARM64_INTRIN_VMULXS_LANE_F32:
	case ARM64_INTRIN_VMULXS_LANEQ_F32:
	case ARM64_INTRIN_VPADDS_F32:
	case ARM64_INTRIN_VPMAXNMS_F32:
	case ARM64_INTRIN_VPMAXS_F32:
	case ARM64_INTRIN_VPMINNMS_F32:
	case ARM64_INTRIN_VPMINS_F32:
	case ARM64_INTRIN_VRECPES_F32:
	case ARM64_INTRIN_VRECPSS_F32:
	case ARM64_INTRIN_VRECPXS_F32:
	case ARM64_INTRIN_VRNDNS_F32:
	case ARM64_INTRIN_VRSQRTES_F32:
	case ARM64_INTRIN_VRSQRTSS_F32:
	case ARM64_INTRIN_VCVT_F32_U64:
		return {Type::FloatType(4)};
	case ARM64_INTRIN_VABD_F16:
	case ARM64_INTRIN_VABD_F32:
	case ARM64_INTRIN_VABD_F64:
	case ARM64_INTRIN_VABDD_F64:
	case ARM64_INTRIN_VABS_F16:
	case ARM64_INTRIN_VABS_F32:
	case ARM64_INTRIN_VABS_F64:
	case ARM64_INTRIN_VADD_F16:
	case ARM64_INTRIN_VADD_F32:
	case ARM64_INTRIN_VADD_F64:
	case ARM64_INTRIN_VADDVQ_F64:
	case ARM64_INTRIN_VBFDOT_F32:
	case ARM64_INTRIN_VBFDOT_LANE_F32:
	case ARM64_INTRIN_VBFDOT_LANEQ_F32:
	case ARM64_INTRIN_VBSL_F16:
	case ARM64_INTRIN_VBSL_F32:
	case ARM64_INTRIN_VBSL_F64:
	case ARM64_INTRIN_VCADD_ROT270_F16:
	case ARM64_INTRIN_VCADD_ROT270_F32:
	case ARM64_INTRIN_VCADD_ROT90_F16:
	case ARM64_INTRIN_VCADD_ROT90_F32:
	case ARM64_INTRIN_VCMLA_F16:
	case ARM64_INTRIN_VCMLA_F32:
	case ARM64_INTRIN_VCMLA_LANE_F16:
	case ARM64_INTRIN_VCMLA_LANE_F32:
	case ARM64_INTRIN_VCMLA_LANEQ_F16:
	case ARM64_INTRIN_VCMLA_ROT180_F16:
	case ARM64_INTRIN_VCMLA_ROT180_F32:
	case ARM64_INTRIN_VCMLA_ROT180_LANE_F16:
	case ARM64_INTRIN_VCMLA_ROT180_LANE_F32:
	case ARM64_INTRIN_VCMLA_ROT180_LANEQ_F16:
	case ARM64_INTRIN_VCMLA_ROT270_F16:
	case ARM64_INTRIN_VCMLA_ROT270_F32:
	case ARM64_INTRIN_VCMLA_ROT270_LANE_F16:
	case ARM64_INTRIN_VCMLA_ROT270_LANE_F32:
	case ARM64_INTRIN_VCMLA_ROT270_LANEQ_F16:
	case ARM64_INTRIN_VCMLA_ROT90_F16:
	case ARM64_INTRIN_VCMLA_ROT90_F32:
	case ARM64_INTRIN_VCMLA_ROT90_LANE_F16:
	case ARM64_INTRIN_VCMLA_ROT90_LANE_F32:
	case ARM64_INTRIN_VCMLA_ROT90_LANEQ_F16:
	case ARM64_INTRIN_VCREATE_BF16:
	case ARM64_INTRIN_VCREATE_F16:
	case ARM64_INTRIN_VCREATE_F32:
	case ARM64_INTRIN_VCREATE_F64:
	case ARM64_INTRIN_VCVT_BF16_F32:
	case ARM64_INTRIN_VCVT_F16_F32:
	case ARM64_INTRIN_VCVT_F16_S16:
	case ARM64_INTRIN_VCVT_F16_U16:
	case ARM64_INTRIN_VCVT_F32_F64:
	case ARM64_INTRIN_VCVT_F32_S32:
	case ARM64_INTRIN_VCVT_F32_U32:
	case ARM64_INTRIN_VCVT_F64_S64:
	case ARM64_INTRIN_VCVT_F64_U64:
	case ARM64_INTRIN_VCVT_F64_U32:
	case ARM64_INTRIN_VCVT_N_F16_S16:
	case ARM64_INTRIN_VCVT_N_F16_U16:
	case ARM64_INTRIN_VCVT_N_F32_S32:
	case ARM64_INTRIN_VCVT_N_F32_U32:
	case ARM64_INTRIN_VCVT_N_F64_S64:
	case ARM64_INTRIN_VCVT_N_F64_U64:
	case ARM64_INTRIN_VCVTD_F64_S64:
	case ARM64_INTRIN_VCVTD_F64_U64:
	case ARM64_INTRIN_VCVTD_N_F64_U32:
	case ARM64_INTRIN_VCVTD_N_F64_S64:
	case ARM64_INTRIN_VCVTD_N_F64_U64:
	case ARM64_INTRIN_VCVTX_F32_F64:
	case ARM64_INTRIN_VDIV_F16:
	case ARM64_INTRIN_VDIV_F32:
	case ARM64_INTRIN_VDIV_F64:
	case ARM64_INTRIN_VDUP_LANE_BF16:
	case ARM64_INTRIN_VDUP_LANE_F16:
	case ARM64_INTRIN_VDUP_LANE_F32:
	case ARM64_INTRIN_VDUP_LANE_F64:
	case ARM64_INTRIN_VDUP_LANEQ_BF16:
	case ARM64_INTRIN_VDUP_LANEQ_F16:
	case ARM64_INTRIN_VDUP_LANEQ_F32:
	case ARM64_INTRIN_VDUP_LANEQ_F64:
	case ARM64_INTRIN_VDUP_N_BF16:
	case ARM64_INTRIN_VDUP_N_F16:
	case ARM64_INTRIN_VDUP_N_F32:
	case ARM64_INTRIN_VDUP_N_F64:
	case ARM64_INTRIN_VDUPD_LANE_F64:
	case ARM64_INTRIN_VDUPD_LANEQ_F64:
	case ARM64_INTRIN_VEXT_F16:
	case ARM64_INTRIN_VEXT_F32:
	case ARM64_INTRIN_VEXT_F64:
	case ARM64_INTRIN_VFMA_F16:
	case ARM64_INTRIN_VFMA_F32:
	case ARM64_INTRIN_VFMA_F64:
	case ARM64_INTRIN_VFMA_LANE_F16:
	case ARM64_INTRIN_VFMA_LANE_F32:
	case ARM64_INTRIN_VFMA_LANE_F64:
	case ARM64_INTRIN_VFMA_LANEQ_F16:
	case ARM64_INTRIN_VFMA_LANEQ_F32:
	case ARM64_INTRIN_VFMA_LANEQ_F64:
	case ARM64_INTRIN_VFMA_N_F16:
	case ARM64_INTRIN_VFMA_N_F32:
	case ARM64_INTRIN_VFMA_N_F64:
	case ARM64_INTRIN_VFMAD_LANE_F64:
	case ARM64_INTRIN_VFMAD_LANEQ_F64:
	case ARM64_INTRIN_VFMLAL_HIGH_F16:
	case ARM64_INTRIN_VFMLAL_LANE_HIGH_F16:
	case ARM64_INTRIN_VFMLAL_LANE_LOW_F16:
	case ARM64_INTRIN_VFMLAL_LANEQ_HIGH_F16:
	case ARM64_INTRIN_VFMLAL_LANEQ_LOW_F16:
	case ARM64_INTRIN_VFMLAL_LOW_F16:
	case ARM64_INTRIN_VFMLSL_HIGH_F16:
	case ARM64_INTRIN_VFMLSL_LANE_HIGH_F16:
	case ARM64_INTRIN_VFMLSL_LANE_LOW_F16:
	case ARM64_INTRIN_VFMLSL_LANEQ_HIGH_F16:
	case ARM64_INTRIN_VFMLSL_LANEQ_LOW_F16:
	case ARM64_INTRIN_VFMLSL_LOW_F16:
	case ARM64_INTRIN_VFMS_F16:
	case ARM64_INTRIN_VFMS_F32:
	case ARM64_INTRIN_VFMS_F64:
	case ARM64_INTRIN_VFMS_LANE_F16:
	case ARM64_INTRIN_VFMS_LANE_F32:
	case ARM64_INTRIN_VFMS_LANE_F64:
	case ARM64_INTRIN_VFMS_LANEQ_F16:
	case ARM64_INTRIN_VFMS_LANEQ_F32:
	case ARM64_INTRIN_VFMS_LANEQ_F64:
	case ARM64_INTRIN_VFMS_N_F16:
	case ARM64_INTRIN_VFMS_N_F32:
	case ARM64_INTRIN_VFMS_N_F64:
	case ARM64_INTRIN_VFMSD_LANE_F64:
	case ARM64_INTRIN_VFMSD_LANEQ_F64:
	case ARM64_INTRIN_VGET_HIGH_BF16:
	case ARM64_INTRIN_VGET_HIGH_F16:
	case ARM64_INTRIN_VGET_HIGH_F32:
	case ARM64_INTRIN_VGET_HIGH_F64:
	case ARM64_INTRIN_VGET_LANE_F64:
	case ARM64_INTRIN_VGET_LOW_BF16:
	case ARM64_INTRIN_VGET_LOW_F16:
	case ARM64_INTRIN_VGET_LOW_F32:
	case ARM64_INTRIN_VGET_LOW_F64:
	case ARM64_INTRIN_VGETQ_LANE_F64:
	case ARM64_INTRIN_VMAX_F16:
	case ARM64_INTRIN_VMAX_F32:
	case ARM64_INTRIN_VMAX_F64:
	case ARM64_INTRIN_VMAXNM_F16:
	case ARM64_INTRIN_VMAXNM_F32:
	case ARM64_INTRIN_VMAXNM_F64:
	case ARM64_INTRIN_VMAXNMVQ_F64:
	case ARM64_INTRIN_VMAXVQ_F64:
	case ARM64_INTRIN_VMIN_F16:
	case ARM64_INTRIN_VMIN_F32:
	case ARM64_INTRIN_VMIN_F64:
	case ARM64_INTRIN_VMINNM_F16:
	case ARM64_INTRIN_VMINNM_F32:
	case ARM64_INTRIN_VMINNM_F64:
	case ARM64_INTRIN_VMINNMVQ_F64:
	case ARM64_INTRIN_VMINVQ_F64:
	case ARM64_INTRIN_VMOV_N_F16:
	case ARM64_INTRIN_VMOV_N_F32:
	case ARM64_INTRIN_VMOV_N_F64:
	case ARM64_INTRIN_VMUL_F16:
	case ARM64_INTRIN_VMUL_F32:
	case ARM64_INTRIN_VMUL_F64:
	case ARM64_INTRIN_VMUL_LANE_F16:
	case ARM64_INTRIN_VMUL_LANE_F32:
	case ARM64_INTRIN_VMUL_LANE_F64:
	case ARM64_INTRIN_VMUL_LANEQ_F16:
	case ARM64_INTRIN_VMUL_LANEQ_F32:
	case ARM64_INTRIN_VMUL_LANEQ_F64:
	case ARM64_INTRIN_VMUL_N_F16:
	case ARM64_INTRIN_VMUL_N_F32:
	case ARM64_INTRIN_VMUL_N_F64:
	case ARM64_INTRIN_VMULD_LANE_F64:
	case ARM64_INTRIN_VMULD_LANEQ_F64:
	case ARM64_INTRIN_VMULX_F16:
	case ARM64_INTRIN_VMULX_F32:
	case ARM64_INTRIN_VMULX_F64:
	case ARM64_INTRIN_VMULX_LANE_F16:
	case ARM64_INTRIN_VMULX_LANE_F32:
	case ARM64_INTRIN_VMULX_LANE_F64:
	case ARM64_INTRIN_VMULX_LANEQ_F16:
	case ARM64_INTRIN_VMULX_LANEQ_F32:
	case ARM64_INTRIN_VMULX_LANEQ_F64:
	case ARM64_INTRIN_VMULX_N_F16:
	case ARM64_INTRIN_VMULXD_F64:
	case ARM64_INTRIN_VMULXD_LANE_F64:
	case ARM64_INTRIN_VMULXD_LANEQ_F64:
	case ARM64_INTRIN_VNEG_F16:
	case ARM64_INTRIN_VNEG_F32:
	case ARM64_INTRIN_VNEG_F64:
	case ARM64_INTRIN_VPADD_F16:
	case ARM64_INTRIN_VPADD_F32:
	case ARM64_INTRIN_VPADDD_F64:
	case ARM64_INTRIN_VPMAX_F16:
	case ARM64_INTRIN_VPMAX_F32:
	case ARM64_INTRIN_VPMAXNM_F16:
	case ARM64_INTRIN_VPMAXNM_F32:
	case ARM64_INTRIN_VPMAXNMQD_F64:
	case ARM64_INTRIN_VPMAXQD_F64:
	case ARM64_INTRIN_VPMIN_F16:
	case ARM64_INTRIN_VPMIN_F32:
	case ARM64_INTRIN_VPMINNM_F16:
	case ARM64_INTRIN_VPMINNM_F32:
	case ARM64_INTRIN_VPMINNMQD_F64:
	case ARM64_INTRIN_VPMINQD_F64:
	case ARM64_INTRIN_VRECPE_F16:
	case ARM64_INTRIN_VRECPE_F32:
	case ARM64_INTRIN_VRECPE_F64:
	case ARM64_INTRIN_VRECPED_F64:
	case ARM64_INTRIN_VRECPS_F16:
	case ARM64_INTRIN_VRECPS_F32:
	case ARM64_INTRIN_VRECPS_F64:
	case ARM64_INTRIN_VRECPSD_F64:
	case ARM64_INTRIN_VRECPXD_F64:
	case ARM64_INTRIN_VREV64_F16:
	case ARM64_INTRIN_VREV64_F32:
	case ARM64_INTRIN_VRND32X_F32:
	case ARM64_INTRIN_VRND32X_F64:
	case ARM64_INTRIN_VRND32Z_F32:
	case ARM64_INTRIN_VRND32Z_F64:
	case ARM64_INTRIN_VRND64X_F32:
	case ARM64_INTRIN_VRND64X_F64:
	case ARM64_INTRIN_VRND64Z_F32:
	case ARM64_INTRIN_VRND64Z_F64:
	case ARM64_INTRIN_VRND_F16:
	case ARM64_INTRIN_VRND_F32:
	case ARM64_INTRIN_VRND_F64:
	case ARM64_INTRIN_VRNDA_F16:
	case ARM64_INTRIN_VRNDA_F32:
	case ARM64_INTRIN_VRNDA_F64:
	case ARM64_INTRIN_VRNDI_F16:
	case ARM64_INTRIN_VRNDI_F32:
	case ARM64_INTRIN_VRNDI_F64:
	case ARM64_INTRIN_VRNDM_F16:
	case ARM64_INTRIN_VRNDM_F32:
	case ARM64_INTRIN_VRNDM_F64:
	case ARM64_INTRIN_VRNDN_F16:
	case ARM64_INTRIN_VRNDN_F32:
	case ARM64_INTRIN_VRNDN_F64:
	case ARM64_INTRIN_VRNDP_F16:
	case ARM64_INTRIN_VRNDP_F32:
	case ARM64_INTRIN_VRNDP_F64:
	case ARM64_INTRIN_VRNDX_F16:
	case ARM64_INTRIN_VRNDX_F32:
	case ARM64_INTRIN_VRNDX_F64:
	case ARM64_INTRIN_VRSQRTE_F16:
	case ARM64_INTRIN_VRSQRTE_F32:
	case ARM64_INTRIN_VRSQRTE_F64:
	case ARM64_INTRIN_VRSQRTED_F64:
	case ARM64_INTRIN_VRSQRTS_F16:
	case ARM64_INTRIN_VRSQRTS_F32:
	case ARM64_INTRIN_VRSQRTS_F64:
	case ARM64_INTRIN_VRSQRTSD_F64:
	case ARM64_INTRIN_VSET_LANE_BF16:
	case ARM64_INTRIN_VSET_LANE_F16:
	case ARM64_INTRIN_VSET_LANE_F32:
	case ARM64_INTRIN_VSET_LANE_F64:
	case ARM64_INTRIN_VSQRT_F16:
	case ARM64_INTRIN_VSQRT_F32:
	case ARM64_INTRIN_VSQRT_F64:
	case ARM64_INTRIN_VSUB_F16:
	case ARM64_INTRIN_VSUB_F32:
	case ARM64_INTRIN_VSUB_F64:
	case ARM64_INTRIN_VTRN1_F16:
	case ARM64_INTRIN_VTRN1_F32:
	case ARM64_INTRIN_VTRN2_F16:
	case ARM64_INTRIN_VTRN2_F32:
	case ARM64_INTRIN_VUZP1_F16:
	case ARM64_INTRIN_VUZP1_F32:
	case ARM64_INTRIN_VUZP2_F16:
	case ARM64_INTRIN_VUZP2_F32:
	case ARM64_INTRIN_VZIP1_F16:
	case ARM64_INTRIN_VZIP1_F32:
	case ARM64_INTRIN_VZIP2_F16:
	case ARM64_INTRIN_VZIP2_F32:
		return {Type::FloatType(8)};
	case ARM64_INTRIN_VADDV_S8:
	case ARM64_INTRIN_VADDV_U8:
	case ARM64_INTRIN_VADDVQ_S8:
	case ARM64_INTRIN_VADDVQ_U8:
	case ARM64_INTRIN_VDUPB_LANE_P8:
	case ARM64_INTRIN_VDUPB_LANE_S8:
	case ARM64_INTRIN_VDUPB_LANE_U8:
	case ARM64_INTRIN_VDUPB_LANEQ_P8:
	case ARM64_INTRIN_VDUPB_LANEQ_S8:
	case ARM64_INTRIN_VDUPB_LANEQ_U8:
	case ARM64_INTRIN_VGET_LANE_P8:
	case ARM64_INTRIN_VGET_LANE_S8:
	case ARM64_INTRIN_VGET_LANE_U8:
	case ARM64_INTRIN_VGETQ_LANE_P8:
	case ARM64_INTRIN_VGETQ_LANE_S8:
	case ARM64_INTRIN_VGETQ_LANE_U8:
	case ARM64_INTRIN_VMAXV_S8:
	case ARM64_INTRIN_VMAXV_U8:
	case ARM64_INTRIN_VMAXVQ_S8:
	case ARM64_INTRIN_VMAXVQ_U8:
	case ARM64_INTRIN_VMINV_S8:
	case ARM64_INTRIN_VMINV_U8:
	case ARM64_INTRIN_VMINVQ_S8:
	case ARM64_INTRIN_VMINVQ_U8:
	case ARM64_INTRIN_VQABSB_S8:
	case ARM64_INTRIN_VQADDB_S8:
	case ARM64_INTRIN_VQADDB_U8:
	case ARM64_INTRIN_VQMOVNH_S16:
	case ARM64_INTRIN_VQMOVNH_U16:
	case ARM64_INTRIN_VQMOVUNH_S16:
	case ARM64_INTRIN_VQNEGB_S8:
	case ARM64_INTRIN_VQRSHLB_S8:
	case ARM64_INTRIN_VQRSHLB_U8:
	case ARM64_INTRIN_VQRSHRNH_N_S16:
	case ARM64_INTRIN_VQRSHRNH_N_U16:
	case ARM64_INTRIN_VQRSHRUNH_N_S16:
	case ARM64_INTRIN_VQSHLB_N_S8:
	case ARM64_INTRIN_VQSHLB_N_U8:
	case ARM64_INTRIN_VQSHLB_S8:
	case ARM64_INTRIN_VQSHLB_U8:
	case ARM64_INTRIN_VQSHLUB_N_S8:
	case ARM64_INTRIN_VQSHRNH_N_S16:
	case ARM64_INTRIN_VQSHRNH_N_U16:
	case ARM64_INTRIN_VQSHRUNH_N_S16:
	case ARM64_INTRIN_VQSUBB_S8:
	case ARM64_INTRIN_VQSUBB_U8:
	case ARM64_INTRIN_VSQADDB_U8:
	case ARM64_INTRIN_VUQADDB_S8:
		return {Type::IntegerType(1, false)};
	case ARM64_INTRIN_VABAL_HIGH_S16:
	case ARM64_INTRIN_VABAL_HIGH_S32:
	case ARM64_INTRIN_VABAL_HIGH_S8:
	case ARM64_INTRIN_VABAL_HIGH_U16:
	case ARM64_INTRIN_VABAL_HIGH_U32:
	case ARM64_INTRIN_VABAL_HIGH_U8:
	case ARM64_INTRIN_VABAL_S16:
	case ARM64_INTRIN_VABAL_S32:
	case ARM64_INTRIN_VABAL_S8:
	case ARM64_INTRIN_VABAL_U16:
	case ARM64_INTRIN_VABAL_U32:
	case ARM64_INTRIN_VABAL_U8:
	case ARM64_INTRIN_VABAQ_S16:
	case ARM64_INTRIN_VABAQ_S32:
	case ARM64_INTRIN_VABAQ_S8:
	case ARM64_INTRIN_VABAQ_U16:
	case ARM64_INTRIN_VABAQ_U32:
	case ARM64_INTRIN_VABAQ_U8:
	case ARM64_INTRIN_VABDL_HIGH_S16:
	case ARM64_INTRIN_VABDL_HIGH_S32:
	case ARM64_INTRIN_VABDL_HIGH_S8:
	case ARM64_INTRIN_VABDL_HIGH_U16:
	case ARM64_INTRIN_VABDL_HIGH_U32:
	case ARM64_INTRIN_VABDL_HIGH_U8:
	case ARM64_INTRIN_VABDL_S16:
	case ARM64_INTRIN_VABDL_S32:
	case ARM64_INTRIN_VABDL_S8:
	case ARM64_INTRIN_VABDL_U16:
	case ARM64_INTRIN_VABDL_U32:
	case ARM64_INTRIN_VABDL_U8:
	case ARM64_INTRIN_VABDQ_S16:
	case ARM64_INTRIN_VABDQ_S32:
	case ARM64_INTRIN_VABDQ_S8:
	case ARM64_INTRIN_VABDQ_U16:
	case ARM64_INTRIN_VABDQ_U32:
	case ARM64_INTRIN_VABDQ_U8:
	case ARM64_INTRIN_VABSQ_S16:
	case ARM64_INTRIN_VABSQ_S32:
	case ARM64_INTRIN_VABSQ_S64:
	case ARM64_INTRIN_VABSQ_S8:
	case ARM64_INTRIN_VADDHN_HIGH_S16:
	case ARM64_INTRIN_VADDHN_HIGH_S32:
	case ARM64_INTRIN_VADDHN_HIGH_S64:
	case ARM64_INTRIN_VADDHN_HIGH_U16:
	case ARM64_INTRIN_VADDHN_HIGH_U32:
	case ARM64_INTRIN_VADDHN_HIGH_U64:
	case ARM64_INTRIN_VADDL_HIGH_S16:
	case ARM64_INTRIN_VADDL_HIGH_S32:
	case ARM64_INTRIN_VADDL_HIGH_S8:
	case ARM64_INTRIN_VADDL_HIGH_U16:
	case ARM64_INTRIN_VADDL_HIGH_U32:
	case ARM64_INTRIN_VADDL_HIGH_U8:
	case ARM64_INTRIN_VADDL_S16:
	case ARM64_INTRIN_VADDL_S32:
	case ARM64_INTRIN_VADDL_S8:
	case ARM64_INTRIN_VADDL_U16:
	case ARM64_INTRIN_VADDL_U32:
	case ARM64_INTRIN_VADDL_U8:
	case ARM64_INTRIN_VADDQ_P128:
	case ARM64_INTRIN_VADDQ_P16:
	case ARM64_INTRIN_VADDQ_P64:
	case ARM64_INTRIN_VADDQ_P8:
	case ARM64_INTRIN_VADDQ_S16:
	case ARM64_INTRIN_VADDQ_S32:
	case ARM64_INTRIN_VADDQ_S64:
	case ARM64_INTRIN_VADDQ_S8:
	case ARM64_INTRIN_VADDQ_U16:
	case ARM64_INTRIN_VADDQ_U32:
	case ARM64_INTRIN_VADDQ_U64:
	case ARM64_INTRIN_VADDQ_U8:
	case ARM64_INTRIN_VADDW_HIGH_S16:
	case ARM64_INTRIN_VADDW_HIGH_S32:
	case ARM64_INTRIN_VADDW_HIGH_S8:
	case ARM64_INTRIN_VADDW_HIGH_U16:
	case ARM64_INTRIN_VADDW_HIGH_U32:
	case ARM64_INTRIN_VADDW_HIGH_U8:
	case ARM64_INTRIN_VADDW_S16:
	case ARM64_INTRIN_VADDW_S32:
	case ARM64_INTRIN_VADDW_S8:
	case ARM64_INTRIN_VADDW_U16:
	case ARM64_INTRIN_VADDW_U32:
	case ARM64_INTRIN_VADDW_U8:
	case ARM64_INTRIN_VAESDQ_U8:
	case ARM64_INTRIN_VAESEQ_U8:
	case ARM64_INTRIN_VAESIMCQ_U8:
	case ARM64_INTRIN_VAESMCQ_U8:
	case ARM64_INTRIN_VANDQ_S16:
	case ARM64_INTRIN_VANDQ_S32:
	case ARM64_INTRIN_VANDQ_S64:
	case ARM64_INTRIN_VANDQ_S8:
	case ARM64_INTRIN_VANDQ_U16:
	case ARM64_INTRIN_VANDQ_U32:
	case ARM64_INTRIN_VANDQ_U64:
	case ARM64_INTRIN_VANDQ_U8:
	case ARM64_INTRIN_VBCAXQ_S16:
	case ARM64_INTRIN_VBCAXQ_S32:
	case ARM64_INTRIN_VBCAXQ_S64:
	case ARM64_INTRIN_VBCAXQ_S8:
	case ARM64_INTRIN_VBCAXQ_U16:
	case ARM64_INTRIN_VBCAXQ_U32:
	case ARM64_INTRIN_VBCAXQ_U64:
	case ARM64_INTRIN_VBCAXQ_U8:
	case ARM64_INTRIN_VBICQ_S16:
	case ARM64_INTRIN_VBICQ_S32:
	case ARM64_INTRIN_VBICQ_S64:
	case ARM64_INTRIN_VBICQ_S8:
	case ARM64_INTRIN_VBICQ_U16:
	case ARM64_INTRIN_VBICQ_U32:
	case ARM64_INTRIN_VBICQ_U64:
	case ARM64_INTRIN_VBICQ_U8:
	case ARM64_INTRIN_VBSLQ_P16:
	case ARM64_INTRIN_VBSLQ_P64:
	case ARM64_INTRIN_VBSLQ_P8:
	case ARM64_INTRIN_VBSLQ_S16:
	case ARM64_INTRIN_VBSLQ_S32:
	case ARM64_INTRIN_VBSLQ_S64:
	case ARM64_INTRIN_VBSLQ_S8:
	case ARM64_INTRIN_VBSLQ_U16:
	case ARM64_INTRIN_VBSLQ_U32:
	case ARM64_INTRIN_VBSLQ_U64:
	case ARM64_INTRIN_VBSLQ_U8:
	case ARM64_INTRIN_VCAGEQ_F16:
	case ARM64_INTRIN_VCAGEQ_F32:
	case ARM64_INTRIN_VCAGEQ_F64:
	case ARM64_INTRIN_VCAGTQ_F16:
	case ARM64_INTRIN_VCAGTQ_F32:
	case ARM64_INTRIN_VCAGTQ_F64:
	case ARM64_INTRIN_VCALEQ_F16:
	case ARM64_INTRIN_VCALEQ_F32:
	case ARM64_INTRIN_VCALEQ_F64:
	case ARM64_INTRIN_VCALTQ_F16:
	case ARM64_INTRIN_VCALTQ_F32:
	case ARM64_INTRIN_VCALTQ_F64:
	case ARM64_INTRIN_VCEQQ_F16:
	case ARM64_INTRIN_VCEQQ_F32:
	case ARM64_INTRIN_VCEQQ_F64:
	case ARM64_INTRIN_VCEQQ_P64:
	case ARM64_INTRIN_VCEQQ_P8:
	case ARM64_INTRIN_VCEQQ_S16:
	case ARM64_INTRIN_VCEQQ_S32:
	case ARM64_INTRIN_VCEQQ_S64:
	case ARM64_INTRIN_VCEQQ_S8:
	case ARM64_INTRIN_VCEQQ_U16:
	case ARM64_INTRIN_VCEQQ_U32:
	case ARM64_INTRIN_VCEQQ_U64:
	case ARM64_INTRIN_VCEQQ_U8:
	case ARM64_INTRIN_VCEQZQ_F16:
	case ARM64_INTRIN_VCEQZQ_F32:
	case ARM64_INTRIN_VCEQZQ_F64:
	case ARM64_INTRIN_VCEQZQ_P64:
	case ARM64_INTRIN_VCEQZQ_P8:
	case ARM64_INTRIN_VCEQZQ_S16:
	case ARM64_INTRIN_VCEQZQ_S32:
	case ARM64_INTRIN_VCEQZQ_S64:
	case ARM64_INTRIN_VCEQZQ_S8:
	case ARM64_INTRIN_VCEQZQ_U16:
	case ARM64_INTRIN_VCEQZQ_U32:
	case ARM64_INTRIN_VCEQZQ_U64:
	case ARM64_INTRIN_VCEQZQ_U8:
	case ARM64_INTRIN_VCGEQ_F16:
	case ARM64_INTRIN_VCGEQ_F32:
	case ARM64_INTRIN_VCGEQ_F64:
	case ARM64_INTRIN_VCGEQ_S16:
	case ARM64_INTRIN_VCGEQ_S32:
	case ARM64_INTRIN_VCGEQ_S64:
	case ARM64_INTRIN_VCGEQ_S8:
	case ARM64_INTRIN_VCGEQ_U16:
	case ARM64_INTRIN_VCGEQ_U32:
	case ARM64_INTRIN_VCGEQ_U64:
	case ARM64_INTRIN_VCGEQ_U8:
	case ARM64_INTRIN_VCGEZQ_F16:
	case ARM64_INTRIN_VCGEZQ_F32:
	case ARM64_INTRIN_VCGEZQ_F64:
	case ARM64_INTRIN_VCGEZQ_S16:
	case ARM64_INTRIN_VCGEZQ_S32:
	case ARM64_INTRIN_VCGEZQ_S64:
	case ARM64_INTRIN_VCGEZQ_S8:
	case ARM64_INTRIN_VCGTQ_F16:
	case ARM64_INTRIN_VCGTQ_F32:
	case ARM64_INTRIN_VCGTQ_F64:
	case ARM64_INTRIN_VCGTQ_S16:
	case ARM64_INTRIN_VCGTQ_S32:
	case ARM64_INTRIN_VCGTQ_S64:
	case ARM64_INTRIN_VCGTQ_S8:
	case ARM64_INTRIN_VCGTQ_U16:
	case ARM64_INTRIN_VCGTQ_U32:
	case ARM64_INTRIN_VCGTQ_U64:
	case ARM64_INTRIN_VCGTQ_U8:
	case ARM64_INTRIN_VCGTZQ_F16:
	case ARM64_INTRIN_VCGTZQ_F32:
	case ARM64_INTRIN_VCGTZQ_F64:
	case ARM64_INTRIN_VCGTZQ_S16:
	case ARM64_INTRIN_VCGTZQ_S32:
	case ARM64_INTRIN_VCGTZQ_S64:
	case ARM64_INTRIN_VCGTZQ_S8:
	case ARM64_INTRIN_VCLEQ_F16:
	case ARM64_INTRIN_VCLEQ_F32:
	case ARM64_INTRIN_VCLEQ_F64:
	case ARM64_INTRIN_VCLEQ_S16:
	case ARM64_INTRIN_VCLEQ_S32:
	case ARM64_INTRIN_VCLEQ_S64:
	case ARM64_INTRIN_VCLEQ_S8:
	case ARM64_INTRIN_VCLEQ_U16:
	case ARM64_INTRIN_VCLEQ_U32:
	case ARM64_INTRIN_VCLEQ_U64:
	case ARM64_INTRIN_VCLEQ_U8:
	case ARM64_INTRIN_VCLEZQ_F16:
	case ARM64_INTRIN_VCLEZQ_F32:
	case ARM64_INTRIN_VCLEZQ_F64:
	case ARM64_INTRIN_VCLEZQ_S16:
	case ARM64_INTRIN_VCLEZQ_S32:
	case ARM64_INTRIN_VCLEZQ_S64:
	case ARM64_INTRIN_VCLEZQ_S8:
	case ARM64_INTRIN_VCLSQ_S16:
	case ARM64_INTRIN_VCLSQ_S32:
	case ARM64_INTRIN_VCLSQ_S8:
	case ARM64_INTRIN_VCLSQ_U16:
	case ARM64_INTRIN_VCLSQ_U32:
	case ARM64_INTRIN_VCLSQ_U8:
	case ARM64_INTRIN_VCLTQ_F16:
	case ARM64_INTRIN_VCLTQ_F32:
	case ARM64_INTRIN_VCLTQ_F64:
	case ARM64_INTRIN_VCLTQ_S16:
	case ARM64_INTRIN_VCLTQ_S32:
	case ARM64_INTRIN_VCLTQ_S64:
	case ARM64_INTRIN_VCLTQ_S8:
	case ARM64_INTRIN_VCLTQ_U16:
	case ARM64_INTRIN_VCLTQ_U32:
	case ARM64_INTRIN_VCLTQ_U64:
	case ARM64_INTRIN_VCLTQ_U8:
	case ARM64_INTRIN_VCLTZQ_F16:
	case ARM64_INTRIN_VCLTZQ_F32:
	case ARM64_INTRIN_VCLTZQ_F64:
	case ARM64_INTRIN_VCLTZQ_S16:
	case ARM64_INTRIN_VCLTZQ_S32:
	case ARM64_INTRIN_VCLTZQ_S64:
	case ARM64_INTRIN_VCLTZQ_S8:
	case ARM64_INTRIN_VCLZQ_S16:
	case ARM64_INTRIN_VCLZQ_S32:
	case ARM64_INTRIN_VCLZQ_S8:
	case ARM64_INTRIN_VCLZQ_U16:
	case ARM64_INTRIN_VCLZQ_U32:
	case ARM64_INTRIN_VCLZQ_U8:
	case ARM64_INTRIN_VCNTQ_P8:
	case ARM64_INTRIN_VCNTQ_S8:
	case ARM64_INTRIN_VCNTQ_U8:
	case ARM64_INTRIN_VCVTAQ_S16_F16:
	case ARM64_INTRIN_VCVTAQ_S32_F32:
	case ARM64_INTRIN_VCVTAQ_S64_F64:
	case ARM64_INTRIN_VCVTAQ_U16_F16:
	case ARM64_INTRIN_VCVTAQ_U32_F32:
	case ARM64_INTRIN_VCVTAQ_U64_F64:
	case ARM64_INTRIN_VCVTMQ_S16_F16:
	case ARM64_INTRIN_VCVTMQ_S32_F32:
	case ARM64_INTRIN_VCVTMQ_S64_F64:
	case ARM64_INTRIN_VCVTMQ_U16_F16:
	case ARM64_INTRIN_VCVTMQ_U32_F32:
	case ARM64_INTRIN_VCVTMQ_U64_F64:
	case ARM64_INTRIN_VCVTNQ_S16_F16:
	case ARM64_INTRIN_VCVTNQ_S32_F32:
	case ARM64_INTRIN_VCVTNQ_S64_F64:
	case ARM64_INTRIN_VCVTNQ_U16_F16:
	case ARM64_INTRIN_VCVTNQ_U32_F32:
	case ARM64_INTRIN_VCVTNQ_U64_F64:
	case ARM64_INTRIN_VCVTPQ_S16_F16:
	case ARM64_INTRIN_VCVTPQ_S32_F32:
	case ARM64_INTRIN_VCVTPQ_S64_F64:
	case ARM64_INTRIN_VCVTPQ_U16_F16:
	case ARM64_INTRIN_VCVTPQ_U32_F32:
	case ARM64_INTRIN_VCVTPQ_U64_F64:
	case ARM64_INTRIN_VCVTQ_N_S16_F16:
	case ARM64_INTRIN_VCVTQ_N_S32_F32:
	case ARM64_INTRIN_VCVTQ_N_S64_F64:
	case ARM64_INTRIN_VCVTQ_N_U16_F16:
	case ARM64_INTRIN_VCVTQ_N_U32_F32:
	case ARM64_INTRIN_VCVTQ_N_U64_F64:
	case ARM64_INTRIN_VCVTQ_S16_F16:
	case ARM64_INTRIN_VCVTQ_S32_F32:
	case ARM64_INTRIN_VCVTQ_S64_F64:
	case ARM64_INTRIN_VCVTQ_U16_F16:
	case ARM64_INTRIN_VCVTQ_U32_F32:
	case ARM64_INTRIN_VCVTQ_U64_F64:
	case ARM64_INTRIN_VDOTQ_LANEQ_S32:
	case ARM64_INTRIN_VDOTQ_LANEQ_U32:
	case ARM64_INTRIN_VDOTQ_LANE_S32:
	case ARM64_INTRIN_VDOTQ_LANE_U32:
	case ARM64_INTRIN_VDOTQ_S32:
	case ARM64_INTRIN_VDOTQ_U32:
	case ARM64_INTRIN_VDUPQ_LANEQ_P16:
	case ARM64_INTRIN_VDUPQ_LANEQ_P64:
	case ARM64_INTRIN_VDUPQ_LANEQ_P8:
	case ARM64_INTRIN_VDUPQ_LANEQ_S16:
	case ARM64_INTRIN_VDUPQ_LANEQ_S32:
	case ARM64_INTRIN_VDUPQ_LANEQ_S64:
	case ARM64_INTRIN_VDUPQ_LANEQ_S8:
	case ARM64_INTRIN_VDUPQ_LANEQ_U16:
	case ARM64_INTRIN_VDUPQ_LANEQ_U32:
	case ARM64_INTRIN_VDUPQ_LANEQ_U64:
	case ARM64_INTRIN_VDUPQ_LANEQ_U8:
	case ARM64_INTRIN_VDUPQ_LANE_P16:
	case ARM64_INTRIN_VDUPQ_LANE_P64:
	case ARM64_INTRIN_VDUPQ_LANE_P8:
	case ARM64_INTRIN_VDUPQ_LANE_S16:
	case ARM64_INTRIN_VDUPQ_LANE_S32:
	case ARM64_INTRIN_VDUPQ_LANE_S64:
	case ARM64_INTRIN_VDUPQ_LANE_S8:
	case ARM64_INTRIN_VDUPQ_LANE_U16:
	case ARM64_INTRIN_VDUPQ_LANE_U32:
	case ARM64_INTRIN_VDUPQ_LANE_U64:
	case ARM64_INTRIN_VDUPQ_LANE_U8:
	case ARM64_INTRIN_VDUPQ_N_P16:
	case ARM64_INTRIN_VDUPQ_N_P64:
	case ARM64_INTRIN_VDUPQ_N_P8:
	case ARM64_INTRIN_VDUPQ_N_S16:
	case ARM64_INTRIN_VDUPQ_N_S32:
	case ARM64_INTRIN_VDUPQ_N_S64:
	case ARM64_INTRIN_VDUPQ_N_S8:
	case ARM64_INTRIN_VDUPQ_N_U16:
	case ARM64_INTRIN_VDUPQ_N_U32:
	case ARM64_INTRIN_VDUPQ_N_U64:
	case ARM64_INTRIN_VDUPQ_N_U8:
	case ARM64_INTRIN_VEOR3Q_S16:
	case ARM64_INTRIN_VEOR3Q_S32:
	case ARM64_INTRIN_VEOR3Q_S64:
	case ARM64_INTRIN_VEOR3Q_S8:
	case ARM64_INTRIN_VEOR3Q_U16:
	case ARM64_INTRIN_VEOR3Q_U32:
	case ARM64_INTRIN_VEOR3Q_U64:
	case ARM64_INTRIN_VEOR3Q_U8:
	case ARM64_INTRIN_VEORQ_S16:
	case ARM64_INTRIN_VEORQ_S32:
	case ARM64_INTRIN_VEORQ_S64:
	case ARM64_INTRIN_VEORQ_S8:
	case ARM64_INTRIN_VEORQ_U16:
	case ARM64_INTRIN_VEORQ_U32:
	case ARM64_INTRIN_VEORQ_U64:
	case ARM64_INTRIN_VEORQ_U8:
	case ARM64_INTRIN_VEXTQ_P16:
	case ARM64_INTRIN_VEXTQ_P64:
	case ARM64_INTRIN_VEXTQ_P8:
	case ARM64_INTRIN_VEXTQ_S16:
	case ARM64_INTRIN_VEXTQ_S32:
	case ARM64_INTRIN_VEXTQ_S64:
	case ARM64_INTRIN_VEXTQ_S8:
	case ARM64_INTRIN_VEXTQ_U16:
	case ARM64_INTRIN_VEXTQ_U32:
	case ARM64_INTRIN_VEXTQ_U64:
	case ARM64_INTRIN_VEXTQ_U8:
	case ARM64_INTRIN_VHADDQ_S16:
	case ARM64_INTRIN_VHADDQ_S32:
	case ARM64_INTRIN_VHADDQ_S8:
	case ARM64_INTRIN_VHADDQ_U16:
	case ARM64_INTRIN_VHADDQ_U32:
	case ARM64_INTRIN_VHADDQ_U8:
	case ARM64_INTRIN_VHSUBQ_S16:
	case ARM64_INTRIN_VHSUBQ_S32:
	case ARM64_INTRIN_VHSUBQ_S8:
	case ARM64_INTRIN_VHSUBQ_U16:
	case ARM64_INTRIN_VHSUBQ_U32:
	case ARM64_INTRIN_VHSUBQ_U8:
	case ARM64_INTRIN_VLDRQ_P128:
	case ARM64_INTRIN_VMAXQ_S16:
	case ARM64_INTRIN_VMAXQ_S32:
	case ARM64_INTRIN_VMAXQ_S8:
	case ARM64_INTRIN_VMAXQ_U16:
	case ARM64_INTRIN_VMAXQ_U32:
	case ARM64_INTRIN_VMAXQ_U8:
	case ARM64_INTRIN_VMINQ_S16:
	case ARM64_INTRIN_VMINQ_S32:
	case ARM64_INTRIN_VMINQ_S8:
	case ARM64_INTRIN_VMINQ_U16:
	case ARM64_INTRIN_VMINQ_U32:
	case ARM64_INTRIN_VMINQ_U8:
	case ARM64_INTRIN_VMLAL_HIGH_LANEQ_S16:
	case ARM64_INTRIN_VMLAL_HIGH_LANEQ_S32:
	case ARM64_INTRIN_VMLAL_HIGH_LANEQ_U16:
	case ARM64_INTRIN_VMLAL_HIGH_LANEQ_U32:
	case ARM64_INTRIN_VMLAL_HIGH_LANE_S16:
	case ARM64_INTRIN_VMLAL_HIGH_LANE_S32:
	case ARM64_INTRIN_VMLAL_HIGH_LANE_U16:
	case ARM64_INTRIN_VMLAL_HIGH_LANE_U32:
	case ARM64_INTRIN_VMLAL_HIGH_N_S16:
	case ARM64_INTRIN_VMLAL_HIGH_N_S32:
	case ARM64_INTRIN_VMLAL_HIGH_N_U16:
	case ARM64_INTRIN_VMLAL_HIGH_N_U32:
	case ARM64_INTRIN_VMLAL_HIGH_S16:
	case ARM64_INTRIN_VMLAL_HIGH_S32:
	case ARM64_INTRIN_VMLAL_HIGH_S8:
	case ARM64_INTRIN_VMLAL_HIGH_U16:
	case ARM64_INTRIN_VMLAL_HIGH_U32:
	case ARM64_INTRIN_VMLAL_HIGH_U8:
	case ARM64_INTRIN_VMLAL_LANEQ_S16:
	case ARM64_INTRIN_VMLAL_LANEQ_S32:
	case ARM64_INTRIN_VMLAL_LANEQ_U16:
	case ARM64_INTRIN_VMLAL_LANEQ_U32:
	case ARM64_INTRIN_VMLAL_LANE_S16:
	case ARM64_INTRIN_VMLAL_LANE_S32:
	case ARM64_INTRIN_VMLAL_LANE_U16:
	case ARM64_INTRIN_VMLAL_LANE_U32:
	case ARM64_INTRIN_VMLAL_N_S16:
	case ARM64_INTRIN_VMLAL_N_S32:
	case ARM64_INTRIN_VMLAL_N_U16:
	case ARM64_INTRIN_VMLAL_N_U32:
	case ARM64_INTRIN_VMLAL_S16:
	case ARM64_INTRIN_VMLAL_S32:
	case ARM64_INTRIN_VMLAL_S8:
	case ARM64_INTRIN_VMLAL_U16:
	case ARM64_INTRIN_VMLAL_U32:
	case ARM64_INTRIN_VMLAL_U8:
	case ARM64_INTRIN_VMLAQ_LANEQ_S16:
	case ARM64_INTRIN_VMLAQ_LANEQ_S32:
	case ARM64_INTRIN_VMLAQ_LANEQ_U16:
	case ARM64_INTRIN_VMLAQ_LANEQ_U32:
	case ARM64_INTRIN_VMLAQ_LANE_S16:
	case ARM64_INTRIN_VMLAQ_LANE_S32:
	case ARM64_INTRIN_VMLAQ_LANE_U16:
	case ARM64_INTRIN_VMLAQ_LANE_U32:
	case ARM64_INTRIN_VMLAQ_N_S16:
	case ARM64_INTRIN_VMLAQ_N_S32:
	case ARM64_INTRIN_VMLAQ_N_U16:
	case ARM64_INTRIN_VMLAQ_N_U32:
	case ARM64_INTRIN_VMLAQ_S16:
	case ARM64_INTRIN_VMLAQ_S32:
	case ARM64_INTRIN_VMLAQ_S8:
	case ARM64_INTRIN_VMLAQ_U16:
	case ARM64_INTRIN_VMLAQ_U32:
	case ARM64_INTRIN_VMLAQ_U8:
	case ARM64_INTRIN_VMLSL_HIGH_LANEQ_S16:
	case ARM64_INTRIN_VMLSL_HIGH_LANEQ_S32:
	case ARM64_INTRIN_VMLSL_HIGH_LANEQ_U16:
	case ARM64_INTRIN_VMLSL_HIGH_LANEQ_U32:
	case ARM64_INTRIN_VMLSL_HIGH_LANE_S16:
	case ARM64_INTRIN_VMLSL_HIGH_LANE_S32:
	case ARM64_INTRIN_VMLSL_HIGH_LANE_U16:
	case ARM64_INTRIN_VMLSL_HIGH_LANE_U32:
	case ARM64_INTRIN_VMLSL_HIGH_N_S16:
	case ARM64_INTRIN_VMLSL_HIGH_N_S32:
	case ARM64_INTRIN_VMLSL_HIGH_N_U16:
	case ARM64_INTRIN_VMLSL_HIGH_N_U32:
	case ARM64_INTRIN_VMLSL_HIGH_S16:
	case ARM64_INTRIN_VMLSL_HIGH_S32:
	case ARM64_INTRIN_VMLSL_HIGH_S8:
	case ARM64_INTRIN_VMLSL_HIGH_U16:
	case ARM64_INTRIN_VMLSL_HIGH_U32:
	case ARM64_INTRIN_VMLSL_HIGH_U8:
	case ARM64_INTRIN_VMLSL_LANEQ_S16:
	case ARM64_INTRIN_VMLSL_LANEQ_S32:
	case ARM64_INTRIN_VMLSL_LANEQ_U16:
	case ARM64_INTRIN_VMLSL_LANEQ_U32:
	case ARM64_INTRIN_VMLSL_LANE_S16:
	case ARM64_INTRIN_VMLSL_LANE_S32:
	case ARM64_INTRIN_VMLSL_LANE_U16:
	case ARM64_INTRIN_VMLSL_LANE_U32:
	case ARM64_INTRIN_VMLSL_N_S16:
	case ARM64_INTRIN_VMLSL_N_S32:
	case ARM64_INTRIN_VMLSL_N_U16:
	case ARM64_INTRIN_VMLSL_N_U32:
	case ARM64_INTRIN_VMLSL_S16:
	case ARM64_INTRIN_VMLSL_S32:
	case ARM64_INTRIN_VMLSL_S8:
	case ARM64_INTRIN_VMLSL_U16:
	case ARM64_INTRIN_VMLSL_U32:
	case ARM64_INTRIN_VMLSL_U8:
	case ARM64_INTRIN_VMLSQ_LANEQ_S16:
	case ARM64_INTRIN_VMLSQ_LANEQ_S32:
	case ARM64_INTRIN_VMLSQ_LANEQ_U16:
	case ARM64_INTRIN_VMLSQ_LANEQ_U32:
	case ARM64_INTRIN_VMLSQ_LANE_S16:
	case ARM64_INTRIN_VMLSQ_LANE_S32:
	case ARM64_INTRIN_VMLSQ_LANE_U16:
	case ARM64_INTRIN_VMLSQ_LANE_U32:
	case ARM64_INTRIN_VMLSQ_N_S16:
	case ARM64_INTRIN_VMLSQ_N_S32:
	case ARM64_INTRIN_VMLSQ_N_U16:
	case ARM64_INTRIN_VMLSQ_N_U32:
	case ARM64_INTRIN_VMLSQ_S16:
	case ARM64_INTRIN_VMLSQ_S32:
	case ARM64_INTRIN_VMLSQ_S8:
	case ARM64_INTRIN_VMLSQ_U16:
	case ARM64_INTRIN_VMLSQ_U32:
	case ARM64_INTRIN_VMLSQ_U8:
	case ARM64_INTRIN_VMMLAQ_S32:
	case ARM64_INTRIN_VMMLAQ_U32:
	case ARM64_INTRIN_VMOVL_HIGH_S16:
	case ARM64_INTRIN_VMOVL_HIGH_S32:
	case ARM64_INTRIN_VMOVL_HIGH_S8:
	case ARM64_INTRIN_VMOVL_HIGH_U16:
	case ARM64_INTRIN_VMOVL_HIGH_U32:
	case ARM64_INTRIN_VMOVL_HIGH_U8:
	case ARM64_INTRIN_VMOVL_S16:
	case ARM64_INTRIN_VMOVL_S32:
	case ARM64_INTRIN_VMOVL_S8:
	case ARM64_INTRIN_VMOVL_U16:
	case ARM64_INTRIN_VMOVL_U32:
	case ARM64_INTRIN_VMOVL_U8:
	case ARM64_INTRIN_VMOVN_HIGH_S16:
	case ARM64_INTRIN_VMOVN_HIGH_S32:
	case ARM64_INTRIN_VMOVN_HIGH_S64:
	case ARM64_INTRIN_VMOVN_HIGH_U16:
	case ARM64_INTRIN_VMOVN_HIGH_U32:
	case ARM64_INTRIN_VMOVN_HIGH_U64:
	case ARM64_INTRIN_VMOVQ_N_P16:
	case ARM64_INTRIN_VMOVQ_N_P8:
	case ARM64_INTRIN_VMOVQ_N_S16:
	case ARM64_INTRIN_VMOVQ_N_S32:
	case ARM64_INTRIN_VMOVQ_N_S64:
	case ARM64_INTRIN_VMOVQ_N_S8:
	case ARM64_INTRIN_VMOVQ_N_U16:
	case ARM64_INTRIN_VMOVQ_N_U32:
	case ARM64_INTRIN_VMOVQ_N_U64:
	case ARM64_INTRIN_VMOVQ_N_U8:
	case ARM64_INTRIN_VMULL_HIGH_LANEQ_S16:
	case ARM64_INTRIN_VMULL_HIGH_LANEQ_S32:
	case ARM64_INTRIN_VMULL_HIGH_LANEQ_U16:
	case ARM64_INTRIN_VMULL_HIGH_LANEQ_U32:
	case ARM64_INTRIN_VMULL_HIGH_LANE_S16:
	case ARM64_INTRIN_VMULL_HIGH_LANE_S32:
	case ARM64_INTRIN_VMULL_HIGH_LANE_U16:
	case ARM64_INTRIN_VMULL_HIGH_LANE_U32:
	case ARM64_INTRIN_VMULL_HIGH_N_S16:
	case ARM64_INTRIN_VMULL_HIGH_N_S32:
	case ARM64_INTRIN_VMULL_HIGH_N_U16:
	case ARM64_INTRIN_VMULL_HIGH_N_U32:
	case ARM64_INTRIN_VMULL_HIGH_P64:
	case ARM64_INTRIN_VMULL_HIGH_P8:
	case ARM64_INTRIN_VMULL_HIGH_S16:
	case ARM64_INTRIN_VMULL_HIGH_S32:
	case ARM64_INTRIN_VMULL_HIGH_S8:
	case ARM64_INTRIN_VMULL_HIGH_U16:
	case ARM64_INTRIN_VMULL_HIGH_U32:
	case ARM64_INTRIN_VMULL_HIGH_U8:
	case ARM64_INTRIN_VMULL_LANEQ_S16:
	case ARM64_INTRIN_VMULL_LANEQ_S32:
	case ARM64_INTRIN_VMULL_LANEQ_U16:
	case ARM64_INTRIN_VMULL_LANEQ_U32:
	case ARM64_INTRIN_VMULL_LANE_S16:
	case ARM64_INTRIN_VMULL_LANE_S32:
	case ARM64_INTRIN_VMULL_LANE_U16:
	case ARM64_INTRIN_VMULL_LANE_U32:
	case ARM64_INTRIN_VMULL_N_S16:
	case ARM64_INTRIN_VMULL_N_S32:
	case ARM64_INTRIN_VMULL_N_U16:
	case ARM64_INTRIN_VMULL_N_U32:
	case ARM64_INTRIN_VMULL_P64:
	case ARM64_INTRIN_VMULL_P8:
	case ARM64_INTRIN_VMULL_S16:
	case ARM64_INTRIN_VMULL_S32:
	case ARM64_INTRIN_VMULL_S8:
	case ARM64_INTRIN_VMULL_U16:
	case ARM64_INTRIN_VMULL_U32:
	case ARM64_INTRIN_VMULL_U8:
	case ARM64_INTRIN_VMULQ_LANEQ_S16:
	case ARM64_INTRIN_VMULQ_LANEQ_S32:
	case ARM64_INTRIN_VMULQ_LANEQ_U16:
	case ARM64_INTRIN_VMULQ_LANEQ_U32:
	case ARM64_INTRIN_VMULQ_LANE_S16:
	case ARM64_INTRIN_VMULQ_LANE_S32:
	case ARM64_INTRIN_VMULQ_LANE_U16:
	case ARM64_INTRIN_VMULQ_LANE_U32:
	case ARM64_INTRIN_VMULQ_N_S16:
	case ARM64_INTRIN_VMULQ_N_S32:
	case ARM64_INTRIN_VMULQ_N_U16:
	case ARM64_INTRIN_VMULQ_N_U32:
	case ARM64_INTRIN_VMULQ_P8:
	case ARM64_INTRIN_VMULQ_S16:
	case ARM64_INTRIN_VMULQ_S32:
	case ARM64_INTRIN_VMULQ_S8:
	case ARM64_INTRIN_VMULQ_U16:
	case ARM64_INTRIN_VMULQ_U32:
	case ARM64_INTRIN_VMULQ_U8:
	case ARM64_INTRIN_VMVNQ_P8:
	case ARM64_INTRIN_VMVNQ_S16:
	case ARM64_INTRIN_VMVNQ_S32:
	case ARM64_INTRIN_VMVNQ_S8:
	case ARM64_INTRIN_VMVNQ_U16:
	case ARM64_INTRIN_VMVNQ_U32:
	case ARM64_INTRIN_VMVNQ_U8:
	case ARM64_INTRIN_VNEGQ_S16:
	case ARM64_INTRIN_VNEGQ_S32:
	case ARM64_INTRIN_VNEGQ_S64:
	case ARM64_INTRIN_VNEGQ_S8:
	case ARM64_INTRIN_VORNQ_S16:
	case ARM64_INTRIN_VORNQ_S32:
	case ARM64_INTRIN_VORNQ_S64:
	case ARM64_INTRIN_VORNQ_S8:
	case ARM64_INTRIN_VORNQ_U16:
	case ARM64_INTRIN_VORNQ_U32:
	case ARM64_INTRIN_VORNQ_U64:
	case ARM64_INTRIN_VORNQ_U8:
	case ARM64_INTRIN_VORRQ_S16:
	case ARM64_INTRIN_VORRQ_S32:
	case ARM64_INTRIN_VORRQ_S64:
	case ARM64_INTRIN_VORRQ_S8:
	case ARM64_INTRIN_VORRQ_U16:
	case ARM64_INTRIN_VORRQ_U32:
	case ARM64_INTRIN_VORRQ_U64:
	case ARM64_INTRIN_VORRQ_U8:
	case ARM64_INTRIN_VPADALQ_S16:
	case ARM64_INTRIN_VPADALQ_S32:
	case ARM64_INTRIN_VPADALQ_S8:
	case ARM64_INTRIN_VPADALQ_U16:
	case ARM64_INTRIN_VPADALQ_U32:
	case ARM64_INTRIN_VPADALQ_U8:
	case ARM64_INTRIN_VPADDLQ_S16:
	case ARM64_INTRIN_VPADDLQ_S32:
	case ARM64_INTRIN_VPADDLQ_S8:
	case ARM64_INTRIN_VPADDLQ_U16:
	case ARM64_INTRIN_VPADDLQ_U32:
	case ARM64_INTRIN_VPADDLQ_U8:
	case ARM64_INTRIN_VPADDQ_S16:
	case ARM64_INTRIN_VPADDQ_S32:
	case ARM64_INTRIN_VPADDQ_S64:
	case ARM64_INTRIN_VPADDQ_S8:
	case ARM64_INTRIN_VPADDQ_U16:
	case ARM64_INTRIN_VPADDQ_U32:
	case ARM64_INTRIN_VPADDQ_U64:
	case ARM64_INTRIN_VPADDQ_U8:
	case ARM64_INTRIN_VPMAXQ_S16:
	case ARM64_INTRIN_VPMAXQ_S32:
	case ARM64_INTRIN_VPMAXQ_S8:
	case ARM64_INTRIN_VPMAXQ_U16:
	case ARM64_INTRIN_VPMAXQ_U32:
	case ARM64_INTRIN_VPMAXQ_U8:
	case ARM64_INTRIN_VPMINQ_S16:
	case ARM64_INTRIN_VPMINQ_S32:
	case ARM64_INTRIN_VPMINQ_S8:
	case ARM64_INTRIN_VPMINQ_U16:
	case ARM64_INTRIN_VPMINQ_U32:
	case ARM64_INTRIN_VPMINQ_U8:
	case ARM64_INTRIN_VQABSQ_S16:
	case ARM64_INTRIN_VQABSQ_S32:
	case ARM64_INTRIN_VQABSQ_S64:
	case ARM64_INTRIN_VQABSQ_S8:
	case ARM64_INTRIN_VQADDQ_S16:
	case ARM64_INTRIN_VQADDQ_S32:
	case ARM64_INTRIN_VQADDQ_S64:
	case ARM64_INTRIN_VQADDQ_S8:
	case ARM64_INTRIN_VQADDQ_U16:
	case ARM64_INTRIN_VQADDQ_U32:
	case ARM64_INTRIN_VQADDQ_U64:
	case ARM64_INTRIN_VQADDQ_U8:
	case ARM64_INTRIN_VQDMLAL_HIGH_LANEQ_S16:
	case ARM64_INTRIN_VQDMLAL_HIGH_LANEQ_S32:
	case ARM64_INTRIN_VQDMLAL_HIGH_LANE_S16:
	case ARM64_INTRIN_VQDMLAL_HIGH_LANE_S32:
	case ARM64_INTRIN_VQDMLAL_HIGH_N_S16:
	case ARM64_INTRIN_VQDMLAL_HIGH_N_S32:
	case ARM64_INTRIN_VQDMLAL_HIGH_S16:
	case ARM64_INTRIN_VQDMLAL_HIGH_S32:
	case ARM64_INTRIN_VQDMLAL_LANEQ_S16:
	case ARM64_INTRIN_VQDMLAL_LANEQ_S32:
	case ARM64_INTRIN_VQDMLAL_LANE_S16:
	case ARM64_INTRIN_VQDMLAL_LANE_S32:
	case ARM64_INTRIN_VQDMLAL_N_S16:
	case ARM64_INTRIN_VQDMLAL_N_S32:
	case ARM64_INTRIN_VQDMLAL_S16:
	case ARM64_INTRIN_VQDMLAL_S32:
	case ARM64_INTRIN_VQDMLSL_HIGH_LANEQ_S16:
	case ARM64_INTRIN_VQDMLSL_HIGH_LANEQ_S32:
	case ARM64_INTRIN_VQDMLSL_HIGH_LANE_S16:
	case ARM64_INTRIN_VQDMLSL_HIGH_LANE_S32:
	case ARM64_INTRIN_VQDMLSL_HIGH_N_S16:
	case ARM64_INTRIN_VQDMLSL_HIGH_N_S32:
	case ARM64_INTRIN_VQDMLSL_HIGH_S16:
	case ARM64_INTRIN_VQDMLSL_HIGH_S32:
	case ARM64_INTRIN_VQDMLSL_LANEQ_S16:
	case ARM64_INTRIN_VQDMLSL_LANEQ_S32:
	case ARM64_INTRIN_VQDMLSL_LANE_S16:
	case ARM64_INTRIN_VQDMLSL_LANE_S32:
	case ARM64_INTRIN_VQDMLSL_N_S16:
	case ARM64_INTRIN_VQDMLSL_N_S32:
	case ARM64_INTRIN_VQDMLSL_S16:
	case ARM64_INTRIN_VQDMLSL_S32:
	case ARM64_INTRIN_VQDMULHQ_LANEQ_S16:
	case ARM64_INTRIN_VQDMULHQ_LANEQ_S32:
	case ARM64_INTRIN_VQDMULHQ_LANE_S16:
	case ARM64_INTRIN_VQDMULHQ_LANE_S32:
	case ARM64_INTRIN_VQDMULHQ_N_S16:
	case ARM64_INTRIN_VQDMULHQ_N_S32:
	case ARM64_INTRIN_VQDMULHQ_S16:
	case ARM64_INTRIN_VQDMULHQ_S32:
	case ARM64_INTRIN_VQDMULL_HIGH_LANEQ_S16:
	case ARM64_INTRIN_VQDMULL_HIGH_LANEQ_S32:
	case ARM64_INTRIN_VQDMULL_HIGH_LANE_S16:
	case ARM64_INTRIN_VQDMULL_HIGH_LANE_S32:
	case ARM64_INTRIN_VQDMULL_HIGH_N_S16:
	case ARM64_INTRIN_VQDMULL_HIGH_N_S32:
	case ARM64_INTRIN_VQDMULL_HIGH_S16:
	case ARM64_INTRIN_VQDMULL_HIGH_S32:
	case ARM64_INTRIN_VQDMULL_LANEQ_S16:
	case ARM64_INTRIN_VQDMULL_LANEQ_S32:
	case ARM64_INTRIN_VQDMULL_LANE_S16:
	case ARM64_INTRIN_VQDMULL_LANE_S32:
	case ARM64_INTRIN_VQDMULL_N_S16:
	case ARM64_INTRIN_VQDMULL_N_S32:
	case ARM64_INTRIN_VQDMULL_S16:
	case ARM64_INTRIN_VQDMULL_S32:
	case ARM64_INTRIN_VQMOVN_HIGH_S16:
	case ARM64_INTRIN_VQMOVN_HIGH_S32:
	case ARM64_INTRIN_VQMOVN_HIGH_S64:
	case ARM64_INTRIN_VQMOVN_HIGH_U16:
	case ARM64_INTRIN_VQMOVN_HIGH_U32:
	case ARM64_INTRIN_VQMOVN_HIGH_U64:
	case ARM64_INTRIN_VQMOVUN_HIGH_S16:
	case ARM64_INTRIN_VQMOVUN_HIGH_S32:
	case ARM64_INTRIN_VQMOVUN_HIGH_S64:
	case ARM64_INTRIN_VQNEGQ_S16:
	case ARM64_INTRIN_VQNEGQ_S32:
	case ARM64_INTRIN_VQNEGQ_S64:
	case ARM64_INTRIN_VQNEGQ_S8:
	case ARM64_INTRIN_VQRDMLAHQ_LANEQ_S16:
	case ARM64_INTRIN_VQRDMLAHQ_LANEQ_S32:
	case ARM64_INTRIN_VQRDMLAHQ_LANE_S16:
	case ARM64_INTRIN_VQRDMLAHQ_LANE_S32:
	case ARM64_INTRIN_VQRDMLAHQ_S16:
	case ARM64_INTRIN_VQRDMLAHQ_S32:
	case ARM64_INTRIN_VQRDMLSHQ_LANEQ_S16:
	case ARM64_INTRIN_VQRDMLSHQ_LANEQ_S32:
	case ARM64_INTRIN_VQRDMLSHQ_LANE_S16:
	case ARM64_INTRIN_VQRDMLSHQ_LANE_S32:
	case ARM64_INTRIN_VQRDMLSHQ_S16:
	case ARM64_INTRIN_VQRDMLSHQ_S32:
	case ARM64_INTRIN_VQRDMULHQ_LANEQ_S16:
	case ARM64_INTRIN_VQRDMULHQ_LANEQ_S32:
	case ARM64_INTRIN_VQRDMULHQ_LANE_S16:
	case ARM64_INTRIN_VQRDMULHQ_LANE_S32:
	case ARM64_INTRIN_VQRDMULHQ_N_S16:
	case ARM64_INTRIN_VQRDMULHQ_N_S32:
	case ARM64_INTRIN_VQRDMULHQ_S16:
	case ARM64_INTRIN_VQRDMULHQ_S32:
	case ARM64_INTRIN_VQRSHLQ_S16:
	case ARM64_INTRIN_VQRSHLQ_S32:
	case ARM64_INTRIN_VQRSHLQ_S64:
	case ARM64_INTRIN_VQRSHLQ_S8:
	case ARM64_INTRIN_VQRSHLQ_U16:
	case ARM64_INTRIN_VQRSHLQ_U32:
	case ARM64_INTRIN_VQRSHLQ_U64:
	case ARM64_INTRIN_VQRSHLQ_U8:
	case ARM64_INTRIN_VQRSHRN_HIGH_N_S16:
	case ARM64_INTRIN_VQRSHRN_HIGH_N_S32:
	case ARM64_INTRIN_VQRSHRN_HIGH_N_S64:
	case ARM64_INTRIN_VQRSHRN_HIGH_N_U16:
	case ARM64_INTRIN_VQRSHRN_HIGH_N_U32:
	case ARM64_INTRIN_VQRSHRN_HIGH_N_U64:
	case ARM64_INTRIN_VQRSHRUN_HIGH_N_S16:
	case ARM64_INTRIN_VQRSHRUN_HIGH_N_S32:
	case ARM64_INTRIN_VQRSHRUN_HIGH_N_S64:
	case ARM64_INTRIN_VQSHLQ_N_S16:
	case ARM64_INTRIN_VQSHLQ_N_S32:
	case ARM64_INTRIN_VQSHLQ_N_S64:
	case ARM64_INTRIN_VQSHLQ_N_S8:
	case ARM64_INTRIN_VQSHLQ_N_U16:
	case ARM64_INTRIN_VQSHLQ_N_U32:
	case ARM64_INTRIN_VQSHLQ_N_U64:
	case ARM64_INTRIN_VQSHLQ_N_U8:
	case ARM64_INTRIN_VQSHLQ_S16:
	case ARM64_INTRIN_VQSHLQ_S32:
	case ARM64_INTRIN_VQSHLQ_S64:
	case ARM64_INTRIN_VQSHLQ_S8:
	case ARM64_INTRIN_VQSHLQ_U16:
	case ARM64_INTRIN_VQSHLQ_U32:
	case ARM64_INTRIN_VQSHLQ_U64:
	case ARM64_INTRIN_VQSHLQ_U8:
	case ARM64_INTRIN_VQSHLUQ_N_S16:
	case ARM64_INTRIN_VQSHLUQ_N_S32:
	case ARM64_INTRIN_VQSHLUQ_N_S64:
	case ARM64_INTRIN_VQSHLUQ_N_S8:
	case ARM64_INTRIN_VQSHRN_HIGH_N_S16:
	case ARM64_INTRIN_VQSHRN_HIGH_N_S32:
	case ARM64_INTRIN_VQSHRN_HIGH_N_S64:
	case ARM64_INTRIN_VQSHRN_HIGH_N_U16:
	case ARM64_INTRIN_VQSHRN_HIGH_N_U32:
	case ARM64_INTRIN_VQSHRN_HIGH_N_U64:
	case ARM64_INTRIN_VQSHRUN_HIGH_N_S16:
	case ARM64_INTRIN_VQSHRUN_HIGH_N_S32:
	case ARM64_INTRIN_VQSHRUN_HIGH_N_S64:
	case ARM64_INTRIN_VQSUBQ_S16:
	case ARM64_INTRIN_VQSUBQ_S32:
	case ARM64_INTRIN_VQSUBQ_S64:
	case ARM64_INTRIN_VQSUBQ_S8:
	case ARM64_INTRIN_VQSUBQ_U16:
	case ARM64_INTRIN_VQSUBQ_U32:
	case ARM64_INTRIN_VQSUBQ_U64:
	case ARM64_INTRIN_VQSUBQ_U8:
	case ARM64_INTRIN_VRADDHN_HIGH_S16:
	case ARM64_INTRIN_VRADDHN_HIGH_S32:
	case ARM64_INTRIN_VRADDHN_HIGH_S64:
	case ARM64_INTRIN_VRADDHN_HIGH_U16:
	case ARM64_INTRIN_VRADDHN_HIGH_U32:
	case ARM64_INTRIN_VRADDHN_HIGH_U64:
	case ARM64_INTRIN_VRAX1Q_U64:
	case ARM64_INTRIN_VRBITQ_P8:
	case ARM64_INTRIN_VRBITQ_S8:
	case ARM64_INTRIN_VRBITQ_U8:
	case ARM64_INTRIN_VRECPEQ_U32:
	case ARM64_INTRIN_VREV16Q_P8:
	case ARM64_INTRIN_VREV16Q_S8:
	case ARM64_INTRIN_VREV16Q_U8:
	case ARM64_INTRIN_VREV32Q_P16:
	case ARM64_INTRIN_VREV32Q_P8:
	case ARM64_INTRIN_VREV32Q_S16:
	case ARM64_INTRIN_VREV32Q_S8:
	case ARM64_INTRIN_VREV32Q_U16:
	case ARM64_INTRIN_VREV32Q_U8:
	case ARM64_INTRIN_VREV64Q_P16:
	case ARM64_INTRIN_VREV64Q_P8:
	case ARM64_INTRIN_VREV64Q_S16:
	case ARM64_INTRIN_VREV64Q_S32:
	case ARM64_INTRIN_VREV64Q_S8:
	case ARM64_INTRIN_VREV64Q_U16:
	case ARM64_INTRIN_VREV64Q_U32:
	case ARM64_INTRIN_VREV64Q_U8:
	case ARM64_INTRIN_VRHADDQ_S16:
	case ARM64_INTRIN_VRHADDQ_S32:
	case ARM64_INTRIN_VRHADDQ_S8:
	case ARM64_INTRIN_VRHADDQ_U16:
	case ARM64_INTRIN_VRHADDQ_U32:
	case ARM64_INTRIN_VRHADDQ_U8:
	case ARM64_INTRIN_VRSHLQ_S16:
	case ARM64_INTRIN_VRSHLQ_S32:
	case ARM64_INTRIN_VRSHLQ_S64:
	case ARM64_INTRIN_VRSHLQ_S8:
	case ARM64_INTRIN_VRSHLQ_U16:
	case ARM64_INTRIN_VRSHLQ_U32:
	case ARM64_INTRIN_VRSHLQ_U64:
	case ARM64_INTRIN_VRSHLQ_U8:
	case ARM64_INTRIN_VRSHRN_HIGH_N_S16:
	case ARM64_INTRIN_VRSHRN_HIGH_N_S32:
	case ARM64_INTRIN_VRSHRN_HIGH_N_S64:
	case ARM64_INTRIN_VRSHRN_HIGH_N_U16:
	case ARM64_INTRIN_VRSHRN_HIGH_N_U32:
	case ARM64_INTRIN_VRSHRN_HIGH_N_U64:
	case ARM64_INTRIN_VRSHRQ_N_S16:
	case ARM64_INTRIN_VRSHRQ_N_S32:
	case ARM64_INTRIN_VRSHRQ_N_S64:
	case ARM64_INTRIN_VRSHRQ_N_S8:
	case ARM64_INTRIN_VRSHRQ_N_U16:
	case ARM64_INTRIN_VRSHRQ_N_U32:
	case ARM64_INTRIN_VRSHRQ_N_U64:
	case ARM64_INTRIN_VRSHRQ_N_U8:
	case ARM64_INTRIN_VRSQRTEQ_U32:
	case ARM64_INTRIN_VRSRAQ_N_S16:
	case ARM64_INTRIN_VRSRAQ_N_S32:
	case ARM64_INTRIN_VRSRAQ_N_S64:
	case ARM64_INTRIN_VRSRAQ_N_S8:
	case ARM64_INTRIN_VRSRAQ_N_U16:
	case ARM64_INTRIN_VRSRAQ_N_U32:
	case ARM64_INTRIN_VRSRAQ_N_U64:
	case ARM64_INTRIN_VRSRAQ_N_U8:
	case ARM64_INTRIN_VRSUBHN_HIGH_S16:
	case ARM64_INTRIN_VRSUBHN_HIGH_S32:
	case ARM64_INTRIN_VRSUBHN_HIGH_S64:
	case ARM64_INTRIN_VRSUBHN_HIGH_U16:
	case ARM64_INTRIN_VRSUBHN_HIGH_U32:
	case ARM64_INTRIN_VRSUBHN_HIGH_U64:
	case ARM64_INTRIN_VSETQ_LANE_P16:
	case ARM64_INTRIN_VSETQ_LANE_P64:
	case ARM64_INTRIN_VSETQ_LANE_P8:
	case ARM64_INTRIN_VSETQ_LANE_S16:
	case ARM64_INTRIN_VSETQ_LANE_S32:
	case ARM64_INTRIN_VSETQ_LANE_S64:
	case ARM64_INTRIN_VSETQ_LANE_S8:
	case ARM64_INTRIN_VSETQ_LANE_U16:
	case ARM64_INTRIN_VSETQ_LANE_U32:
	case ARM64_INTRIN_VSETQ_LANE_U64:
	case ARM64_INTRIN_VSETQ_LANE_U8:
	case ARM64_INTRIN_VSHA1CQ_U32:
	case ARM64_INTRIN_VSHA1MQ_U32:
	case ARM64_INTRIN_VSHA1PQ_U32:
	case ARM64_INTRIN_VSHA1SU0Q_U32:
	case ARM64_INTRIN_VSHA1SU1Q_U32:
	case ARM64_INTRIN_VSHA256H2Q_U32:
	case ARM64_INTRIN_VSHA256HQ_U32:
	case ARM64_INTRIN_VSHA256SU0Q_U32:
	case ARM64_INTRIN_VSHA256SU1Q_U32:
	case ARM64_INTRIN_VSHA512H2Q_U64:
	case ARM64_INTRIN_VSHA512HQ_U64:
	case ARM64_INTRIN_VSHA512SU0Q_U64:
	case ARM64_INTRIN_VSHA512SU1Q_U64:
	case ARM64_INTRIN_VSHLL_HIGH_N_S16:
	case ARM64_INTRIN_VSHLL_HIGH_N_S32:
	case ARM64_INTRIN_VSHLL_HIGH_N_S8:
	case ARM64_INTRIN_VSHLL_HIGH_N_U16:
	case ARM64_INTRIN_VSHLL_HIGH_N_U32:
	case ARM64_INTRIN_VSHLL_HIGH_N_U8:
	case ARM64_INTRIN_VSHLL_N_S16:
	case ARM64_INTRIN_VSHLL_N_S32:
	case ARM64_INTRIN_VSHLL_N_S8:
	case ARM64_INTRIN_VSHLL_N_U16:
	case ARM64_INTRIN_VSHLL_N_U32:
	case ARM64_INTRIN_VSHLL_N_U8:
	case ARM64_INTRIN_VSHLQ_N_S16:
	case ARM64_INTRIN_VSHLQ_N_S32:
	case ARM64_INTRIN_VSHLQ_N_S64:
	case ARM64_INTRIN_VSHLQ_N_S8:
	case ARM64_INTRIN_VSHLQ_N_U16:
	case ARM64_INTRIN_VSHLQ_N_U32:
	case ARM64_INTRIN_VSHLQ_N_U64:
	case ARM64_INTRIN_VSHLQ_N_U8:
	case ARM64_INTRIN_VSHLQ_S16:
	case ARM64_INTRIN_VSHLQ_S32:
	case ARM64_INTRIN_VSHLQ_S64:
	case ARM64_INTRIN_VSHLQ_S8:
	case ARM64_INTRIN_VSHLQ_U16:
	case ARM64_INTRIN_VSHLQ_U32:
	case ARM64_INTRIN_VSHLQ_U64:
	case ARM64_INTRIN_VSHLQ_U8:
	case ARM64_INTRIN_VSHRN_HIGH_N_S16:
	case ARM64_INTRIN_VSHRN_HIGH_N_S32:
	case ARM64_INTRIN_VSHRN_HIGH_N_S64:
	case ARM64_INTRIN_VSHRN_HIGH_N_U16:
	case ARM64_INTRIN_VSHRN_HIGH_N_U32:
	case ARM64_INTRIN_VSHRN_HIGH_N_U64:
	case ARM64_INTRIN_VSHRQ_N_S16:
	case ARM64_INTRIN_VSHRQ_N_S32:
	case ARM64_INTRIN_VSHRQ_N_S64:
	case ARM64_INTRIN_VSHRQ_N_S8:
	case ARM64_INTRIN_VSHRQ_N_U16:
	case ARM64_INTRIN_VSHRQ_N_U32:
	case ARM64_INTRIN_VSHRQ_N_U64:
	case ARM64_INTRIN_VSHRQ_N_U8:
	case ARM64_INTRIN_VSLIQ_N_P16:
	case ARM64_INTRIN_VSLIQ_N_P64:
	case ARM64_INTRIN_VSLIQ_N_P8:
	case ARM64_INTRIN_VSLIQ_N_S16:
	case ARM64_INTRIN_VSLIQ_N_S32:
	case ARM64_INTRIN_VSLIQ_N_S64:
	case ARM64_INTRIN_VSLIQ_N_S8:
	case ARM64_INTRIN_VSLIQ_N_U16:
	case ARM64_INTRIN_VSLIQ_N_U32:
	case ARM64_INTRIN_VSLIQ_N_U64:
	case ARM64_INTRIN_VSLIQ_N_U8:
	case ARM64_INTRIN_VSM3PARTW1Q_U32:
	case ARM64_INTRIN_VSM3PARTW2Q_U32:
	case ARM64_INTRIN_VSM3SS1Q_U32:
	case ARM64_INTRIN_VSM3TT1AQ_U32:
	case ARM64_INTRIN_VSM3TT1BQ_U32:
	case ARM64_INTRIN_VSM3TT2AQ_U32:
	case ARM64_INTRIN_VSM3TT2BQ_U32:
	case ARM64_INTRIN_VSM4EKEYQ_U32:
	case ARM64_INTRIN_VSM4EQ_U32:
	case ARM64_INTRIN_VSQADDQ_U16:
	case ARM64_INTRIN_VSQADDQ_U32:
	case ARM64_INTRIN_VSQADDQ_U64:
	case ARM64_INTRIN_VSQADDQ_U8:
	case ARM64_INTRIN_VSRAQ_N_S16:
	case ARM64_INTRIN_VSRAQ_N_S32:
	case ARM64_INTRIN_VSRAQ_N_S64:
	case ARM64_INTRIN_VSRAQ_N_S8:
	case ARM64_INTRIN_VSRAQ_N_U16:
	case ARM64_INTRIN_VSRAQ_N_U32:
	case ARM64_INTRIN_VSRAQ_N_U64:
	case ARM64_INTRIN_VSRAQ_N_U8:
	case ARM64_INTRIN_VSRIQ_N_P16:
	case ARM64_INTRIN_VSRIQ_N_P64:
	case ARM64_INTRIN_VSRIQ_N_P8:
	case ARM64_INTRIN_VSRIQ_N_S16:
	case ARM64_INTRIN_VSRIQ_N_S32:
	case ARM64_INTRIN_VSRIQ_N_S64:
	case ARM64_INTRIN_VSRIQ_N_S8:
	case ARM64_INTRIN_VSRIQ_N_U16:
	case ARM64_INTRIN_VSRIQ_N_U32:
	case ARM64_INTRIN_VSRIQ_N_U64:
	case ARM64_INTRIN_VSRIQ_N_U8:
	case ARM64_INTRIN_VSUBHN_HIGH_S16:
	case ARM64_INTRIN_VSUBHN_HIGH_S32:
	case ARM64_INTRIN_VSUBHN_HIGH_S64:
	case ARM64_INTRIN_VSUBHN_HIGH_U16:
	case ARM64_INTRIN_VSUBHN_HIGH_U32:
	case ARM64_INTRIN_VSUBHN_HIGH_U64:
	case ARM64_INTRIN_VSUBL_HIGH_S16:
	case ARM64_INTRIN_VSUBL_HIGH_S32:
	case ARM64_INTRIN_VSUBL_HIGH_S8:
	case ARM64_INTRIN_VSUBL_HIGH_U16:
	case ARM64_INTRIN_VSUBL_HIGH_U32:
	case ARM64_INTRIN_VSUBL_HIGH_U8:
	case ARM64_INTRIN_VSUBL_S16:
	case ARM64_INTRIN_VSUBL_S32:
	case ARM64_INTRIN_VSUBL_S8:
	case ARM64_INTRIN_VSUBL_U16:
	case ARM64_INTRIN_VSUBL_U32:
	case ARM64_INTRIN_VSUBL_U8:
	case ARM64_INTRIN_VSUBQ_S16:
	case ARM64_INTRIN_VSUBQ_S32:
	case ARM64_INTRIN_VSUBQ_S64:
	case ARM64_INTRIN_VSUBQ_S8:
	case ARM64_INTRIN_VSUBQ_U16:
	case ARM64_INTRIN_VSUBQ_U32:
	case ARM64_INTRIN_VSUBQ_U64:
	case ARM64_INTRIN_VSUBQ_U8:
	case ARM64_INTRIN_VSUBW_HIGH_S16:
	case ARM64_INTRIN_VSUBW_HIGH_S32:
	case ARM64_INTRIN_VSUBW_HIGH_S8:
	case ARM64_INTRIN_VSUBW_HIGH_U16:
	case ARM64_INTRIN_VSUBW_HIGH_U32:
	case ARM64_INTRIN_VSUBW_HIGH_U8:
	case ARM64_INTRIN_VSUBW_S16:
	case ARM64_INTRIN_VSUBW_S32:
	case ARM64_INTRIN_VSUBW_S8:
	case ARM64_INTRIN_VSUBW_U16:
	case ARM64_INTRIN_VSUBW_U32:
	case ARM64_INTRIN_VSUBW_U8:
	case ARM64_INTRIN_VSUDOTQ_LANEQ_S32:
	case ARM64_INTRIN_VSUDOTQ_LANE_S32:
	case ARM64_INTRIN_VTRN1Q_P16:
	case ARM64_INTRIN_VTRN1Q_P64:
	case ARM64_INTRIN_VTRN1Q_P8:
	case ARM64_INTRIN_VTRN1Q_S16:
	case ARM64_INTRIN_VTRN1Q_S32:
	case ARM64_INTRIN_VTRN1Q_S64:
	case ARM64_INTRIN_VTRN1Q_S8:
	case ARM64_INTRIN_VTRN1Q_U16:
	case ARM64_INTRIN_VTRN1Q_U32:
	case ARM64_INTRIN_VTRN1Q_U64:
	case ARM64_INTRIN_VTRN1Q_U8:
	case ARM64_INTRIN_VTRN2Q_P16:
	case ARM64_INTRIN_VTRN2Q_P64:
	case ARM64_INTRIN_VTRN2Q_P8:
	case ARM64_INTRIN_VTRN2Q_S16:
	case ARM64_INTRIN_VTRN2Q_S32:
	case ARM64_INTRIN_VTRN2Q_S64:
	case ARM64_INTRIN_VTRN2Q_S8:
	case ARM64_INTRIN_VTRN2Q_U16:
	case ARM64_INTRIN_VTRN2Q_U32:
	case ARM64_INTRIN_VTRN2Q_U64:
	case ARM64_INTRIN_VTRN2Q_U8:
	case ARM64_INTRIN_VTSTQ_P64:
	case ARM64_INTRIN_VTSTQ_P8:
	case ARM64_INTRIN_VTSTQ_S16:
	case ARM64_INTRIN_VTSTQ_S32:
	case ARM64_INTRIN_VTSTQ_S64:
	case ARM64_INTRIN_VTSTQ_S8:
	case ARM64_INTRIN_VTSTQ_U16:
	case ARM64_INTRIN_VTSTQ_U32:
	case ARM64_INTRIN_VTSTQ_U64:
	case ARM64_INTRIN_VTSTQ_U8:
	case ARM64_INTRIN_VUQADDQ_S16:
	case ARM64_INTRIN_VUQADDQ_S32:
	case ARM64_INTRIN_VUQADDQ_S64:
	case ARM64_INTRIN_VUQADDQ_S8:
	case ARM64_INTRIN_VUSDOTQ_LANEQ_S32:
	case ARM64_INTRIN_VUSDOTQ_LANE_S32:
	case ARM64_INTRIN_VUSDOTQ_S32:
	case ARM64_INTRIN_VUSMMLAQ_S32:
	case ARM64_INTRIN_VUZP1Q_P16:
	case ARM64_INTRIN_VUZP1Q_P64:
	case ARM64_INTRIN_VUZP1Q_P8:
	case ARM64_INTRIN_VUZP1Q_S16:
	case ARM64_INTRIN_VUZP1Q_S32:
	case ARM64_INTRIN_VUZP1Q_S64:
	case ARM64_INTRIN_VUZP1Q_S8:
	case ARM64_INTRIN_VUZP1Q_U16:
	case ARM64_INTRIN_VUZP1Q_U32:
	case ARM64_INTRIN_VUZP1Q_U64:
	case ARM64_INTRIN_VUZP1Q_U8:
	case ARM64_INTRIN_VUZP2Q_P16:
	case ARM64_INTRIN_VUZP2Q_P64:
	case ARM64_INTRIN_VUZP2Q_P8:
	case ARM64_INTRIN_VUZP2Q_S16:
	case ARM64_INTRIN_VUZP2Q_S32:
	case ARM64_INTRIN_VUZP2Q_S64:
	case ARM64_INTRIN_VUZP2Q_S8:
	case ARM64_INTRIN_VUZP2Q_U16:
	case ARM64_INTRIN_VUZP2Q_U32:
	case ARM64_INTRIN_VUZP2Q_U64:
	case ARM64_INTRIN_VUZP2Q_U8:
	case ARM64_INTRIN_VXARQ_U64:
	case ARM64_INTRIN_VZIP1Q_P16:
	case ARM64_INTRIN_VZIP1Q_P64:
	case ARM64_INTRIN_VZIP1Q_P8:
	case ARM64_INTRIN_VZIP1Q_S16:
	case ARM64_INTRIN_VZIP1Q_S32:
	case ARM64_INTRIN_VZIP1Q_S64:
	case ARM64_INTRIN_VZIP1Q_S8:
	case ARM64_INTRIN_VZIP1Q_U16:
	case ARM64_INTRIN_VZIP1Q_U32:
	case ARM64_INTRIN_VZIP1Q_U64:
	case ARM64_INTRIN_VZIP1Q_U8:
	case ARM64_INTRIN_VZIP2Q_P16:
	case ARM64_INTRIN_VZIP2Q_P64:
	case ARM64_INTRIN_VZIP2Q_P8:
	case ARM64_INTRIN_VZIP2Q_S16:
	case ARM64_INTRIN_VZIP2Q_S32:
	case ARM64_INTRIN_VZIP2Q_S64:
	case ARM64_INTRIN_VZIP2Q_S8:
	case ARM64_INTRIN_VZIP2Q_U16:
	case ARM64_INTRIN_VZIP2Q_U32:
	case ARM64_INTRIN_VZIP2Q_U64:
	case ARM64_INTRIN_VZIP2Q_U8:
		return {Type::IntegerType(16, false)};
	case ARM64_INTRIN_VADDLV_S8:
	case ARM64_INTRIN_VADDLV_U8:
	case ARM64_INTRIN_VADDLVQ_S8:
	case ARM64_INTRIN_VADDLVQ_U8:
	case ARM64_INTRIN_VADDV_S16:
	case ARM64_INTRIN_VADDV_U16:
	case ARM64_INTRIN_VADDVQ_S16:
	case ARM64_INTRIN_VADDVQ_U16:
	case ARM64_INTRIN_VCAGEH_F16:
	case ARM64_INTRIN_VCAGTH_F16:
	case ARM64_INTRIN_VCALEH_F16:
	case ARM64_INTRIN_VCALTH_F16:
	case ARM64_INTRIN_VCEQH_F16:
	case ARM64_INTRIN_VCEQZH_F16:
	case ARM64_INTRIN_VCGEH_F16:
	case ARM64_INTRIN_VCGEZH_F16:
	case ARM64_INTRIN_VCGTH_F16:
	case ARM64_INTRIN_VCGTZH_F16:
	case ARM64_INTRIN_VCLEH_F16:
	case ARM64_INTRIN_VCLEZH_F16:
	case ARM64_INTRIN_VCLTH_F16:
	case ARM64_INTRIN_VCLTZH_F16:
	case ARM64_INTRIN_VCVTAH_S16_F16:
	case ARM64_INTRIN_VCVTAH_U16_F16:
	case ARM64_INTRIN_VCVTH_N_S16_F16:
	case ARM64_INTRIN_VCVTH_N_U16_F16:
	case ARM64_INTRIN_VCVTH_S16_F16:
	case ARM64_INTRIN_VCVTH_U16_F16:
	case ARM64_INTRIN_VCVTMH_S16_F16:
	case ARM64_INTRIN_VCVTMH_U16_F16:
	case ARM64_INTRIN_VCVTNH_S16_F16:
	case ARM64_INTRIN_VCVTNH_U16_F16:
	case ARM64_INTRIN_VCVTPH_S16_F16:
	case ARM64_INTRIN_VCVTPH_U16_F16:
	case ARM64_INTRIN_VDUPH_LANE_P16:
	case ARM64_INTRIN_VDUPH_LANE_S16:
	case ARM64_INTRIN_VDUPH_LANE_U16:
	case ARM64_INTRIN_VDUPH_LANEQ_P16:
	case ARM64_INTRIN_VDUPH_LANEQ_S16:
	case ARM64_INTRIN_VDUPH_LANEQ_U16:
	case ARM64_INTRIN_VGET_LANE_P16:
	case ARM64_INTRIN_VGET_LANE_S16:
	case ARM64_INTRIN_VGET_LANE_U16:
	case ARM64_INTRIN_VGETQ_LANE_P16:
	case ARM64_INTRIN_VGETQ_LANE_S16:
	case ARM64_INTRIN_VGETQ_LANE_U16:
	case ARM64_INTRIN_VMAXV_S16:
	case ARM64_INTRIN_VMAXV_U16:
	case ARM64_INTRIN_VMAXVQ_S16:
	case ARM64_INTRIN_VMAXVQ_U16:
	case ARM64_INTRIN_VMINV_S16:
	case ARM64_INTRIN_VMINV_U16:
	case ARM64_INTRIN_VMINVQ_S16:
	case ARM64_INTRIN_VMINVQ_U16:
	case ARM64_INTRIN_VQABSH_S16:
	case ARM64_INTRIN_VQADDH_S16:
	case ARM64_INTRIN_VQADDH_U16:
	case ARM64_INTRIN_VQDMULHH_LANE_S16:
	case ARM64_INTRIN_VQDMULHH_LANEQ_S16:
	case ARM64_INTRIN_VQDMULHH_S16:
	case ARM64_INTRIN_VQMOVNS_S32:
	case ARM64_INTRIN_VQMOVNS_U32:
	case ARM64_INTRIN_VQMOVUNS_S32:
	case ARM64_INTRIN_VQNEGH_S16:
	case ARM64_INTRIN_VQRDMLAHH_LANE_S16:
	case ARM64_INTRIN_VQRDMLAHH_LANEQ_S16:
	case ARM64_INTRIN_VQRDMLAHH_S16:
	case ARM64_INTRIN_VQRDMLSHH_LANE_S16:
	case ARM64_INTRIN_VQRDMLSHH_LANEQ_S16:
	case ARM64_INTRIN_VQRDMLSHH_S16:
	case ARM64_INTRIN_VQRDMULHH_LANE_S16:
	case ARM64_INTRIN_VQRDMULHH_LANEQ_S16:
	case ARM64_INTRIN_VQRDMULHH_S16:
	case ARM64_INTRIN_VQRSHLH_S16:
	case ARM64_INTRIN_VQRSHLH_U16:
	case ARM64_INTRIN_VQRSHRNS_N_S32:
	case ARM64_INTRIN_VQRSHRNS_N_U32:
	case ARM64_INTRIN_VQRSHRUNS_N_S32:
	case ARM64_INTRIN_VQSHLH_N_S16:
	case ARM64_INTRIN_VQSHLH_N_U16:
	case ARM64_INTRIN_VQSHLH_S16:
	case ARM64_INTRIN_VQSHLH_U16:
	case ARM64_INTRIN_VQSHLUH_N_S16:
	case ARM64_INTRIN_VQSHRNS_N_S32:
	case ARM64_INTRIN_VQSHRNS_N_U32:
	case ARM64_INTRIN_VQSHRUNS_N_S32:
	case ARM64_INTRIN_VQSUBH_S16:
	case ARM64_INTRIN_VQSUBH_U16:
	case ARM64_INTRIN_VSQADDH_U16:
	case ARM64_INTRIN_VUQADDH_S16:
		return {Type::IntegerType(2, false)};
	case ARM64_INTRIN___CRC32B:
	case ARM64_INTRIN___CRC32CB:
	case ARM64_INTRIN___CRC32CD:
	case ARM64_INTRIN___CRC32CH:
	case ARM64_INTRIN___CRC32CW:
	case ARM64_INTRIN___CRC32D:
	case ARM64_INTRIN___CRC32H:
	case ARM64_INTRIN___CRC32W:
	case ARM64_INTRIN_VADDLV_S16:
	case ARM64_INTRIN_VADDLV_U16:
	case ARM64_INTRIN_VADDLVQ_S16:
	case ARM64_INTRIN_VADDLVQ_U16:
	case ARM64_INTRIN_VADDV_S32:
	case ARM64_INTRIN_VADDV_U32:
	case ARM64_INTRIN_VADDVQ_S32:
	case ARM64_INTRIN_VADDVQ_U32:
	case ARM64_INTRIN_VCAGES_F32:
	case ARM64_INTRIN_VCAGTS_F32:
	case ARM64_INTRIN_VCALES_F32:
	case ARM64_INTRIN_VCALTS_F32:
	case ARM64_INTRIN_VCEQS_F32:
	case ARM64_INTRIN_VCEQZS_F32:
	case ARM64_INTRIN_VCGES_F32:
	case ARM64_INTRIN_VCGEZS_F32:
	case ARM64_INTRIN_VCGTS_F32:
	case ARM64_INTRIN_VCGTZS_F32:
	case ARM64_INTRIN_VCLES_F32:
	case ARM64_INTRIN_VCLEZS_F32:
	case ARM64_INTRIN_VCLTS_F32:
	case ARM64_INTRIN_VCLTZS_F32:
	case ARM64_INTRIN_VCVTAH_S32_F16:
	case ARM64_INTRIN_VCVTAH_U32_F16:
	case ARM64_INTRIN_VCVTAS_S32_F32:
	case ARM64_INTRIN_VCVTAS_U32_F32:
	case ARM64_INTRIN_VCVTH_N_S32_F16:
	case ARM64_INTRIN_VCVTH_N_U32_F16:
	case ARM64_INTRIN_VCVTH_S32_F16:
	case ARM64_INTRIN_VCVTH_U32_F16:
	case ARM64_INTRIN_VCVTMH_S32_F16:
	case ARM64_INTRIN_VCVTMH_U32_F16:
	case ARM64_INTRIN_VCVTMS_S32_F32:
	case ARM64_INTRIN_VCVTMS_U32_F32:
	case ARM64_INTRIN_VCVTNH_S32_F16:
	case ARM64_INTRIN_VCVTNH_U32_F16:
	case ARM64_INTRIN_VCVTNS_S32_F32:
	case ARM64_INTRIN_VCVTNS_U32_F32:
	case ARM64_INTRIN_VCVTPH_S32_F16:
	case ARM64_INTRIN_VCVTPH_U32_F16:
	case ARM64_INTRIN_VCVTPS_S32_F32:
	case ARM64_INTRIN_VCVTPS_U32_F32:
	case ARM64_INTRIN_VCVTS_N_S32_F32:
	case ARM64_INTRIN_VCVTS_N_U32_F32:
	case ARM64_INTRIN_VCVTS_S32_F32:
	case ARM64_INTRIN_VCVTS_U32_F32:
	case ARM64_INTRIN_VDUPS_LANE_S32:
	case ARM64_INTRIN_VDUPS_LANE_U32:
	case ARM64_INTRIN_VDUPS_LANEQ_S32:
	case ARM64_INTRIN_VDUPS_LANEQ_U32:
	case ARM64_INTRIN_VGET_LANE_S32:
	case ARM64_INTRIN_VGET_LANE_U32:
	case ARM64_INTRIN_VGETQ_LANE_S32:
	case ARM64_INTRIN_VGETQ_LANE_U32:
	case ARM64_INTRIN_VMAXV_S32:
	case ARM64_INTRIN_VMAXV_U32:
	case ARM64_INTRIN_VMAXVQ_S32:
	case ARM64_INTRIN_VMAXVQ_U32:
	case ARM64_INTRIN_VMINV_S32:
	case ARM64_INTRIN_VMINV_U32:
	case ARM64_INTRIN_VMINVQ_S32:
	case ARM64_INTRIN_VMINVQ_U32:
	case ARM64_INTRIN_VQABSS_S32:
	case ARM64_INTRIN_VQADDS_S32:
	case ARM64_INTRIN_VQADDS_U32:
	case ARM64_INTRIN_VQDMLALH_LANE_S16:
	case ARM64_INTRIN_VQDMLALH_LANEQ_S16:
	case ARM64_INTRIN_VQDMLALH_S16:
	case ARM64_INTRIN_VQDMLSLH_LANE_S16:
	case ARM64_INTRIN_VQDMLSLH_LANEQ_S16:
	case ARM64_INTRIN_VQDMLSLH_S16:
	case ARM64_INTRIN_VQDMULHS_LANE_S32:
	case ARM64_INTRIN_VQDMULHS_LANEQ_S32:
	case ARM64_INTRIN_VQDMULHS_S32:
	case ARM64_INTRIN_VQDMULLH_LANE_S16:
	case ARM64_INTRIN_VQDMULLH_LANEQ_S16:
	case ARM64_INTRIN_VQDMULLH_S16:
	case ARM64_INTRIN_VQMOVND_S64:
	case ARM64_INTRIN_VQMOVND_U64:
	case ARM64_INTRIN_VQMOVUND_S64:
	case ARM64_INTRIN_VQNEGS_S32:
	case ARM64_INTRIN_VQRDMLAHS_LANE_S32:
	case ARM64_INTRIN_VQRDMLAHS_LANEQ_S32:
	case ARM64_INTRIN_VQRDMLAHS_S32:
	case ARM64_INTRIN_VQRDMLSHS_LANE_S32:
	case ARM64_INTRIN_VQRDMLSHS_LANEQ_S32:
	case ARM64_INTRIN_VQRDMLSHS_S32:
	case ARM64_INTRIN_VQRDMULHS_LANE_S32:
	case ARM64_INTRIN_VQRDMULHS_LANEQ_S32:
	case ARM64_INTRIN_VQRDMULHS_S32:
	case ARM64_INTRIN_VQRSHLS_S32:
	case ARM64_INTRIN_VQRSHLS_U32:
	case ARM64_INTRIN_VQRSHRND_N_S64:
	case ARM64_INTRIN_VQRSHRND_N_U64:
	case ARM64_INTRIN_VQRSHRUND_N_S64:
	case ARM64_INTRIN_VQSHLS_N_S32:
	case ARM64_INTRIN_VQSHLS_N_U32:
	case ARM64_INTRIN_VQSHLS_S32:
	case ARM64_INTRIN_VQSHLS_U32:
	case ARM64_INTRIN_VQSHLUS_N_S32:
	case ARM64_INTRIN_VQSHRND_N_S64:
	case ARM64_INTRIN_VQSHRND_N_U64:
	case ARM64_INTRIN_VQSHRUND_N_S64:
	case ARM64_INTRIN_VQSUBS_S32:
	case ARM64_INTRIN_VQSUBS_U32:
	case ARM64_INTRIN_VSHA1H_U32:
	case ARM64_INTRIN_VSQADDS_U32:
	case ARM64_INTRIN_VUQADDS_S32:
		return {Type::IntegerType(4, false)};
	case ARM64_INTRIN_VABA_S16:
	case ARM64_INTRIN_VABA_S32:
	case ARM64_INTRIN_VABA_S8:
	case ARM64_INTRIN_VABA_U16:
	case ARM64_INTRIN_VABA_U32:
	case ARM64_INTRIN_VABA_U8:
	case ARM64_INTRIN_VABD_S16:
	case ARM64_INTRIN_VABD_S32:
	case ARM64_INTRIN_VABD_S8:
	case ARM64_INTRIN_VABD_U16:
	case ARM64_INTRIN_VABD_U32:
	case ARM64_INTRIN_VABD_U8:
	case ARM64_INTRIN_VABS_S16:
	case ARM64_INTRIN_VABS_S32:
	case ARM64_INTRIN_VABS_S64:
	case ARM64_INTRIN_VABS_S8:
	case ARM64_INTRIN_VABSD_S64:
	case ARM64_INTRIN_VADD_P16:
	case ARM64_INTRIN_VADD_P64:
	case ARM64_INTRIN_VADD_P8:
	case ARM64_INTRIN_VADD_S16:
	case ARM64_INTRIN_VADD_S32:
	case ARM64_INTRIN_VADD_S64:
	case ARM64_INTRIN_VADD_S8:
	case ARM64_INTRIN_VADD_U16:
	case ARM64_INTRIN_VADD_U32:
	case ARM64_INTRIN_VADD_U64:
	case ARM64_INTRIN_VADD_U8:
	case ARM64_INTRIN_VADDD_S64:
	case ARM64_INTRIN_VADDD_U64:
	case ARM64_INTRIN_VADDHN_S16:
	case ARM64_INTRIN_VADDHN_S32:
	case ARM64_INTRIN_VADDHN_S64:
	case ARM64_INTRIN_VADDHN_U16:
	case ARM64_INTRIN_VADDHN_U32:
	case ARM64_INTRIN_VADDHN_U64:
	case ARM64_INTRIN_VADDLV_S32:
	case ARM64_INTRIN_VADDLV_U32:
	case ARM64_INTRIN_VADDLVQ_S32:
	case ARM64_INTRIN_VADDLVQ_U32:
	case ARM64_INTRIN_VADDVQ_S64:
	case ARM64_INTRIN_VADDVQ_U64:
	case ARM64_INTRIN_VAND_S16:
	case ARM64_INTRIN_VAND_S32:
	case ARM64_INTRIN_VAND_S64:
	case ARM64_INTRIN_VAND_S8:
	case ARM64_INTRIN_VAND_U16:
	case ARM64_INTRIN_VAND_U32:
	case ARM64_INTRIN_VAND_U64:
	case ARM64_INTRIN_VAND_U8:
	case ARM64_INTRIN_VBIC_S16:
	case ARM64_INTRIN_VBIC_S32:
	case ARM64_INTRIN_VBIC_S64:
	case ARM64_INTRIN_VBIC_S8:
	case ARM64_INTRIN_VBIC_U16:
	case ARM64_INTRIN_VBIC_U32:
	case ARM64_INTRIN_VBIC_U64:
	case ARM64_INTRIN_VBIC_U8:
	case ARM64_INTRIN_VBSL_P16:
	case ARM64_INTRIN_VBSL_P64:
	case ARM64_INTRIN_VBSL_P8:
	case ARM64_INTRIN_VBSL_S16:
	case ARM64_INTRIN_VBSL_S32:
	case ARM64_INTRIN_VBSL_S64:
	case ARM64_INTRIN_VBSL_S8:
	case ARM64_INTRIN_VBSL_U16:
	case ARM64_INTRIN_VBSL_U32:
	case ARM64_INTRIN_VBSL_U64:
	case ARM64_INTRIN_VBSL_U8:
	case ARM64_INTRIN_VCAGE_F16:
	case ARM64_INTRIN_VCAGE_F32:
	case ARM64_INTRIN_VCAGE_F64:
	case ARM64_INTRIN_VCAGED_F64:
	case ARM64_INTRIN_VCAGT_F16:
	case ARM64_INTRIN_VCAGT_F32:
	case ARM64_INTRIN_VCAGT_F64:
	case ARM64_INTRIN_VCAGTD_F64:
	case ARM64_INTRIN_VCALE_F16:
	case ARM64_INTRIN_VCALE_F32:
	case ARM64_INTRIN_VCALE_F64:
	case ARM64_INTRIN_VCALED_F64:
	case ARM64_INTRIN_VCALT_F16:
	case ARM64_INTRIN_VCALT_F32:
	case ARM64_INTRIN_VCALT_F64:
	case ARM64_INTRIN_VCALTD_F64:
	case ARM64_INTRIN_VCEQ_F16:
	case ARM64_INTRIN_VCEQ_F32:
	case ARM64_INTRIN_VCEQ_F64:
	case ARM64_INTRIN_VCEQ_P64:
	case ARM64_INTRIN_VCEQ_P8:
	case ARM64_INTRIN_VCEQ_S16:
	case ARM64_INTRIN_VCEQ_S32:
	case ARM64_INTRIN_VCEQ_S64:
	case ARM64_INTRIN_VCEQ_S8:
	case ARM64_INTRIN_VCEQ_U16:
	case ARM64_INTRIN_VCEQ_U32:
	case ARM64_INTRIN_VCEQ_U64:
	case ARM64_INTRIN_VCEQ_U8:
	case ARM64_INTRIN_VCEQD_F64:
	case ARM64_INTRIN_VCEQD_S64:
	case ARM64_INTRIN_VCEQD_U64:
	case ARM64_INTRIN_VCEQZ_F16:
	case ARM64_INTRIN_VCEQZ_F32:
	case ARM64_INTRIN_VCEQZ_F64:
	case ARM64_INTRIN_VCEQZ_P64:
	case ARM64_INTRIN_VCEQZ_P8:
	case ARM64_INTRIN_VCEQZ_S16:
	case ARM64_INTRIN_VCEQZ_S32:
	case ARM64_INTRIN_VCEQZ_S64:
	case ARM64_INTRIN_VCEQZ_S8:
	case ARM64_INTRIN_VCEQZ_U16:
	case ARM64_INTRIN_VCEQZ_U32:
	case ARM64_INTRIN_VCEQZ_U64:
	case ARM64_INTRIN_VCEQZ_U8:
	case ARM64_INTRIN_VCEQZD_F64:
	case ARM64_INTRIN_VCEQZD_S64:
	case ARM64_INTRIN_VCEQZD_U64:
	case ARM64_INTRIN_VCGE_F16:
	case ARM64_INTRIN_VCGE_F32:
	case ARM64_INTRIN_VCGE_F64:
	case ARM64_INTRIN_VCGE_S16:
	case ARM64_INTRIN_VCGE_S32:
	case ARM64_INTRIN_VCGE_S64:
	case ARM64_INTRIN_VCGE_S8:
	case ARM64_INTRIN_VCGE_U16:
	case ARM64_INTRIN_VCGE_U32:
	case ARM64_INTRIN_VCGE_U64:
	case ARM64_INTRIN_VCGE_U8:
	case ARM64_INTRIN_VCGED_F64:
	case ARM64_INTRIN_VCGED_S64:
	case ARM64_INTRIN_VCGED_U64:
	case ARM64_INTRIN_VCGEZ_F16:
	case ARM64_INTRIN_VCGEZ_F32:
	case ARM64_INTRIN_VCGEZ_F64:
	case ARM64_INTRIN_VCGEZ_S16:
	case ARM64_INTRIN_VCGEZ_S32:
	case ARM64_INTRIN_VCGEZ_S64:
	case ARM64_INTRIN_VCGEZ_S8:
	case ARM64_INTRIN_VCGEZD_F64:
	case ARM64_INTRIN_VCGEZD_S64:
	case ARM64_INTRIN_VCGT_F16:
	case ARM64_INTRIN_VCGT_F32:
	case ARM64_INTRIN_VCGT_F64:
	case ARM64_INTRIN_VCGT_S16:
	case ARM64_INTRIN_VCGT_S32:
	case ARM64_INTRIN_VCGT_S64:
	case ARM64_INTRIN_VCGT_S8:
	case ARM64_INTRIN_VCGT_U16:
	case ARM64_INTRIN_VCGT_U32:
	case ARM64_INTRIN_VCGT_U64:
	case ARM64_INTRIN_VCGT_U8:
	case ARM64_INTRIN_VCGTD_F64:
	case ARM64_INTRIN_VCGTD_S64:
	case ARM64_INTRIN_VCGTD_U64:
	case ARM64_INTRIN_VCGTZ_F16:
	case ARM64_INTRIN_VCGTZ_F32:
	case ARM64_INTRIN_VCGTZ_F64:
	case ARM64_INTRIN_VCGTZ_S16:
	case ARM64_INTRIN_VCGTZ_S32:
	case ARM64_INTRIN_VCGTZ_S64:
	case ARM64_INTRIN_VCGTZ_S8:
	case ARM64_INTRIN_VCGTZD_F64:
	case ARM64_INTRIN_VCGTZD_S64:
	case ARM64_INTRIN_VCLE_F16:
	case ARM64_INTRIN_VCLE_F32:
	case ARM64_INTRIN_VCLE_F64:
	case ARM64_INTRIN_VCLE_S16:
	case ARM64_INTRIN_VCLE_S32:
	case ARM64_INTRIN_VCLE_S64:
	case ARM64_INTRIN_VCLE_S8:
	case ARM64_INTRIN_VCLE_U16:
	case ARM64_INTRIN_VCLE_U32:
	case ARM64_INTRIN_VCLE_U64:
	case ARM64_INTRIN_VCLE_U8:
	case ARM64_INTRIN_VCLED_F64:
	case ARM64_INTRIN_VCLED_S64:
	case ARM64_INTRIN_VCLED_U64:
	case ARM64_INTRIN_VCLEZ_F16:
	case ARM64_INTRIN_VCLEZ_F32:
	case ARM64_INTRIN_VCLEZ_F64:
	case ARM64_INTRIN_VCLEZ_S16:
	case ARM64_INTRIN_VCLEZ_S32:
	case ARM64_INTRIN_VCLEZ_S64:
	case ARM64_INTRIN_VCLEZ_S8:
	case ARM64_INTRIN_VCLEZD_F64:
	case ARM64_INTRIN_VCLEZD_S64:
	case ARM64_INTRIN_VCLS_S16:
	case ARM64_INTRIN_VCLS_S32:
	case ARM64_INTRIN_VCLS_S8:
	case ARM64_INTRIN_VCLS_U16:
	case ARM64_INTRIN_VCLS_U32:
	case ARM64_INTRIN_VCLS_U8:
	case ARM64_INTRIN_VCLT_F16:
	case ARM64_INTRIN_VCLT_F32:
	case ARM64_INTRIN_VCLT_F64:
	case ARM64_INTRIN_VCLT_S16:
	case ARM64_INTRIN_VCLT_S32:
	case ARM64_INTRIN_VCLT_S64:
	case ARM64_INTRIN_VCLT_S8:
	case ARM64_INTRIN_VCLT_U16:
	case ARM64_INTRIN_VCLT_U32:
	case ARM64_INTRIN_VCLT_U64:
	case ARM64_INTRIN_VCLT_U8:
	case ARM64_INTRIN_VCLTD_F64:
	case ARM64_INTRIN_VCLTD_S64:
	case ARM64_INTRIN_VCLTD_U64:
	case ARM64_INTRIN_VCLTZ_F16:
	case ARM64_INTRIN_VCLTZ_F32:
	case ARM64_INTRIN_VCLTZ_F64:
	case ARM64_INTRIN_VCLTZ_S16:
	case ARM64_INTRIN_VCLTZ_S32:
	case ARM64_INTRIN_VCLTZ_S64:
	case ARM64_INTRIN_VCLTZ_S8:
	case ARM64_INTRIN_VCLTZD_F64:
	case ARM64_INTRIN_VCLTZD_S64:
	case ARM64_INTRIN_VCLZ_S16:
	case ARM64_INTRIN_VCLZ_S32:
	case ARM64_INTRIN_VCLZ_S8:
	case ARM64_INTRIN_VCLZ_U16:
	case ARM64_INTRIN_VCLZ_U32:
	case ARM64_INTRIN_VCLZ_U8:
	case ARM64_INTRIN_VCNT_P8:
	case ARM64_INTRIN_VCNT_S8:
	case ARM64_INTRIN_VCNT_U8:
	case ARM64_INTRIN_VCREATE_P16:
	case ARM64_INTRIN_VCREATE_P64:
	case ARM64_INTRIN_VCREATE_P8:
	case ARM64_INTRIN_VCREATE_S16:
	case ARM64_INTRIN_VCREATE_S32:
	case ARM64_INTRIN_VCREATE_S64:
	case ARM64_INTRIN_VCREATE_S8:
	case ARM64_INTRIN_VCREATE_U16:
	case ARM64_INTRIN_VCREATE_U32:
	case ARM64_INTRIN_VCREATE_U64:
	case ARM64_INTRIN_VCREATE_U8:
	case ARM64_INTRIN_VCVT_N_S16_F16:
	case ARM64_INTRIN_VCVT_N_S32_F32:
	case ARM64_INTRIN_VCVT_N_S64_F64:
	case ARM64_INTRIN_VCVT_N_U16_F16:
	case ARM64_INTRIN_VCVT_N_U32_F32:
	case ARM64_INTRIN_VCVT_N_U64_F64:
	case ARM64_INTRIN_VCVT_S16_F16:
	case ARM64_INTRIN_VCVT_S32_F32:
	case ARM64_INTRIN_VCVT_S64_F64:
	case ARM64_INTRIN_VCVT_U16_F16:
	case ARM64_INTRIN_VCVT_U32_F32:
	case ARM64_INTRIN_VCVT_U64_F64:
	case ARM64_INTRIN_VCVTA_S16_F16:
	case ARM64_INTRIN_VCVTA_S32_F32:
	case ARM64_INTRIN_VCVTA_S64_F64:
	case ARM64_INTRIN_VCVTA_U16_F16:
	case ARM64_INTRIN_VCVTA_U32_F32:
	case ARM64_INTRIN_VCVTA_U64_F64:
	case ARM64_INTRIN_VCVTAD_S64_F64:
	case ARM64_INTRIN_VCVTAD_U64_F64:
	case ARM64_INTRIN_VCVTAH_S64_F16:
	case ARM64_INTRIN_VCVTAH_U64_F16:
	case ARM64_INTRIN_VCVTD_N_S64_F64:
	case ARM64_INTRIN_VCVTD_N_U64_F64:
	case ARM64_INTRIN_VCVTD_S64_F64:
	case ARM64_INTRIN_VCVTD_U64_F64:
	case ARM64_INTRIN_VCVTH_N_S64_F16:
	case ARM64_INTRIN_VCVTH_N_U64_F16:
	case ARM64_INTRIN_VCVTH_S64_F16:
	case ARM64_INTRIN_VCVTH_U64_F16:
	case ARM64_INTRIN_VCVTM_S16_F16:
	case ARM64_INTRIN_VCVTM_S32_F32:
	case ARM64_INTRIN_VCVTM_S64_F64:
	case ARM64_INTRIN_VCVTM_U16_F16:
	case ARM64_INTRIN_VCVTM_U32_F32:
	case ARM64_INTRIN_VCVTM_U64_F64:
	case ARM64_INTRIN_VCVTMD_S64_F64:
	case ARM64_INTRIN_VCVTMD_U64_F64:
	case ARM64_INTRIN_VCVTMH_S64_F16:
	case ARM64_INTRIN_VCVTMH_U64_F16:
	case ARM64_INTRIN_VCVTN_S16_F16:
	case ARM64_INTRIN_VCVTN_S32_F32:
	case ARM64_INTRIN_VCVTN_S64_F64:
	case ARM64_INTRIN_VCVTN_U16_F16:
	case ARM64_INTRIN_VCVTN_U32_F32:
	case ARM64_INTRIN_VCVTN_U64_F64:
	case ARM64_INTRIN_VCVTND_S64_F64:
	case ARM64_INTRIN_VCVTND_U64_F64:
	case ARM64_INTRIN_VCVTNH_S64_F16:
	case ARM64_INTRIN_VCVTNH_U64_F16:
	case ARM64_INTRIN_VCVTP_S16_F16:
	case ARM64_INTRIN_VCVTP_S32_F32:
	case ARM64_INTRIN_VCVTP_S64_F64:
	case ARM64_INTRIN_VCVTP_U16_F16:
	case ARM64_INTRIN_VCVTP_U32_F32:
	case ARM64_INTRIN_VCVTP_U64_F64:
	case ARM64_INTRIN_VCVTPD_S64_F64:
	case ARM64_INTRIN_VCVTPD_U64_F64:
	case ARM64_INTRIN_VCVTPH_S64_F16:
	case ARM64_INTRIN_VCVTPH_U64_F16:
	case ARM64_INTRIN_VDOT_LANE_S32:
	case ARM64_INTRIN_VDOT_LANE_U32:
	case ARM64_INTRIN_VDOT_LANEQ_S32:
	case ARM64_INTRIN_VDOT_LANEQ_U32:
	case ARM64_INTRIN_VDOT_S32:
	case ARM64_INTRIN_VDOT_U32:
	case ARM64_INTRIN_VDUP_LANE_P16:
	case ARM64_INTRIN_VDUP_LANE_P64:
	case ARM64_INTRIN_VDUP_LANE_P8:
	case ARM64_INTRIN_VDUP_LANE_S16:
	case ARM64_INTRIN_VDUP_LANE_S32:
	case ARM64_INTRIN_VDUP_LANE_S64:
	case ARM64_INTRIN_VDUP_LANE_S8:
	case ARM64_INTRIN_VDUP_LANE_U16:
	case ARM64_INTRIN_VDUP_LANE_U32:
	case ARM64_INTRIN_VDUP_LANE_U64:
	case ARM64_INTRIN_VDUP_LANE_U8:
	case ARM64_INTRIN_VDUP_LANEQ_P16:
	case ARM64_INTRIN_VDUP_LANEQ_P64:
	case ARM64_INTRIN_VDUP_LANEQ_P8:
	case ARM64_INTRIN_VDUP_LANEQ_S16:
	case ARM64_INTRIN_VDUP_LANEQ_S32:
	case ARM64_INTRIN_VDUP_LANEQ_S64:
	case ARM64_INTRIN_VDUP_LANEQ_S8:
	case ARM64_INTRIN_VDUP_LANEQ_U16:
	case ARM64_INTRIN_VDUP_LANEQ_U32:
	case ARM64_INTRIN_VDUP_LANEQ_U64:
	case ARM64_INTRIN_VDUP_LANEQ_U8:
	case ARM64_INTRIN_VDUP_N_P16:
	case ARM64_INTRIN_VDUP_N_P64:
	case ARM64_INTRIN_VDUP_N_P8:
	case ARM64_INTRIN_VDUP_N_S16:
	case ARM64_INTRIN_VDUP_N_S32:
	case ARM64_INTRIN_VDUP_N_S64:
	case ARM64_INTRIN_VDUP_N_S8:
	case ARM64_INTRIN_VDUP_N_U16:
	case ARM64_INTRIN_VDUP_N_U32:
	case ARM64_INTRIN_VDUP_N_U64:
	case ARM64_INTRIN_VDUP_N_U8:
	case ARM64_INTRIN_VDUPD_LANE_S64:
	case ARM64_INTRIN_VDUPD_LANE_U64:
	case ARM64_INTRIN_VDUPD_LANEQ_S64:
	case ARM64_INTRIN_VDUPD_LANEQ_U64:
	case ARM64_INTRIN_VEOR_S16:
	case ARM64_INTRIN_VEOR_S32:
	case ARM64_INTRIN_VEOR_S64:
	case ARM64_INTRIN_VEOR_S8:
	case ARM64_INTRIN_VEOR_U16:
	case ARM64_INTRIN_VEOR_U32:
	case ARM64_INTRIN_VEOR_U64:
	case ARM64_INTRIN_VEOR_U8:
	case ARM64_INTRIN_VEXT_P16:
	case ARM64_INTRIN_VEXT_P64:
	case ARM64_INTRIN_VEXT_P8:
	case ARM64_INTRIN_VEXT_S16:
	case ARM64_INTRIN_VEXT_S32:
	case ARM64_INTRIN_VEXT_S64:
	case ARM64_INTRIN_VEXT_S8:
	case ARM64_INTRIN_VEXT_U16:
	case ARM64_INTRIN_VEXT_U32:
	case ARM64_INTRIN_VEXT_U64:
	case ARM64_INTRIN_VEXT_U8:
	case ARM64_INTRIN_VGET_HIGH_P16:
	case ARM64_INTRIN_VGET_HIGH_P64:
	case ARM64_INTRIN_VGET_HIGH_P8:
	case ARM64_INTRIN_VGET_HIGH_S16:
	case ARM64_INTRIN_VGET_HIGH_S32:
	case ARM64_INTRIN_VGET_HIGH_S64:
	case ARM64_INTRIN_VGET_HIGH_S8:
	case ARM64_INTRIN_VGET_HIGH_U16:
	case ARM64_INTRIN_VGET_HIGH_U32:
	case ARM64_INTRIN_VGET_HIGH_U64:
	case ARM64_INTRIN_VGET_HIGH_U8:
	case ARM64_INTRIN_VGET_LANE_P64:
	case ARM64_INTRIN_VGET_LANE_S64:
	case ARM64_INTRIN_VGET_LANE_U64:
	case ARM64_INTRIN_VGET_LOW_P16:
	case ARM64_INTRIN_VGET_LOW_P64:
	case ARM64_INTRIN_VGET_LOW_P8:
	case ARM64_INTRIN_VGET_LOW_S16:
	case ARM64_INTRIN_VGET_LOW_S32:
	case ARM64_INTRIN_VGET_LOW_S64:
	case ARM64_INTRIN_VGET_LOW_S8:
	case ARM64_INTRIN_VGET_LOW_U16:
	case ARM64_INTRIN_VGET_LOW_U32:
	case ARM64_INTRIN_VGET_LOW_U64:
	case ARM64_INTRIN_VGET_LOW_U8:
	case ARM64_INTRIN_VGETQ_LANE_P64:
	case ARM64_INTRIN_VGETQ_LANE_S64:
	case ARM64_INTRIN_VGETQ_LANE_U64:
	case ARM64_INTRIN_VHADD_S16:
	case ARM64_INTRIN_VHADD_S32:
	case ARM64_INTRIN_VHADD_S8:
	case ARM64_INTRIN_VHADD_U16:
	case ARM64_INTRIN_VHADD_U32:
	case ARM64_INTRIN_VHADD_U8:
	case ARM64_INTRIN_VHSUB_S16:
	case ARM64_INTRIN_VHSUB_S32:
	case ARM64_INTRIN_VHSUB_S8:
	case ARM64_INTRIN_VHSUB_U16:
	case ARM64_INTRIN_VHSUB_U32:
	case ARM64_INTRIN_VHSUB_U8:
	case ARM64_INTRIN_VMAX_S16:
	case ARM64_INTRIN_VMAX_S32:
	case ARM64_INTRIN_VMAX_S8:
	case ARM64_INTRIN_VMAX_U16:
	case ARM64_INTRIN_VMAX_U32:
	case ARM64_INTRIN_VMAX_U8:
	case ARM64_INTRIN_VMIN_S16:
	case ARM64_INTRIN_VMIN_S32:
	case ARM64_INTRIN_VMIN_S8:
	case ARM64_INTRIN_VMIN_U16:
	case ARM64_INTRIN_VMIN_U32:
	case ARM64_INTRIN_VMIN_U8:
	case ARM64_INTRIN_VMLA_LANE_S16:
	case ARM64_INTRIN_VMLA_LANE_S32:
	case ARM64_INTRIN_VMLA_LANE_U16:
	case ARM64_INTRIN_VMLA_LANE_U32:
	case ARM64_INTRIN_VMLA_LANEQ_S16:
	case ARM64_INTRIN_VMLA_LANEQ_S32:
	case ARM64_INTRIN_VMLA_LANEQ_U16:
	case ARM64_INTRIN_VMLA_LANEQ_U32:
	case ARM64_INTRIN_VMLA_N_S16:
	case ARM64_INTRIN_VMLA_N_S32:
	case ARM64_INTRIN_VMLA_N_U16:
	case ARM64_INTRIN_VMLA_N_U32:
	case ARM64_INTRIN_VMLA_S16:
	case ARM64_INTRIN_VMLA_S32:
	case ARM64_INTRIN_VMLA_S8:
	case ARM64_INTRIN_VMLA_U16:
	case ARM64_INTRIN_VMLA_U32:
	case ARM64_INTRIN_VMLA_U8:
	case ARM64_INTRIN_VMLS_LANE_S16:
	case ARM64_INTRIN_VMLS_LANE_S32:
	case ARM64_INTRIN_VMLS_LANE_U16:
	case ARM64_INTRIN_VMLS_LANE_U32:
	case ARM64_INTRIN_VMLS_LANEQ_S16:
	case ARM64_INTRIN_VMLS_LANEQ_S32:
	case ARM64_INTRIN_VMLS_LANEQ_U16:
	case ARM64_INTRIN_VMLS_LANEQ_U32:
	case ARM64_INTRIN_VMLS_N_S16:
	case ARM64_INTRIN_VMLS_N_S32:
	case ARM64_INTRIN_VMLS_N_U16:
	case ARM64_INTRIN_VMLS_N_U32:
	case ARM64_INTRIN_VMLS_S16:
	case ARM64_INTRIN_VMLS_S32:
	case ARM64_INTRIN_VMLS_S8:
	case ARM64_INTRIN_VMLS_U16:
	case ARM64_INTRIN_VMLS_U32:
	case ARM64_INTRIN_VMLS_U8:
	case ARM64_INTRIN_VMOV_N_P16:
	case ARM64_INTRIN_VMOV_N_P8:
	case ARM64_INTRIN_VMOV_N_S16:
	case ARM64_INTRIN_VMOV_N_S32:
	case ARM64_INTRIN_VMOV_N_S64:
	case ARM64_INTRIN_VMOV_N_S8:
	case ARM64_INTRIN_VMOV_N_U16:
	case ARM64_INTRIN_VMOV_N_U32:
	case ARM64_INTRIN_VMOV_N_U64:
	case ARM64_INTRIN_VMOV_N_U8:
	case ARM64_INTRIN_VMOVN_S16:
	case ARM64_INTRIN_VMOVN_S32:
	case ARM64_INTRIN_VMOVN_S64:
	case ARM64_INTRIN_VMOVN_U16:
	case ARM64_INTRIN_VMOVN_U32:
	case ARM64_INTRIN_VMOVN_U64:
	case ARM64_INTRIN_VMUL_LANE_S16:
	case ARM64_INTRIN_VMUL_LANE_S32:
	case ARM64_INTRIN_VMUL_LANE_U16:
	case ARM64_INTRIN_VMUL_LANE_U32:
	case ARM64_INTRIN_VMUL_LANEQ_S16:
	case ARM64_INTRIN_VMUL_LANEQ_S32:
	case ARM64_INTRIN_VMUL_LANEQ_U16:
	case ARM64_INTRIN_VMUL_LANEQ_U32:
	case ARM64_INTRIN_VMUL_N_S16:
	case ARM64_INTRIN_VMUL_N_S32:
	case ARM64_INTRIN_VMUL_N_U16:
	case ARM64_INTRIN_VMUL_N_U32:
	case ARM64_INTRIN_VMUL_P8:
	case ARM64_INTRIN_VMUL_S16:
	case ARM64_INTRIN_VMUL_S32:
	case ARM64_INTRIN_VMUL_S8:
	case ARM64_INTRIN_VMUL_U16:
	case ARM64_INTRIN_VMUL_U32:
	case ARM64_INTRIN_VMUL_U8:
	case ARM64_INTRIN_VMVN_P8:
	case ARM64_INTRIN_VMVN_S16:
	case ARM64_INTRIN_VMVN_S32:
	case ARM64_INTRIN_VMVN_S8:
	case ARM64_INTRIN_VMVN_U16:
	case ARM64_INTRIN_VMVN_U32:
	case ARM64_INTRIN_VMVN_U8:
	case ARM64_INTRIN_VNEG_S16:
	case ARM64_INTRIN_VNEG_S32:
	case ARM64_INTRIN_VNEG_S64:
	case ARM64_INTRIN_VNEG_S8:
	case ARM64_INTRIN_VNEGD_S64:
	case ARM64_INTRIN_VORN_S16:
	case ARM64_INTRIN_VORN_S32:
	case ARM64_INTRIN_VORN_S64:
	case ARM64_INTRIN_VORN_S8:
	case ARM64_INTRIN_VORN_U16:
	case ARM64_INTRIN_VORN_U32:
	case ARM64_INTRIN_VORN_U64:
	case ARM64_INTRIN_VORN_U8:
	case ARM64_INTRIN_VORR_S16:
	case ARM64_INTRIN_VORR_S32:
	case ARM64_INTRIN_VORR_S64:
	case ARM64_INTRIN_VORR_S8:
	case ARM64_INTRIN_VORR_U16:
	case ARM64_INTRIN_VORR_U32:
	case ARM64_INTRIN_VORR_U64:
	case ARM64_INTRIN_VORR_U8:
	case ARM64_INTRIN_VPADAL_S16:
	case ARM64_INTRIN_VPADAL_S32:
	case ARM64_INTRIN_VPADAL_S8:
	case ARM64_INTRIN_VPADAL_U16:
	case ARM64_INTRIN_VPADAL_U32:
	case ARM64_INTRIN_VPADAL_U8:
	case ARM64_INTRIN_VPADD_S16:
	case ARM64_INTRIN_VPADD_S32:
	case ARM64_INTRIN_VPADD_S8:
	case ARM64_INTRIN_VPADD_U16:
	case ARM64_INTRIN_VPADD_U32:
	case ARM64_INTRIN_VPADD_U8:
	case ARM64_INTRIN_VPADDD_S64:
	case ARM64_INTRIN_VPADDD_U64:
	case ARM64_INTRIN_VPADDL_S16:
	case ARM64_INTRIN_VPADDL_S32:
	case ARM64_INTRIN_VPADDL_S8:
	case ARM64_INTRIN_VPADDL_U16:
	case ARM64_INTRIN_VPADDL_U32:
	case ARM64_INTRIN_VPADDL_U8:
	case ARM64_INTRIN_VPMAX_S16:
	case ARM64_INTRIN_VPMAX_S32:
	case ARM64_INTRIN_VPMAX_S8:
	case ARM64_INTRIN_VPMAX_U16:
	case ARM64_INTRIN_VPMAX_U32:
	case ARM64_INTRIN_VPMAX_U8:
	case ARM64_INTRIN_VPMIN_S16:
	case ARM64_INTRIN_VPMIN_S32:
	case ARM64_INTRIN_VPMIN_S8:
	case ARM64_INTRIN_VPMIN_U16:
	case ARM64_INTRIN_VPMIN_U32:
	case ARM64_INTRIN_VPMIN_U8:
	case ARM64_INTRIN_VQABS_S16:
	case ARM64_INTRIN_VQABS_S32:
	case ARM64_INTRIN_VQABS_S64:
	case ARM64_INTRIN_VQABS_S8:
	case ARM64_INTRIN_VQABSD_S64:
	case ARM64_INTRIN_VQADD_S16:
	case ARM64_INTRIN_VQADD_S32:
	case ARM64_INTRIN_VQADD_S64:
	case ARM64_INTRIN_VQADD_S8:
	case ARM64_INTRIN_VQADD_U16:
	case ARM64_INTRIN_VQADD_U32:
	case ARM64_INTRIN_VQADD_U64:
	case ARM64_INTRIN_VQADD_U8:
	case ARM64_INTRIN_VQADDD_S64:
	case ARM64_INTRIN_VQADDD_U64:
	case ARM64_INTRIN_VQDMLALS_LANE_S32:
	case ARM64_INTRIN_VQDMLALS_LANEQ_S32:
	case ARM64_INTRIN_VQDMLALS_S32:
	case ARM64_INTRIN_VQDMLSLS_LANE_S32:
	case ARM64_INTRIN_VQDMLSLS_LANEQ_S32:
	case ARM64_INTRIN_VQDMLSLS_S32:
	case ARM64_INTRIN_VQDMULH_LANE_S16:
	case ARM64_INTRIN_VQDMULH_LANE_S32:
	case ARM64_INTRIN_VQDMULH_LANEQ_S16:
	case ARM64_INTRIN_VQDMULH_LANEQ_S32:
	case ARM64_INTRIN_VQDMULH_N_S16:
	case ARM64_INTRIN_VQDMULH_N_S32:
	case ARM64_INTRIN_VQDMULH_S16:
	case ARM64_INTRIN_VQDMULH_S32:
	case ARM64_INTRIN_VQDMULLS_LANE_S32:
	case ARM64_INTRIN_VQDMULLS_LANEQ_S32:
	case ARM64_INTRIN_VQDMULLS_S32:
	case ARM64_INTRIN_VQMOVN_S16:
	case ARM64_INTRIN_VQMOVN_S32:
	case ARM64_INTRIN_VQMOVN_S64:
	case ARM64_INTRIN_VQMOVN_U16:
	case ARM64_INTRIN_VQMOVN_U32:
	case ARM64_INTRIN_VQMOVN_U64:
	case ARM64_INTRIN_VQMOVUN_S16:
	case ARM64_INTRIN_VQMOVUN_S32:
	case ARM64_INTRIN_VQMOVUN_S64:
	case ARM64_INTRIN_VQNEG_S16:
	case ARM64_INTRIN_VQNEG_S32:
	case ARM64_INTRIN_VQNEG_S64:
	case ARM64_INTRIN_VQNEG_S8:
	case ARM64_INTRIN_VQNEGD_S64:
	case ARM64_INTRIN_VQRDMLAH_LANE_S16:
	case ARM64_INTRIN_VQRDMLAH_LANE_S32:
	case ARM64_INTRIN_VQRDMLAH_LANEQ_S16:
	case ARM64_INTRIN_VQRDMLAH_LANEQ_S32:
	case ARM64_INTRIN_VQRDMLAH_S16:
	case ARM64_INTRIN_VQRDMLAH_S32:
	case ARM64_INTRIN_VQRDMLSH_LANE_S16:
	case ARM64_INTRIN_VQRDMLSH_LANE_S32:
	case ARM64_INTRIN_VQRDMLSH_LANEQ_S16:
	case ARM64_INTRIN_VQRDMLSH_LANEQ_S32:
	case ARM64_INTRIN_VQRDMLSH_S16:
	case ARM64_INTRIN_VQRDMLSH_S32:
	case ARM64_INTRIN_VQRDMULH_LANE_S16:
	case ARM64_INTRIN_VQRDMULH_LANE_S32:
	case ARM64_INTRIN_VQRDMULH_LANEQ_S16:
	case ARM64_INTRIN_VQRDMULH_LANEQ_S32:
	case ARM64_INTRIN_VQRDMULH_N_S16:
	case ARM64_INTRIN_VQRDMULH_N_S32:
	case ARM64_INTRIN_VQRDMULH_S16:
	case ARM64_INTRIN_VQRDMULH_S32:
	case ARM64_INTRIN_VQRSHL_S16:
	case ARM64_INTRIN_VQRSHL_S32:
	case ARM64_INTRIN_VQRSHL_S64:
	case ARM64_INTRIN_VQRSHL_S8:
	case ARM64_INTRIN_VQRSHL_U16:
	case ARM64_INTRIN_VQRSHL_U32:
	case ARM64_INTRIN_VQRSHL_U64:
	case ARM64_INTRIN_VQRSHL_U8:
	case ARM64_INTRIN_VQRSHLD_S64:
	case ARM64_INTRIN_VQRSHLD_U64:
	case ARM64_INTRIN_VQRSHRN_N_S16:
	case ARM64_INTRIN_VQRSHRN_N_S32:
	case ARM64_INTRIN_VQRSHRN_N_S64:
	case ARM64_INTRIN_VQRSHRN_N_U16:
	case ARM64_INTRIN_VQRSHRN_N_U32:
	case ARM64_INTRIN_VQRSHRN_N_U64:
	case ARM64_INTRIN_VQRSHRUN_N_S16:
	case ARM64_INTRIN_VQRSHRUN_N_S32:
	case ARM64_INTRIN_VQRSHRUN_N_S64:
	case ARM64_INTRIN_VQSHL_N_S16:
	case ARM64_INTRIN_VQSHL_N_S32:
	case ARM64_INTRIN_VQSHL_N_S64:
	case ARM64_INTRIN_VQSHL_N_S8:
	case ARM64_INTRIN_VQSHL_N_U16:
	case ARM64_INTRIN_VQSHL_N_U32:
	case ARM64_INTRIN_VQSHL_N_U64:
	case ARM64_INTRIN_VQSHL_N_U8:
	case ARM64_INTRIN_VQSHL_S16:
	case ARM64_INTRIN_VQSHL_S32:
	case ARM64_INTRIN_VQSHL_S64:
	case ARM64_INTRIN_VQSHL_S8:
	case ARM64_INTRIN_VQSHL_U16:
	case ARM64_INTRIN_VQSHL_U32:
	case ARM64_INTRIN_VQSHL_U64:
	case ARM64_INTRIN_VQSHL_U8:
	case ARM64_INTRIN_VQSHLD_N_S64:
	case ARM64_INTRIN_VQSHLD_N_U64:
	case ARM64_INTRIN_VQSHLD_S64:
	case ARM64_INTRIN_VQSHLD_U64:
	case ARM64_INTRIN_VQSHLU_N_S16:
	case ARM64_INTRIN_VQSHLU_N_S32:
	case ARM64_INTRIN_VQSHLU_N_S64:
	case ARM64_INTRIN_VQSHLU_N_S8:
	case ARM64_INTRIN_VQSHLUD_N_S64:
	case ARM64_INTRIN_VQSHRN_N_S16:
	case ARM64_INTRIN_VQSHRN_N_S32:
	case ARM64_INTRIN_VQSHRN_N_S64:
	case ARM64_INTRIN_VQSHRN_N_U16:
	case ARM64_INTRIN_VQSHRN_N_U32:
	case ARM64_INTRIN_VQSHRN_N_U64:
	case ARM64_INTRIN_VQSHRUN_N_S16:
	case ARM64_INTRIN_VQSHRUN_N_S32:
	case ARM64_INTRIN_VQSHRUN_N_S64:
	case ARM64_INTRIN_VQSUB_S16:
	case ARM64_INTRIN_VQSUB_S32:
	case ARM64_INTRIN_VQSUB_S64:
	case ARM64_INTRIN_VQSUB_S8:
	case ARM64_INTRIN_VQSUB_U16:
	case ARM64_INTRIN_VQSUB_U32:
	case ARM64_INTRIN_VQSUB_U64:
	case ARM64_INTRIN_VQSUB_U8:
	case ARM64_INTRIN_VQSUBD_S64:
	case ARM64_INTRIN_VQSUBD_U64:
	case ARM64_INTRIN_VRADDHN_S16:
	case ARM64_INTRIN_VRADDHN_S32:
	case ARM64_INTRIN_VRADDHN_S64:
	case ARM64_INTRIN_VRADDHN_U16:
	case ARM64_INTRIN_VRADDHN_U32:
	case ARM64_INTRIN_VRADDHN_U64:
	case ARM64_INTRIN_VRBIT_P8:
	case ARM64_INTRIN_VRBIT_S8:
	case ARM64_INTRIN_VRBIT_U8:
	case ARM64_INTRIN_VRECPE_U32:
	case ARM64_INTRIN_VREV16_P8:
	case ARM64_INTRIN_VREV16_S8:
	case ARM64_INTRIN_VREV16_U8:
	case ARM64_INTRIN_VREV32_P16:
	case ARM64_INTRIN_VREV32_P8:
	case ARM64_INTRIN_VREV32_S16:
	case ARM64_INTRIN_VREV32_S8:
	case ARM64_INTRIN_VREV32_U16:
	case ARM64_INTRIN_VREV32_U8:
	case ARM64_INTRIN_VREV64_P16:
	case ARM64_INTRIN_VREV64_P8:
	case ARM64_INTRIN_VREV64_S16:
	case ARM64_INTRIN_VREV64_S32:
	case ARM64_INTRIN_VREV64_S8:
	case ARM64_INTRIN_VREV64_U16:
	case ARM64_INTRIN_VREV64_U32:
	case ARM64_INTRIN_VREV64_U8:
	case ARM64_INTRIN_VRHADD_S16:
	case ARM64_INTRIN_VRHADD_S32:
	case ARM64_INTRIN_VRHADD_S8:
	case ARM64_INTRIN_VRHADD_U16:
	case ARM64_INTRIN_VRHADD_U32:
	case ARM64_INTRIN_VRHADD_U8:
	case ARM64_INTRIN_VRSHL_S16:
	case ARM64_INTRIN_VRSHL_S32:
	case ARM64_INTRIN_VRSHL_S64:
	case ARM64_INTRIN_VRSHL_S8:
	case ARM64_INTRIN_VRSHL_U16:
	case ARM64_INTRIN_VRSHL_U32:
	case ARM64_INTRIN_VRSHL_U64:
	case ARM64_INTRIN_VRSHL_U8:
	case ARM64_INTRIN_VRSHLD_S64:
	case ARM64_INTRIN_VRSHLD_U64:
	case ARM64_INTRIN_VRSHR_N_S16:
	case ARM64_INTRIN_VRSHR_N_S32:
	case ARM64_INTRIN_VRSHR_N_S64:
	case ARM64_INTRIN_VRSHR_N_S8:
	case ARM64_INTRIN_VRSHR_N_U16:
	case ARM64_INTRIN_VRSHR_N_U32:
	case ARM64_INTRIN_VRSHR_N_U64:
	case ARM64_INTRIN_VRSHR_N_U8:
	case ARM64_INTRIN_VRSHRD_N_S64:
	case ARM64_INTRIN_VRSHRD_N_U64:
	case ARM64_INTRIN_VRSHRN_N_S16:
	case ARM64_INTRIN_VRSHRN_N_S32:
	case ARM64_INTRIN_VRSHRN_N_S64:
	case ARM64_INTRIN_VRSHRN_N_U16:
	case ARM64_INTRIN_VRSHRN_N_U32:
	case ARM64_INTRIN_VRSHRN_N_U64:
	case ARM64_INTRIN_VRSQRTE_U32:
	case ARM64_INTRIN_VRSRA_N_S16:
	case ARM64_INTRIN_VRSRA_N_S32:
	case ARM64_INTRIN_VRSRA_N_S64:
	case ARM64_INTRIN_VRSRA_N_S8:
	case ARM64_INTRIN_VRSRA_N_U16:
	case ARM64_INTRIN_VRSRA_N_U32:
	case ARM64_INTRIN_VRSRA_N_U64:
	case ARM64_INTRIN_VRSRA_N_U8:
	case ARM64_INTRIN_VRSRAD_N_S64:
	case ARM64_INTRIN_VRSRAD_N_U64:
	case ARM64_INTRIN_VRSUBHN_S16:
	case ARM64_INTRIN_VRSUBHN_S32:
	case ARM64_INTRIN_VRSUBHN_S64:
	case ARM64_INTRIN_VRSUBHN_U16:
	case ARM64_INTRIN_VRSUBHN_U32:
	case ARM64_INTRIN_VRSUBHN_U64:
	case ARM64_INTRIN_VSET_LANE_P16:
	case ARM64_INTRIN_VSET_LANE_P64:
	case ARM64_INTRIN_VSET_LANE_P8:
	case ARM64_INTRIN_VSET_LANE_S16:
	case ARM64_INTRIN_VSET_LANE_S32:
	case ARM64_INTRIN_VSET_LANE_S64:
	case ARM64_INTRIN_VSET_LANE_S8:
	case ARM64_INTRIN_VSET_LANE_U16:
	case ARM64_INTRIN_VSET_LANE_U32:
	case ARM64_INTRIN_VSET_LANE_U64:
	case ARM64_INTRIN_VSET_LANE_U8:
	case ARM64_INTRIN_VSHL_N_S16:
	case ARM64_INTRIN_VSHL_N_S32:
	case ARM64_INTRIN_VSHL_N_S64:
	case ARM64_INTRIN_VSHL_N_S8:
	case ARM64_INTRIN_VSHL_N_U16:
	case ARM64_INTRIN_VSHL_N_U32:
	case ARM64_INTRIN_VSHL_N_U64:
	case ARM64_INTRIN_VSHL_N_U8:
	case ARM64_INTRIN_VSHL_S16:
	case ARM64_INTRIN_VSHL_S32:
	case ARM64_INTRIN_VSHL_S64:
	case ARM64_INTRIN_VSHL_S8:
	case ARM64_INTRIN_VSHL_U16:
	case ARM64_INTRIN_VSHL_U32:
	case ARM64_INTRIN_VSHL_U64:
	case ARM64_INTRIN_VSHL_U8:
	case ARM64_INTRIN_VSHLD_N_S64:
	case ARM64_INTRIN_VSHLD_N_U64:
	case ARM64_INTRIN_VSHLD_S64:
	case ARM64_INTRIN_VSHLD_U64:
	case ARM64_INTRIN_VSHR_N_S16:
	case ARM64_INTRIN_VSHR_N_S32:
	case ARM64_INTRIN_VSHR_N_S64:
	case ARM64_INTRIN_VSHR_N_S8:
	case ARM64_INTRIN_VSHR_N_U16:
	case ARM64_INTRIN_VSHR_N_U32:
	case ARM64_INTRIN_VSHR_N_U64:
	case ARM64_INTRIN_VSHR_N_U8:
	case ARM64_INTRIN_VSHRD_N_S64:
	case ARM64_INTRIN_VSHRD_N_U64:
	case ARM64_INTRIN_VSHRN_N_S16:
	case ARM64_INTRIN_VSHRN_N_S32:
	case ARM64_INTRIN_VSHRN_N_S64:
	case ARM64_INTRIN_VSHRN_N_U16:
	case ARM64_INTRIN_VSHRN_N_U32:
	case ARM64_INTRIN_VSHRN_N_U64:
	case ARM64_INTRIN_VSLI_N_P16:
	case ARM64_INTRIN_VSLI_N_P64:
	case ARM64_INTRIN_VSLI_N_P8:
	case ARM64_INTRIN_VSLI_N_S16:
	case ARM64_INTRIN_VSLI_N_S32:
	case ARM64_INTRIN_VSLI_N_S64:
	case ARM64_INTRIN_VSLI_N_S8:
	case ARM64_INTRIN_VSLI_N_U16:
	case ARM64_INTRIN_VSLI_N_U32:
	case ARM64_INTRIN_VSLI_N_U64:
	case ARM64_INTRIN_VSLI_N_U8:
	case ARM64_INTRIN_VSLID_N_S64:
	case ARM64_INTRIN_VSLID_N_U64:
	case ARM64_INTRIN_VSQADD_U16:
	case ARM64_INTRIN_VSQADD_U32:
	case ARM64_INTRIN_VSQADD_U64:
	case ARM64_INTRIN_VSQADD_U8:
	case ARM64_INTRIN_VSQADDD_U64:
	case ARM64_INTRIN_VSRA_N_S16:
	case ARM64_INTRIN_VSRA_N_S32:
	case ARM64_INTRIN_VSRA_N_S64:
	case ARM64_INTRIN_VSRA_N_S8:
	case ARM64_INTRIN_VSRA_N_U16:
	case ARM64_INTRIN_VSRA_N_U32:
	case ARM64_INTRIN_VSRA_N_U64:
	case ARM64_INTRIN_VSRA_N_U8:
	case ARM64_INTRIN_VSRAD_N_S64:
	case ARM64_INTRIN_VSRAD_N_U64:
	case ARM64_INTRIN_VSRI_N_P16:
	case ARM64_INTRIN_VSRI_N_P64:
	case ARM64_INTRIN_VSRI_N_P8:
	case ARM64_INTRIN_VSRI_N_S16:
	case ARM64_INTRIN_VSRI_N_S32:
	case ARM64_INTRIN_VSRI_N_S64:
	case ARM64_INTRIN_VSRI_N_S8:
	case ARM64_INTRIN_VSRI_N_U16:
	case ARM64_INTRIN_VSRI_N_U32:
	case ARM64_INTRIN_VSRI_N_U64:
	case ARM64_INTRIN_VSRI_N_U8:
	case ARM64_INTRIN_VSRID_N_S64:
	case ARM64_INTRIN_VSRID_N_U64:
	case ARM64_INTRIN_VSUB_S16:
	case ARM64_INTRIN_VSUB_S32:
	case ARM64_INTRIN_VSUB_S64:
	case ARM64_INTRIN_VSUB_S8:
	case ARM64_INTRIN_VSUB_U16:
	case ARM64_INTRIN_VSUB_U32:
	case ARM64_INTRIN_VSUB_U64:
	case ARM64_INTRIN_VSUB_U8:
	case ARM64_INTRIN_VSUBD_S64:
	case ARM64_INTRIN_VSUBD_U64:
	case ARM64_INTRIN_VSUBHN_S16:
	case ARM64_INTRIN_VSUBHN_S32:
	case ARM64_INTRIN_VSUBHN_S64:
	case ARM64_INTRIN_VSUBHN_U16:
	case ARM64_INTRIN_VSUBHN_U32:
	case ARM64_INTRIN_VSUBHN_U64:
	case ARM64_INTRIN_VSUDOT_LANE_S32:
	case ARM64_INTRIN_VSUDOT_LANEQ_S32:
	case ARM64_INTRIN_VTRN1_P16:
	case ARM64_INTRIN_VTRN1_P8:
	case ARM64_INTRIN_VTRN1_S16:
	case ARM64_INTRIN_VTRN1_S32:
	case ARM64_INTRIN_VTRN1_S8:
	case ARM64_INTRIN_VTRN1_U16:
	case ARM64_INTRIN_VTRN1_U32:
	case ARM64_INTRIN_VTRN1_U8:
	case ARM64_INTRIN_VTRN2_P16:
	case ARM64_INTRIN_VTRN2_P8:
	case ARM64_INTRIN_VTRN2_S16:
	case ARM64_INTRIN_VTRN2_S32:
	case ARM64_INTRIN_VTRN2_S8:
	case ARM64_INTRIN_VTRN2_U16:
	case ARM64_INTRIN_VTRN2_U32:
	case ARM64_INTRIN_VTRN2_U8:
	case ARM64_INTRIN_VTST_P64:
	case ARM64_INTRIN_VTST_P8:
	case ARM64_INTRIN_VTST_S16:
	case ARM64_INTRIN_VTST_S32:
	case ARM64_INTRIN_VTST_S64:
	case ARM64_INTRIN_VTST_S8:
	case ARM64_INTRIN_VTST_U16:
	case ARM64_INTRIN_VTST_U32:
	case ARM64_INTRIN_VTST_U64:
	case ARM64_INTRIN_VTST_U8:
	case ARM64_INTRIN_VTSTD_S64:
	case ARM64_INTRIN_VTSTD_U64:
	case ARM64_INTRIN_VUQADD_S16:
	case ARM64_INTRIN_VUQADD_S32:
	case ARM64_INTRIN_VUQADD_S64:
	case ARM64_INTRIN_VUQADD_S8:
	case ARM64_INTRIN_VUQADDD_S64:
	case ARM64_INTRIN_VUSDOT_LANE_S32:
	case ARM64_INTRIN_VUSDOT_LANEQ_S32:
	case ARM64_INTRIN_VUSDOT_S32:
	case ARM64_INTRIN_VUZP1_P16:
	case ARM64_INTRIN_VUZP1_P8:
	case ARM64_INTRIN_VUZP1_S16:
	case ARM64_INTRIN_VUZP1_S32:
	case ARM64_INTRIN_VUZP1_S8:
	case ARM64_INTRIN_VUZP1_U16:
	case ARM64_INTRIN_VUZP1_U32:
	case ARM64_INTRIN_VUZP1_U8:
	case ARM64_INTRIN_VUZP2_P16:
	case ARM64_INTRIN_VUZP2_P8:
	case ARM64_INTRIN_VUZP2_S16:
	case ARM64_INTRIN_VUZP2_S32:
	case ARM64_INTRIN_VUZP2_S8:
	case ARM64_INTRIN_VUZP2_U16:
	case ARM64_INTRIN_VUZP2_U32:
	case ARM64_INTRIN_VUZP2_U8:
	case ARM64_INTRIN_VZIP1_P16:
	case ARM64_INTRIN_VZIP1_P8:
	case ARM64_INTRIN_VZIP1_S16:
	case ARM64_INTRIN_VZIP1_S32:
	case ARM64_INTRIN_VZIP1_S8:
	case ARM64_INTRIN_VZIP1_U16:
	case ARM64_INTRIN_VZIP1_U32:
	case ARM64_INTRIN_VZIP1_U8:
	case ARM64_INTRIN_VZIP2_P16:
	case ARM64_INTRIN_VZIP2_P8:
	case ARM64_INTRIN_VZIP2_S16:
	case ARM64_INTRIN_VZIP2_S32:
	case ARM64_INTRIN_VZIP2_S8:
	case ARM64_INTRIN_VZIP2_U16:
	case ARM64_INTRIN_VZIP2_U32:
	case ARM64_INTRIN_VZIP2_U8:
		return {Type::IntegerType(8, false)};
	default:
		return vector<Confidence<Ref<Type>>>();
	}
}

static void add_input_reg(
    vector<ExprId>& inputs, LowLevelILFunction& il, InstructionOperand& operand)
{
	// TODO: test that arrangement specifier is being used to extract correctly sized register
	// eg: V0.1d -> REG_V0_D0
	inputs.push_back(ILREG_O(operand));
}

static void add_input_imm(
    vector<ExprId>& inputs, LowLevelILFunction& il, InstructionOperand& operand)
{
	inputs.push_back(il.Const(0, operand.immediate));
}

static void add_input_lane(
    vector<ExprId>& inputs, LowLevelILFunction& il, InstructionOperand& operand)
{
	inputs.push_back(il.Const(1, operand.lane));
}

static void add_output_reg(
    vector<RegisterOrFlag>& outputs, LowLevelILFunction& il, InstructionOperand& operand)
{
	// TODO: test that arrangement specifier is being used to extract correctly sized register
	// eg: V0.1d -> REG_V0_D0
	outputs.push_back(RegisterOrFlag::Register(REG_O(operand)));
}

bool NeonGetLowLevelILForInstruction(
    Architecture* arch, uint64_t addr, LowLevelILFunction& il, Instruction& instr, size_t addrSize)
{
	NeonIntrinsic intrin_id = (NeonIntrinsic)ARM64_INTRIN_INVALID;
	vector<RegisterOrFlag> outputs;
	vector<ExprId> inputs;

	// printf("%s() operation:%d encoding:%d\n", __func__, instr.operation, instr.encoding);

	switch (instr.encoding)
	{
	case ENC_ABS_ASIMDMISC_R:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VABS_S8;  // ABS Vd.8B,Vn.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VABSQ_S8;  // ABS Vd.16B,Vn.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VABS_S16;  // ABS Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VABSQ_S16;  // ABS Vd.8H,Vn.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VABS_S32;  // ABS Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VABSQ_S32;  // ABS Vd.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VABSQ_S64;  // ABS Vd.2D,Vn.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_ABS_ASISDMISC_R:
		intrin_id = ARM64_INTRIN_VABS_S64;  // ABS Dd,Dn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_ADDHN_ASIMDDIFF_N:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VADDHN_S16;  // ADDHN Vd.8B,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VADDHN_S32;  // ADDHN Vd.4H,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VADDHN_S64;  // ADDHN Vd.2S,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VADDHN_U16;  // ADDHN Vd.8B,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VADDHN_U32;  // ADDHN Vd.4H,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VADDHN_U64;  // ADDHN Vd.2S,Vn.2D,Vm.2D
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VADDHN_HIGH_S16;  // ADDHN2 Vd.16B,Vn.8H,Vm.8H
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VADDHN_HIGH_S32;  // ADDHN2 Vd.8H,Vn.4S,Vm.4S
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VADDHN_HIGH_S64;  // ADDHN2 Vd.4S,Vn.2D,Vm.2D
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VADDHN_HIGH_U16;  // ADDHN2 Vd.16B,Vn.8H,Vm.8H
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VADDHN_HIGH_U32;  // ADDHN2 Vd.8H,Vn.4S,Vm.4S
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VADDHN_HIGH_U64;  // ADDHN2 Vd.4S,Vn.2D,Vm.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_ADDP_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VPADD_S8;  // ADDP Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VPADD_S16;  // ADDP Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VPADD_S32;  // ADDP Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VPADD_U8;  // ADDP Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VPADD_U16;  // ADDP Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VPADD_U32;  // ADDP Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VPADDQ_S8;  // ADDP Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VPADDQ_S16;  // ADDP Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VPADDQ_S32;  // ADDP Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VPADDQ_S64;  // ADDP Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VPADDQ_U8;  // ADDP Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VPADDQ_U16;  // ADDP Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VPADDQ_U32;  // ADDP Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VPADDQ_U64;  // ADDP Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[2].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VADDV_S32;  // ADDP Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[2].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VADDV_U32;  // ADDP Vd.2S,Vn.2S,Vm.2S
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_ADDP_ASISDPAIR_ONLY:
		intrin_id = ARM64_INTRIN_VPADDD_S64;  // ADDP Dd,Vn.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_ADDV_ASIMDALL_ONLY:
		intrin_id = ARM64_INTRIN_VADDV_S8;  // ADDV Bd,Vn.8B
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_ADD_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VADD_S8;  // ADD Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VADDQ_S8;  // ADD Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VADD_S16;  // ADD Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VADDQ_S16;  // ADD Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VADD_S32;  // ADD Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VADDQ_S32;  // ADD Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VADDQ_S64;  // ADD Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VADD_U8;  // ADD Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VADDQ_U8;  // ADD Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VADD_U16;  // ADD Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VADDQ_U16;  // ADD Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VADD_U32;  // ADD Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VADDQ_U32;  // ADD Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VADDQ_U64;  // ADD Vd.2D,Vn.2D,Vm.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_ADD_ASISDSAME_ONLY:
		intrin_id = ARM64_INTRIN_VADD_S64;  // ADD Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_AESD_B_CRYPTOAES:
		intrin_id = ARM64_INTRIN_VAESDQ_U8;  // AESD Vd.16B,Vn.16B
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_AESE_B_CRYPTOAES:
		intrin_id = ARM64_INTRIN_VAESEQ_U8;  // AESE Vd.16B,Vn.16B
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_AESIMC_B_CRYPTOAES:
		intrin_id = ARM64_INTRIN_VAESIMCQ_U8;  // AESIMC Vd.16B,Vn.16B
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_AESMC_B_CRYPTOAES:
		intrin_id = ARM64_INTRIN_VAESMCQ_U8;  // AESMC Vd.16B,Vn.16B
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_AND_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VAND_S8;  // AND Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VANDQ_S8;  // AND Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VAND_S16;  // AND Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VANDQ_S16;  // AND Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VAND_S32;  // AND Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VANDQ_S32;  // AND Vd.16B,Vn.16B,Vm.16B
		// if(None) intrin_id = ARM64_INTRIN_VAND_S64; // AND Dd,Dn,Dm
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VANDQ_S64;  // AND Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VAND_U8;  // AND Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VANDQ_U8;  // AND Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VAND_U16;  // AND Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VANDQ_U16;  // AND Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VAND_U32;  // AND Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VANDQ_U32;  // AND Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VAND_U64;  // AND Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VANDQ_U64;  // AND Vd.16B,Vn.16B,Vm.16B
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_BCAX_VVV16_CRYPTO4:
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VBCAXQ_U8;  // BCAX Vd.16B,Vn.16B,Vm.16B,Va.16B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VBCAXQ_U16;  // BCAX Vd.16B,Vn.16B,Vm.16B,Va.16B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VBCAXQ_U32;  // BCAX Vd.16B,Vn.16B,Vm.16B,Va.16B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VBCAXQ_U64;  // BCAX Vd.16B,Vn.16B,Vm.16B,Va.16B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VBCAXQ_S8;  // BCAX Vd.16B,Vn.16B,Vm.16B,Va.16B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VBCAXQ_S16;  // BCAX Vd.16B,Vn.16B,Vm.16B,Va.16B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VBCAXQ_S32;  // BCAX Vd.16B,Vn.16B,Vm.16B,Va.16B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VBCAXQ_S64;  // BCAX Vd.16B,Vn.16B,Vm.16B,Va.16B
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_reg(inputs, il, instr.operands[3]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_BFCVTN_ASIMDMISC_4S:
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCVT_BF16_F32;  // BFCVTN Vd.4H,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCVTQ_LOW_BF16_F32;  // BFCVTN Vd.4H,Vn.4S
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCVTQ_HIGH_BF16_F32;  // BFCVTN2 Vd.8H,Vn.4S
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_BFCVT_BS_FLOATDP1:
		intrin_id = ARM64_INTRIN_VCVTH_BF16_F32;  // BFCVT Hd,Sn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_BFDOT_ASIMDELEM_E:
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VBFDOT_LANE_F32;  // BFDOT Vd.2S,Vn.4H,Vm.2H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VBFDOTQ_LANEQ_F32;  // BFDOT Vd.4S,Vn.8H,Vm.2H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VBFDOT_LANEQ_F32;  // BFDOT Vd.2S,Vn.4H,Vm.2H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VBFDOTQ_LANE_F32;  // BFDOT Vd.4S,Vn.8H,Vm.2H[lane]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_BFDOT_ASIMDSAME2_D:
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VBFDOT_F32;  // BFDOT Vd.2S,Vn.4H,Vm.4H
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VBFDOTQ_F32;  // BFDOT Vd.4S,Vn.8H,Vm.8H
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_BFMMLA_ASIMDSAME2_E:
		intrin_id = ARM64_INTRIN_VBFMMLAQ_F32;  // BFMMLA Vd.4S,Vn.8H,Vm.8H
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_BIC_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VBIC_S8;  // BIC Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VBICQ_S8;  // BIC Vd.16B,Vn.16B,Vm.16B
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_BIT_ASIMDSAME_ONLY:
		// There is no intrinsic for the bit instruction in the ARM documentation.
		// Although, the bit instruction is just a bsl instruction with a specific operand order.
		if (instr.operands[0].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VBSL_S8;  // BSL Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VBSLQ_S8;  // BSL Vd.16B,Vn.16B,Vm.16B
		// As per bsl & bit documentation:
		//
		// "Bitwise Select. This instruction sets each bit in the destination SIMD and FP register
		// to the corresponding bit from the first source SIMD and FP register when the original
		// destination bit was 1, otherwise from the second source SIMD and FP register."
		//
		// and as per bit documentation:
		//
		// "Bitwise Insert if True. This instruction inserts each bit from the first source SIMD
		// and FP register into the SIMD and FP destination register if the corresponding bit of
		// the second source SIMD and FP register is 1, otherwise leaves the bit in the destination
		// register unchanged."
		//
		// We can then emulate this behavior using the bsl instruction as follow:
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[0]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_BIF_ASIMDSAME_ONLY:
		// There is no intrinsic for the bif instruction in the ARM documentation.
		// Although, the bif instruction is just a bsl instruction with a specific operand order.
		if (instr.operands[0].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VBSL_S8;  // BIF Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VBSLQ_S8;  // BIF Vd.16B,Vn.16B,Vm.16B
		// As per BSL documentation:
		//
		// "Bitwise Select. This instruction sets each bit in the destination SIMD and FP register
		// to the corresponding bit from the first source SIMD and FP register when the original
		// destination bit was 1, otherwise from the second source SIMD and FP register."
		//
		// and as per bif documentation:
		//
		// "Bitwise Insert if False. This instruction inserts each bit from the first source SIMD
		// and FP register into the destination SIMD and FP register if the corresponding bit of the
		// second source SIMD and FP register is 0, otherwise leaves the bit in the destination
		// register unchanged."
		//
		// We can then emulate this behavior using the bsl instruction as follow:
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_BSL_ASIMDSAME_ONLY:
		if (instr.operands[0].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VBSL_S8;  // BSL Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VBSLQ_S8;  // BSL Vd.16B,Vn.16B,Vm.16B
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_CLS_ASIMDMISC_R:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VCLS_S8;  // CLS Vd.8B,Vn.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VCLSQ_S8;  // CLS Vd.16B,Vn.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCLS_S16;  // CLS Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCLSQ_S16;  // CLS Vd.8H,Vn.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCLS_S32;  // CLS Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCLSQ_S32;  // CLS Vd.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VCLS_U8;  // CLS Vd.8B,Vn.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VCLSQ_U8;  // CLS Vd.16B,Vn.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCLS_U16;  // CLS Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCLSQ_U16;  // CLS Vd.8H,Vn.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCLS_U32;  // CLS Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCLSQ_U32;  // CLS Vd.4S,Vn.4S
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_CLZ_ASIMDMISC_R:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VCLZ_S8;  // CLZ Vd.8B,Vn.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VCLZQ_S8;  // CLZ Vd.16B,Vn.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCLZ_S16;  // CLZ Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCLZQ_S16;  // CLZ Vd.8H,Vn.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCLZ_S32;  // CLZ Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCLZQ_S32;  // CLZ Vd.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VCLZ_U8;  // CLZ Vd.8B,Vn.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VCLZQ_U8;  // CLZ Vd.16B,Vn.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCLZ_U16;  // CLZ Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCLZQ_U16;  // CLZ Vd.8H,Vn.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCLZ_U32;  // CLZ Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCLZQ_U32;  // CLZ Vd.4S,Vn.4S
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_CMEQ_ASIMDMISC_Z:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VCEQZ_S8;  // CMEQ Vd.8B,Vn.8B,#0
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VCEQZQ_S8;  // CMEQ Vd.16B,Vn.16B,#0
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCEQZ_S16;  // CMEQ Vd.4H,Vn.4H,#0
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCEQZQ_S16;  // CMEQ Vd.8H,Vn.8H,#0
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCEQZ_S32;  // CMEQ Vd.2S,Vn.2S,#0
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCEQZQ_S32;  // CMEQ Vd.4S,Vn.4S,#0
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VCEQZ_U8;  // CMEQ Vd.8B,Vn.8B,#0
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VCEQZQ_U8;  // CMEQ Vd.16B,Vn.16B,#0
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCEQZ_U16;  // CMEQ Vd.4H,Vn.4H,#0
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCEQZQ_U16;  // CMEQ Vd.8H,Vn.8H,#0
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCEQZ_U32;  // CMEQ Vd.2S,Vn.2S,#0
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCEQZQ_U32;  // CMEQ Vd.4S,Vn.4S,#0
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VCEQZ_P8;  // CMEQ Vd.8B,Vn.8B,#0
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VCEQZQ_P8;  // CMEQ Vd.16B,Vn.16B,#0
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCEQZQ_S64;  // CMEQ Vd.2D,Vn.2D,#0
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCEQZQ_U64;  // CMEQ Vd.2D,Vn.2D,#0
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCEQZQ_P64;  // CMEQ Vd.2D,Vn.2D,#0
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_CMEQ_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VCEQ_S8;  // CMEQ Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VCEQQ_S8;  // CMEQ Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCEQ_S16;  // CMEQ Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCEQQ_S16;  // CMEQ Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCEQ_S32;  // CMEQ Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCEQQ_S32;  // CMEQ Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VCEQ_U8;  // CMEQ Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VCEQQ_U8;  // CMEQ Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCEQ_U16;  // CMEQ Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCEQQ_U16;  // CMEQ Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCEQ_U32;  // CMEQ Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCEQQ_U32;  // CMEQ Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VCEQ_P8;  // CMEQ Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VCEQQ_P8;  // CMEQ Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCEQQ_S64;  // CMEQ Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCEQQ_U64;  // CMEQ Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCEQQ_P64;  // CMEQ Vd.2D,Vn.2D,Vm.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_CMEQ_ASISDMISC_Z:
		intrin_id = ARM64_INTRIN_VCEQZ_S64;  // CMEQ Dd,Dn,#0
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_CMEQ_ASISDSAME_ONLY:
		intrin_id = ARM64_INTRIN_VCEQ_S64;  // CMEQ Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_CMGE_ASIMDMISC_Z:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VCGEZ_S8;  // CMGE Vd.8B,Vn.8B,#0
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VCGEZQ_S8;  // CMGE Vd.16B,Vn.16B,#0
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCGEZ_S16;  // CMGE Vd.4H,Vn.4H,#0
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCGEZQ_S16;  // CMGE Vd.8H,Vn.8H,#0
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCGEZ_S32;  // CMGE Vd.2S,Vn.2S,#0
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCGEZQ_S32;  // CMGE Vd.4S,Vn.4S,#0
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCGEZQ_S64;  // CMGE Vd.2D,Vn.2D,#0
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_CMGE_ASIMDSAME_ONLY:
		if (instr.operands[2].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VCGE_S8;  // CMGE Vd.8B,Vm.8B,Vn.8B
		if (instr.operands[2].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VCGEQ_S8;  // CMGE Vd.16B,Vm.16B,Vn.16B
		if (instr.operands[2].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCGE_S16;  // CMGE Vd.4H,Vm.4H,Vn.4H
		if (instr.operands[2].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCGEQ_S16;  // CMGE Vd.8H,Vm.8H,Vn.8H
		if (instr.operands[2].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCGE_S32;  // CMGE Vd.2S,Vm.2S,Vn.2S
		if (instr.operands[2].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCGEQ_S32;  // CMGE Vd.4S,Vm.4S,Vn.4S
		if (instr.operands[2].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCGEQ_S64;  // CMGE Vd.2D,Vm.2D,Vn.2D
		if (instr.operands[2].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VCLE_S8;  // CMGE Vd.8B,Vm.8B,Vn.8B
		if (instr.operands[2].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VCLEQ_S8;  // CMGE Vd.16B,Vm.16B,Vn.16B
		if (instr.operands[2].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCLE_S16;  // CMGE Vd.4H,Vm.4H,Vn.4H
		if (instr.operands[2].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCLEQ_S16;  // CMGE Vd.8H,Vm.8H,Vn.8H
		if (instr.operands[2].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCLE_S32;  // CMGE Vd.2S,Vm.2S,Vn.2S
		if (instr.operands[2].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCLEQ_S32;  // CMGE Vd.4S,Vm.4S,Vn.4S
		if (instr.operands[2].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCLEQ_S64;  // CMGE Vd.2D,Vm.2D,Vn.2D
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_CMGE_ASISDMISC_Z:
		intrin_id = ARM64_INTRIN_VCGEZ_S64;  // CMGE Dd,Dn,#0
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_CMGE_ASISDSAME_ONLY:
		intrin_id = ARM64_INTRIN_VCGE_S64;  // CMGE Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_CMGT_ASIMDMISC_Z:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VCGTZ_S8;  // CMGT Vd.8B,Vn.8B,#0
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VCGTZQ_S8;  // CMGT Vd.16B,Vn.16B,#0
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCGTZ_S16;  // CMGT Vd.4H,Vn.4H,#0
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCGTZQ_S16;  // CMGT Vd.8H,Vn.8H,#0
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCGTZ_S32;  // CMGT Vd.2S,Vn.2S,#0
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCGTZQ_S32;  // CMGT Vd.4S,Vn.4S,#0
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCGTZQ_S64;  // CMGT Vd.2D,Vn.2D,#0
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_CMGT_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VCGT_S8;  // CMGT Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VCGTQ_S8;  // CMGT Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCGT_S16;  // CMGT Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCGTQ_S16;  // CMGT Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCGT_S32;  // CMGT Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCGTQ_S32;  // CMGT Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCGTQ_S64;  // CMGT Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[2].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VCLT_S8;  // CMGT Vd.8B,Vm.8B,Vn.8B
		if (instr.operands[2].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VCLTQ_S8;  // CMGT Vd.16B,Vm.16B,Vn.16B
		if (instr.operands[2].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCLT_S16;  // CMGT Vd.4H,Vm.4H,Vn.4H
		if (instr.operands[2].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCLTQ_S16;  // CMGT Vd.8H,Vm.8H,Vn.8H
		if (instr.operands[2].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCLT_S32;  // CMGT Vd.2S,Vm.2S,Vn.2S
		if (instr.operands[2].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCLTQ_S32;  // CMGT Vd.4S,Vm.4S,Vn.4S
		if (instr.operands[2].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCLTQ_S64;  // CMGT Vd.2D,Vm.2D,Vn.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_CMGT_ASISDMISC_Z:
		intrin_id = ARM64_INTRIN_VCGTZ_S64;  // CMGT Dd,Dn,#0
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_CMGT_ASISDSAME_ONLY:
		intrin_id = ARM64_INTRIN_VCGT_S64;  // CMGT Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_CMHI_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VCGT_U8;  // CMHI Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VCGTQ_U8;  // CMHI Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCGT_U16;  // CMHI Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCGTQ_U16;  // CMHI Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCGT_U32;  // CMHI Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCGTQ_U32;  // CMHI Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCGTQ_U64;  // CMHI Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[2].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VCLT_U8;  // CMHI Vd.8B,Vm.8B,Vn.8B
		if (instr.operands[2].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VCLTQ_U8;  // CMHI Vd.16B,Vm.16B,Vn.16B
		if (instr.operands[2].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCLT_U16;  // CMHI Vd.4H,Vm.4H,Vn.4H
		if (instr.operands[2].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCLTQ_U16;  // CMHI Vd.8H,Vm.8H,Vn.8H
		if (instr.operands[2].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCLT_U32;  // CMHI Vd.2S,Vm.2S,Vn.2S
		if (instr.operands[2].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCLTQ_U32;  // CMHI Vd.4S,Vm.4S,Vn.4S
		if (instr.operands[2].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCLTQ_U64;  // CMHI Vd.2D,Vm.2D,Vn.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_CMHI_ASISDSAME_ONLY:
		intrin_id = ARM64_INTRIN_VCGT_U64;  // CMHI Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_CMHS_ASIMDSAME_ONLY:
		if (instr.operands[2].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VCGE_U8;  // CMHS Vd.8B,Vm.8B,Vn.8B
		if (instr.operands[2].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VCGEQ_U8;  // CMHS Vd.16B,Vm.16B,Vn.16B
		if (instr.operands[2].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCGE_U16;  // CMHS Vd.4H,Vm.4H,Vn.4H
		if (instr.operands[2].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCGEQ_U16;  // CMHS Vd.8H,Vm.8H,Vn.8H
		if (instr.operands[2].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCGE_U32;  // CMHS Vd.2S,Vm.2S,Vn.2S
		if (instr.operands[2].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCGEQ_U32;  // CMHS Vd.4S,Vm.4S,Vn.4S
		if (instr.operands[2].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCGEQ_U64;  // CMHS Vd.2D,Vm.2D,Vn.2D
		if (instr.operands[2].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VCLE_U8;  // CMHS Vd.8B,Vm.8B,Vn.8B
		if (instr.operands[2].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VCLEQ_U8;  // CMHS Vd.16B,Vm.16B,Vn.16B
		if (instr.operands[2].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCLE_U16;  // CMHS Vd.4H,Vm.4H,Vn.4H
		if (instr.operands[2].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCLEQ_U16;  // CMHS Vd.8H,Vm.8H,Vn.8H
		if (instr.operands[2].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCLE_U32;  // CMHS Vd.2S,Vm.2S,Vn.2S
		if (instr.operands[2].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCLEQ_U32;  // CMHS Vd.4S,Vm.4S,Vn.4S
		if (instr.operands[2].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCLEQ_U64;  // CMHS Vd.2D,Vm.2D,Vn.2D
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_CMHS_ASISDSAME_ONLY:
		intrin_id = ARM64_INTRIN_VCGE_U64;  // CMHS Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_CMLE_ASIMDMISC_Z:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VCLEZ_S8;  // CMLE Vd.8B,Vn.8B,#0
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VCLEZQ_S8;  // CMLE Vd.16B,Vn.16B,#0
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCLEZ_S16;  // CMLE Vd.4H,Vn.4H,#0
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCLEZQ_S16;  // CMLE Vd.8H,Vn.8H,#0
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCLEZ_S32;  // CMLE Vd.2S,Vn.2S,#0
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCLEZQ_S32;  // CMLE Vd.4S,Vn.4S,#0
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCLEZQ_S64;  // CMLE Vd.2D,Vn.2D,#0
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCLEZ_F32;  // CMLE Vd.2S,Vn.2S,#0
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_CMLE_ASISDMISC_Z:
		intrin_id = ARM64_INTRIN_VCLEZ_S64;  // CMLE Dd,Dn,#0
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_CMLT_ASIMDMISC_Z:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VCLTZ_S8;  // CMLT Vd.8B,Vn.8B,#0
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VCLTZQ_S8;  // CMLT Vd.16B,Vn.16B,#0
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCLTZ_S16;  // CMLT Vd.4H,Vn.4H,#0
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCLTZQ_S16;  // CMLT Vd.8H,Vn.8H,#0
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCLTZ_S32;  // CMLT Vd.2S,Vn.2S,#0
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCLTZQ_S32;  // CMLT Vd.4S,Vn.4S,#0
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCLTZQ_S64;  // CMLT Vd.2D,Vn.2D,#0
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_CMLT_ASISDMISC_Z:
		intrin_id = ARM64_INTRIN_VCLTZ_S64;  // CMLT Dd,Dn,#0
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_CMTST_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VTST_S8;  // CMTST Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VTSTQ_S8;  // CMTST Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VTST_S16;  // CMTST Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VTSTQ_S16;  // CMTST Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VTST_S32;  // CMTST Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VTSTQ_S32;  // CMTST Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VTST_U8;  // CMTST Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VTSTQ_U8;  // CMTST Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VTST_U16;  // CMTST Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VTSTQ_U16;  // CMTST Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VTST_U32;  // CMTST Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VTSTQ_U32;  // CMTST Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VTST_P8;  // CMTST Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VTSTQ_P8;  // CMTST Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VTSTQ_S64;  // CMTST Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VTSTQ_U64;  // CMTST Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VTSTQ_P64;  // CMTST Vd.2D,Vn.2D,Vm.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_CMTST_ASISDSAME_ONLY:
		intrin_id = ARM64_INTRIN_VTST_S64;  // CMTST Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_CNT_ASIMDMISC_R:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VCNT_S8;  // CNT Vd.8B,Vn.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VCNTQ_S8;  // CNT Vd.16B,Vn.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VCNT_U8;  // CNT Vd.8B,Vn.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VCNTQ_U8;  // CNT Vd.16B,Vn.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VCNT_P8;  // CNT Vd.8B,Vn.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VCNTQ_P8;  // CNT Vd.16B,Vn.16B
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_CRC32B_32C_DP_2SRC:
		intrin_id = ARM64_INTRIN___CRC32B;  // CRC32B Wd,Wn,Wm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_CRC32CB_32C_DP_2SRC:
		intrin_id = ARM64_INTRIN___CRC32CB;  // CRC32CB Wd,Wn,Wm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_CRC32CH_32C_DP_2SRC:
		intrin_id = ARM64_INTRIN___CRC32CH;  // CRC32CH Wd,Wn,Wm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_CRC32CW_32C_DP_2SRC:
		intrin_id = ARM64_INTRIN___CRC32CW;  // CRC32CW Wd,Wn,Wm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_CRC32CX_64C_DP_2SRC:
		intrin_id = ARM64_INTRIN___CRC32CD;  // CRC32CX Wd,Wn,Xm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_CRC32H_32C_DP_2SRC:
		intrin_id = ARM64_INTRIN___CRC32H;  // CRC32H Wd,Wn,Wm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_CRC32W_32C_DP_2SRC:
		intrin_id = ARM64_INTRIN___CRC32W;  // CRC32W Wd,Wn,Wm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_CRC32X_64C_DP_2SRC:
		intrin_id = ARM64_INTRIN___CRC32D;  // CRC32X Wd,Wn,Xm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_DUP_ASIMDINS_DR_R:
		// This instrinsic is already handled in GetLowLevelIlForInstruction, in il.cpp
		break; // Should be unreachable
	case ENC_MOV_DUP_ASISDONE_ONLY: // The lifter use this instead of ENC_DUP_ASISDONE_ONLY
		// NOTE(ek0): The decoder only returns the base arrSpec. Not sure if intended,
		// so in the meantime we'll lift to the LANEQ version of the intrinsic.
		if (instr.operands[1].arrSpec == ARRSPEC_1BYTE)
			intrin_id = ARM64_INTRIN_VDUPB_LANEQ_S8; // DUP Bd, Vn.B[lane]
		else if (instr.operands[1].arrSpec == ARRSPEC_1HALF)
			intrin_id = ARM64_INTRIN_VDUPH_LANEQ_S16;  // DUP Hd,Vn.H[lane]
		else if (instr.operands[1].arrSpec == ARRSPEC_1SINGLE)
			intrin_id = ARM64_INTRIN_VDUPS_LANEQ_S32;  // DUP Sd,Vn.S[lane]
		else if (instr.operands[1].arrSpec == ARRSPEC_1DOUBLE)
			intrin_id = ARM64_INTRIN_VDUPD_LANEQ_S64;  // DUP Dd,Vn.D[lane]
		else
			break; // Should be unreachable
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_lane(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_DUP_ASIMDINS_DV_V:
		// Lifting DUP <Vd>.<T>,<Vn>.<Ts>[<index>]
		if (instr.operands[0].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VDUP_LANEQ_S8;
		else if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VDUPQ_LANEQ_S8;
		else if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VDUP_LANEQ_S16;
		else if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VDUPQ_LANEQ_S16;
		else if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VDUP_LANEQ_S32;
		else if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VDUPQ_LANEQ_S32;
		else if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VDUPQ_LANEQ_S64;
		else
			break; // Should be unreachable
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_lane(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_EOR3_VVV16_CRYPTO4:
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VEOR3Q_U8;  // EOR3 Vd.16B,Vn.16B,Vm.16B,Va.16B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VEOR3Q_U16;  // EOR3 Vd.16B,Vn.16B,Vm.16B,Va.16B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VEOR3Q_U32;  // EOR3 Vd.16B,Vn.16B,Vm.16B,Va.16B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VEOR3Q_U64;  // EOR3 Vd.16B,Vn.16B,Vm.16B,Va.16B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VEOR3Q_S8;  // EOR3 Vd.16B,Vn.16B,Vm.16B,Va.16B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VEOR3Q_S16;  // EOR3 Vd.16B,Vn.16B,Vm.16B,Va.16B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VEOR3Q_S32;  // EOR3 Vd.16B,Vn.16B,Vm.16B,Va.16B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VEOR3Q_S64;  // EOR3 Vd.16B,Vn.16B,Vm.16B,Va.16B
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_reg(inputs, il, instr.operands[3]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_EOR_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VEOR_S8;  // EOR Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VEORQ_S8;  // EOR Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VEOR_S16;  // EOR Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VEORQ_S16;  // EOR Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VEOR_S32;  // EOR Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VEORQ_S32;  // EOR Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VEOR_S64;  // EOR Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VEORQ_S64;  // EOR Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VEOR_U8;  // EOR Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VEORQ_U8;  // EOR Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VEOR_U16;  // EOR Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VEORQ_U16;  // EOR Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VEOR_U32;  // EOR Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VEORQ_U32;  // EOR Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VEOR_U64;  // EOR Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VEORQ_U64;  // EOR Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VADD_P8;  // EOR Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VADD_P16;  // EOR Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VADD_P64;  // EOR Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VADDQ_P8;  // EOR Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VADDQ_P16;  // EOR Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VADDQ_P64;  // EOR Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VADDQ_P128;  // EOR Vd.16B,Vn.16B,Vm.16B
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_EXT_ASIMDEXT_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VEXT_S8;  // EXT Vd.8B,Vn.8B,Vm.8B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VEXTQ_S8;  // EXT Vd.16B,Vn.16B,Vm.16B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VEXT_S16;  // EXT Vd.8B,Vn.8B,Vm.8B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VEXTQ_S16;  // EXT Vd.16B,Vn.16B,Vm.16B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VEXT_S32;  // EXT Vd.8B,Vn.8B,Vm.8B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VEXTQ_S32;  // EXT Vd.16B,Vn.16B,Vm.16B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VEXT_S64;  // EXT Vd.8B,Vn.8B,Vm.8B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VEXTQ_S64;  // EXT Vd.16B,Vn.16B,Vm.16B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VEXT_U8;  // EXT Vd.8B,Vn.8B,Vm.8B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VEXTQ_U8;  // EXT Vd.16B,Vn.16B,Vm.16B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VEXT_U16;  // EXT Vd.8B,Vn.8B,Vm.8B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VEXTQ_U16;  // EXT Vd.16B,Vn.16B,Vm.16B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VEXT_U32;  // EXT Vd.8B,Vn.8B,Vm.8B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VEXTQ_U32;  // EXT Vd.16B,Vn.16B,Vm.16B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VEXT_U64;  // EXT Vd.8B,Vn.8B,Vm.8B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VEXTQ_U64;  // EXT Vd.16B,Vn.16B,Vm.16B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VEXT_P64;  // EXT Vd.8B,Vn.8B,Vm.8B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VEXTQ_P64;  // EXT Vd.16B,Vn.16B,Vm.16B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VEXT_F32;  // EXT Vd.8B,Vn.8B,Vm.8B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VEXTQ_F32;  // EXT Vd.16B,Vn.16B,Vm.16B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VEXT_F64;  // EXT Vd.8B,Vn.8B,Vm.8B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VEXTQ_F64;  // EXT Vd.16B,Vn.16B,Vm.16B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VEXT_P8;  // EXT Vd.8B,Vn.8B,Vm.8B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VEXTQ_P8;  // EXT Vd.16B,Vn.16B,Vm.16B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VEXT_P16;  // EXT Vd.8B,Vn.8B,Vm.8B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VEXTQ_P16;  // EXT Vd.16B,Vn.16B,Vm.16B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VEXT_F16;  // EXT Vd.8B,Vn.8B,Vm.8B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VEXTQ_F16;  // EXT Vd.16B,Vn.16B,Vm.16B,#n
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_imm(inputs, il, instr.operands[3]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FABD_ASIMDSAMEFP16_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VABD_F32;  // FABD Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VABDQ_F32;  // FABD Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VABDQ_F64;  // FABD Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VABD_F16;  // FABD Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VABDQ_F16;  // FABD Vd.8H,Vn.8H,Vm.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FABD_ASISDSAMEFP16_ONLY:
		intrin_id = ARM64_INTRIN_VABD_F64;  // FABD Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FABS_D_FLOATDP1:
		intrin_id = ARM64_INTRIN_VABS_F64;  // FABS Dd,Dn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FABS_H_FLOATDP1:
		intrin_id = ARM64_INTRIN_VABSH_F16;  // FABS Hd,Hn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FABS_ASIMDMISCFP16_R:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VABS_F32;  // FABS Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VABSQ_F32;  // FABS Vd.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VABSQ_F64;  // FABS Vd.2D,Vn.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VABS_F16;  // FABS Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VABSQ_F16;  // FABS Vd.8H,Vn.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FACGE_ASIMDSAMEFP16_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCAGE_F32;  // FACGE Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCAGEQ_F32;  // FACGE Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCAGEQ_F64;  // FACGE Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[2].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCALE_F32;  // FACGE Vd.2S,Vm.2S,Vn.2S
		if (instr.operands[2].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCALEQ_F32;  // FACGE Vd.4S,Vm.4S,Vn.4S
		if (instr.operands[2].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCALEQ_F64;  // FACGE Vd.2D,Vm.2D,Vn.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCAGE_F16;  // FACGE Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCAGEQ_F16;  // FACGE Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCALE_F16;  // FACGE Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCALEQ_F16;  // FACGE Vd.8H,Vn.8H,Vm.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FACGE_ASISDSAMEFP16_ONLY:
		intrin_id = ARM64_INTRIN_VCAGE_F64;  // FACGE Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FACGT_ASIMDSAMEFP16_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCAGT_F32;  // FACGT Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCAGTQ_F32;  // FACGT Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCAGTQ_F64;  // FACGT Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[2].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCALT_F32;  // FACGT Vd.2S,Vm.2S,Vn.2S
		if (instr.operands[2].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCALTQ_F32;  // FACGT Vd.4S,Vm.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCALTQ_F64;  // FACGT Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCAGT_F16;  // FACGT Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCAGTQ_F16;  // FACGT Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCALT_F16;  // FACGT Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCALTQ_F16;  // FACGT Vd.8H,Vn.8H,Vm.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FACGT_ASISDSAMEFP16_ONLY:
		intrin_id = ARM64_INTRIN_VCAGT_F64;  // FACGT Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FADDP_ASIMDSAMEFP16_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VPADD_F32;  // FADDP Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VPADDQ_F32;  // FADDP Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VPADDQ_F64;  // FADDP Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VPADD_F16;  // FADDP Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VPADDQ_F16;  // FADDP Vd.8H,Vn.8H,Vm.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FADDP_ASISDPAIR_ONLY_H:
		intrin_id = ARM64_INTRIN_VPADDS_F32;  // FADDP Sd,Vn.2S
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FADD_D_FLOATDP2:
		intrin_id = ARM64_INTRIN_VADD_F64;  // FADD Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FADD_H_FLOATDP2:
		intrin_id = ARM64_INTRIN_VADDH_F16;  // FADD Hd,Hn,Hm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FADD_ASIMDSAMEFP16_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VADD_F32;  // FADD Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VADDQ_F32;  // FADD Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VADDQ_F64;  // FADD Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VADD_F16;  // FADD Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VADDQ_F16;  // FADD Vd.8H,Vn.8H,Vm.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCADD_ASIMDSAME2_C:
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCADD_ROT90_F16;  // FCADD Vd.4H,Vn.4H,Vm.4H,#90
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCADD_ROT90_F32;  // FCADD Vd.2S,Vn.2S,Vm.2S,#90
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCADDQ_ROT90_F16;  // FCADD Vd.8H,Vn.8H,Vm.8H,#90
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCADDQ_ROT90_F32;  // FCADD Vd.4S,Vn.4S,Vm.4S,#90
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCADDQ_ROT90_F64;  // FCADD Vd.2D,Vn.2D,Vm.2D,#90
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCADD_ROT270_F16;  // FCADD Vd.4H,Vn.4H,Vm.4H,#270
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCADD_ROT270_F32;  // FCADD Vd.2S,Vn.2S,Vm.2S,#270
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCADDQ_ROT270_F16;  // FCADD Vd.8H,Vn.8H,Vm.8H,#270
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCADDQ_ROT270_F32;  // FCADD Vd.4S,Vn.4S,Vm.4S,#270
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCADDQ_ROT270_F64;  // FCADD Vd.2D,Vn.2D,Vm.2D,#270
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCMEQ_ASIMDMISCFP16_FZ:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCEQZ_F32;  // FCMEQ Vd.2S,Vn.2S,#0
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCEQZQ_F32;  // FCMEQ Vd.4S,Vn.4S,#0
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCEQZQ_F64;  // FCMEQ Vd.2D,Vn.2D,#0
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCEQZ_F16;  // FCMEQ Vd.4H,Vn.4H,#0
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCEQZQ_F16;  // FCMEQ Vd.8H,Vn.8H,#0
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCMEQ_ASIMDSAMEFP16_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCEQ_F32;  // FCMEQ Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCEQQ_F32;  // FCMEQ Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCEQQ_F64;  // FCMEQ Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCEQ_F16;  // FCMEQ Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCEQQ_F16;  // FCMEQ Vd.8H,Vn.8H,Vm.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCMEQ_ASISDSAMEFP16_ONLY:
		intrin_id = ARM64_INTRIN_VCEQ_F64;  // FCMEQ Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCMGE_ASIMDMISCFP16_FZ:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCGEZ_F32;  // FCMGE Vd.2S,Vn.2S,#0
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCGEZQ_F32;  // FCMGE Vd.4S,Vn.4S,#0
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCGEZQ_F64;  // FCMGE Vd.2D,Vn.2D,#0
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCGEZ_F16;  // FCMGE Vd.4H,Vn.4H,#0
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCGEZQ_F16;  // FCMGE Vd.8H,Vn.8H,#0
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCMGE_ASIMDSAMEFP16_ONLY:
		if (instr.operands[2].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCGE_F32;  // FCMGE Vd.2S,Vm.2S,Vn.2S
		if (instr.operands[2].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCGEQ_F32;  // FCMGE Vd.4S,Vm.4S,Vn.4S
		if (instr.operands[2].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCGEQ_F64;  // FCMGE Vd.2D,Vm.2D,Vn.2D
		if (instr.operands[2].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCLE_F32;  // FCMGE Vd.2S,Vm.2S,Vn.2S
		if (instr.operands[2].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCLEQ_F32;  // FCMGE Vd.4S,Vm.4S,Vn.4S
		if (instr.operands[2].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCLEQ_F64;  // FCMGE Vd.2D,Vm.2D,Vn.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCGE_F16;  // FCMGE Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCGEQ_F16;  // FCMGE Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCLE_F16;  // FCMGE Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCLEQ_F16;  // FCMGE Vd.8H,Vn.8H,Vm.8H
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCMGE_ASISDSAMEFP16_ONLY:
		intrin_id = ARM64_INTRIN_VCGE_F64;  // FCMGE Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCMGT_ASIMDMISCFP16_FZ:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCGTZ_F32;  // FCMGT Vd.2S,Vn.2S,#0
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCGTZQ_F32;  // FCMGT Vd.4S,Vn.4S,#0
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCGTZQ_F64;  // FCMGT Vd.2D,Vn.2D,#0
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCGTZ_F16;  // FCMGT Vd.4H,Vn.4H,#0
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCGTZQ_F16;  // FCMGT Vd.8H,Vn.8H,#0
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCMGT_ASIMDSAMEFP16_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCGT_F32;  // FCMGT Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCGTQ_F32;  // FCMGT Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCGTQ_F64;  // FCMGT Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[2].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCLT_F32;  // FCMGT Vd.2S,Vm.2S,Vn.2S
		if (instr.operands[2].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCLTQ_F32;  // FCMGT Vd.4S,Vm.4S,Vn.4S
		if (instr.operands[2].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCLTQ_F64;  // FCMGT Vd.2D,Vm.2D,Vn.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCGT_F16;  // FCMGT Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCGTQ_F16;  // FCMGT Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCLT_F16;  // FCMGT Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCLTQ_F16;  // FCMGT Vd.8H,Vn.8H,Vm.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCMGT_ASISDSAMEFP16_ONLY:
		intrin_id = ARM64_INTRIN_VCGT_F64;  // FCMGT Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCMLA_ASIMDSAME2_C:
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCMLA_F16;  // FCMLA Vd.4H,Vn.4H,Vm.4H,#0
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCMLA_F32;  // FCMLA Vd.2S,Vn.2S,Vm.2S,#0
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCMLA_LANE_F16;  // FCMLA Vd.4H,Vn.4H,Vm.H[lane],#0
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCMLA_LANE_F32;  // FCMLA Vd.2S,Vn.2S,Vm.2S[lane],#0
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCMLA_LANEQ_F16;  // FCMLA Vd.4H,Vn.4H,Vm.H[lane],#0
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCMLAQ_F16;  // FCMLA Vd.8H,Vn.8H,Vm.8H,#0
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCMLAQ_F32;  // FCMLA Vd.4S,Vn.4S,Vm.4S,#0
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCMLAQ_F64;  // FCMLA Vd.2D,Vn.2D,Vm.2D,#0
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCMLAQ_LANE_F16;  // FCMLA Vd.8H,Vn.8H,Vm.H[lane],#0
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCMLAQ_LANE_F32;  // FCMLA Vd.4S,Vn.4S,Vm.S[lane],#0
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCMLAQ_LANEQ_F16;  // FCMLA Vd.8H,Vn.8H,Vm.H[lane],#0
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCMLAQ_LANEQ_F32;  // FCMLA Vd.4S,Vn.4S,Vm.S[lane],#0
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCMLA_ROT90_F16;  // FCMLA Vd.4H,Vn.4H,Vm.4H,#90
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCMLA_ROT90_F32;  // FCMLA Vd.2S,Vn.2S,Vm.2S,#90
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCMLA_ROT90_LANE_F16;  // FCMLA Vd.4H,Vn.4H,Vm.H[lane],#90
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCMLA_ROT90_LANE_F32;  // FCMLA Vd.2S,Vn.2S,Vm.2S[lane],#90
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCMLA_ROT90_LANEQ_F16;  // FCMLA Vd.4H,Vn.4H,Vm.H[lane],#90
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCMLAQ_ROT90_F16;  // FCMLA Vd.8H,Vn.8H,Vm.8H,#90
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCMLAQ_ROT90_F32;  // FCMLA Vd.4S,Vn.4S,Vm.4S,#90
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCMLAQ_ROT90_F64;  // FCMLA Vd.2D,Vn.2D,Vm.2D,#90
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCMLAQ_ROT90_LANE_F16;  // FCMLA Vd.8H,Vn.8H,Vm.H[lane],#90
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCMLAQ_ROT90_LANE_F32;  // FCMLA Vd.4S,Vn.4S,Vm.S[lane],#90
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCMLAQ_ROT90_LANEQ_F16;  // FCMLA Vd.8H,Vn.8H,Vm.H[lane],#90
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCMLAQ_ROT90_LANEQ_F32;  // FCMLA Vd.4S,Vn.4S,Vm.S[lane],#90
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCMLA_ROT180_F16;  // FCMLA Vd.4H,Vn.4H,Vm.4H,#180
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCMLA_ROT180_F32;  // FCMLA Vd.2S,Vn.2S,Vm.2S,#180
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCMLAQ_ROT180_F16;  // FCMLA Vd.8H,Vn.8H,Vm.8H,#180
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCMLAQ_ROT180_F32;  // FCMLA Vd.4S,Vn.4S,Vm.4S,#180
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCMLAQ_ROT180_F64;  // FCMLA Vd.2D,Vn.2D,Vm.2D,#180
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCMLA_ROT270_F16;  // FCMLA Vd.4H,Vn.4H,Vm.4H,#270
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCMLA_ROT270_F32;  // FCMLA Vd.2S,Vn.2S,Vm.2S,#270
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCMLAQ_ROT270_F16;  // FCMLA Vd.8H,Vn.8H,Vm.8H,#270
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCMLAQ_ROT270_F32;  // FCMLA Vd.4S,Vn.4S,Vm.4S,#270
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCMLAQ_ROT270_F64;  // FCMLA Vd.2D,Vn.2D,Vm.2D,#270
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCMLE_ASIMDMISCFP16_FZ:
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCLEZQ_F32;  // FCMLE Vd.4S,Vn.4S,#0
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCLEZQ_F64;  // FCMLE Vd.2D,Vn.2D,#0
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCLEZ_F16;  // FCMLE Vd.4H,Vn.4H,#0
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCLEZQ_F16;  // FCMLE Vd.8H,Vn.8H,#0
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCMLE_ASISDMISCFP16_FZ:
		intrin_id = ARM64_INTRIN_VCLEZ_F64;  // FCMLE Dd,Dn,#0
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCMLT_ASIMDMISCFP16_FZ:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCLTZ_F32;  // FCMLT Vd.2S,Vn.2S,#0
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCLTZQ_F32;  // FCMLT Vd.4S,Vn.4S,#0
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCLTZQ_F64;  // FCMLT Vd.2D,Vn.2D,#0
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCLTZ_F16;  // FCMLT Vd.4H,Vn.4H,#0
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCLTZQ_F16;  // FCMLT Vd.8H,Vn.8H,#0
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCMLT_ASISDMISCFP16_FZ:
		intrin_id = ARM64_INTRIN_VCLTZ_F64;  // FCMLT Dd,Dn,#0
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTAS_32D_FLOAT2INT:
		intrin_id = ARM64_INTRIN_VCVTA_S64_F64;  // FCVTAS Dd,Dn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTAS_32S_FLOAT2INT:
		intrin_id = ARM64_INTRIN_VCVTAS_S32_F32;  // FCVTAS Sd,Sn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTAS_ASIMDMISCFP16_R:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCVTA_S32_F32;  // FCVTAS Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCVTAQ_S32_F32;  // FCVTAS Vd.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCVTAQ_S64_F64;  // FCVTAS Vd.2D,Vn.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCVTA_S16_F16;  // FCVTAS Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCVTAQ_S16_F16;  // FCVTAS Vd.8H,Vn.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTAS_ASISDMISCFP16_R:
		intrin_id = ARM64_INTRIN_VCVTAH_S16_F16;  // FCVTAS Hd,Hn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTAU_32D_FLOAT2INT:
		intrin_id = ARM64_INTRIN_VCVTA_U64_F64;  // FCVTAU Dd,Dn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTAU_32S_FLOAT2INT:
		intrin_id = ARM64_INTRIN_VCVTAS_U32_F32;  // FCVTAU Sd,Sn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTAU_ASIMDMISCFP16_R:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCVTA_U32_F32;  // FCVTAU Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCVTAQ_U32_F32;  // FCVTAU Vd.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCVTAQ_U64_F64;  // FCVTAU Vd.2D,Vn.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCVTA_U16_F16;  // FCVTAU Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCVTAQ_U16_F16;  // FCVTAU Vd.8H,Vn.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTAU_ASISDMISCFP16_R:
		intrin_id = ARM64_INTRIN_VCVTAH_U16_F16;  // FCVTAU Hd,Hn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTL_ASIMDMISC_L:
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCVT_F32_F16;  // FCVTL Vd.4S,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCVT_HIGH_F32_F16;  // FCVTL2 Vd.4S,Vn.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCVT_F64_F32;  // FCVTL Vd.2D,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCVT_HIGH_F64_F32;  // FCVTL2 Vd.2D,Vn.4S
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTMS_32D_FLOAT2INT:
		intrin_id = ARM64_INTRIN_VCVTM_S64_F64;  // FCVTMS Dd,Dn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTMS_32S_FLOAT2INT:
		intrin_id = ARM64_INTRIN_VCVTMS_S32_F32;  // FCVTMS Sd,Sn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTMS_ASIMDMISCFP16_R:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCVTM_S32_F32;  // FCVTMS Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCVTMQ_S32_F32;  // FCVTMS Vd.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCVTMQ_S64_F64;  // FCVTMS Vd.2D,Vn.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCVTM_S16_F16;  // FCVTMS Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCVTMQ_S16_F16;  // FCVTMS Vd.8H,Vn.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTMS_ASISDMISCFP16_R:
		intrin_id = ARM64_INTRIN_VCVTMH_S16_F16;  // FCVTMS Hd,Hn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTMU_32D_FLOAT2INT:
		intrin_id = ARM64_INTRIN_VCVTM_U64_F64;  // FCVTMU Dd,Dn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTMU_32S_FLOAT2INT:
		intrin_id = ARM64_INTRIN_VCVTMS_U32_F32;  // FCVTMU Sd,Sn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTMU_ASIMDMISCFP16_R:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCVTM_U32_F32;  // FCVTMU Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCVTMQ_U32_F32;  // FCVTMU Vd.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCVTMQ_U64_F64;  // FCVTMU Vd.2D,Vn.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCVTM_U16_F16;  // FCVTMU Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCVTMQ_U16_F16;  // FCVTMU Vd.8H,Vn.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTMU_ASISDMISCFP16_R:
		intrin_id = ARM64_INTRIN_VCVTMH_U16_F16;  // FCVTMU Hd,Hn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTNS_32D_FLOAT2INT:
		intrin_id = ARM64_INTRIN_VCVTN_S64_F64;  // FCVTNS Dd,Dn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTNS_32S_FLOAT2INT:
		intrin_id = ARM64_INTRIN_VCVTNS_S32_F32;  // FCVTNS Sd,Sn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTNS_ASIMDMISCFP16_R:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCVTN_S32_F32;  // FCVTNS Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCVTNQ_S32_F32;  // FCVTNS Vd.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCVTNQ_S64_F64;  // FCVTNS Vd.2D,Vn.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCVTN_S16_F16;  // FCVTNS Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCVTNQ_S16_F16;  // FCVTNS Vd.8H,Vn.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTNS_ASISDMISCFP16_R:
		intrin_id = ARM64_INTRIN_VCVTNH_S16_F16;  // FCVTNS Hd,Hn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTNU_32D_FLOAT2INT:
		intrin_id = ARM64_INTRIN_VCVTN_U64_F64;  // FCVTNU Dd,Dn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTNU_32S_FLOAT2INT:
		intrin_id = ARM64_INTRIN_VCVTNS_U32_F32;  // FCVTNU Sd,Sn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTNU_ASIMDMISCFP16_R:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCVTN_U32_F32;  // FCVTNU Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCVTNQ_U32_F32;  // FCVTNU Vd.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCVTNQ_U64_F64;  // FCVTNU Vd.2D,Vn.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCVTN_U16_F16;  // FCVTNU Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCVTNQ_U16_F16;  // FCVTNU Vd.8H,Vn.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTNU_ASISDMISCFP16_R:
		intrin_id = ARM64_INTRIN_VCVTNH_U16_F16;  // FCVTNU Hd,Hn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTN_ASIMDMISC_N:
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCVT_F16_F32;  // FCVTN Vd.4H,Vn.4S
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCVT_HIGH_F16_F32;  // FCVTN2 Vd.8H,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCVT_F32_F64;  // FCVTN Vd.2S,Vn.2D
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCVT_HIGH_F32_F64;  // FCVTN2 Vd.4S,Vn.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTPS_32D_FLOAT2INT:
		intrin_id = ARM64_INTRIN_VCVTP_S64_F64;  // FCVTPS Dd,Dn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTPS_32S_FLOAT2INT:
		intrin_id = ARM64_INTRIN_VCVTPS_S32_F32;  // FCVTPS Sd,Sn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTPS_ASIMDMISCFP16_R:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCVTP_S32_F32;  // FCVTPS Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCVTPQ_S32_F32;  // FCVTPS Vd.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCVTPQ_S64_F64;  // FCVTPS Vd.2D,Vn.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCVTP_S16_F16;  // FCVTPS Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCVTPQ_S16_F16;  // FCVTPS Vd.8H,Vn.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTPS_ASISDMISCFP16_R:
		intrin_id = ARM64_INTRIN_VCVTPH_S16_F16;  // FCVTPS Hd,Hn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTPU_32D_FLOAT2INT:
		intrin_id = ARM64_INTRIN_VCVTP_U64_F64;  // FCVTPU Dd,Dn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTPU_32S_FLOAT2INT:
		intrin_id = ARM64_INTRIN_VCVTPS_U32_F32;  // FCVTPU Sd,Sn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTPU_ASIMDMISCFP16_R:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCVTP_U32_F32;  // FCVTPU Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCVTPQ_U32_F32;  // FCVTPU Vd.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCVTPQ_U64_F64;  // FCVTPU Vd.2D,Vn.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCVTP_U16_F16;  // FCVTPU Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCVTPQ_U16_F16;  // FCVTPU Vd.8H,Vn.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTPU_ASISDMISCFP16_R:
		intrin_id = ARM64_INTRIN_VCVTPH_U16_F16;  // FCVTPU Hd,Hn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTXN_ASIMDMISC_N:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCVTX_F32_F64;  // FCVTXN Vd.2S,Vn.2D
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCVTX_HIGH_F32_F64;  // FCVTXN2 Vd.4S,Vn.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTXN_ASISDMISC_N:
		intrin_id = ARM64_INTRIN_VCVTXD_F32_F64;  // FCVTXN Sd,Dn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTZS_64D_FLOAT2INT:
		intrin_id = ARM64_INTRIN_VCVTD_S64_F64;  // FCVTZS Xd,Dn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTZS_32D_FLOAT2INT:
		intrin_id = ARM64_INTRIN_VCVT_S64_F64;  // FCVTZS Dd,Dn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTZS_32S_FLOAT2INT:
		intrin_id = ARM64_INTRIN_VCVTS_S32_F32;  // FCVTZS Sd,Sn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTZS_ASIMDMISCFP16_R:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCVT_S32_F32;  // FCVTZS Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCVTQ_S32_F32;  // FCVTZS Vd.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCVTQ_S64_F64;  // FCVTZS Vd.2D,Vn.2D
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCVT_N_S32_F32;  // FCVTZS Vd.2S,Vn.2S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCVTQ_N_S32_F32;  // FCVTZS Vd.4S,Vn.4S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCVTQ_N_S64_F64;  // FCVTZS Vd.2D,Vn.2D,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCVT_S16_F16;  // FCVTZS Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCVTQ_S16_F16;  // FCVTZS Vd.8H,Vn.8H
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCVT_U16_F16;  // FCVTZS Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCVTQ_U16_F16;  // FCVTZS Vd.8H,Vn.8H
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCVT_N_S16_F16;  // FCVTZS Vd.4H,Vn.4H,#n
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCVTQ_N_S16_F16;  // FCVTZS Vd.8H,Vn.8H,#n
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTZS_ASISDMISCFP16_R:
		intrin_id = ARM64_INTRIN_VCVTH_S16_F16;  // FCVTZS Hd,Hn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTZU_64D_FLOAT2INT:
		intrin_id = ARM64_INTRIN_VCVTD_U64_F64;  // FCVTZU Xd,Dn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTZU_32D_FLOAT2INT:
		intrin_id = ARM64_INTRIN_VCVT_U64_F64;  // FCVTZU Dd,Dn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTZU_32S_FLOAT2INT:
		intrin_id = ARM64_INTRIN_VCVTS_U32_F32;  // FCVTZU Sd,Sn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UCVTF_D32_FLOAT2FIX:
		intrin_id = ARM64_INTRIN_VCVTD_N_F64_U32; // UCVTF <Dd>, <Wn>, #<fbits>
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UCVTF_D64_FLOAT2FIX:
		intrin_id = ARM64_INTRIN_VCVTD_N_F64_U64; // UCVTF <Dd>, <Xn>, #<fbits>
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UCVTF_H32_FLOAT2FIX:
		intrin_id = ARM64_INTRIN_VCVTH_N_F16_U32; // UCVTF <Hd>, <Wn>, #<fbits>
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UCVTF_H64_FLOAT2FIX: // UCVTF <Hd>, <Xn>, #<fbits>
		intrin_id = ARM64_INTRIN_VCVTH_N_F16_U64;
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTZU_64D_FLOAT2FIX:
		intrin_id = ARM64_INTRIN_VCVTD_N_U64_F64;  // FCVTZU Xd, Dn, #n
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UCVTF_S32_FLOAT2FIX:
		intrin_id = ARM64_INTRIN_VCVTS_N_F32_U32;  // ucvtf <Sd>, <Wn>, #<fbits>
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UCVTF_S64_FLOAT2FIX:
		intrin_id = ARM64_INTRIN_VCVTS_N_F32_U64;  // ucvtf <Sd>, <Xn>, #<fbits>
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTZU_ASIMDMISC_R:
		// Lift instruction such as fcvtzu v23.4s, v22.4s and fcvtzu v9.2d, v18.2d
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCVT_U32_F32;  // FCVTZU Vd.2S,Vn.2S
		else if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCVTQ_U32_F32;  // FCVTZU Vd.4S,Vn.4S
		else if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCVTQ_U64_F64;  // FCVTZU Vd.2D,Vn.2D
		else
			break; // Should be unreachable.
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTZU_ASIMDSHF_C:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCVT_N_U32_F32;  // FCVTZU Vd.2S,Vn.2S,#n
		else if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCVTQ_N_U32_F32;  // FCVTZU Vd.4S,Vn.4S,#n
		else if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCVTQ_N_U64_F64;  // FCVTZU Vd.2D,Vn.2D,#n
		else if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCVT_N_U16_F16;  // FCVTZU Vd.4H,Vn.4H,#n
		else if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCVTQ_N_U16_F16;  // FCVTZU Vd.8H,Vn.8H,#n
		else
			break; // Should be unreachable
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTZU_ASIMDMISCFP16_R:
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCVT_U16_F16;  // FCVTZU Vd.4H,Vn.4H
		else if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCVTQ_U16_F16;  // FCVTZU Vd.8H,Vn.8H
		else
			break; // Should be unreachable
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCVTZU_ASISDMISCFP16_R:
		intrin_id = ARM64_INTRIN_VCVTH_U16_F16;  // FCVTZU Hd,Hn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FDIV_D_FLOATDP2:
		intrin_id = ARM64_INTRIN_VDIV_F64;  // FDIV Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FDIV_H_FLOATDP2:
		intrin_id = ARM64_INTRIN_VDIVH_F16;  // FDIV Hd,Hn,Hm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FDIV_ASIMDSAMEFP16_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VDIV_F32;  // FDIV Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VDIVQ_F32;  // FDIV Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VDIVQ_F64;  // FDIV Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VDIV_F16;  // FDIV Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VDIVQ_F16;  // FDIV Vd.8H,Vn.8H,Vm.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMADD_D_FLOATDP3:
		intrin_id = ARM64_INTRIN_VFMA_F64;  // FMADD Dd,Dn,Dm,Da
		add_input_reg(inputs, il, instr.operands[3]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMADD_H_FLOATDP3:
		intrin_id = ARM64_INTRIN_VFMAH_F16;  // FMADD Hd,Hn,Hm,Ha
		add_input_reg(inputs, il, instr.operands[3]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMAXNMP_ASIMDSAMEFP16_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VPMAXNM_F32;  // FMAXNMP Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VPMAXNMQ_F32;  // FMAXNMP Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VPMAXNMQ_F64;  // FMAXNMP Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VPMAXNM_F16;  // FMAXNMP Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VPMAXNMQ_F16;  // FMAXNMP Vd.8H,Vn.8H,Vm.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMAXNMP_ASISDPAIR_ONLY_H:
		intrin_id = ARM64_INTRIN_VPMAXNMS_F32;  // FMAXNMP Sd,Vn.2S
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMAXNMV_ASIMDALL_ONLY_H:
		intrin_id = ARM64_INTRIN_VMAXNMVQ_F32;  // FMAXNMV Sd,Vn.4S
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMAXNM_D_FLOATDP2:
		intrin_id = ARM64_INTRIN_VMAXNM_F64;  // FMAXNM Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMAXNM_H_FLOATDP2:
		intrin_id = ARM64_INTRIN_VMAXNMH_F16;  // FMAXNM Hd,Hn,Hm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMAXNM_ASIMDSAMEFP16_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMAXNM_F32;  // FMAXNM Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMAXNMQ_F32;  // FMAXNM Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMAXNMQ_F64;  // FMAXNM Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMAXNM_F16;  // FMAXNM Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMAXNMQ_F16;  // FMAXNM Vd.8H,Vn.8H,Vm.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMAXP_ASIMDSAMEFP16_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VPMAX_F32;  // FMAXP Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VPMAXQ_F32;  // FMAXP Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VPMAXQ_F64;  // FMAXP Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VPMAX_F16;  // FMAXP Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VPMAXQ_F16;  // FMAXP Vd.8H,Vn.8H,Vm.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMAXP_ASISDPAIR_ONLY_H:
		intrin_id = ARM64_INTRIN_VPMAXS_F32;  // FMAXP Sd,Vn.2S
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMAXV_ASIMDALL_ONLY_H:
		intrin_id = ARM64_INTRIN_VMAXVQ_F32;  // FMAXV Sd,Vn.4S
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMAX_D_FLOATDP2:
		intrin_id = ARM64_INTRIN_VMAX_F64;  // FMAX Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMAX_H_FLOATDP2:
		intrin_id = ARM64_INTRIN_VMAXH_F16;  // FMAX Hd,Hn,Hm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMAX_ASIMDSAMEFP16_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMAX_F32;  // FMAX Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMAXQ_F32;  // FMAX Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMAXQ_F64;  // FMAX Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMAX_F16;  // FMAX Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMAXQ_F16;  // FMAX Vd.8H,Vn.8H,Vm.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMINNMP_ASIMDSAMEFP16_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VPMINNM_F32;  // FMINNMP Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VPMINNMQ_F32;  // FMINNMP Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VPMINNMQ_F64;  // FMINNMP Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VPMINNM_F16;  // FMINNMP Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VPMINNMQ_F16;  // FMINNMP Vd.8H,Vn.8H,Vm.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMINNMP_ASISDPAIR_ONLY_H:
		intrin_id = ARM64_INTRIN_VPMINNMS_F32;  // FMINNMP Sd,Vn.2S
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMINNMV_ASIMDALL_ONLY_H:
		intrin_id = ARM64_INTRIN_VMINNMVQ_F32;  // FMINNMV Sd,Vn.4S
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMINNM_D_FLOATDP2:
		intrin_id = ARM64_INTRIN_VMINNM_F64;  // FMINNM Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMINNM_H_FLOATDP2:
		intrin_id = ARM64_INTRIN_VMINNMH_F16;  // FMINNM Hd,Hn,Hm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMINNM_ASIMDSAMEFP16_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMINNM_F32;  // FMINNM Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMINNMQ_F32;  // FMINNM Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMINNMQ_F64;  // FMINNM Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMINNM_F16;  // FMINNM Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMINNMQ_F16;  // FMINNM Vd.8H,Vn.8H,Vm.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMINP_ASIMDSAMEFP16_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VPMIN_F32;  // FMINP Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VPMINQ_F32;  // FMINP Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VPMINQ_F64;  // FMINP Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VPMIN_F16;  // FMINP Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VPMINQ_F16;  // FMINP Vd.8H,Vn.8H,Vm.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMINP_ASISDPAIR_ONLY_H:
		intrin_id = ARM64_INTRIN_VPMINS_F32;  // FMINP Sd,Vn.2S
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMINV_ASIMDALL_ONLY_H:
		intrin_id = ARM64_INTRIN_VMINVQ_F32;  // FMINV Sd,Vn.4S
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMIN_D_FLOATDP2:
		intrin_id = ARM64_INTRIN_VMIN_F64;  // FMIN Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMIN_H_FLOATDP2:
		intrin_id = ARM64_INTRIN_VMINH_F16;  // FMIN Hd,Hn,Hm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMIN_ASIMDSAMEFP16_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMIN_F32;  // FMIN Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMINQ_F32;  // FMIN Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMINQ_F64;  // FMIN Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMIN_F16;  // FMIN Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMINQ_F16;  // FMIN Vd.8H,Vn.8H,Vm.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMLAL2_ASIMDELEM_LH:
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VFMLAL_LANE_HIGH_F16;  // FMLAL2 Vd.2S,Vn.2H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VFMLALQ_LANE_HIGH_F16;  // FMLAL2 Vd.4S,Vn.4H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VFMLAL_LANEQ_HIGH_F16;  // FMLAL2 Vd.2S,Vn.2H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VFMLALQ_LANEQ_HIGH_F16;  // FMLAL2 Vd.4S,Vn.4H,Vm.H[lane]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMLAL2_ASIMDSAME_F:
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VFMLAL_HIGH_F16;  // FMLAL2 Vd.2S,Vn.2H,Vm.2H
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VFMLALQ_HIGH_F16;  // FMLAL2 Vd.4S,Vn.4H,Vm.4H
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMLAL_ASIMDELEM_LH:
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VFMLAL_LANE_LOW_F16;  // FMLAL Vd.2S,Vn.2H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VFMLAL_LANEQ_LOW_F16;  // FMLAL Vd.2S,Vn.2H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VFMLALQ_LANE_LOW_F16;  // FMLAL Vd.4S,Vn.4H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VFMLALQ_LANEQ_LOW_F16;  // FMLAL Vd.4S,Vn.4H,Vm.H[lane]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMLAL_ASIMDSAME_F:
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VFMLAL_LOW_F16;  // FMLAL Vd.2S,Vn.2H,Vm.2H
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VFMLALQ_LOW_F16;  // FMLAL Vd.4S,Vn.4H,Vm.4H
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMLA_ASIMDELEM_RH_H:
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VFMA_LANE_F32;  // FMLA Vd.2S,Vn.2S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VFMAQ_LANE_F32;  // FMLA Vd.4S,Vn.4S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VFMAQ_LANE_F64;  // FMLA Vd.2D,Vn.2D,Vm.D[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VFMA_LANEQ_F32;  // FMLA Vd.2S,Vn.2S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VFMAQ_LANEQ_F32;  // FMLA Vd.4S,Vn.4S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VFMAQ_LANEQ_F64;  // FMLA Vd.2D,Vn.2D,Vm.D[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VFMA_LANE_F16;  // FMLA Vd.4H,Vn.4H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VFMAQ_LANE_F16;  // FMLA Vd.8H,Vn.8H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VFMA_LANEQ_F16;  // FMLA Vd.4H,Vn.4H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VFMAQ_LANEQ_F16;  // FMLA Vd.8H,Vn.8H,Vm.H[lane]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMLA_ASIMDSAMEFP16_ONLY:
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VFMA_F32;  // FMLA Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VFMAQ_F32;  // FMLA Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VFMAQ_F64;  // FMLA Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VFMA_N_F32;  // FMLA Vd.2S,Vn.2S,Vm.S[0]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VFMAQ_N_F32;  // FMLA Vd.4S,Vn.4S,Vm.S[0]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VFMAQ_N_F64;  // FMLA Vd.2D,Vn.2D,Vm.D[0]
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VFMA_F16;  // FMLA Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VFMAQ_F16;  // FMLA Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VFMA_N_F16;  // FMLA Vd.4H,Vn.4H,Vm.H[0]
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VFMAQ_N_F16;  // FMLA Vd.8H,Vn.8H,Vm.H[0]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMLA_ASISDELEM_RH_H:
		intrin_id = ARM64_INTRIN_VFMA_LANE_F64;  // FMLA Dd,Dn,Vm.D[lane]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMLSL2_ASIMDELEM_LH:
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VFMLSL_LANE_HIGH_F16;  // FMLSL2 Vd.2S,Vn.2H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VFMLSLQ_LANE_HIGH_F16;  // FMLSL2 Vd.4S,Vn.4H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VFMLSL_LANEQ_HIGH_F16;  // FMLSL2 Vd.2S,Vn.2H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VFMLSLQ_LANEQ_HIGH_F16;  // FMLSL2 Vd.4S,Vn.4H,Vm.H[lane]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMLSL2_ASIMDSAME_F:
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VFMLSL_HIGH_F16;  // FMLSL2 Vd.2S,Vn.2H,Vm.2H
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VFMLSLQ_HIGH_F16;  // FMLSL2 Vd.4S,Vn.4H,Vm.4H
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMLSL_ASIMDELEM_LH:
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VFMLSL_LANE_LOW_F16;  // FMLSL Vd.2S,Vn.2H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VFMLSL_LANEQ_LOW_F16;  // FMLSL Vd.2S,Vn.2H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VFMLSLQ_LANE_LOW_F16;  // FMLSL Vd.4S,Vn.4H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VFMLSLQ_LANEQ_LOW_F16;  // FMLSL Vd.4S,Vn.4H,Vm.H[lane]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMLSL_ASIMDSAME_F:
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VFMLSL_LOW_F16;  // FMLSL Vd.2S,Vn.2H,Vm.2H
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VFMLSLQ_LOW_F16;  // FMLSL Vd.4S,Vn.4H,Vm.4H
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMLS_ASIMDELEM_RH_H:
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VFMS_LANE_F32;  // FMLS Vd.2S,Vn.2S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VFMSQ_LANE_F32;  // FMLS Vd.4S,Vn.4S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VFMSQ_LANE_F64;  // FMLS Vd.2D,Vn.2D,Vm.D[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VFMS_LANEQ_F32;  // FMLS Vd.2S,Vn.2S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VFMSQ_LANEQ_F32;  // FMLS Vd.4S,Vn.4S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VFMSQ_LANEQ_F64;  // FMLS Vd.2D,Vn.2D,Vm.D[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VFMS_LANE_F16;  // FMLS Vd.4H,Vn.4H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VFMSQ_LANE_F16;  // FMLS Vd.8H,Vn.8H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VFMS_LANEQ_F16;  // FMLS Vd.4H,Vn.4H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VFMSQ_LANEQ_F16;  // FMLS Vd.8H,Vn.8H,Vm.H[lane]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMLS_ASIMDSAMEFP16_ONLY:
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VFMS_F32;  // FMLS Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VFMSQ_F32;  // FMLS Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VFMSQ_F64;  // FMLS Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VFMS_N_F32;  // FMLS Vd.2S,Vn.2S,Vm.S[0]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VFMSQ_N_F32;  // FMLS Vd.4S,Vn.4S,Vm.S[0]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VFMSQ_N_F64;  // FMLS Vd.2D,Vn.2D,Vm.D[0]
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VFMS_F16;  // FMLS Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VFMSQ_F16;  // FMLS Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VFMS_N_F16;  // FMLS Vd.4H,Vn.4H,Vm.H[0]
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VFMSQ_N_F16;  // FMLS Vd.8H,Vn.8H,Vm.H[0]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMLS_ASISDELEM_RH_H:
		intrin_id = ARM64_INTRIN_VFMS_LANE_F64;  // FMLS Dd,Dn,Vm.D[lane]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMSUB_D_FLOATDP3:
		intrin_id = ARM64_INTRIN_VFMS_F64;  // FMSUB Dd,Dn,Dm,Da
		add_input_reg(inputs, il, instr.operands[3]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMSUB_H_FLOATDP3:
		intrin_id = ARM64_INTRIN_VFMSH_F16;  // FMSUB Hd,Hn,Hm,Ha
		add_input_reg(inputs, il, instr.operands[3]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMULX_ASIMDELEM_RH_H:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMULX_LANE_F32;  // FMULX Vd.2S,Vn.2S,Vm.S[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMULXQ_LANE_F32;  // FMULX Vd.4S,Vn.4S,Vm.S[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMULXQ_LANE_F64;  // FMULX Vd.2D,Vn.2D,Vm.D[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMULX_LANEQ_F32;  // FMULX Vd.2S,Vn.2S,Vm.S[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMULXQ_LANEQ_F32;  // FMULX Vd.4S,Vn.4S,Vm.S[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMULXQ_LANEQ_F64;  // FMULX Vd.2D,Vn.2D,Vm.D[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMULX_LANE_F16;  // FMULX Vd.4H,Vn.4H,Vm.H[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMULXQ_LANE_F16;  // FMULX Vd.8H,Vn.8H,Vm.H[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMULX_LANEQ_F16;  // FMULX Vd.4H,Vn.4H,Vm.H[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMULXQ_LANEQ_F16;  // FMULX Vd.8H,Vn.8H,Vm.H[lane]
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMULX_ASIMDSAMEFP16_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMULX_F32;  // FMULX Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMULXQ_F32;  // FMULX Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMULXQ_F64;  // FMULX Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMULX_F16;  // FMULX Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMULXQ_F16;  // FMULX Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMULX_N_F16;  // FMULX Vd.4H,Vn.4H,Vm.H[0]
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMULXQ_N_F16;  // FMULX Vd.8H,Vn.8H,Vm.H[0]
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMULX_ASISDELEM_RH_H:
		intrin_id = ARM64_INTRIN_VMULX_LANE_F64;  // FMULX Dd,Dn,Vm.D[lane]
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMULX_ASISDSAMEFP16_ONLY:
		intrin_id = ARM64_INTRIN_VMULX_F64;  // FMULX Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMUL_D_FLOATDP2:
		intrin_id = ARM64_INTRIN_VMUL_F64;  // FMUL Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMUL_H_FLOATDP2:
		intrin_id = ARM64_INTRIN_VMULH_F16;  // FMUL Hd,Hn,Hm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMUL_ASIMDELEM_RH_H:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMUL_LANE_F32;  // FMUL Vd.2S,Vn.2S,Vm.S[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMULQ_LANE_F32;  // FMUL Vd.4S,Vn.4S,Vm.S[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMULQ_LANE_F64;  // FMUL Vd.2D,Vn.2D,Vm.D[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMUL_LANEQ_F32;  // FMUL Vd.2S,Vn.2S,Vm.S[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMULQ_LANEQ_F32;  // FMUL Vd.4S,Vn.4S,Vm.S[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMULQ_LANEQ_F64;  // FMUL Vd.2D,Vn.2D,Vm.D[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMUL_LANE_F16;  // FMUL Vd.4H,Vn.4H,Vm.H[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMULQ_LANE_F16;  // FMUL Vd.8H,Vn.8H,Vm.H[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMUL_LANEQ_F16;  // FMUL Vd.4H,Vn.4H,Vm.H[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMULQ_LANEQ_F16;  // FMUL Vd.8H,Vn.8H,Vm.H[lane]
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMUL_ASIMDSAMEFP16_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMUL_F32;  // FMUL Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMULQ_F32;  // FMUL Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMULQ_F64;  // FMUL Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMUL_N_F32;  // FMUL Vd.2S,Vn.2S,Vm.S[0]
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMULQ_N_F32;  // FMUL Vd.4S,Vn.4S,Vm.S[0]
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMULQ_N_F64;  // FMUL Vd.2D,Vn.2D,Vm.D[0]
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMUL_F16;  // FMUL Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMULQ_F16;  // FMUL Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMUL_N_F16;  // FMUL Vd.4H,Vn.4H,Vm.H[0]
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMULQ_N_F16;  // FMUL Vd.8H,Vn.8H,Vm.H[0]
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FMUL_ASISDELEM_RH_H:
		intrin_id = ARM64_INTRIN_VMUL_LANE_F64;  // FMUL Dd,Dn,Vm.D[lane]
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FNEG_D_FLOATDP1:
		intrin_id = ARM64_INTRIN_VNEG_F64;  // FNEG Dd,Dn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FNEG_H_FLOATDP1:
		intrin_id = ARM64_INTRIN_VNEGH_F16;  // FNEG Hd,Hn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FNEG_ASIMDMISCFP16_R:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VNEG_F32;  // FNEG Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VNEGQ_F32;  // FNEG Vd.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VNEGQ_F64;  // FNEG Vd.2D,Vn.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VNEG_F16;  // FNEG Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VNEGQ_F16;  // FNEG Vd.8H,Vn.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRECPE_ASIMDMISCFP16_R:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VRECPE_F32;  // FRECPE Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VRECPEQ_F32;  // FRECPE Vd.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VRECPEQ_F64;  // FRECPE Vd.2D,Vn.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VRECPE_F16;  // FRECPE Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VRECPEQ_F16;  // FRECPE Vd.8H,Vn.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRECPE_ASISDMISCFP16_R:
		intrin_id = ARM64_INTRIN_VRECPE_F64;  // FRECPE Dd,Dn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRECPS_ASIMDSAMEFP16_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VRECPS_F32;  // FRECPS Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VRECPSQ_F32;  // FRECPS Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VRECPSQ_F64;  // FRECPS Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VRECPS_F16;  // FRECPS Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VRECPSQ_F16;  // FRECPS Vd.8H,Vn.8H,Vm.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRECPS_ASISDSAMEFP16_ONLY:
		intrin_id = ARM64_INTRIN_VRECPS_F64;  // FRECPS Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRECPX_ASISDMISCFP16_R:
		intrin_id = ARM64_INTRIN_VRECPXS_F32;  // FRECPX Sd,Sn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRINT32X_D_FLOATDP1:
		intrin_id = ARM64_INTRIN_VRND32X_F64;  // FRINT32X Dd,Dn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRINT32X_ASIMDMISC_R:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VRND32X_F32;  // FRINT32X Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VRND32XQ_F32;  // FRINT32X Vd.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VRND32XQ_F64;  // FRINT32X Vd.2D,Vn.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRINT32Z_D_FLOATDP1:
		intrin_id = ARM64_INTRIN_VRND32Z_F64;  // FRINT32Z Dd,Dn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRINT32Z_ASIMDMISC_R:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VRND32Z_F32;  // FRINT32Z Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VRND32ZQ_F32;  // FRINT32Z Vd.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VRND32ZQ_F64;  // FRINT32Z Vd.2D,Vn.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRINT64X_D_FLOATDP1:
		intrin_id = ARM64_INTRIN_VRND64X_F64;  // FRINT64X Dd,Dn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRINT64X_ASIMDMISC_R:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VRND64X_F32;  // FRINT64X Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VRND64XQ_F32;  // FRINT64X Vd.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VRND64XQ_F64;  // FRINT64X Vd.2D,Vn.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRINT64Z_D_FLOATDP1:
		intrin_id = ARM64_INTRIN_VRND64Z_F64;  // FRINT64Z Dd,Dn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRINT64Z_ASIMDMISC_R:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VRND64Z_F32;  // FRINT64Z Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VRND64ZQ_F32;  // FRINT64Z Vd.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VRND64ZQ_F64;  // FRINT64Z Vd.2D,Vn.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRINTA_D_FLOATDP1:
		intrin_id = ARM64_INTRIN_VRNDA_F64;  // FRINTA Dd,Dn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRINTA_H_FLOATDP1:
		intrin_id = ARM64_INTRIN_VRNDAH_F16;  // FRINTA Hd,Hn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRINTA_ASIMDMISCFP16_R:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VRNDA_F32;  // FRINTA Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VRNDAQ_F32;  // FRINTA Vd.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VRNDAQ_F64;  // FRINTA Vd.2D,Vn.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VRNDA_F16;  // FRINTA Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VRNDAQ_F16;  // FRINTA Vd.8H,Vn.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRINTI_D_FLOATDP1:
		intrin_id = ARM64_INTRIN_VRNDI_F64;  // FRINTI Dd,Dn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRINTI_H_FLOATDP1:
		intrin_id = ARM64_INTRIN_VRNDIH_F16;  // FRINTI Hd,Hn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRINTI_ASIMDMISCFP16_R:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VRNDI_F32;  // FRINTI Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VRNDIQ_F32;  // FRINTI Vd.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VRNDIQ_F64;  // FRINTI Vd.2D,Vn.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VRNDI_F16;  // FRINTI Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VRNDIQ_F16;  // FRINTI Vd.8H,Vn.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRINTM_D_FLOATDP1:
		intrin_id = ARM64_INTRIN_VRNDM_F64;  // FRINTM Dd,Dn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRINTM_H_FLOATDP1:
		intrin_id = ARM64_INTRIN_VRNDMH_F16;  // FRINTM Hd,Hn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRINTM_ASIMDMISCFP16_R:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VRNDM_F32;  // FRINTM Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VRNDMQ_F32;  // FRINTM Vd.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VRNDMQ_F64;  // FRINTM Vd.2D,Vn.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VRNDM_F16;  // FRINTM Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VRNDMQ_F16;  // FRINTM Vd.8H,Vn.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRINTN_D_FLOATDP1:
		intrin_id = ARM64_INTRIN_VRNDN_F64;  // FRINTN Dd,Dn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRINTN_H_FLOATDP1:
		intrin_id = ARM64_INTRIN_VRNDNH_F16;  // FRINTN Hd,Hn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRINTN_S_FLOATDP1:
		intrin_id = ARM64_INTRIN_VRNDNS_F32;  // FRINTN Sd,Sn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRINTN_ASIMDMISCFP16_R:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VRNDN_F32;  // FRINTN Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VRNDNQ_F32;  // FRINTN Vd.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VRNDNQ_F64;  // FRINTN Vd.2D,Vn.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VRNDN_F16;  // FRINTN Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VRNDNQ_F16;  // FRINTN Vd.8H,Vn.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRINTP_D_FLOATDP1:
		intrin_id = ARM64_INTRIN_VRNDP_F64;  // FRINTP Dd,Dn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRINTP_H_FLOATDP1:
		intrin_id = ARM64_INTRIN_VRNDPH_F16;  // FRINTP Hd,Hn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRINTP_ASIMDMISCFP16_R:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VRNDP_F32;  // FRINTP Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VRNDPQ_F32;  // FRINTP Vd.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VRNDPQ_F64;  // FRINTP Vd.2D,Vn.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VRNDP_F16;  // FRINTP Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VRNDPQ_F16;  // FRINTP Vd.8H,Vn.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRINTX_D_FLOATDP1:
		intrin_id = ARM64_INTRIN_VRNDX_F64;  // FRINTX Dd,Dn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRINTX_H_FLOATDP1:
		intrin_id = ARM64_INTRIN_VRNDXH_F16;  // FRINTX Hd,Hn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRINTX_ASIMDMISCFP16_R:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VRNDX_F32;  // FRINTX Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VRNDXQ_F32;  // FRINTX Vd.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VRNDXQ_F64;  // FRINTX Vd.2D,Vn.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VRNDX_F16;  // FRINTX Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VRNDXQ_F16;  // FRINTX Vd.8H,Vn.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRINTZ_D_FLOATDP1:
		intrin_id = ARM64_INTRIN_VRND_F64;  // FRINTZ Dd,Dn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRINTZ_H_FLOATDP1:
		intrin_id = ARM64_INTRIN_VRNDH_F16;  // FRINTZ Hd,Hn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRINTZ_ASIMDMISCFP16_R:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VRND_F32;  // FRINTZ Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VRNDQ_F32;  // FRINTZ Vd.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VRNDQ_F64;  // FRINTZ Vd.2D,Vn.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VRND_F16;  // FRINTZ Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VRNDQ_F16;  // FRINTZ Vd.8H,Vn.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRSQRTE_ASIMDMISCFP16_R:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VRSQRTE_F32;  // FRSQRTE Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VRSQRTEQ_F32;  // FRSQRTE Vd.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VRSQRTEQ_F64;  // FRSQRTE Vd.2D,Vn.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VRSQRTE_F16;  // FRSQRTE Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VRSQRTEQ_F16;  // FRSQRTE Vd.8H,Vn.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRSQRTE_ASISDMISCFP16_R:
		intrin_id = ARM64_INTRIN_VRSQRTE_F64;  // FRSQRTE Dd,Dn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRSQRTS_ASIMDSAMEFP16_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VRSQRTS_F32;  // FRSQRTS Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VRSQRTSQ_F32;  // FRSQRTS Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VRSQRTSQ_F64;  // FRSQRTS Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VRSQRTS_F16;  // FRSQRTS Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VRSQRTSQ_F16;  // FRSQRTS Vd.8H,Vn.8H,Vm.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FRSQRTS_ASISDSAMEFP16_ONLY:
		intrin_id = ARM64_INTRIN_VRSQRTS_F64;  // FRSQRTS Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FSQRT_D_FLOATDP1:
		intrin_id = ARM64_INTRIN_VSQRT_F64;  // FSQRT Dd,Dn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FSQRT_H_FLOATDP1:
		intrin_id = ARM64_INTRIN_VSQRTH_F16;  // FSQRT Hd,Hn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FSQRT_ASIMDMISCFP16_R:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VSQRT_F32;  // FSQRT Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSQRTQ_F32;  // FSQRT Vd.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VSQRTQ_F64;  // FSQRT Vd.2D,Vn.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VSQRT_F16;  // FSQRT Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSQRTQ_F16;  // FSQRT Vd.8H,Vn.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FSUB_D_FLOATDP2:
		intrin_id = ARM64_INTRIN_VSUB_F64;  // FSUB Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FSUB_H_FLOATDP2:
		intrin_id = ARM64_INTRIN_VSUBH_F16;  // FSUB Hd,Hn,Hm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FSUB_ASIMDSAMEFP16_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VSUB_F32;  // FSUB Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSUBQ_F32;  // FSUB Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VSUBQ_F64;  // FSUB Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VSUB_F16;  // FSUB Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSUBQ_F16;  // FSUB Vd.8H,Vn.8H,Vm.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_INS_ASIMDINS_IR_R:
		if (instr.operands[1].arrSpec == ARRSPEC_1DOUBLE)
			intrin_id = ARM64_INTRIN_VCREATE_S8;  // INS Vd.D[0],Xn
		if (instr.operands[1].arrSpec == ARRSPEC_1DOUBLE)
			intrin_id = ARM64_INTRIN_VCREATE_S16;  // INS Vd.D[0],Xn
		if (instr.operands[1].arrSpec == ARRSPEC_1DOUBLE)
			intrin_id = ARM64_INTRIN_VCREATE_S32;  // INS Vd.D[0],Xn
		if (instr.operands[1].arrSpec == ARRSPEC_1DOUBLE)
			intrin_id = ARM64_INTRIN_VCREATE_S64;  // INS Vd.D[0],Xn
		if (instr.operands[1].arrSpec == ARRSPEC_1DOUBLE)
			intrin_id = ARM64_INTRIN_VCREATE_U8;  // INS Vd.D[0],Xn
		if (instr.operands[1].arrSpec == ARRSPEC_1DOUBLE)
			intrin_id = ARM64_INTRIN_VCREATE_U16;  // INS Vd.D[0],Xn
		if (instr.operands[1].arrSpec == ARRSPEC_1DOUBLE)
			intrin_id = ARM64_INTRIN_VCREATE_U32;  // INS Vd.D[0],Xn
		if (instr.operands[1].arrSpec == ARRSPEC_1DOUBLE)
			intrin_id = ARM64_INTRIN_VCREATE_U64;  // INS Vd.D[0],Xn
		if (instr.operands[1].arrSpec == ARRSPEC_1DOUBLE)
			intrin_id = ARM64_INTRIN_VCREATE_P64;  // INS Vd.D[0],Xn
		if (instr.operands[1].arrSpec == ARRSPEC_1DOUBLE)
			intrin_id = ARM64_INTRIN_VCREATE_F16;  // INS Vd.D[0],Xn
		if (instr.operands[1].arrSpec == ARRSPEC_1DOUBLE)
			intrin_id = ARM64_INTRIN_VCREATE_F32;  // INS Vd.D[0],Xn
		if (instr.operands[1].arrSpec == ARRSPEC_1DOUBLE)
			intrin_id = ARM64_INTRIN_VCREATE_P8;  // INS Vd.D[0],Xn
		if (instr.operands[1].arrSpec == ARRSPEC_1DOUBLE)
			intrin_id = ARM64_INTRIN_VCREATE_P16;  // INS Vd.D[0],Xn
		if (instr.operands[1].arrSpec == ARRSPEC_1DOUBLE)
			intrin_id = ARM64_INTRIN_VCREATE_F64;  // INS Vd.D[0],Xn
		if (instr.operands[1].arrSpec == ARRSPEC_1DOUBLE)
			intrin_id = ARM64_INTRIN_VDUP_N_S64;  // INS Vd.D[0],rn
		if (instr.operands[1].arrSpec == ARRSPEC_1DOUBLE)
			intrin_id = ARM64_INTRIN_VDUP_N_U64;  // INS Vd.D[0],rn
		if (instr.operands[1].arrSpec == ARRSPEC_1DOUBLE)
			intrin_id = ARM64_INTRIN_VDUP_N_P64;  // INS Vd.D[0],rn
		if (instr.operands[1].arrSpec == ARRSPEC_1DOUBLE)
			intrin_id = ARM64_INTRIN_VDUP_N_F64;  // INS Vd.D[0],rn
		if (instr.operands[1].arrSpec == ARRSPEC_1DOUBLE)
			intrin_id = ARM64_INTRIN_VCREATE_BF16;  // INS Vd.D[0],Xn
		if (instr.operands[1].arrSpec == ARRSPEC_1HALF)
			intrin_id = ARM64_INTRIN_VSET_LANE_BF16;  // INS Vd.H[lane],Vn.H[0]
		if (instr.operands[1].arrSpec == ARRSPEC_1HALF)
			intrin_id = ARM64_INTRIN_VSETQ_LANE_BF16;  // INS Vd.H[lane],Vn.H[0]
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_LDR_Q_LOADLIT:
		intrin_id = ARM64_INTRIN_VLDRQ_P128;  // LDR Qd,[Xn]
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_LD2_ASISDLSE_R2:
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VLD2Q_S8;
		else if (instr.operands[0].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VLD2_S8;
		else if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VLD2_S16;
		else if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VLD2Q_S16;
		else if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VLD2_S32;
		else if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VLD2Q_S32;
		else if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VLD2Q_S64;
		else
			break; // Should be unreachable.
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_MLA_ASIMDELEM_R:
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMLA_LANE_S16;  // MLA Vd.4H,Vn.4H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMLAQ_LANE_S16;  // MLA Vd.8H,Vn.8H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMLA_LANE_S32;  // MLA Vd.2S,Vn.2S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLAQ_LANE_S32;  // MLA Vd.4S,Vn.4S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMLA_LANE_U16;  // MLA Vd.4H,Vn.4H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMLAQ_LANE_U16;  // MLA Vd.8H,Vn.8H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMLA_LANE_U32;  // MLA Vd.2S,Vn.2S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLAQ_LANE_U32;  // MLA Vd.4S,Vn.4S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMLA_LANEQ_S16;  // MLA Vd.4H,Vn.4H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMLAQ_LANEQ_S16;  // MLA Vd.8H,Vn.8H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMLA_LANEQ_S32;  // MLA Vd.2S,Vn.2S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLAQ_LANEQ_S32;  // MLA Vd.4S,Vn.4S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMLA_LANEQ_U16;  // MLA Vd.4H,Vn.4H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMLAQ_LANEQ_U16;  // MLA Vd.8H,Vn.8H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMLA_LANEQ_U32;  // MLA Vd.2S,Vn.2S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLAQ_LANEQ_U32;  // MLA Vd.4S,Vn.4S,Vm.S[lane]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_MLA_ASIMDSAME_ONLY:
		if (instr.operands[0].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VMLA_S8;  // MLA Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VMLAQ_S8;  // MLA Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMLA_S16;  // MLA Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMLAQ_S16;  // MLA Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMLA_S32;  // MLA Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLAQ_S32;  // MLA Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[0].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VMLA_U8;  // MLA Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VMLAQ_U8;  // MLA Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMLA_U16;  // MLA Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMLAQ_U16;  // MLA Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMLA_U32;  // MLA Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLAQ_U32;  // MLA Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMLA_N_S16;  // MLA Vd.4H,Vn.4H,Vm.H[0]
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMLAQ_N_S16;  // MLA Vd.8H,Vn.8H,Vm.H[0]
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMLA_N_S32;  // MLA Vd.2S,Vn.2S,Vm.S[0]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLAQ_N_S32;  // MLA Vd.4S,Vn.4S,Vm.S[0]
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMLA_N_U16;  // MLA Vd.4H,Vn.4H,Vm.H[0]
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMLAQ_N_U16;  // MLA Vd.8H,Vn.8H,Vm.H[0]
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMLA_N_U32;  // MLA Vd.2S,Vn.2S,Vm.S[0]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLAQ_N_U32;  // MLA Vd.4S,Vn.4S,Vm.S[0]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_MLS_ASIMDELEM_R:
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMLS_LANE_S16;  // MLS Vd.4H,Vn.4H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMLSQ_LANE_S16;  // MLS Vd.8H,Vn.8H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMLS_LANE_S32;  // MLS Vd.2S,Vn.2S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLSQ_LANE_S32;  // MLS Vd.4S,Vn.4S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMLS_LANE_U16;  // MLS Vd.4H,Vn.4H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMLSQ_LANE_U16;  // MLS Vd.8H,Vn.8H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMLS_LANE_U32;  // MLS Vd.2S,Vn.2S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLSQ_LANE_U32;  // MLS Vd.4S,Vn.4S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMLS_LANEQ_S16;  // MLS Vd.4H,Vn.4H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMLSQ_LANEQ_S16;  // MLS Vd.8H,Vn.8H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMLS_LANEQ_S32;  // MLS Vd.2S,Vn.2S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLSQ_LANEQ_S32;  // MLS Vd.4S,Vn.4S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMLS_LANEQ_U16;  // MLS Vd.4H,Vn.4H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMLSQ_LANEQ_U16;  // MLS Vd.8H,Vn.8H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMLS_LANEQ_U32;  // MLS Vd.2S,Vn.2S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLSQ_LANEQ_U32;  // MLS Vd.4S,Vn.4S,Vm.S[lane]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_MLS_ASIMDSAME_ONLY:
		if (instr.operands[0].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VMLS_S8;  // MLS Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VMLSQ_S8;  // MLS Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMLS_S16;  // MLS Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMLSQ_S16;  // MLS Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMLS_S32;  // MLS Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLSQ_S32;  // MLS Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[0].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VMLS_U8;  // MLS Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VMLSQ_U8;  // MLS Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMLS_U16;  // MLS Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMLSQ_U16;  // MLS Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMLS_U32;  // MLS Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLSQ_U32;  // MLS Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMLS_N_S16;  // MLS Vd.4H,Vn.4H,Vm.H[0]
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMLSQ_N_S16;  // MLS Vd.8H,Vn.8H,Vm.H[0]
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMLS_N_S32;  // MLS Vd.2S,Vn.2S,Vm.S[0]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLSQ_N_S32;  // MLS Vd.4S,Vn.4S,Vm.S[0]
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMLS_N_U16;  // MLS Vd.4H,Vn.4H,Vm.H[0]
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMLSQ_N_U16;  // MLS Vd.8H,Vn.8H,Vm.H[0]
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMLS_N_U32;  // MLS Vd.2S,Vn.2S,Vm.S[0]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLSQ_N_U32;  // MLS Vd.4S,Vn.4S,Vm.S[0]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_MOV_INS_ASIMDINS_IR_R:
		if (instr.operands[1].arrSpec == ARRSPEC_1BYTE)
			intrin_id = ARM64_INTRIN_VSET_LANE_U8;  // MOV Vd.B[lane],Rn
		if (instr.operands[1].arrSpec == ARRSPEC_1HALF)
			intrin_id = ARM64_INTRIN_VSET_LANE_U16;  // MOV Vd.H[lane],Rn
		if (instr.operands[1].arrSpec == ARRSPEC_1SINGLE)
			intrin_id = ARM64_INTRIN_VSET_LANE_U32;  // MOV Vd.S[lane],Rn
		if (instr.operands[1].arrSpec == ARRSPEC_1DOUBLE)
			intrin_id = ARM64_INTRIN_VSET_LANE_U64;  // MOV Vd.D[lane],Rn
		if (instr.operands[1].arrSpec == ARRSPEC_1DOUBLE)
			intrin_id = ARM64_INTRIN_VSET_LANE_P64;  // MOV Vd.D[lane],Rn
		if (instr.operands[1].arrSpec == ARRSPEC_1BYTE)
			intrin_id = ARM64_INTRIN_VSET_LANE_S8;  // MOV Vd.B[lane],Rn
		if (instr.operands[1].arrSpec == ARRSPEC_1HALF)
			intrin_id = ARM64_INTRIN_VSET_LANE_S16;  // MOV Vd.H[lane],Rn
		if (instr.operands[1].arrSpec == ARRSPEC_1SINGLE)
			intrin_id = ARM64_INTRIN_VSET_LANE_S32;  // MOV Vd.S[lane],Rn
		if (instr.operands[1].arrSpec == ARRSPEC_1DOUBLE)
			intrin_id = ARM64_INTRIN_VSET_LANE_S64;  // MOV Vd.D[lane],Rn
		if (instr.operands[1].arrSpec == ARRSPEC_1BYTE)
			intrin_id = ARM64_INTRIN_VSET_LANE_P8;  // MOV Vd.B[lane],Rn
		if (instr.operands[1].arrSpec == ARRSPEC_1HALF)
			intrin_id = ARM64_INTRIN_VSET_LANE_P16;  // MOV Vd.H[lane],Rn
		if (instr.operands[1].arrSpec == ARRSPEC_1SINGLE)
			intrin_id = ARM64_INTRIN_VSET_LANE_F32;  // MOV Vd.S[lane],Rn
		if (instr.operands[1].arrSpec == ARRSPEC_1DOUBLE)
			intrin_id = ARM64_INTRIN_VSET_LANE_F64;  // MOV Vd.D[lane],Rn
		if (instr.operands[1].arrSpec == ARRSPEC_1BYTE)
			intrin_id = ARM64_INTRIN_VSETQ_LANE_U8;  // MOV Vd.B[lane],Rn
		if (instr.operands[1].arrSpec == ARRSPEC_1HALF)
			intrin_id = ARM64_INTRIN_VSETQ_LANE_U16;  // MOV Vd.H[lane],Rn
		if (instr.operands[1].arrSpec == ARRSPEC_1SINGLE)
			intrin_id = ARM64_INTRIN_VSETQ_LANE_U32;  // MOV Vd.S[lane],Rn
		if (instr.operands[1].arrSpec == ARRSPEC_1DOUBLE)
			intrin_id = ARM64_INTRIN_VSETQ_LANE_U64;  // MOV Vd.D[lane],Rn
		if (instr.operands[1].arrSpec == ARRSPEC_1DOUBLE)
			intrin_id = ARM64_INTRIN_VSETQ_LANE_P64;  // MOV Vd.D[lane],Rn
		if (instr.operands[1].arrSpec == ARRSPEC_1BYTE)
			intrin_id = ARM64_INTRIN_VSETQ_LANE_S8;  // MOV Vd.B[lane],Rn
		if (instr.operands[1].arrSpec == ARRSPEC_1HALF)
			intrin_id = ARM64_INTRIN_VSETQ_LANE_S16;  // MOV Vd.H[lane],Rn
		if (instr.operands[1].arrSpec == ARRSPEC_1SINGLE)
			intrin_id = ARM64_INTRIN_VSETQ_LANE_S32;  // MOV Vd.S[lane],Rn
		if (instr.operands[1].arrSpec == ARRSPEC_1DOUBLE)
			intrin_id = ARM64_INTRIN_VSETQ_LANE_S64;  // MOV Vd.D[lane],Rn
		if (instr.operands[1].arrSpec == ARRSPEC_1BYTE)
			intrin_id = ARM64_INTRIN_VSETQ_LANE_P8;  // MOV Vd.B[lane],Rn
		if (instr.operands[1].arrSpec == ARRSPEC_1HALF)
			intrin_id = ARM64_INTRIN_VSETQ_LANE_P16;  // MOV Vd.H[lane],Rn
		if (instr.operands[1].arrSpec == ARRSPEC_1SINGLE)
			intrin_id = ARM64_INTRIN_VSETQ_LANE_F32;  // MOV Vd.S[lane],Rn
		if (instr.operands[1].arrSpec == ARRSPEC_1DOUBLE)
			intrin_id = ARM64_INTRIN_VSETQ_LANE_F64;  // MOV Vd.D[lane],Rn
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_lane(inputs, il, instr.operands[0]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_MOV_ORR_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_1HALF)
			intrin_id = ARM64_INTRIN_VSET_LANE_F16;  // MOV Vd.H[lane],Vn.H[0]
		if (instr.operands[1].arrSpec == ARRSPEC_1HALF)
			intrin_id = ARM64_INTRIN_VSETQ_LANE_F16;  // MOV Vd.H[lane],Vn.H[0]
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_lane(inputs, il, instr.operands[0]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_MUL_ASIMDELEM_R:
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMUL_LANE_S16;  // MUL Vd.4H,Vn.4H,Vm.H[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMULQ_LANE_S16;  // MUL Vd.8H,Vn.8H,Vm.H[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMUL_LANE_S32;  // MUL Vd.2S,Vn.2S,Vm.S[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMULQ_LANE_S32;  // MUL Vd.4S,Vn.4S,Vm.S[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMUL_LANE_U16;  // MUL Vd.4H,Vn.4H,Vm.H[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMULQ_LANE_U16;  // MUL Vd.8H,Vn.8H,Vm.H[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMUL_LANE_U32;  // MUL Vd.2S,Vn.2S,Vm.S[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMULQ_LANE_U32;  // MUL Vd.4S,Vn.4S,Vm.S[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMUL_LANEQ_S16;  // MUL Vd.4H,Vn.4H,Vm.H[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMULQ_LANEQ_S16;  // MUL Vd.8H,Vn.8H,Vm.H[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMUL_LANEQ_S32;  // MUL Vd.2S,Vn.2S,Vm.S[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMULQ_LANEQ_S32;  // MUL Vd.4S,Vn.4S,Vm.S[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMUL_LANEQ_U16;  // MUL Vd.4H,Vn.4H,Vm.H[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMULQ_LANEQ_U16;  // MUL Vd.8H,Vn.8H,Vm.H[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMUL_LANEQ_U32;  // MUL Vd.2S,Vn.2S,Vm.S[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMULQ_LANEQ_U32;  // MUL Vd.4S,Vn.4S,Vm.S[lane]
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_MUL_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VMUL_S8;  // MUL Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VMULQ_S8;  // MUL Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMUL_S16;  // MUL Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMULQ_S16;  // MUL Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMUL_S32;  // MUL Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMULQ_S32;  // MUL Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VMUL_U8;  // MUL Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VMULQ_U8;  // MUL Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMUL_U16;  // MUL Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMULQ_U16;  // MUL Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMUL_U32;  // MUL Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMULQ_U32;  // MUL Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMUL_N_S16;  // MUL Vd.4H,Vn.4H,Vm.H[0]
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMULQ_N_S16;  // MUL Vd.8H,Vn.8H,Vm.H[0]
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMUL_N_S32;  // MUL Vd.2S,Vn.2S,Vm.S[0]
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMULQ_N_S32;  // MUL Vd.4S,Vn.4S,Vm.S[0]
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMUL_N_U16;  // MUL Vd.4H,Vn.4H,Vm.H[0]
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMULQ_N_U16;  // MUL Vd.8H,Vn.8H,Vm.H[0]
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMUL_N_U32;  // MUL Vd.2S,Vn.2S,Vm.S[0]
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMULQ_N_U32;  // MUL Vd.4S,Vn.4S,Vm.S[0]
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_MVN_NOT_ASIMDMISC_R:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VMVN_S8;  // MVN Vd.8B,Vn.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VMVNQ_S8;  // MVN Vd.16B,Vn.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VMVN_S16;  // MVN Vd.8B,Vn.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VMVNQ_S16;  // MVN Vd.16B,Vn.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VMVN_S32;  // MVN Vd.8B,Vn.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VMVNQ_S32;  // MVN Vd.16B,Vn.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VMVN_U8;  // MVN Vd.8B,Vn.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VMVNQ_U8;  // MVN Vd.16B,Vn.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VMVN_U16;  // MVN Vd.8B,Vn.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VMVNQ_U16;  // MVN Vd.16B,Vn.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VMVN_U32;  // MVN Vd.8B,Vn.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VMVNQ_U32;  // MVN Vd.16B,Vn.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VMVN_P8;  // MVN Vd.8B,Vn.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VMVNQ_P8;  // MVN Vd.16B,Vn.16B
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_NEG_ASIMDMISC_R:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VNEG_S8;  // NEG Vd.8B,Vn.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VNEGQ_S8;  // NEG Vd.16B,Vn.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VNEG_S16;  // NEG Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VNEGQ_S16;  // NEG Vd.8H,Vn.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VNEG_S32;  // NEG Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VNEGQ_S32;  // NEG Vd.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VNEGQ_S64;  // NEG Vd.2D,Vn.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_NEG_ASISDMISC_R:
		intrin_id = ARM64_INTRIN_VNEG_S64;  // NEG Dd,Dn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_ORN_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VORN_S8;  // ORN Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VORNQ_S8;  // ORN Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VORN_S16;  // ORN Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VORNQ_S16;  // ORN Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VORN_S32;  // ORN Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VORNQ_S32;  // ORN Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VORN_S64;  // ORN Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VORNQ_S64;  // ORN Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VORN_U8;  // ORN Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VORNQ_U8;  // ORN Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VORN_U16;  // ORN Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VORNQ_U16;  // ORN Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VORN_U32;  // ORN Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VORNQ_U32;  // ORN Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VORN_U64;  // ORN Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VORNQ_U64;  // ORN Vd.16B,Vn.16B,Vm.16B
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_ORR_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VORR_S8;  // ORR Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VORRQ_S8;  // ORR Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VORR_S16;  // ORR Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VORRQ_S16;  // ORR Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VORR_S32;  // ORR Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VORRQ_S32;  // ORR Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VORR_S64;  // ORR Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VORRQ_S64;  // ORR Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VORR_U8;  // ORR Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VORRQ_U8;  // ORR Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VORR_U16;  // ORR Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VORRQ_U16;  // ORR Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VORR_U32;  // ORR Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VORRQ_U32;  // ORR Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VORR_U64;  // ORR Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VORRQ_U64;  // ORR Vd.16B,Vn.16B,Vm.16B
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_PMULL_ASIMDDIFF_L:
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES && instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VMULL_P8;  // PMULL Vd.8H,Vn.8B,Vm.8B
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES && instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VMULL_HIGH_P8;  // PMULL2 Vd.8H,Vn.16B,Vm.16B
		if (instr.operands[0].arrSpec == ARRSPEC_FULL && instr.operands[1].arrSpec == ARRSPEC_1DOUBLE)
			intrin_id = ARM64_INTRIN_VMULL_P64;  // PMULL Vd.1Q,Vn.1D,Vm.1D
		if (instr.operands[0].arrSpec == ARRSPEC_FULL && instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMULL_HIGH_P64;  // PMULL2 Vd.1Q,Vn.2D,Vm.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_PMUL_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VMUL_P8;  // PMUL Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VMULQ_P8;  // PMUL Vd.16B,Vn.16B,Vm.16B
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_RADDHN_ASIMDDIFF_N:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VRADDHN_S16;  // RADDHN Vd.8B,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VRADDHN_S32;  // RADDHN Vd.4H,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VRADDHN_S64;  // RADDHN Vd.2S,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VRADDHN_U16;  // RADDHN Vd.8B,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VRADDHN_U32;  // RADDHN Vd.4H,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VRADDHN_U64;  // RADDHN Vd.2S,Vn.2D,Vm.2D
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VRADDHN_HIGH_S16;  // RADDHN2 Vd.16B,Vn.8H,Vm.8H
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VRADDHN_HIGH_S32;  // RADDHN2 Vd.8H,Vn.4S,Vm.4S
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VRADDHN_HIGH_S64;  // RADDHN2 Vd.4S,Vn.2D,Vm.2D
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VRADDHN_HIGH_U16;  // RADDHN2 Vd.16B,Vn.8H,Vm.8H
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VRADDHN_HIGH_U32;  // RADDHN2 Vd.8H,Vn.4S,Vm.4S
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VRADDHN_HIGH_U64;  // RADDHN2 Vd.4S,Vn.2D,Vm.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_RAX1_VVV2_CRYPTOSHA512_3:
		intrin_id = ARM64_INTRIN_VRAX1Q_U64;  // RAX1 Vd.2D,Vn.2D,Vm.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_RBIT_ASIMDMISC_R:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VRBIT_S8;  // RBIT Vd.8B,Vn.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VRBITQ_S8;  // RBIT Vd.16B,Vn.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VRBIT_U8;  // RBIT Vd.8B,Vn.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VRBITQ_U8;  // RBIT Vd.16B,Vn.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VRBIT_P8;  // RBIT Vd.8B,Vn.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VRBITQ_P8;  // RBIT Vd.16B,Vn.16B
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_REV16_ASIMDMISC_R:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VREV16_S8;  // REV16 Vd.8B,Vn.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VREV16Q_S8;  // REV16 Vd.16B,Vn.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VREV16_U8;  // REV16 Vd.8B,Vn.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VREV16Q_U8;  // REV16 Vd.16B,Vn.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VREV16_P8;  // REV16 Vd.8B,Vn.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VREV16Q_P8;  // REV16 Vd.16B,Vn.16B
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_REV32_ASIMDMISC_R:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VREV32_S8;  // REV32 Vd.8B,Vn.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VREV32Q_S8;  // REV32 Vd.16B,Vn.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VREV32_S16;  // REV32 Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VREV32Q_S16;  // REV32 Vd.8H,Vn.8H
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VREV32_U8;  // REV32 Vd.8B,Vn.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VREV32Q_U8;  // REV32 Vd.16B,Vn.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VREV32_U16;  // REV32 Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VREV32Q_U16;  // REV32 Vd.8H,Vn.8H
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VREV32_P8;  // REV32 Vd.8B,Vn.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VREV32Q_P8;  // REV32 Vd.16B,Vn.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VREV32_P16;  // REV32 Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VREV32Q_P16;  // REV32 Vd.8H,Vn.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_REV64_ASIMDMISC_R:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VREV64_S8;  // REV64 Vd.8B,Vn.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VREV64Q_S8;  // REV64 Vd.16B,Vn.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VREV64_S16;  // REV64 Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VREV64Q_S16;  // REV64 Vd.8H,Vn.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VREV64_S32;  // REV64 Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VREV64Q_S32;  // REV64 Vd.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VREV64_U8;  // REV64 Vd.8B,Vn.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VREV64Q_U8;  // REV64 Vd.16B,Vn.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VREV64_U16;  // REV64 Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VREV64Q_U16;  // REV64 Vd.8H,Vn.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VREV64_U32;  // REV64 Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VREV64Q_U32;  // REV64 Vd.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VREV64_F32;  // REV64 Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VREV64Q_F32;  // REV64 Vd.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VREV64_P8;  // REV64 Vd.8B,Vn.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VREV64Q_P8;  // REV64 Vd.16B,Vn.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VREV64_P16;  // REV64 Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VREV64Q_P16;  // REV64 Vd.8H,Vn.8H
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VREV64_F16;  // REV64 Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VREV64Q_F16;  // REV64 Vd.8H,Vn.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_RSHRN_ASIMDSHF_N:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VRSHRN_N_S16;  // RSHRN Vd.8B,Vn.8H,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VRSHRN_N_S32;  // RSHRN Vd.4H,Vn.4S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VRSHRN_N_S64;  // RSHRN Vd.2S,Vn.2D,#n
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VRSHRN_N_U16;  // RSHRN Vd.8B,Vn.8H,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VRSHRN_N_U32;  // RSHRN Vd.4H,Vn.4S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VRSHRN_N_U64;  // RSHRN Vd.2S,Vn.2D,#n
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VRSHRN_HIGH_N_S16;  // RSHRN2 Vd.16B,Vn.8H,#n
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VRSHRN_HIGH_N_S32;  // RSHRN2 Vd.8H,Vn.4S,#n
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VRSHRN_HIGH_N_S64;  // RSHRN2 Vd.4S,Vn.2D,#n
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VRSHRN_HIGH_N_U16;  // RSHRN2 Vd.16B,Vn.8H,#n
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VRSHRN_HIGH_N_U32;  // RSHRN2 Vd.8H,Vn.4S,#n
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VRSHRN_HIGH_N_U64;  // RSHRN2 Vd.4S,Vn.2D,#n
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_RSUBHN_ASIMDDIFF_N:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VRSUBHN_S16;  // RSUBHN Vd.8B,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VRSUBHN_S32;  // RSUBHN Vd.4H,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VRSUBHN_S64;  // RSUBHN Vd.2S,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VRSUBHN_U16;  // RSUBHN Vd.8B,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VRSUBHN_U32;  // RSUBHN Vd.4H,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VRSUBHN_U64;  // RSUBHN Vd.2S,Vn.2D,Vm.2D
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VRSUBHN_HIGH_S16;  // RSUBHN2 Vd.16B,Vn.8H,Vm.8H
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VRSUBHN_HIGH_S32;  // RSUBHN2 Vd.8H,Vn.4S,Vm.4S
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VRSUBHN_HIGH_S64;  // RSUBHN2 Vd.4S,Vn.2D,Vm.2D
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VRSUBHN_HIGH_U16;  // RSUBHN2 Vd.16B,Vn.8H,Vm.8H
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VRSUBHN_HIGH_U32;  // RSUBHN2 Vd.8H,Vn.4S,Vm.4S
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VRSUBHN_HIGH_U64;  // RSUBHN2 Vd.4S,Vn.2D,Vm.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SABAL_ASIMDDIFF_L:
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VABAL_S8;  // SABAL Vd.8H,Vn.8B,Vm.8B
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VABAL_S16;  // SABAL Vd.4S,Vn.4H,Vm.4H
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VABAL_S32;  // SABAL Vd.2D,Vn.2S,Vm.2S
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VABAL_HIGH_S8;  // SABAL2 Vd.8H,Vn.16B,Vm.16B
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VABAL_HIGH_S16;  // SABAL2 Vd.4S,Vn.8H,Vm.8H
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VABAL_HIGH_S32;  // SABAL2 Vd.2D,Vn.4S,Vm.4S
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SABA_ASIMDSAME_ONLY:
		if (instr.operands[0].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VABA_S8;  // SABA Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VABAQ_S8;  // SABA Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VABA_S16;  // SABA Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VABAQ_S16;  // SABA Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VABA_S32;  // SABA Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VABAQ_S32;  // SABA Vd.4S,Vn.4S,Vm.4S
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SABDL_ASIMDDIFF_L:
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VABDL_S8;  // SABDL Vd.8H,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VABDL_S16;  // SABDL Vd.4S,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VABDL_S32;  // SABDL Vd.2D,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VABDL_HIGH_S8;  // SABDL2 Vd.8H,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VABDL_HIGH_S16;  // SABDL2 Vd.4S,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VABDL_HIGH_S32;  // SABDL2 Vd.2D,Vn.4S,Vm.4S
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SABD_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VABD_S8;  // SABD Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VABDQ_S8;  // SABD Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VABD_S16;  // SABD Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VABDQ_S16;  // SABD Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VABD_S32;  // SABD Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VABDQ_S32;  // SABD Vd.4S,Vn.4S,Vm.4S
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SADALP_ASIMDMISC_P:
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VPADAL_S8;  // SADALP Vd.4H,Vn.8B
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VPADALQ_S8;  // SADALP Vd.8H,Vn.16B
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VPADAL_S16;  // SADALP Vd.2S,Vn.4H
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VPADALQ_S16;  // SADALP Vd.4S,Vn.8H
		if (instr.operands[0].arrSpec == ARRSPEC_1DOUBLE)
			intrin_id = ARM64_INTRIN_VPADAL_S32;  // SADALP Vd.1D,Vn.2S
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VPADALQ_S32;  // SADALP Vd.2D,Vn.4S
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SADDLP_ASIMDMISC_P:
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VPADDL_S8;  // SADDLP Vd.4H,Vn.8B
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VPADDLQ_S8;  // SADDLP Vd.8H,Vn.16B
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VPADDL_S16;  // SADDLP Vd.2S,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VPADDLQ_S16;  // SADDLP Vd.4S,Vn.8H
		if (instr.operands[1].arrSpec == ARRSPEC_1DOUBLE)
			intrin_id = ARM64_INTRIN_VPADDL_S32;  // SADDLP Vd.1D,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VPADDLQ_S32;  // SADDLP Vd.2D,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_1DOUBLE)
			intrin_id = ARM64_INTRIN_VADDLV_S32;  // SADDLP Vd.1D,Vn.2S
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SADDLV_ASIMDALL_ONLY:
		intrin_id = ARM64_INTRIN_VADDLV_S8;  // SADDLV Hd,Vn.8B
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SADDL_ASIMDDIFF_L:
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VADDL_S8;  // SADDL Vd.8H,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VADDL_S16;  // SADDL Vd.4S,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VADDL_S32;  // SADDL Vd.2D,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VADDL_HIGH_S8;  // SADDL2 Vd.8H,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VADDL_HIGH_S16;  // SADDL2 Vd.4S,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VADDL_HIGH_S32;  // SADDL2 Vd.2D,Vn.4S,Vm.4S
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SADDW_ASIMDDIFF_W:
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VADDW_S8;  // SADDW Vd.8H,Vn.8H,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VADDW_S16;  // SADDW Vd.4S,Vn.4S,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VADDW_S32;  // SADDW Vd.2D,Vn.2D,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VADDW_HIGH_S8;  // SADDW2 Vd.8H,Vn.8H,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VADDW_HIGH_S16;  // SADDW2 Vd.4S,Vn.4S,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VADDW_HIGH_S32;  // SADDW2 Vd.2D,Vn.2D,Vm.4S
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SCVTF_D64_FLOAT2INT:
		// Lift instruction such as `scvtf d3, x15` to vcvtd_f64_s64(int64_t)
		intrin_id = ARM64_INTRIN_VCVTD_F64_S64;  // SCVTF Dd,Dn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SCVTF_D32_FLOAT2INT:
		intrin_id = ARM64_INTRIN_VCVT_F64_S64;  // SCVTF Dd,Dn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SCVTF_S32_FLOAT2INT:
		intrin_id = ARM64_INTRIN_VCVTS_F32_S32;  // SCVTF Sd,Sn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SCVTF_ASIMDMISCFP16_R:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCVT_F32_S32;  // SCVTF Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCVTQ_F32_S32;  // SCVTF Vd.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCVTQ_F64_S64;  // SCVTF Vd.2D,Vn.2D
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCVT_N_F32_S32;  // SCVTF Vd.2S,Vn.2S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCVTQ_N_F32_S32;  // SCVTF Vd.4S,Vn.4S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCVTQ_N_F64_S64;  // SCVTF Vd.2D,Vn.2D,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCVT_F16_S16;  // SCVTF Vd.4H,Vn.4H,#0
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCVTQ_F16_S16;  // SCVTF Vd.8H,Vn.8H,#0
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCVT_N_F16_S16;  // SCVTF Vd.4H,Vn.4H,#n
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCVTQ_N_F16_S16;  // SCVTF Vd.8H,Vn.8H,#n
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SCVTF_ASISDMISCFP16_R:
		intrin_id = ARM64_INTRIN_VCVTH_F16_S16;  // SCVTF Hd,Hn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SDOT_ASIMDELEM_D:
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VDOT_LANE_S32;  // SDOT Vd.2S,Vn.8B,Vm.4B[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VDOTQ_LANEQ_S32;  // SDOT Vd.4S,Vn.16B,Vm.4B[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VDOT_LANEQ_S32;  // SDOT Vd.2S,Vn.8B,Vm.4B[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VDOTQ_LANE_S32;  // SDOT Vd.4S,Vn.16B,Vm.4B[lane]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SDOT_ASIMDSAME2_D:
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VDOT_S32;  // SDOT Vd.2S,Vn.8B,Vm.8B
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VDOTQ_S32;  // SDOT Vd.4S,Vn.16B,Vm.16B
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SHA1C_QSV_CRYPTOSHA3:
		intrin_id = ARM64_INTRIN_VSHA1CQ_U32;  // SHA1C Qd,Sn,Vm.4S
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SHA1H_SS_CRYPTOSHA2:
		intrin_id = ARM64_INTRIN_VSHA1H_U32;  // SHA1H Sd,Sn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SHA1M_QSV_CRYPTOSHA3:
		intrin_id = ARM64_INTRIN_VSHA1MQ_U32;  // SHA1M Qd,Sn,Vm.4S
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SHA1P_QSV_CRYPTOSHA3:
		intrin_id = ARM64_INTRIN_VSHA1PQ_U32;  // SHA1P Qd,Sn,Vm.4S
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SHA1SU0_VVV_CRYPTOSHA3:
		intrin_id = ARM64_INTRIN_VSHA1SU0Q_U32;  // SHA1SU0 Vd.4S,Vn.4S,Vm.4S
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SHA1SU1_VV_CRYPTOSHA2:
		intrin_id = ARM64_INTRIN_VSHA1SU1Q_U32;  // SHA1SU1 Vd.4S,Vn.4S
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SHA256H2_QQV_CRYPTOSHA3:
		intrin_id = ARM64_INTRIN_VSHA256H2Q_U32;  // SHA256H2 Qd,Qn,Vm.4S
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SHA256H_QQV_CRYPTOSHA3:
		intrin_id = ARM64_INTRIN_VSHA256HQ_U32;  // SHA256H Qd,Qn,Vm.4S
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SHA256SU0_VV_CRYPTOSHA2:
		intrin_id = ARM64_INTRIN_VSHA256SU0Q_U32;  // SHA256SU0 Vd.4S,Vn.4S
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SHA256SU1_VVV_CRYPTOSHA3:
		intrin_id = ARM64_INTRIN_VSHA256SU1Q_U32;  // SHA256SU1 Vd.4S,Vn.4S,Vm.4S
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SHA512H2_QQV_CRYPTOSHA512_3:
		intrin_id = ARM64_INTRIN_VSHA512H2Q_U64;  // SHA512H2 Qd,Qn,Vm.2D
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SHA512H_QQV_CRYPTOSHA512_3:
		intrin_id = ARM64_INTRIN_VSHA512HQ_U64;  // SHA512H Qd,Qn,Vm.2D
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SHA512SU0_VV2_CRYPTOSHA512_2:
		intrin_id = ARM64_INTRIN_VSHA512SU0Q_U64;  // SHA512SU0 Vd.2D,Vn.2D
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SHA512SU1_VVV2_CRYPTOSHA512_3:
		intrin_id = ARM64_INTRIN_VSHA512SU1Q_U64;  // SHA512SU1 Vd.2D,Vn.2D,Vm.2D
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SHADD_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VHADD_S8;  // SHADD Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VHADDQ_S8;  // SHADD Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VHADD_S16;  // SHADD Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VHADDQ_S16;  // SHADD Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VHADD_S32;  // SHADD Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VHADDQ_S32;  // SHADD Vd.4S,Vn.4S,Vm.4S
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SHLL_ASIMDMISC_S:
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSHLL_N_S8;  // SHLL Vd.8H,Vn.8B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSHLL_N_S16;  // SHLL Vd.4S,Vn.4H,#n
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VSHLL_N_S32;  // SHLL Vd.2D,Vn.2S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSHLL_N_U8;  // SHLL Vd.8H,Vn.8B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSHLL_N_U16;  // SHLL Vd.4S,Vn.4H,#n
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VSHLL_N_U32;  // SHLL Vd.2D,Vn.2S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSHLL_HIGH_N_S8;  // SHLL2 Vd.8H,Vn.16B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSHLL_HIGH_N_S16;  // SHLL2 Vd.4S,Vn.8H,#n
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VSHLL_HIGH_N_S32;  // SHLL2 Vd.2D,Vn.4S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSHLL_HIGH_N_U8;  // SHLL2 Vd.8H,Vn.16B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSHLL_HIGH_N_U16;  // SHLL2 Vd.4S,Vn.8H,#n
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VSHLL_HIGH_N_U32;  // SHLL2 Vd.2D,Vn.4S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCVT_F32_BF16;  // SHLL Vd.4S,Vn.8H,#16
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCVTQ_LOW_F32_BF16;  // SHLL Vd.4S,Vn.8H,#16
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCVTQ_HIGH_F32_BF16;  // SHLL2 Vd.4S,Vn.8H,#16
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SHL_ASIMDSHF_R:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VSHL_N_S8;  // SHL Vd.8B,Vn.8B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VSHL_N_S16;  // SHL Vd.4H,Vn.4H,#n
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSHLQ_N_S16;  // SHL Vd.8H,Vn.8H,#n
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VSHL_N_S32;  // SHL Vd.2S,Vn.2S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSHLQ_N_S32;  // SHL Vd.4S,Vn.4S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VSHLQ_N_S64;  // SHL Vd.2D,Vn.2D,#n
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VSHL_N_U8;  // SHL Vd.8B,Vn.8B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VSHL_N_U16;  // SHL Vd.4H,Vn.4H,#n
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSHLQ_N_U16;  // SHL Vd.8H,Vn.8H,#n
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VSHL_N_U32;  // SHL Vd.2S,Vn.2S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSHLQ_N_U32;  // SHL Vd.4S,Vn.4S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VSHLQ_N_U64;  // SHL Vd.2D,Vn.2D,#n
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SHL_ASISDSHF_R:
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VSHLQ_N_S8;  // SHL Vd.16B,Vn.16B,#n
		// if(None) intrin_id = ARM64_INTRIN_VSHL_N_S64; // SHL Dd,Dn,#n
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VSHLQ_N_U8;  // SHL Vd.16B,Vn.16B,#n
		// if(None) intrin_id = ARM64_INTRIN_VSHL_N_U64; // SHL Dd,Dn,#n
		// if(None) intrin_id = ARM64_INTRIN_VSHLD_N_S64; // SHL Dd,Dn,#n
		// if(None) intrin_id = ARM64_INTRIN_VSHLD_N_U64; // SHL Dd,Dn,#n
		// if(None) intrin_id = ARM64_INTRIN_VCVTAH_F32_BF16; // SHL Dd,Dn,#16
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SHRN_ASIMDSHF_N:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VSHRN_N_S16;  // SHRN Vd.8B,Vn.8H,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VSHRN_N_S32;  // SHRN Vd.4H,Vn.4S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VSHRN_N_S64;  // SHRN Vd.2S,Vn.2D,#n
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VSHRN_N_U16;  // SHRN Vd.8B,Vn.8H,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VSHRN_N_U32;  // SHRN Vd.4H,Vn.4S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VSHRN_N_U64;  // SHRN Vd.2S,Vn.2D,#n
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VSHRN_HIGH_N_S16;  // SHRN2 Vd.16B,Vn.8H,#n
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSHRN_HIGH_N_S32;  // SHRN2 Vd.8H,Vn.4S,#n
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSHRN_HIGH_N_S64;  // SHRN2 Vd.4S,Vn.2D,#n
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VSHRN_HIGH_N_U16;  // SHRN2 Vd.16B,Vn.8H,#n
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSHRN_HIGH_N_U32;  // SHRN2 Vd.8H,Vn.4S,#n
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSHRN_HIGH_N_U64;  // SHRN2 Vd.4S,Vn.2D,#n
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SHSUB_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VHSUB_S8;  // SHSUB Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VHSUBQ_S8;  // SHSUB Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VHSUB_S16;  // SHSUB Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VHSUBQ_S16;  // SHSUB Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VHSUB_S32;  // SHSUB Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VHSUBQ_S32;  // SHSUB Vd.4S,Vn.4S,Vm.4S
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SLI_ASIMDSHF_R:
		if (instr.operands[0].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VSLI_N_S8;  // SLI Vd.8B,Vn.8B,#n
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VSLI_N_S16;  // SLI Vd.4H,Vn.4H,#n
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSLIQ_N_S16;  // SLI Vd.8H,Vn.8H,#n
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VSLI_N_S32;  // SLI Vd.2S,Vn.2S,#n
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSLIQ_N_S32;  // SLI Vd.4S,Vn.4S,#n
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VSLIQ_N_S64;  // SLI Vd.2D,Vn.2D,#n
		if (instr.operands[0].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VSLI_N_U8;  // SLI Vd.8B,Vn.8B,#n
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VSLI_N_U16;  // SLI Vd.4H,Vn.4H,#n
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSLIQ_N_U16;  // SLI Vd.8H,Vn.8H,#n
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VSLI_N_U32;  // SLI Vd.2S,Vn.2S,#n
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSLIQ_N_U32;  // SLI Vd.4S,Vn.4S,#n
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VSLIQ_N_U64;  // SLI Vd.2D,Vn.2D,#n
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VSLIQ_N_P64;  // SLI Vd.2D,Vn.2D,#n
		if (instr.operands[0].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VSLI_N_P8;  // SLI Vd.8B,Vn.8B,#n
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VSLI_N_P16;  // SLI Vd.4H,Vn.4H,#n
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSLIQ_N_P16;  // SLI Vd.8H,Vn.8H,#n
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SLI_ASISDSHF_R:
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VSLIQ_N_S8;  // SLI Vd.16B,Vn.16B,#n
		// if(None) intrin_id = ARM64_INTRIN_VSLI_N_S64; // SLI Dd,Dn,#n
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VSLIQ_N_U8;  // SLI Vd.16B,Vn.16B,#n
		// if(None) intrin_id = ARM64_INTRIN_VSLI_N_U64; // SLI Dd,Dn,#n
		// if(None) intrin_id = ARM64_INTRIN_VSLI_N_P64; // SLI Dd,Dn,#n
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VSLIQ_N_P8;  // SLI Vd.16B,Vn.16B,#n
		// if(None) intrin_id = ARM64_INTRIN_VSLID_N_S64; // SLI Dd,Dn,#n
		// if(None) intrin_id = ARM64_INTRIN_VSLID_N_U64; // SLI Dd,Dn,#n
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SM3PARTW1_VVV4_CRYPTOSHA512_3:
		intrin_id = ARM64_INTRIN_VSM3PARTW1Q_U32;  // SM3PARTW1 Vd.4S,Vn.4S,Vm.4S
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SM3PARTW2_VVV4_CRYPTOSHA512_3:
		intrin_id = ARM64_INTRIN_VSM3PARTW2Q_U32;  // SM3PARTW2 Vd.4S,Vn.4S,Vm.4S
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SM3SS1_VVV4_CRYPTO4:
		intrin_id = ARM64_INTRIN_VSM3SS1Q_U32;  // SM3SS1 Vd.4S,Vn.4S,Vm.4S,Va.4S
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_reg(inputs, il, instr.operands[3]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SM3TT1A_VVV4_CRYPTO3_IMM2:
		intrin_id = ARM64_INTRIN_VSM3TT1AQ_U32;  // SM3TT1A Vd.4S,Vn.4S,Vm.4S[imm2]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SM3TT1B_VVV4_CRYPTO3_IMM2:
		intrin_id = ARM64_INTRIN_VSM3TT1BQ_U32;  // SM3TT1B Vd.4S,Vn.4S,Vm.4S[imm2]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SM3TT2A_VVV4_CRYPTO3_IMM2:
		intrin_id = ARM64_INTRIN_VSM3TT2AQ_U32;  // SM3TT2A Vd.4S,Vn.4S,Vm.4S[imm2]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SM3TT2B_VVV_CRYPTO3_IMM2:
		intrin_id = ARM64_INTRIN_VSM3TT2BQ_U32;  // SM3TT2B Vd.4S,Vn.4S,Vm.4S[imm2]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SM4EKEY_VVV4_CRYPTOSHA512_3:
		intrin_id = ARM64_INTRIN_VSM4EKEYQ_U32;  // SM4EKEY Vd.4S,Vn.4S,Vm.4S
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SM4E_VV4_CRYPTOSHA512_2:
		intrin_id = ARM64_INTRIN_VSM4EQ_U32;  // SM4E Vd.4S,Vn.4S
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SMAXP_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VPMAX_S8;  // SMAXP Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VPMAX_S16;  // SMAXP Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VPMAX_S32;  // SMAXP Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VPMAXQ_S8;  // SMAXP Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VPMAXQ_S16;  // SMAXP Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VPMAXQ_S32;  // SMAXP Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[2].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMAXV_S32;  // SMAXP Vd.2S,Vn.2S,Vm.2S
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SMAXV_ASIMDALL_ONLY:
		intrin_id = ARM64_INTRIN_VMAXV_S8;  // SMAXV Bd,Vn.8B
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SMAX_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VMAX_S8;  // SMAX Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VMAXQ_S8;  // SMAX Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMAX_S16;  // SMAX Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMAXQ_S16;  // SMAX Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMAX_S32;  // SMAX Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMAXQ_S32;  // SMAX Vd.4S,Vn.4S,Vm.4S
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SMINP_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VPMIN_S8;  // SMINP Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VPMIN_S16;  // SMINP Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VPMIN_S32;  // SMINP Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VPMINQ_S8;  // SMINP Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VPMINQ_S16;  // SMINP Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VPMINQ_S32;  // SMINP Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[2].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMINV_S32;  // SMINP Vd.2S,Vn.2S,Vm.2S
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SMINV_ASIMDALL_ONLY:
		intrin_id = ARM64_INTRIN_VMINV_S8;  // SMINV Bd,Vn.8B
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SMIN_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VMIN_S8;  // SMIN Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VMINQ_S8;  // SMIN Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMIN_S16;  // SMIN Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMINQ_S16;  // SMIN Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMIN_S32;  // SMIN Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMINQ_S32;  // SMIN Vd.4S,Vn.4S,Vm.4S
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SMLAL_ASIMDDIFF_L:
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMLAL_S8;  // SMLAL Vd.8H,Vn.8B,Vm.8B
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLAL_S16;  // SMLAL Vd.4S,Vn.4H,Vm.4H
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMLAL_S32;  // SMLAL Vd.2D,Vn.2S,Vm.2S
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMLAL_HIGH_S8;  // SMLAL2 Vd.8H,Vn.16B,Vm.16B
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLAL_HIGH_S16;  // SMLAL2 Vd.4S,Vn.8H,Vm.8H
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMLAL_HIGH_S32;  // SMLAL2 Vd.2D,Vn.4S,Vm.4S
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLAL_N_S16;  // SMLAL Vd.4S,Vn.4H,Vm.H[0]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMLAL_N_S32;  // SMLAL Vd.2D,Vn.2S,Vm.S[0]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLAL_HIGH_N_S16;  // SMLAL2 Vd.4S,Vn.8H,Vm.H[0]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMLAL_HIGH_N_S32;  // SMLAL2 Vd.2D,Vn.4S,Vm.S[0]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SMLAL_ASIMDELEM_L:
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLAL_LANE_S16;  // SMLAL Vd.4S,Vn.4H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMLAL_LANE_S32;  // SMLAL Vd.2D,Vn.2S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLAL_HIGH_LANE_S16;  // SMLAL2 Vd.4S,Vn.8H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMLAL_HIGH_LANE_S32;  // SMLAL2 Vd.2D,Vn.4S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLAL_LANEQ_S16;  // SMLAL Vd.4S,Vn.4H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMLAL_LANEQ_S32;  // SMLAL Vd.2D,Vn.2S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLAL_HIGH_LANEQ_S16;  // SMLAL2 Vd.4S,Vn.8H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMLAL_HIGH_LANEQ_S32;  // SMLAL2 Vd.2D,Vn.4S,Vm.S[lane]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SMLSL_ASIMDDIFF_L:
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMLSL_S8;  // SMLSL Vd.8H,Vn.8B,Vm.8B
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLSL_S16;  // SMLSL Vd.4S,Vn.4H,Vm.4H
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMLSL_S32;  // SMLSL Vd.2D,Vn.2S,Vm.2S
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMLSL_HIGH_S8;  // SMLSL2 Vd.8H,Vn.16B,Vm.16B
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLSL_HIGH_S16;  // SMLSL2 Vd.4S,Vn.8H,Vm.8H
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMLSL_HIGH_S32;  // SMLSL2 Vd.2D,Vn.4S,Vm.4S
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLSL_N_S16;  // SMLSL Vd.4S,Vn.4H,Vm.H[0]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMLSL_N_S32;  // SMLSL Vd.2D,Vn.2S,Vm.S[0]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLSL_HIGH_N_S16;  // SMLSL2 Vd.4S,Vn.8H,Vm.H[0]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMLSL_HIGH_N_S32;  // SMLSL2 Vd.2D,Vn.4S,Vm.S[0]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SMLSL_ASIMDELEM_L:
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLSL_LANE_S16;  // SMLSL Vd.4S,Vn.4H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMLSL_LANE_S32;  // SMLSL Vd.2D,Vn.2S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLSL_HIGH_LANE_S16;  // SMLSL2 Vd.4S,Vn.8H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMLSL_HIGH_LANE_S32;  // SMLSL2 Vd.2D,Vn.4S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLSL_LANEQ_S16;  // SMLSL Vd.4S,Vn.4H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMLSL_LANEQ_S32;  // SMLSL Vd.2D,Vn.2S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLSL_HIGH_LANEQ_S16;  // SMLSL2 Vd.4S,Vn.8H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMLSL_HIGH_LANEQ_S32;  // SMLSL2 Vd.2D,Vn.4S,Vm.S[lane]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SMMLA_ASIMDSAME2_G:
		intrin_id = ARM64_INTRIN_VMMLAQ_S32;  // SMMLA Vd.4S,Vn.16B,Vm.16B
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SMOV_ASIMDINS_W_W:
		intrin_id = ARM64_INTRIN_VGET_LANE_S8;  // SMOV Rd,Vn.B[lane]
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_lane(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SMULL_ASIMDDIFF_L:
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMULL_S8;  // SMULL Vd.8H,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMULL_S16;  // SMULL Vd.4S,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMULL_S32;  // SMULL Vd.2D,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMULL_HIGH_S8;  // SMULL2 Vd.8H,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMULL_HIGH_S16;  // SMULL2 Vd.4S,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMULL_HIGH_S32;  // SMULL2 Vd.2D,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMULL_N_S16;  // SMULL Vd.4S,Vn.4H,Vm.H[0]
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMULL_N_S32;  // SMULL Vd.2D,Vn.2S,Vm.S[0]
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMULL_HIGH_N_S16;  // SMULL2 Vd.4S,Vn.8H,Vm.H[0]
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMULL_HIGH_N_S32;  // SMULL2 Vd.2D,Vn.4S,Vm.S[0]
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SMULL_ASIMDELEM_L:
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMULL_LANE_S16;  // SMULL Vd.4S,Vn.4H,Vm.H[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMULL_LANE_S32;  // SMULL Vd.2D,Vn.2S,Vm.S[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMULL_HIGH_LANE_S16;  // SMULL2 Vd.4S,Vn.8H,Vm.H[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMULL_HIGH_LANE_S32;  // SMULL2 Vd.2D,Vn.4S,Vm.S[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMULL_LANEQ_S16;  // SMULL Vd.4S,Vn.4H,Vm.H[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMULL_LANEQ_S32;  // SMULL Vd.2D,Vn.2S,Vm.S[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMULL_HIGH_LANEQ_S16;  // SMULL2 Vd.4S,Vn.8H,Vm.H[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMULL_HIGH_LANEQ_S32;  // SMULL2 Vd.2D,Vn.4S,Vm.S[lane]
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQABS_ASIMDMISC_R:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VQABS_S8;  // SQABS Vd.8B,Vn.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VQABSQ_S8;  // SQABS Vd.16B,Vn.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VQABS_S16;  // SQABS Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VQABSQ_S16;  // SQABS Vd.8H,Vn.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VQABS_S32;  // SQABS Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQABSQ_S32;  // SQABS Vd.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VQABSQ_S64;  // SQABS Vd.2D,Vn.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQABS_ASISDMISC_R:
		intrin_id = ARM64_INTRIN_VQABS_S64;  // SQABS Dd,Dn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQADD_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VQADD_S8;  // SQADD Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VQADDQ_S8;  // SQADD Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VQADD_S16;  // SQADD Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VQADDQ_S16;  // SQADD Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VQADD_S32;  // SQADD Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQADDQ_S32;  // SQADD Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VQADDQ_S64;  // SQADD Vd.2D,Vn.2D,Vm.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQADD_ASISDSAME_ONLY:
		intrin_id = ARM64_INTRIN_VQADD_S64;  // SQADD Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQDMLAL_ASIMDDIFF_L:
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQDMLAL_S16;  // SQDMLAL Vd.4S,Vn.4H,Vm.4H
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VQDMLAL_S32;  // SQDMLAL Vd.2D,Vn.2S,Vm.2S
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQDMLAL_HIGH_S16;  // SQDMLAL2 Vd.4S,Vn.8H,Vm.8H
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VQDMLAL_HIGH_S32;  // SQDMLAL2 Vd.2D,Vn.4S,Vm.4S
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQDMLAL_N_S16;  // SQDMLAL Vd.4S,Vn.4H,Vm.H[0]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VQDMLAL_N_S32;  // SQDMLAL Vd.2D,Vn.2S,Vm.S[0]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQDMLAL_HIGH_N_S16;  // SQDMLAL2 Vd.4S,Vn.8H,Vm.H[0]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VQDMLAL_HIGH_N_S32;  // SQDMLAL2 Vd.2D,Vn.4S,Vm.S[0]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQDMLAL_ASIMDELEM_L:
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQDMLAL_LANE_S16;  // SQDMLAL Vd.4S,Vn.4H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VQDMLAL_LANE_S32;  // SQDMLAL Vd.2D,Vn.2S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQDMLAL_HIGH_LANE_S16;  // SQDMLAL2 Vd.4S,Vn.8H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VQDMLAL_HIGH_LANE_S32;  // SQDMLAL2 Vd.2D,Vn.4S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQDMLAL_LANEQ_S16;  // SQDMLAL Vd.4S,Vn.4H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VQDMLAL_LANEQ_S32;  // SQDMLAL Vd.2D,Vn.2S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQDMLAL_HIGH_LANEQ_S16;  // SQDMLAL2 Vd.4S,Vn.8H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VQDMLAL_HIGH_LANEQ_S32;  // SQDMLAL2 Vd.2D,Vn.4S,Vm.S[lane]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQDMLAL_ASISDDIFF_ONLY:
		intrin_id = ARM64_INTRIN_VQDMLALH_S16;  // SQDMLAL Sd,Hn,Hm
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQDMLAL_ASISDELEM_L:
		intrin_id = ARM64_INTRIN_VQDMLALH_LANE_S16;  // SQDMLAL Sd,Hn,Vm.H[lane]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQDMLSL_ASIMDDIFF_L:
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQDMLSL_S16;  // SQDMLSL Vd.4S,Vn.4H,Vm.4H
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VQDMLSL_S32;  // SQDMLSL Vd.2D,Vn.2S,Vm.2S
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQDMLSL_HIGH_S16;  // SQDMLSL2 Vd.4S,Vn.8H,Vm.8H
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VQDMLSL_HIGH_S32;  // SQDMLSL2 Vd.2D,Vn.4S,Vm.4S
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQDMLSL_N_S16;  // SQDMLSL Vd.4S,Vn.4H,Vm.H[0]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VQDMLSL_N_S32;  // SQDMLSL Vd.2D,Vn.2S,Vm.S[0]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQDMLSL_HIGH_N_S16;  // SQDMLSL2 Vd.4S,Vn.8H,Vm.H[0]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VQDMLSL_HIGH_N_S32;  // SQDMLSL2 Vd.2D,Vn.4S,Vm.S[0]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQDMLSL_ASIMDELEM_L:
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQDMLSL_LANE_S16;  // SQDMLSL Vd.4S,Vn.4H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VQDMLSL_LANE_S32;  // SQDMLSL Vd.2D,Vn.2S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQDMLSL_HIGH_LANE_S16;  // SQDMLSL2 Vd.4S,Vn.8H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VQDMLSL_HIGH_LANE_S32;  // SQDMLSL2 Vd.2D,Vn.4S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQDMLSL_LANEQ_S16;  // SQDMLSL Vd.4S,Vn.4H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VQDMLSL_LANEQ_S32;  // SQDMLSL Vd.2D,Vn.2S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQDMLSL_HIGH_LANEQ_S16;  // SQDMLSL2 Vd.4S,Vn.8H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VQDMLSL_HIGH_LANEQ_S32;  // SQDMLSL2 Vd.2D,Vn.4S,Vm.S[lane]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQDMLSL_ASISDDIFF_ONLY:
		intrin_id = ARM64_INTRIN_VQDMLSLH_S16;  // SQDMLSL Sd,Hn,Hm
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQDMLSL_ASISDELEM_L:
		intrin_id = ARM64_INTRIN_VQDMLSLH_LANE_S16;  // SQDMLSL Sd,Hn,Vm.H[lane]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQDMULH_ASIMDELEM_R:
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VQDMULH_LANE_S16;  // SQDMULH Vd.4H,Vn.4H,Vm.H[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VQDMULHQ_LANE_S16;  // SQDMULH Vd.8H,Vn.8H,Vm.H[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VQDMULH_LANE_S32;  // SQDMULH Vd.2S,Vn.2S,Vm.S[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQDMULHQ_LANE_S32;  // SQDMULH Vd.4S,Vn.4S,Vm.S[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VQDMULH_LANEQ_S16;  // SQDMULH Vd.4H,Vn.4H,Vm.H[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VQDMULHQ_LANEQ_S16;  // SQDMULH Vd.8H,Vn.8H,Vm.H[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VQDMULH_LANEQ_S32;  // SQDMULH Vd.2S,Vn.2S,Vm.S[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQDMULHQ_LANEQ_S32;  // SQDMULH Vd.4S,Vn.4S,Vm.S[lane]
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQDMULH_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VQDMULH_S16;  // SQDMULH Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VQDMULHQ_S16;  // SQDMULH Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VQDMULH_S32;  // SQDMULH Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQDMULHQ_S32;  // SQDMULH Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VQDMULH_N_S16;  // SQDMULH Vd.4H,Vn.4H,Vm.H[0]
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VQDMULHQ_N_S16;  // SQDMULH Vd.8H,Vn.8H,Vm.H[0]
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VQDMULH_N_S32;  // SQDMULH Vd.2S,Vn.2S,Vm.S[0]
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQDMULHQ_N_S32;  // SQDMULH Vd.4S,Vn.4S,Vm.S[0]
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQDMULH_ASISDELEM_R:
		intrin_id = ARM64_INTRIN_VQDMULHH_LANE_S16;  // SQDMULH Hd,Hn,Vm.H[lane]
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQDMULH_ASISDSAME_ONLY:
		intrin_id = ARM64_INTRIN_VQDMULHH_S16;  // SQDMULH Hd,Hn,Hm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQDMULL_ASIMDDIFF_L:
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQDMULL_S16;  // SQDMULL Vd.4S,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VQDMULL_S32;  // SQDMULL Vd.2D,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQDMULL_HIGH_S16;  // SQDMULL2 Vd.4S,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VQDMULL_HIGH_S32;  // SQDMULL2 Vd.2D,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQDMULL_N_S16;  // SQDMULL Vd.4S,Vn.4H,Vm.H[0]
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VQDMULL_N_S32;  // SQDMULL Vd.2D,Vn.2S,Vm.S[0]
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQDMULL_HIGH_N_S16;  // SQDMULL2 Vd.4S,Vn.8H,Vm.H[0]
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VQDMULL_HIGH_N_S32;  // SQDMULL2 Vd.2D,Vn.4S,Vm.S[0]
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQDMULL_ASIMDELEM_L:
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQDMULL_LANE_S16;  // SQDMULL Vd.4S,Vn.4H,Vm.H[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VQDMULL_LANE_S32;  // SQDMULL Vd.2D,Vn.2S,Vm.S[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQDMULL_HIGH_LANE_S16;  // SQDMULL2 Vd.4S,Vn.8H,Vm.H[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VQDMULL_HIGH_LANE_S32;  // SQDMULL2 Vd.2D,Vn.4S,Vm.S[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQDMULL_LANEQ_S16;  // SQDMULL Vd.4S,Vn.4H,Vm.H[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VQDMULL_LANEQ_S32;  // SQDMULL Vd.2D,Vn.2S,Vm.S[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQDMULL_HIGH_LANEQ_S16;  // SQDMULL2 Vd.4S,Vn.8H,Vm.H[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VQDMULL_HIGH_LANEQ_S32;  // SQDMULL2 Vd.2D,Vn.4S,Vm.S[lane]
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQDMULL_ASISDDIFF_ONLY:
		intrin_id = ARM64_INTRIN_VQDMULLH_S16;  // SQDMULL Sd,Hn,Hm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQDMULL_ASISDELEM_L:
		intrin_id = ARM64_INTRIN_VQDMULLH_LANE_S16;  // SQDMULL Sd,Hn,Vm.H[lane]
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQNEG_ASIMDMISC_R:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VQNEG_S8;  // SQNEG Vd.8B,Vn.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VQNEGQ_S8;  // SQNEG Vd.16B,Vn.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VQNEG_S16;  // SQNEG Vd.4H,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VQNEGQ_S16;  // SQNEG Vd.8H,Vn.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VQNEG_S32;  // SQNEG Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQNEGQ_S32;  // SQNEG Vd.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VQNEGQ_S64;  // SQNEG Vd.2D,Vn.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQNEG_ASISDMISC_R:
		intrin_id = ARM64_INTRIN_VQNEG_S64;  // SQNEG Dd,Dn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQRDMLAH_ASIMDELEM_R:
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VQRDMLAH_LANE_S16;  // SQRDMLAH Vd.4H,Vn.4H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VQRDMLAHQ_LANE_S16;  // SQRDMLAH Vd.8H,Vn.8H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VQRDMLAH_LANEQ_S16;  // SQRDMLAH Vd.4H,Vn.4H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VQRDMLAHQ_LANEQ_S16;  // SQRDMLAH Vd.8H,Vn.8H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VQRDMLAH_LANE_S32;  // SQRDMLAH Vd.2S,Vn.2S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQRDMLAHQ_LANE_S32;  // SQRDMLAH Vd.4S,Vn.4S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VQRDMLAH_LANEQ_S32;  // SQRDMLAH Vd.2S,Vn.2S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQRDMLAHQ_LANEQ_S32;  // SQRDMLAH Vd.4S,Vn.4S,Vm.S[lane]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQRDMLAH_ASIMDSAME2_ONLY:
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VQRDMLAH_S16;  // SQRDMLAH Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VQRDMLAH_S32;  // SQRDMLAH Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VQRDMLAHQ_S16;  // SQRDMLAH Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQRDMLAHQ_S32;  // SQRDMLAH Vd.4S,Vn.4S,Vm.4S
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQRDMLAH_ASISDELEM_R:
		intrin_id = ARM64_INTRIN_VQRDMLAHH_LANE_S16;  // SQRDMLAH Hd,Hn,Vm.H[lane]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQRDMLSH_ASIMDELEM_R:
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VQRDMLSH_LANE_S16;  // SQRDMLSH Vd.4H,Vn.4H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VQRDMLSHQ_LANE_S16;  // SQRDMLSH Vd.8H,Vn.8H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VQRDMLSH_LANEQ_S16;  // SQRDMLSH Vd.4H,Vn.4H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VQRDMLSHQ_LANEQ_S16;  // SQRDMLSH Vd.8H,Vn.8H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VQRDMLSH_LANE_S32;  // SQRDMLSH Vd.2S,Vn.2S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQRDMLSHQ_LANE_S32;  // SQRDMLSH Vd.4S,Vn.4S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VQRDMLSH_LANEQ_S32;  // SQRDMLSH Vd.2S,Vn.2S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQRDMLSHQ_LANEQ_S32;  // SQRDMLSH Vd.4S,Vn.4S,Vm.S[lane]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQRDMLSH_ASIMDSAME2_ONLY:
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VQRDMLSH_S16;  // SQRDMLSH Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VQRDMLSH_S32;  // SQRDMLSH Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VQRDMLSHQ_S16;  // SQRDMLSH Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQRDMLSHQ_S32;  // SQRDMLSH Vd.4S,Vn.4S,Vm.4S
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQRDMLSH_ASISDELEM_R:
		intrin_id = ARM64_INTRIN_VQRDMLSHH_LANE_S16;  // SQRDMLSH Hd,Hn,Vm.H[lane]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQRDMLSH_ASISDSAME2_ONLY:
		intrin_id = ARM64_INTRIN_VQRDMLAHH_S16;  // SQRDMLSH Hd,Hn,Hm
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQRDMULH_ASIMDELEM_R:
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VQRDMULH_LANE_S16;  // SQRDMULH Vd.4H,Vn.4H,Vm.H[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VQRDMULHQ_LANE_S16;  // SQRDMULH Vd.8H,Vn.8H,Vm.H[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VQRDMULH_LANE_S32;  // SQRDMULH Vd.2S,Vn.2S,Vm.S[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQRDMULHQ_LANE_S32;  // SQRDMULH Vd.4S,Vn.4S,Vm.S[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VQRDMULH_LANEQ_S16;  // SQRDMULH Vd.4H,Vn.4H,Vm.H[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VQRDMULHQ_LANEQ_S16;  // SQRDMULH Vd.8H,Vn.8H,Vm.H[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VQRDMULH_LANEQ_S32;  // SQRDMULH Vd.2S,Vn.2S,Vm.S[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQRDMULHQ_LANEQ_S32;  // SQRDMULH Vd.4S,Vn.4S,Vm.S[lane]
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQRDMULH_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VQRDMULH_S16;  // SQRDMULH Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VQRDMULHQ_S16;  // SQRDMULH Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VQRDMULH_S32;  // SQRDMULH Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQRDMULHQ_S32;  // SQRDMULH Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VQRDMULH_N_S16;  // SQRDMULH Vd.4H,Vn.4H,Vm.H[0]
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VQRDMULHQ_N_S16;  // SQRDMULH Vd.8H,Vn.8H,Vm.H[0]
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VQRDMULH_N_S32;  // SQRDMULH Vd.2S,Vn.2S,Vm.S[0]
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQRDMULHQ_N_S32;  // SQRDMULH Vd.4S,Vn.4S,Vm.S[0]
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQRDMULH_ASISDELEM_R:
		intrin_id = ARM64_INTRIN_VQRDMULHH_LANE_S16;  // SQRDMULH Hd,Hn,Vm.H[lane]
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQRDMULH_ASISDSAME_ONLY:
		intrin_id = ARM64_INTRIN_VQRDMULHH_S16;  // SQRDMULH Hd,Hn,Hm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQRSHL_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VQRSHL_S8;  // SQRSHL Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VQRSHLQ_S8;  // SQRSHL Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VQRSHL_S16;  // SQRSHL Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VQRSHLQ_S16;  // SQRSHL Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VQRSHL_S32;  // SQRSHL Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQRSHLQ_S32;  // SQRSHL Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VQRSHLQ_S64;  // SQRSHL Vd.2D,Vn.2D,Vm.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQRSHL_ASISDSAME_ONLY:
		intrin_id = ARM64_INTRIN_VQRSHL_S64;  // SQRSHL Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQRSHRN_ASIMDSHF_N:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VQRSHRN_N_S16;  // SQRSHRN Vd.8B,Vn.8H,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VQRSHRN_N_S32;  // SQRSHRN Vd.4H,Vn.4S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VQRSHRN_N_S64;  // SQRSHRN Vd.2S,Vn.2D,#n
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VQRSHRN_HIGH_N_S16;  // SQRSHRN2 Vd.16B,Vn.8H,#n
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VQRSHRN_HIGH_N_S32;  // SQRSHRN2 Vd.8H,Vn.4S,#n
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQRSHRN_HIGH_N_S64;  // SQRSHRN2 Vd.4S,Vn.2D,#n
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQRSHRN_ASISDSHF_N:
		intrin_id = ARM64_INTRIN_VQRSHRNH_N_S16;  // SQRSHRN Bd,Hn,#n
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQRSHRUN_ASIMDSHF_N:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VQRSHRUN_N_S16;  // SQRSHRUN Vd.8B,Vn.8H,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VQRSHRUN_N_S32;  // SQRSHRUN Vd.4H,Vn.4S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VQRSHRUN_N_S64;  // SQRSHRUN Vd.2S,Vn.2D,#n
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VQRSHRUN_HIGH_N_S16;  // SQRSHRUN2 Vd.16B,Vn.8H,#n
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VQRSHRUN_HIGH_N_S32;  // SQRSHRUN2 Vd.8H,Vn.4S,#n
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQRSHRUN_HIGH_N_S64;  // SQRSHRUN2 Vd.4S,Vn.2D,#n
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQRSHRUN_ASISDSHF_N:
		intrin_id = ARM64_INTRIN_VQRSHRUNH_N_S16;  // SQRSHRUN Bd,Hn,#n
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQSHLU_ASIMDSHF_R:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VQSHLU_N_S8;  // SQSHLU Vd.8B,Vn.8B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VQSHLU_N_S16;  // SQSHLU Vd.4H,Vn.4H,#n
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VQSHLUQ_N_S16;  // SQSHLU Vd.8H,Vn.8H,#n
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VQSHLU_N_S32;  // SQSHLU Vd.2S,Vn.2S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQSHLUQ_N_S32;  // SQSHLU Vd.4S,Vn.4S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VQSHLUQ_N_S64;  // SQSHLU Vd.2D,Vn.2D,#n
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQSHLU_ASISDSHF_R:
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VQSHLUQ_N_S8;  // SQSHLU Vd.16B,Vn.16B,#n
		// if(None) intrin_id = ARM64_INTRIN_VQSHLU_N_S64; // SQSHLU Dd,Dn,#n
		// if(None) intrin_id = ARM64_INTRIN_VQSHLUB_N_S8; // SQSHLU Bd,Bn,#n
		// if(None) intrin_id = ARM64_INTRIN_VQSHLUH_N_S16; // SQSHLU Hd,Hn,#n
		// if(None) intrin_id = ARM64_INTRIN_VQSHLUS_N_S32; // SQSHLU Sd,Sn,#n
		// if(None) intrin_id = ARM64_INTRIN_VQSHLUD_N_S64; // SQSHLU Dd,Dn,#n
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQSHL_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VQSHL_S8;  // SQSHL Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VQSHLQ_S8;  // SQSHL Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VQSHL_S16;  // SQSHL Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VQSHLQ_S16;  // SQSHL Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VQSHL_S32;  // SQSHL Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQSHLQ_S32;  // SQSHL Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VQSHLQ_S64;  // SQSHL Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VQSHLQ_N_S8;  // SQSHL Vd.16B,Vn.16B,#n
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQSHL_ASISDSAME_ONLY:
		intrin_id = ARM64_INTRIN_VQSHL_S64;  // SQSHL Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQSHRN_ASIMDSHF_N:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VQSHRN_N_S16;  // SQSHRN Vd.8B,Vn.8H,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VQSHRN_N_S32;  // SQSHRN Vd.4H,Vn.4S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VQSHRN_N_S64;  // SQSHRN Vd.2S,Vn.2D,#n
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VQSHRN_HIGH_N_S16;  // SQSHRN2 Vd.16B,Vn.8H,#n
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VQSHRN_HIGH_N_S32;  // SQSHRN2 Vd.8H,Vn.4S,#n
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQSHRN_HIGH_N_S64;  // SQSHRN2 Vd.4S,Vn.2D,#n
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQSHRN_ASISDSHF_N:
		intrin_id = ARM64_INTRIN_VQSHRNH_N_S16;  // SQSHRN Bd,Hn,#n
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQSHRUN_ASIMDSHF_N:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VQSHRUN_N_S16;  // SQSHRUN Vd.8B,Vn.8H,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VQSHRUN_N_S32;  // SQSHRUN Vd.4H,Vn.4S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VQSHRUN_N_S64;  // SQSHRUN Vd.2S,Vn.2D,#n
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VQSHRUN_HIGH_N_S16;  // SQSHRUN2 Vd.16B,Vn.8H,#n
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VQSHRUN_HIGH_N_S32;  // SQSHRUN2 Vd.8H,Vn.4S,#n
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQSHRUN_HIGH_N_S64;  // SQSHRUN2 Vd.4S,Vn.2D,#n
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQSHRUN_ASISDSHF_N:
		intrin_id = ARM64_INTRIN_VQSHRUNH_N_S16;  // SQSHRUN Bd,Hn,#n
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQSUB_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VQSUB_S8;  // SQSUB Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VQSUBQ_S8;  // SQSUB Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VQSUB_S16;  // SQSUB Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VQSUBQ_S16;  // SQSUB Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VQSUB_S32;  // SQSUB Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQSUBQ_S32;  // SQSUB Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VQSUBQ_S64;  // SQSUB Vd.2D,Vn.2D,Vm.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQSUB_ASISDSAME_ONLY:
		intrin_id = ARM64_INTRIN_VQSUB_S64;  // SQSUB Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQXTN_ASIMDMISC_N:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VQMOVN_S16;  // SQXTN Vd.8B,Vn.8H
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VQMOVN_S32;  // SQXTN Vd.4H,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VQMOVN_S64;  // SQXTN Vd.2S,Vn.2D
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VQMOVN_HIGH_S16;  // SQXTN2 Vd.16B,Vn.8H
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VQMOVN_HIGH_S32;  // SQXTN2 Vd.8H,Vn.4S
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQMOVN_HIGH_S64;  // SQXTN2 Vd.4S,Vn.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQXTN_ASISDMISC_N:
		intrin_id = ARM64_INTRIN_VQMOVNH_S16;  // SQXTN Bd,Hn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQXTUN_ASIMDMISC_N:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VQMOVUN_S16;  // SQXTUN Vd.8B,Vn.8H
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VQMOVUN_S32;  // SQXTUN Vd.4H,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VQMOVUN_S64;  // SQXTUN Vd.2S,Vn.2D
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VQMOVUN_HIGH_S16;  // SQXTUN2 Vd.16B,Vn.8H
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VQMOVUN_HIGH_S32;  // SQXTUN2 Vd.8H,Vn.4S
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQMOVUN_HIGH_S64;  // SQXTUN2 Vd.4S,Vn.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SQXTUN_ASISDMISC_N:
		intrin_id = ARM64_INTRIN_VQMOVUNH_S16;  // SQXTUN Bd,Hn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SRHADD_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VRHADD_S8;  // SRHADD Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VRHADDQ_S8;  // SRHADD Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VRHADD_S16;  // SRHADD Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VRHADDQ_S16;  // SRHADD Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VRHADD_S32;  // SRHADD Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VRHADDQ_S32;  // SRHADD Vd.4S,Vn.4S,Vm.4S
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SRI_ASIMDSHF_R:
		if (instr.operands[0].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VSRI_N_S8;  // SRI Vd.8B,Vn.8B,#n
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VSRI_N_S16;  // SRI Vd.4H,Vn.4H,#n
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSRIQ_N_S16;  // SRI Vd.8H,Vn.8H,#n
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VSRI_N_S32;  // SRI Vd.2S,Vn.2S,#n
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSRIQ_N_S32;  // SRI Vd.4S,Vn.4S,#n
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VSRIQ_N_S64;  // SRI Vd.2D,Vn.2D,#n
		if (instr.operands[0].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VSRI_N_U8;  // SRI Vd.8B,Vn.8B,#n
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VSRI_N_U16;  // SRI Vd.4H,Vn.4H,#n
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSRIQ_N_U16;  // SRI Vd.8H,Vn.8H,#n
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VSRI_N_U32;  // SRI Vd.2S,Vn.2S,#n
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSRIQ_N_U32;  // SRI Vd.4S,Vn.4S,#n
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VSRIQ_N_U64;  // SRI Vd.2D,Vn.2D,#n
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VSRIQ_N_P64;  // SRI Vd.2D,Vn.2D,#n
		if (instr.operands[0].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VSRI_N_P8;  // SRI Vd.8B,Vn.8B,#n
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VSRI_N_P16;  // SRI Vd.4H,Vn.4H,#n
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSRIQ_N_P16;  // SRI Vd.8H,Vn.8H,#n
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SRI_ASISDSHF_R:
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VSRIQ_N_S8;  // SRI Vd.16B,Vn.16B,#n
		// if(None) intrin_id = ARM64_INTRIN_VSRI_N_S64; // SRI Dd,Dn,#n
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VSRIQ_N_U8;  // SRI Vd.16B,Vn.16B,#n
		// if(None) intrin_id = ARM64_INTRIN_VSRI_N_U64; // SRI Dd,Dn,#n
		// if(None) intrin_id = ARM64_INTRIN_VSRI_N_P64; // SRI Dd,Dn,#n
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VSRIQ_N_P8;  // SRI Vd.16B,Vn.16B,#n
		// if(None) intrin_id = ARM64_INTRIN_VSRID_N_S64; // SRI Dd,Dn,#n
		// if(None) intrin_id = ARM64_INTRIN_VSRID_N_U64; // SRI Dd,Dn,#n
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SRSHL_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VRSHL_S8;  // SRSHL Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VRSHLQ_S8;  // SRSHL Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VRSHL_S16;  // SRSHL Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VRSHLQ_S16;  // SRSHL Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VRSHL_S32;  // SRSHL Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VRSHLQ_S32;  // SRSHL Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VRSHLQ_S64;  // SRSHL Vd.2D,Vn.2D,Vm.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SRSHL_ASISDSAME_ONLY:
		intrin_id = ARM64_INTRIN_VRSHL_S64;  // SRSHL Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SRSHR_ASIMDSHF_R:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VRSHR_N_S8;  // SRSHR Vd.8B,Vn.8B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VRSHR_N_S16;  // SRSHR Vd.4H,Vn.4H,#n
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VRSHRQ_N_S16;  // SRSHR Vd.8H,Vn.8H,#n
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VRSHR_N_S32;  // SRSHR Vd.2S,Vn.2S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VRSHRQ_N_S32;  // SRSHR Vd.4S,Vn.4S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VRSHRQ_N_S64;  // SRSHR Vd.2D,Vn.2D,#n
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SRSHR_ASISDSHF_R:
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VRSHRQ_N_S8;  // SRSHR Vd.16B,Vn.16B,#n
		// if(None) intrin_id = ARM64_INTRIN_VRSHR_N_S64; // SRSHR Dd,Dn,#n
		// if(None) intrin_id = ARM64_INTRIN_VRSHRD_N_S64; // SRSHR Dd,Dn,#n
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SRSRA_ASIMDSHF_R:
		if (instr.operands[0].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VRSRA_N_S8;  // SRSRA Vd.8B,Vn.8B,#n
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VRSRA_N_S16;  // SRSRA Vd.4H,Vn.4H,#n
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VRSRAQ_N_S16;  // SRSRA Vd.8H,Vn.8H,#n
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VRSRA_N_S32;  // SRSRA Vd.2S,Vn.2S,#n
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VRSRAQ_N_S32;  // SRSRA Vd.4S,Vn.4S,#n
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VRSRAQ_N_S64;  // SRSRA Vd.2D,Vn.2D,#n
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SRSRA_ASISDSHF_R:
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VRSRAQ_N_S8;  // SRSRA Vd.16B,Vn.16B,#n
		// if(None) intrin_id = ARM64_INTRIN_VRSRA_N_S64; // SRSRA Dd,Dn,#n
		// if(None) intrin_id = ARM64_INTRIN_VRSRAD_N_S64; // SRSRA Dd,Dn,#n
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SSHLL_ASIMDSHF_L:
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSHLL_N_S8;  // SSHLL Vd.8H,Vn.8B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSHLL_N_S16;  // SSHLL Vd.4S,Vn.4H,#n
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VSHLL_N_S32;  // SSHLL Vd.2D,Vn.2S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSHLL_HIGH_N_S8;  // SSHLL2 Vd.8H,Vn.16B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSHLL_HIGH_N_S16;  // SSHLL2 Vd.4S,Vn.8H,#n
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VSHLL_HIGH_N_S32;  // SSHLL2 Vd.2D,Vn.4S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMOVL_S8;  // SSHLL Vd.8H,Vn.8B,#0
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMOVL_S16;  // SSHLL Vd.4S,Vn.4H,#0
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMOVL_S32;  // SSHLL Vd.2D,Vn.2S,#0
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMOVL_HIGH_S8;  // SSHLL2 Vd.8H,Vn.16B,#0
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMOVL_HIGH_S16;  // SSHLL2 Vd.4S,Vn.8H,#0
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMOVL_HIGH_S32;  // SSHLL2 Vd.2D,Vn.4S,#0
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SSHL_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VSHL_S8;  // SSHL Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VSHLQ_S8;  // SSHL Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VSHL_S16;  // SSHL Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSHLQ_S16;  // SSHL Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VSHL_S32;  // SSHL Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSHLQ_S32;  // SSHL Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VSHLQ_S64;  // SSHL Vd.2D,Vn.2D,Vm.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SSHL_ASISDSAME_ONLY:
		intrin_id = ARM64_INTRIN_VSHL_S64;  // SSHL Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SSHR_ASIMDSHF_R:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VSHR_N_S8;  // SSHR Vd.8B,Vn.8B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VSHR_N_S16;  // SSHR Vd.4H,Vn.4H,#n
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSHRQ_N_S16;  // SSHR Vd.8H,Vn.8H,#n
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VSHR_N_S32;  // SSHR Vd.2S,Vn.2S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSHRQ_N_S32;  // SSHR Vd.4S,Vn.4S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VSHRQ_N_S64;  // SSHR Vd.2D,Vn.2D,#n
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SSHR_ASISDSHF_R:
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VSHRQ_N_S8;  // SSHR Vd.16B,Vn.16B,#n
		// if(None) intrin_id = ARM64_INTRIN_VSHR_N_S64; // SSHR Dd,Dn,#n
		// if(None) intrin_id = ARM64_INTRIN_VSHRD_N_S64; // SSHR Dd,Dn,#n
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SSRA_ASIMDSHF_R:
		if (instr.operands[0].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VSRA_N_S8;  // SSRA Vd.8B,Vn.8B,#n
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VSRA_N_S16;  // SSRA Vd.4H,Vn.4H,#n
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSRAQ_N_S16;  // SSRA Vd.8H,Vn.8H,#n
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VSRA_N_S32;  // SSRA Vd.2S,Vn.2S,#n
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSRAQ_N_S32;  // SSRA Vd.4S,Vn.4S,#n
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VSRAQ_N_S64;  // SSRA Vd.2D,Vn.2D,#n
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SSRA_ASISDSHF_R:
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VSRAQ_N_S8;  // SSRA Vd.16B,Vn.16B,#n
		// if(None) intrin_id = ARM64_INTRIN_VSRA_N_S64; // SSRA Dd,Dn,#n
		// if(None) intrin_id = ARM64_INTRIN_VSRAD_N_S64; // SSRA Dd,Dn,#n
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SSUBL_ASIMDDIFF_L:
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSUBL_S8;  // SSUBL Vd.8H,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSUBL_S16;  // SSUBL Vd.4S,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VSUBL_S32;  // SSUBL Vd.2D,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSUBL_HIGH_S8;  // SSUBL2 Vd.8H,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSUBL_HIGH_S16;  // SSUBL2 Vd.4S,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VSUBL_HIGH_S32;  // SSUBL2 Vd.2D,Vn.4S,Vm.4S
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SSUBW_ASIMDDIFF_W:
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSUBW_S8;  // SSUBW Vd.8H,Vn.8H,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSUBW_S16;  // SSUBW Vd.4S,Vn.4S,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VSUBW_S32;  // SSUBW Vd.2D,Vn.2D,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSUBW_HIGH_S8;  // SSUBW2 Vd.8H,Vn.8H,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSUBW_HIGH_S16;  // SSUBW2 Vd.4S,Vn.4S,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VSUBW_HIGH_S32;  // SSUBW2 Vd.2D,Vn.2D,Vm.4S
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SUBHN_ASIMDDIFF_N:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VSUBHN_S16;  // SUBHN Vd.8B,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VSUBHN_S32;  // SUBHN Vd.4H,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VSUBHN_S64;  // SUBHN Vd.2S,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VSUBHN_U16;  // SUBHN Vd.8B,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VSUBHN_U32;  // SUBHN Vd.4H,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VSUBHN_U64;  // SUBHN Vd.2S,Vn.2D,Vm.2D
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VSUBHN_HIGH_S16;  // SUBHN2 Vd.16B,Vn.8H,Vm.8H
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSUBHN_HIGH_S32;  // SUBHN2 Vd.8H,Vn.4S,Vm.4S
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSUBHN_HIGH_S64;  // SUBHN2 Vd.4S,Vn.2D,Vm.2D
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VSUBHN_HIGH_U16;  // SUBHN2 Vd.16B,Vn.8H,Vm.8H
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSUBHN_HIGH_U32;  // SUBHN2 Vd.8H,Vn.4S,Vm.4S
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSUBHN_HIGH_U64;  // SUBHN2 Vd.4S,Vn.2D,Vm.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SUB_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VSUB_S8;  // SUB Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VSUBQ_S8;  // SUB Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VSUB_S16;  // SUB Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSUBQ_S16;  // SUB Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VSUB_S32;  // SUB Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSUBQ_S32;  // SUB Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VSUBQ_S64;  // SUB Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VSUB_U8;  // SUB Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VSUBQ_U8;  // SUB Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VSUB_U16;  // SUB Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSUBQ_U16;  // SUB Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VSUB_U32;  // SUB Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSUBQ_U32;  // SUB Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VSUBQ_U64;  // SUB Vd.2D,Vn.2D,Vm.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SUB_ASISDSAME_ONLY:
		intrin_id = ARM64_INTRIN_VSUB_S64;  // SUB Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SUDOT_ASIMDELEM_D:
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VSUDOT_LANE_S32;  // SUDOT Vd.2S,Vn.8B,Vm.4B[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VSUDOT_LANEQ_S32;  // SUDOT Vd.2S,Vn.8B,Vm.4B[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSUDOTQ_LANE_S32;  // SUDOT Vd.4S,Vn.16B,Vm.4B[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSUDOTQ_LANEQ_S32;  // SUDOT Vd.4S,Vn.16B,Vm.4B[lane]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SUQADD_ASIMDMISC_R:
		if (instr.operands[0].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VUQADD_S8;  // SUQADD Vd.8B,Vn.8B
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VUQADDQ_S8;  // SUQADD Vd.16B,Vn.16B
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VUQADD_S16;  // SUQADD Vd.4H,Vn.4H
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VUQADDQ_S16;  // SUQADD Vd.8H,Vn.8H
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VUQADD_S32;  // SUQADD Vd.2S,Vn.2S
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VUQADDQ_S32;  // SUQADD Vd.4S,Vn.4S
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VUQADDQ_S64;  // SUQADD Vd.2D,Vn.2D
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_SUQADD_ASISDMISC_R:
		intrin_id = ARM64_INTRIN_VUQADD_S64;  // SUQADD Dd,Dn
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_TBL_ASIMDTBL_L1_1:
		intrin_id = ARM64_INTRIN_VTBL1_S8;
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_TBL_ASIMDTBL_L2_2:
		// TODO
		break;
	case ENC_TBL_ASIMDTBL_L3_3:
		// TODO
		break;
	case ENC_TBL_ASIMDTBL_L4_4:
		// TODO
		break;
	case ENC_ST2_ASISDLSE_R2:
	case ENC_ST2_ASISDLSEP_I2_I:
		// Handling: st2 {Vt.8B - Vt2.8B}, [Xn] [, <IMM>]
		// All these st2 instructions are using the same intrinsic.
		// Semantic between different vector representation is the same at the assembly level.
		if (instr.operands[0].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VST2_S8;   // ST2 {Vt.8B - Vt2.8B}, [Xn], <IMM>
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VST2Q_S8;  // ST2 {Vt.16B - Vt2.16B}, [Xn], <IMM>
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VST2_S16;  // ST2 {Vt.4H - Vt2.4H}, [Xn], <IMM>
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VST2Q_S16; // ST2 {Vt.8H - Vt2.8H}, [Xn], <IMM>
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VST2_S32;  // ST2 {Vt.2S - Vt2.2S}, [Xn], <IMM>
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VST2Q_S32; // ST2 {Vt.4S - Vt2.4S}, [Xn], <IMM>
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VST2Q_S64; // ST2 {Vt.2D - Vt2.2D}, [Xn], <IMM>
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[0]);
		break;
	case ENC_TRN1_ASIMDPERM_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VTRN1_S8;  // TRN1 Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VTRN1Q_S8;  // TRN1 Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VTRN1_S16;  // TRN1 Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VTRN1Q_S16;  // TRN1 Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VTRN1_S32;  // TRN1 Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VTRN1Q_S32;  // TRN1 Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VTRN1Q_S64;  // TRN1 Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VTRN1_U8;  // TRN1 Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VTRN1Q_U8;  // TRN1 Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VTRN1_U16;  // TRN1 Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VTRN1Q_U16;  // TRN1 Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VTRN1_U32;  // TRN1 Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VTRN1Q_U32;  // TRN1 Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VTRN1Q_U64;  // TRN1 Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VTRN1Q_P64;  // TRN1 Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VTRN1_F32;  // TRN1 Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VTRN1Q_F32;  // TRN1 Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VTRN1Q_F64;  // TRN1 Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VTRN1_P8;  // TRN1 Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VTRN1Q_P8;  // TRN1 Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VTRN1_P16;  // TRN1 Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VTRN1Q_P16;  // TRN1 Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VTRN1_F16;  // TRN1 Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VTRN1Q_F16;  // TRN1 Vd.8H,Vn.8H,Vm.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_TRN2_ASIMDPERM_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VTRN2_S8;  // TRN2 Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VTRN2Q_S8;  // TRN2 Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VTRN2_S16;  // TRN2 Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VTRN2Q_S16;  // TRN2 Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VTRN2_S32;  // TRN2 Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VTRN2Q_S32;  // TRN2 Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VTRN2Q_S64;  // TRN2 Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VTRN2_U8;  // TRN2 Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VTRN2Q_U8;  // TRN2 Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VTRN2_U16;  // TRN2 Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VTRN2Q_U16;  // TRN2 Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VTRN2_U32;  // TRN2 Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VTRN2Q_U32;  // TRN2 Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VTRN2Q_U64;  // TRN2 Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VTRN2Q_P64;  // TRN2 Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VTRN2_F32;  // TRN2 Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VTRN2Q_F32;  // TRN2 Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VTRN2Q_F64;  // TRN2 Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VTRN2_P8;  // TRN2 Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VTRN2Q_P8;  // TRN2 Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VTRN2_P16;  // TRN2 Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VTRN2Q_P16;  // TRN2 Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VTRN2_F16;  // TRN2 Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VTRN2Q_F16;  // TRN2 Vd.8H,Vn.8H,Vm.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UABAL_ASIMDDIFF_L:
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VABAL_U8;  // UABAL Vd.8H,Vn.8B,Vm.8B
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VABAL_U16;  // UABAL Vd.4S,Vn.4H,Vm.4H
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VABAL_U32;  // UABAL Vd.2D,Vn.2S,Vm.2S
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VABAL_HIGH_U8;  // UABAL2 Vd.8H,Vn.16B,Vm.16B
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VABAL_HIGH_U16;  // UABAL2 Vd.4S,Vn.8H,Vm.8H
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VABAL_HIGH_U32;  // UABAL2 Vd.2D,Vn.4S,Vm.4S
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UABA_ASIMDSAME_ONLY:
		if (instr.operands[0].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VABA_U8;  // UABA Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VABAQ_U8;  // UABA Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VABA_U16;  // UABA Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VABAQ_U16;  // UABA Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VABA_U32;  // UABA Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VABAQ_U32;  // UABA Vd.4S,Vn.4S,Vm.4S
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UABDL_ASIMDDIFF_L:
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VABDL_U8;  // UABDL Vd.8H,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VABDL_U16;  // UABDL Vd.4S,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VABDL_U32;  // UABDL Vd.2D,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VABDL_HIGH_U8;  // UABDL2 Vd.8H,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VABDL_HIGH_U16;  // UABDL2 Vd.4S,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VABDL_HIGH_U32;  // UABDL2 Vd.2D,Vn.4S,Vm.4S
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UABD_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VABD_U8;  // UABD Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VABDQ_U8;  // UABD Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VABD_U16;  // UABD Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VABDQ_U16;  // UABD Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VABD_U32;  // UABD Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VABDQ_U32;  // UABD Vd.4S,Vn.4S,Vm.4S
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UADALP_ASIMDMISC_P:
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VPADAL_U8;  // UADALP Vd.4H,Vn.8B
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VPADALQ_U8;  // UADALP Vd.8H,Vn.16B
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VPADAL_U16;  // UADALP Vd.2S,Vn.4H
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VPADALQ_U16;  // UADALP Vd.4S,Vn.8H
		if (instr.operands[0].arrSpec == ARRSPEC_1DOUBLE)
			intrin_id = ARM64_INTRIN_VPADAL_U32;  // UADALP Vd.1D,Vn.2S
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VPADALQ_U32;  // UADALP Vd.2D,Vn.4S
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UADDLP_ASIMDMISC_P:
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VPADDL_U8;  // UADDLP Vd.4H,Vn.8B
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VPADDLQ_U8;  // UADDLP Vd.8H,Vn.16B
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VPADDL_U16;  // UADDLP Vd.2S,Vn.4H
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VPADDLQ_U16;  // UADDLP Vd.4S,Vn.8H
		if (instr.operands[1].arrSpec == ARRSPEC_1DOUBLE)
			intrin_id = ARM64_INTRIN_VPADDL_U32;  // UADDLP Vd.1D,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VPADDLQ_U32;  // UADDLP Vd.2D,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_1DOUBLE)
			intrin_id = ARM64_INTRIN_VADDLV_U32;  // UADDLP Vd.1D,Vn.2S
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UADDLV_ASIMDALL_ONLY:
		intrin_id = ARM64_INTRIN_VADDLV_U8;  // UADDLV Hd,Vn.8B
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UADDL_ASIMDDIFF_L:
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VADDL_U8;  // UADDL Vd.8H,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VADDL_U16;  // UADDL Vd.4S,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VADDL_U32;  // UADDL Vd.2D,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VADDL_HIGH_U8;  // UADDL2 Vd.8H,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VADDL_HIGH_U16;  // UADDL2 Vd.4S,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VADDL_HIGH_U32;  // UADDL2 Vd.2D,Vn.4S,Vm.4S
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UADDW_ASIMDDIFF_W:
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VADDW_U8;  // UADDW Vd.8H,Vn.8H,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VADDW_U16;  // UADDW Vd.4S,Vn.4S,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VADDW_U32;  // UADDW Vd.2D,Vn.2D,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VADDW_HIGH_U8;  // UADDW2 Vd.8H,Vn.8H,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VADDW_HIGH_U16;  // UADDW2 Vd.4S,Vn.4S,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VADDW_HIGH_U32;  // UADDW2 Vd.2D,Vn.2D,Vm.4S
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UCVTF_ASISDMISC_R:
	case ENC_UCVTF_D64_FLOAT2INT:
	case ENC_UCVTF_S32_FLOAT2INT:
		if (REGSZ_O(instr.operands[0]) == 8)
			intrin_id = ARM64_INTRIN_VCVT_F64_U64;  // UCVTF Dd,Dn
		else if (REGSZ_O(instr.operands[0]) == 4)
			intrin_id = ARM64_INTRIN_VCVTS_F32_U32;  // UCVTF Sd,Sn
		else
			break;
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UCVTF_ASISDSHF_C:
		intrin_id = ARM64_INTRIN_VCVT_N_F64_U64;  // UCVTF Hd,Hn,#imm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UCVTF_ASISDMISCFP16_R:
		intrin_id = ARM64_INTRIN_VCVTH_F16_U16;  // UCVTF Hd,Hn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UCVTF_S64_FLOAT2INT:
		intrin_id = ARM64_INTRIN_VCVTH_F16_U16;  // ucvtf s29, x5
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UCVTF_H64_FLOAT2INT:
		intrin_id = ARM64_INTRIN_VCVTH_F16_U64;  // ucvtf h3, x2
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UCVTF_H32_FLOAT2INT:
		intrin_id = ARM64_INTRIN_VCVTH_F16_U32;  // ucvtf h5, w12
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UCVTF_D32_FLOAT2INT:
		intrin_id = ARM64_INTRIN_VCVT_F64_U32;  // ucvtf d0, w7
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UCVTF_ASIMDSHF_C:
		intrin_id = ARM64_INTRIN_VCVT_N_F32_U32;
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UCVTF_ASIMDMISC_R:
		intrin_id = ARM64_INTRIN_VCVT_F32_U32;
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UCVTF_ASIMDMISCFP16_R:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCVT_F32_U32;  // UCVTF Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCVTQ_F32_U32;  // UCVTF Vd.4S,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCVTQ_F64_U64;  // UCVTF Vd.2D,Vn.2D
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCVT_N_F32_U32;  // UCVTF Vd.2S,Vn.2S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCVTQ_N_F32_U32;  // UCVTF Vd.4S,Vn.4S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VCVTQ_N_F64_U64;  // UCVTF Vd.2D,Vn.2D,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCVT_F16_U16;  // UCVTF Vd.4H,Vn.4H,#0
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCVTQ_F16_U16;  // UCVTF Vd.8H,Vn.8H
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCVT_N_F16_U16;  // UCVTF Vd.4H,Vn.4H,#n
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCVTQ_N_F16_U16;  // UCVTF Vd.8H,Vn.8H,#n
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UDOT_ASIMDELEM_D:
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VDOT_LANE_U32;  // UDOT Vd.2S,Vn.8B,Vm.4B[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VDOTQ_LANEQ_U32;  // UDOT Vd.4S,Vn.16B,Vm.4B[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VDOT_LANEQ_U32;  // UDOT Vd.2S,Vn.8B,Vm.4B[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VDOTQ_LANE_U32;  // UDOT Vd.4S,Vn.16B,Vm.4B[lane]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UDOT_ASIMDSAME2_D:
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VDOT_U32;  // UDOT Vd.2S,Vn.8B,Vm.8B
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VDOTQ_U32;  // UDOT Vd.4S,Vn.16B,Vm.16B
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UHADD_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VHADD_U8;  // UHADD Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VHADDQ_U8;  // UHADD Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VHADD_U16;  // UHADD Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VHADDQ_U16;  // UHADD Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VHADD_U32;  // UHADD Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VHADDQ_U32;  // UHADD Vd.4S,Vn.4S,Vm.4S
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UHSUB_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VHSUB_U8;  // UHSUB Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VHSUBQ_U8;  // UHSUB Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VHSUB_U16;  // UHSUB Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VHSUBQ_U16;  // UHSUB Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VHSUB_U32;  // UHSUB Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VHSUBQ_U32;  // UHSUB Vd.4S,Vn.4S,Vm.4S
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UMAXP_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VPMAX_U8;  // UMAXP Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VPMAX_U16;  // UMAXP Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VPMAX_U32;  // UMAXP Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VPMAXQ_U8;  // UMAXP Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VPMAXQ_U16;  // UMAXP Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VPMAXQ_U32;  // UMAXP Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[2].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMAXV_U32;  // UMAXP Vd.2S,Vn.2S,Vm.2S
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UMAXV_ASIMDALL_ONLY:
		intrin_id = ARM64_INTRIN_VMAXV_U8;  // UMAXV Bd,Vn.8B
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UMAX_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VMAX_U8;  // UMAX Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VMAXQ_U8;  // UMAX Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMAX_U16;  // UMAX Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMAXQ_U16;  // UMAX Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMAX_U32;  // UMAX Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMAXQ_U32;  // UMAX Vd.4S,Vn.4S,Vm.4S
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UMINP_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VPMIN_U8;  // UMINP Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VPMIN_U16;  // UMINP Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VPMIN_U32;  // UMINP Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VPMINQ_U8;  // UMINP Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VPMINQ_U16;  // UMINP Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VPMINQ_U32;  // UMINP Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[2].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMINV_U32;  // UMINP Vd.2S,Vn.2S,Vm.2S
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UMINV_ASIMDALL_ONLY:
		intrin_id = ARM64_INTRIN_VMINV_U8;  // UMINV Bd,Vn.8B
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UMIN_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VMIN_U8;  // UMIN Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VMINQ_U8;  // UMIN Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMIN_U16;  // UMIN Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMINQ_U16;  // UMIN Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMIN_U32;  // UMIN Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMINQ_U32;  // UMIN Vd.4S,Vn.4S,Vm.4S
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UMLAL_ASIMDDIFF_L:
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMLAL_U8;  // UMLAL Vd.8H,Vn.8B,Vm.8B
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLAL_U16;  // UMLAL Vd.4S,Vn.4H,Vm.4H
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMLAL_U32;  // UMLAL Vd.2D,Vn.2S,Vm.2S
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMLAL_HIGH_U8;  // UMLAL2 Vd.8H,Vn.16B,Vm.16B
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLAL_HIGH_U16;  // UMLAL2 Vd.4S,Vn.8H,Vm.8H
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMLAL_HIGH_U32;  // UMLAL2 Vd.2D,Vn.4S,Vm.4S
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLAL_N_U16;  // UMLAL Vd.4S,Vn.4H,Vm.H[0]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMLAL_N_U32;  // UMLAL Vd.2D,Vn.2S,Vm.S[0]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLAL_HIGH_N_U16;  // UMLAL2 Vd.4S,Vn.8H,Vm.H[0]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMLAL_HIGH_N_U32;  // UMLAL2 Vd.2D,Vn.4S,Vm.S[0]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UMLAL_ASIMDELEM_L:
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLAL_LANE_U16;  // UMLAL Vd.4S,Vn.4H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMLAL_LANE_U32;  // UMLAL Vd.2D,Vn.2S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLAL_HIGH_LANE_U16;  // UMLAL2 Vd.4S,Vn.8H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMLAL_HIGH_LANE_U32;  // UMLAL2 Vd.2D,Vn.4S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLAL_LANEQ_U16;  // UMLAL Vd.4S,Vn.4H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMLAL_LANEQ_U32;  // UMLAL Vd.2D,Vn.2S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLAL_HIGH_LANEQ_U16;  // UMLAL2 Vd.4S,Vn.8H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMLAL_HIGH_LANEQ_U32;  // UMLAL2 Vd.2D,Vn.4S,Vm.S[lane]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UMLSL_ASIMDDIFF_L:
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMLSL_U8;  // UMLSL Vd.8H,Vn.8B,Vm.8B
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLSL_U16;  // UMLSL Vd.4S,Vn.4H,Vm.4H
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMLSL_U32;  // UMLSL Vd.2D,Vn.2S,Vm.2S
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMLSL_HIGH_U8;  // UMLSL2 Vd.8H,Vn.16B,Vm.16B
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLSL_HIGH_U16;  // UMLSL2 Vd.4S,Vn.8H,Vm.8H
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMLSL_HIGH_U32;  // UMLSL2 Vd.2D,Vn.4S,Vm.4S
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLSL_N_U16;  // UMLSL Vd.4S,Vn.4H,Vm.H[0]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMLSL_N_U32;  // UMLSL Vd.2D,Vn.2S,Vm.S[0]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLSL_HIGH_N_U16;  // UMLSL2 Vd.4S,Vn.8H,Vm.H[0]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMLSL_HIGH_N_U32;  // UMLSL2 Vd.2D,Vn.4S,Vm.S[0]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UMLSL_ASIMDELEM_L:
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLSL_LANE_U16;  // UMLSL Vd.4S,Vn.4H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMLSL_LANE_U32;  // UMLSL Vd.2D,Vn.2S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLSL_HIGH_LANE_U16;  // UMLSL2 Vd.4S,Vn.8H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMLSL_HIGH_LANE_U32;  // UMLSL2 Vd.2D,Vn.4S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLSL_LANEQ_U16;  // UMLSL Vd.4S,Vn.4H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMLSL_LANEQ_U32;  // UMLSL Vd.2D,Vn.2S,Vm.S[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMLSL_HIGH_LANEQ_U16;  // UMLSL2 Vd.4S,Vn.8H,Vm.H[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMLSL_HIGH_LANEQ_U32;  // UMLSL2 Vd.2D,Vn.4S,Vm.S[lane]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UMMLA_ASIMDSAME2_G:
		intrin_id = ARM64_INTRIN_VMMLAQ_U32;  // UMMLA Vd.4S,Vn.16B,Vm.16B
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UMOV_ASIMDINS_W_W:
		intrin_id = ARM64_INTRIN_VGET_LANE_U8;  // UMOV Rd,Vn.B[lane]
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_lane(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UMULL_ASIMDDIFF_L:
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMULL_U8;  // UMULL Vd.8H,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMULL_U16;  // UMULL Vd.4S,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMULL_U32;  // UMULL Vd.2D,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMULL_HIGH_U8;  // UMULL2 Vd.8H,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMULL_HIGH_U16;  // UMULL2 Vd.4S,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMULL_HIGH_U32;  // UMULL2 Vd.2D,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMULL_N_U16;  // UMULL Vd.4S,Vn.4H,Vm.H[0]
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMULL_N_U32;  // UMULL Vd.2D,Vn.2S,Vm.S[0]
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMULL_HIGH_N_U16;  // UMULL2 Vd.4S,Vn.8H,Vm.H[0]
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMULL_HIGH_N_U32;  // UMULL2 Vd.2D,Vn.4S,Vm.S[0]
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UMULL_ASIMDELEM_L:
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMULL_LANE_U16;  // UMULL Vd.4S,Vn.4H,Vm.H[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMULL_LANE_U32;  // UMULL Vd.2D,Vn.2S,Vm.S[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMULL_HIGH_LANE_U16;  // UMULL2 Vd.4S,Vn.8H,Vm.H[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMULL_HIGH_LANE_U32;  // UMULL2 Vd.2D,Vn.4S,Vm.S[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMULL_LANEQ_U16;  // UMULL Vd.4S,Vn.4H,Vm.H[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMULL_LANEQ_U32;  // UMULL Vd.2D,Vn.2S,Vm.S[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMULL_HIGH_LANEQ_U16;  // UMULL2 Vd.4S,Vn.8H,Vm.H[lane]
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMULL_HIGH_LANEQ_U32;  // UMULL2 Vd.2D,Vn.4S,Vm.S[lane]
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UQADD_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VQADD_U8;  // UQADD Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VQADDQ_U8;  // UQADD Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VQADD_U16;  // UQADD Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VQADDQ_U16;  // UQADD Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VQADD_U32;  // UQADD Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQADDQ_U32;  // UQADD Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VQADDQ_U64;  // UQADD Vd.2D,Vn.2D,Vm.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UQADD_ASISDSAME_ONLY:
		intrin_id = ARM64_INTRIN_VQADD_U64;  // UQADD Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UQRSHL_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VQRSHL_U8;  // UQRSHL Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VQRSHLQ_U8;  // UQRSHL Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VQRSHL_U16;  // UQRSHL Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VQRSHLQ_U16;  // UQRSHL Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VQRSHL_U32;  // UQRSHL Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQRSHLQ_U32;  // UQRSHL Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VQRSHLQ_U64;  // UQRSHL Vd.2D,Vn.2D,Vm.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UQRSHL_ASISDSAME_ONLY:
		intrin_id = ARM64_INTRIN_VQRSHL_U64;  // UQRSHL Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UQRSHRN_ASIMDSHF_N:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VQRSHRN_N_U16;  // UQRSHRN Vd.8B,Vn.8H,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VQRSHRN_N_U32;  // UQRSHRN Vd.4H,Vn.4S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VQRSHRN_N_U64;  // UQRSHRN Vd.2S,Vn.2D,#n
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VQRSHRN_HIGH_N_U16;  // UQRSHRN2 Vd.16B,Vn.8H,#n
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VQRSHRN_HIGH_N_U32;  // UQRSHRN2 Vd.8H,Vn.4S,#n
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQRSHRN_HIGH_N_U64;  // UQRSHRN2 Vd.4S,Vn.2D,#n
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UQRSHRN_ASISDSHF_N:
		intrin_id = ARM64_INTRIN_VQRSHRNH_N_U16;  // UQRSHRN Bd,Hn,#n
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UQSHL_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VQSHL_U8;  // UQSHL Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VQSHLQ_U8;  // UQSHL Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VQSHL_U16;  // UQSHL Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VQSHLQ_U16;  // UQSHL Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VQSHL_U32;  // UQSHL Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQSHLQ_U32;  // UQSHL Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VQSHLQ_U64;  // UQSHL Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VQSHLQ_N_U8;  // UQSHL Vd.16B,Vn.16B,#n
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UQSHL_ASISDSAME_ONLY:
		intrin_id = ARM64_INTRIN_VQSHL_U64;  // UQSHL Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UQSHRN_ASIMDSHF_N:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VQSHRN_N_U16;  // UQSHRN Vd.8B,Vn.8H,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VQSHRN_N_U32;  // UQSHRN Vd.4H,Vn.4S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VQSHRN_N_U64;  // UQSHRN Vd.2S,Vn.2D,#n
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VQSHRN_HIGH_N_U16;  // UQSHRN2 Vd.16B,Vn.8H,#n
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VQSHRN_HIGH_N_U32;  // UQSHRN2 Vd.8H,Vn.4S,#n
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQSHRN_HIGH_N_U64;  // UQSHRN2 Vd.4S,Vn.2D,#n
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UQSHRN_ASISDSHF_N:
		intrin_id = ARM64_INTRIN_VQSHRNH_N_U16;  // UQSHRN Bd,Hn,#n
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UQSUB_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VQSUB_U8;  // UQSUB Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VQSUBQ_U8;  // UQSUB Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VQSUB_U16;  // UQSUB Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VQSUBQ_U16;  // UQSUB Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VQSUB_U32;  // UQSUB Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQSUBQ_U32;  // UQSUB Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VQSUBQ_U64;  // UQSUB Vd.2D,Vn.2D,Vm.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UQSUB_ASISDSAME_ONLY:
		intrin_id = ARM64_INTRIN_VQSUB_U64;  // UQSUB Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UQXTN_ASIMDMISC_N:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VQMOVN_U16;  // UQXTN Vd.8B,Vn.8H
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VQMOVN_U32;  // UQXTN Vd.4H,Vn.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VQMOVN_U64;  // UQXTN Vd.2S,Vn.2D
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VQMOVN_HIGH_U16;  // UQXTN2 Vd.16B,Vn.8H
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VQMOVN_HIGH_U32;  // UQXTN2 Vd.8H,Vn.4S
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VQMOVN_HIGH_U64;  // UQXTN2 Vd.4S,Vn.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UQXTN_ASISDMISC_N:
		intrin_id = ARM64_INTRIN_VQMOVNH_U16;  // UQXTN Bd,Hn
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_URECPE_ASIMDMISC_R:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VRECPE_U32;  // URECPE Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VRECPEQ_U32;  // URECPE Vd.4S,Vn.4S
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_URHADD_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VRHADD_U8;  // URHADD Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VRHADDQ_U8;  // URHADD Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VRHADD_U16;  // URHADD Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VRHADDQ_U16;  // URHADD Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VRHADD_U32;  // URHADD Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VRHADDQ_U32;  // URHADD Vd.4S,Vn.4S,Vm.4S
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_URSHL_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VRSHL_U8;  // URSHL Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VRSHLQ_U8;  // URSHL Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VRSHL_U16;  // URSHL Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VRSHLQ_U16;  // URSHL Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VRSHL_U32;  // URSHL Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VRSHLQ_U32;  // URSHL Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VRSHLQ_U64;  // URSHL Vd.2D,Vn.2D,Vm.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_URSHL_ASISDSAME_ONLY:
		intrin_id = ARM64_INTRIN_VRSHL_U64;  // URSHL Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_URSHR_ASIMDSHF_R:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VRSHR_N_U8;  // URSHR Vd.8B,Vn.8B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VRSHR_N_U16;  // URSHR Vd.4H,Vn.4H,#n
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VRSHRQ_N_U16;  // URSHR Vd.8H,Vn.8H,#n
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VRSHR_N_U32;  // URSHR Vd.2S,Vn.2S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VRSHRQ_N_U32;  // URSHR Vd.4S,Vn.4S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VRSHRQ_N_U64;  // URSHR Vd.2D,Vn.2D,#n
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_URSHR_ASISDSHF_R:
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VRSHRQ_N_U8;  // URSHR Vd.16B,Vn.16B,#n
		// if(None) intrin_id = ARM64_INTRIN_VRSHR_N_U64; // URSHR Dd,Dn,#n
		// if(None) intrin_id = ARM64_INTRIN_VRSHRD_N_U64; // URSHR Dd,Dn,#n
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_URSQRTE_ASIMDMISC_R:
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VRSQRTE_U32;  // URSQRTE Vd.2S,Vn.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VRSQRTEQ_U32;  // URSQRTE Vd.4S,Vn.4S
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_URSRA_ASIMDSHF_R:
		if (instr.operands[0].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VRSRA_N_U8;  // URSRA Vd.8B,Vn.8B,#n
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VRSRA_N_U16;  // URSRA Vd.4H,Vn.4H,#n
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VRSRAQ_N_U16;  // URSRA Vd.8H,Vn.8H,#n
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VRSRA_N_U32;  // URSRA Vd.2S,Vn.2S,#n
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VRSRAQ_N_U32;  // URSRA Vd.4S,Vn.4S,#n
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VRSRAQ_N_U64;  // URSRA Vd.2D,Vn.2D,#n
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_URSRA_ASISDSHF_R:
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VRSRAQ_N_U8;  // URSRA Vd.16B,Vn.16B,#n
		// if(None) intrin_id = ARM64_INTRIN_VRSRA_N_U64; // URSRA Dd,Dn,#n
		// if(None) intrin_id = ARM64_INTRIN_VRSRAD_N_U64; // URSRA Dd,Dn,#n
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_USDOT_ASIMDELEM_D:
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VUSDOT_LANE_S32;  // USDOT Vd.2S,Vn.8B,Vm.4B[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VUSDOT_LANEQ_S32;  // USDOT Vd.2S,Vn.8B,Vm.4B[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VUSDOTQ_LANE_S32;  // USDOT Vd.4S,Vn.16B,Vm.4B[lane]
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VUSDOTQ_LANEQ_S32;  // USDOT Vd.4S,Vn.16B,Vm.4B[lane]
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_USDOT_ASIMDSAME2_D:
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VUSDOT_S32;  // USDOT Vd.2S,Vn.8B,Vm.8B
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VUSDOTQ_S32;  // USDOT Vd.4S,Vn.16B,Vm.16B
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_USHLL_ASIMDSHF_L:
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSHLL_N_U8;  // USHLL Vd.8H,Vn.8B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSHLL_N_U16;  // USHLL Vd.4S,Vn.4H,#n
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VSHLL_N_U32;  // USHLL Vd.2D,Vn.2S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSHLL_HIGH_N_U8;  // USHLL2 Vd.8H,Vn.16B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSHLL_HIGH_N_U16;  // USHLL2 Vd.4S,Vn.8H,#n
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VSHLL_HIGH_N_U32;  // USHLL2 Vd.2D,Vn.4S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMOVL_U8;  // USHLL Vd.8H,Vn.8B,#0
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMOVL_U16;  // USHLL Vd.4S,Vn.4H,#0
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMOVL_U32;  // USHLL Vd.2D,Vn.2S,#0
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMOVL_HIGH_U8;  // USHLL2 Vd.8H,Vn.16B,#0
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMOVL_HIGH_U16;  // USHLL2 Vd.4S,Vn.8H,#0
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VMOVL_HIGH_U32;  // USHLL2 Vd.2D,Vn.4S,#0
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_USHL_ASIMDSAME_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VSHL_U8;  // USHL Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VSHLQ_U8;  // USHL Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VSHL_U16;  // USHL Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSHLQ_U16;  // USHL Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VSHL_U32;  // USHL Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSHLQ_U32;  // USHL Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VSHLQ_U64;  // USHL Vd.2D,Vn.2D,Vm.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_USHL_ASISDSAME_ONLY:
		intrin_id = ARM64_INTRIN_VSHL_U64;  // USHL Dd,Dn,Dm
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_USHR_ASIMDSHF_R:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VSHR_N_U8;  // USHR Vd.8B,Vn.8B,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VSHR_N_U16;  // USHR Vd.4H,Vn.4H,#n
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSHRQ_N_U16;  // USHR Vd.8H,Vn.8H,#n
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VSHR_N_U32;  // USHR Vd.2S,Vn.2S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSHRQ_N_U32;  // USHR Vd.4S,Vn.4S,#n
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VSHRQ_N_U64;  // USHR Vd.2D,Vn.2D,#n
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_USHR_ASISDSHF_R:
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VSHRQ_N_U8;  // USHR Vd.16B,Vn.16B,#n
		// if(None) intrin_id = ARM64_INTRIN_VSHR_N_U64; // USHR Dd,Dn,#n
		// if(None) intrin_id = ARM64_INTRIN_VSHRD_N_U64; // USHR Dd,Dn,#n
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_USMMLA_ASIMDSAME2_G:
		intrin_id = ARM64_INTRIN_VUSMMLAQ_S32;  // USMMLA Vd.4S,Vn.16B,Vm.16B
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_USQADD_ASIMDMISC_R:
		if (instr.operands[0].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VSQADD_U8;  // USQADD Vd.8B,Vn.8B
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VSQADDQ_U8;  // USQADD Vd.16B,Vn.16B
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VSQADD_U16;  // USQADD Vd.4H,Vn.4H
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSQADDQ_U16;  // USQADD Vd.8H,Vn.8H
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VSQADD_U32;  // USQADD Vd.2S,Vn.2S
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSQADDQ_U32;  // USQADD Vd.4S,Vn.4S
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VSQADDQ_U64;  // USQADD Vd.2D,Vn.2D
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_USQADD_ASISDMISC_R:
		intrin_id = ARM64_INTRIN_VSQADD_U64;  // USQADD Dd,Dn
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_USRA_ASIMDSHF_R:
		if (instr.operands[0].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VSRA_N_U8;  // USRA Vd.8B,Vn.8B,#n
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VSRA_N_U16;  // USRA Vd.4H,Vn.4H,#n
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSRAQ_N_U16;  // USRA Vd.8H,Vn.8H,#n
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VSRA_N_U32;  // USRA Vd.2S,Vn.2S,#n
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSRAQ_N_U32;  // USRA Vd.4S,Vn.4S,#n
		if (instr.operands[0].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VSRAQ_N_U64;  // USRA Vd.2D,Vn.2D,#n
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_USRA_ASISDSHF_R:
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VSRAQ_N_U8;  // USRA Vd.16B,Vn.16B,#n
		// if(None) intrin_id = ARM64_INTRIN_VSRA_N_U64; // USRA Dd,Dn,#n
		// if(None) intrin_id = ARM64_INTRIN_VSRAD_N_U64; // USRA Dd,Dn,#n
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_imm(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_USUBL_ASIMDDIFF_L:
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSUBL_U8;  // USUBL Vd.8H,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSUBL_U16;  // USUBL Vd.4S,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VSUBL_U32;  // USUBL Vd.2D,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSUBL_HIGH_U8;  // USUBL2 Vd.8H,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSUBL_HIGH_U16;  // USUBL2 Vd.4S,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VSUBL_HIGH_U32;  // USUBL2 Vd.2D,Vn.4S,Vm.4S
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_USUBW_ASIMDDIFF_W:
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSUBW_U8;  // USUBW Vd.8H,Vn.8H,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSUBW_U16;  // USUBW Vd.4S,Vn.4S,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VSUBW_U32;  // USUBW Vd.2D,Vn.2D,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VSUBW_HIGH_U8;  // USUBW2 Vd.8H,Vn.8H,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VSUBW_HIGH_U16;  // USUBW2 Vd.4S,Vn.4S,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VSUBW_HIGH_U32;  // USUBW2 Vd.2D,Vn.2D,Vm.4S
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UZP1_ASIMDPERM_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VUZP1_S8;  // UZP1 Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VUZP1Q_S8;  // UZP1 Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VUZP1_S16;  // UZP1 Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VUZP1Q_S16;  // UZP1 Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VUZP1_S32;  // UZP1 Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VUZP1Q_S32;  // UZP1 Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VUZP1Q_S64;  // UZP1 Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VUZP1_U8;  // UZP1 Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VUZP1Q_U8;  // UZP1 Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VUZP1_U16;  // UZP1 Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VUZP1Q_U16;  // UZP1 Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VUZP1_U32;  // UZP1 Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VUZP1Q_U32;  // UZP1 Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VUZP1Q_U64;  // UZP1 Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VUZP1Q_P64;  // UZP1 Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VUZP1_F32;  // UZP1 Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VUZP1Q_F32;  // UZP1 Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VUZP1Q_F64;  // UZP1 Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VUZP1_P8;  // UZP1 Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VUZP1Q_P8;  // UZP1 Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VUZP1_P16;  // UZP1 Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VUZP1Q_P16;  // UZP1 Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VUZP1_F16;  // UZP1 Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VUZP1Q_F16;  // UZP1 Vd.8H,Vn.8H,Vm.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_UZP2_ASIMDPERM_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VUZP2_S8;  // UZP2 Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VUZP2Q_S8;  // UZP2 Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VUZP2_S16;  // UZP2 Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VUZP2Q_S16;  // UZP2 Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VUZP2_S32;  // UZP2 Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VUZP2Q_S32;  // UZP2 Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VUZP2Q_S64;  // UZP2 Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VUZP2_U8;  // UZP2 Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VUZP2Q_U8;  // UZP2 Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VUZP2_U16;  // UZP2 Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VUZP2Q_U16;  // UZP2 Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VUZP2_U32;  // UZP2 Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VUZP2Q_U32;  // UZP2 Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VUZP2Q_U64;  // UZP2 Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VUZP2Q_P64;  // UZP2 Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VUZP2_F32;  // UZP2 Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VUZP2Q_F32;  // UZP2 Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VUZP2Q_F64;  // UZP2 Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VUZP2_P8;  // UZP2 Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VUZP2Q_P8;  // UZP2 Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VUZP2_P16;  // UZP2 Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VUZP2Q_P16;  // UZP2 Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VUZP2_F16;  // UZP2 Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VUZP2Q_F16;  // UZP2 Vd.8H,Vn.8H,Vm.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_XAR_VVV2_CRYPTO3_IMM6:
		intrin_id = ARM64_INTRIN_VXARQ_U64;  // XAR Vd.2D,Vn.2D,Vm.2D,imm6
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_imm(inputs, il, instr.operands[3]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_XTN_ASIMDMISC_N:
		if (instr.operands[0].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VMOVN_S16;  // XTN Vd.8B,Vn.8H
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMOVN_S32;  // XTN Vd.4H,Vn.4S
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMOVN_S64;  // XTN Vd.2S,Vn.2D
		if (instr.operands[0].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VMOVN_U16;  // XTN Vd.8B,Vn.8H
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VMOVN_U32;  // XTN Vd.4H,Vn.4S
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VMOVN_U64;  // XTN Vd.2S,Vn.2D

		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VMOVN_HIGH_S16;  // XTN2 Vd.16B,Vn.8H
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMOVN_HIGH_S32;  // XTN2 Vd.8H,Vn.4S
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMOVN_HIGH_S64;  // XTN2 Vd.4S,Vn.2D
		if (instr.operands[0].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VMOVN_HIGH_U16;  // XTN2 Vd.16B,Vn.8H
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VMOVN_HIGH_U32;  // XTN2 Vd.8H,Vn.4S
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VMOVN_HIGH_U64;  // XTN2 Vd.4S,Vn.2D
		add_input_reg(inputs, il, instr.operands[1]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_ZIP1_ASIMDPERM_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VZIP1_S8;  // ZIP1 Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VZIP1Q_S8;  // ZIP1 Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VZIP1_S16;  // ZIP1 Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VZIP1Q_S16;  // ZIP1 Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VZIP1_S32;  // ZIP1 Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VZIP1Q_S32;  // ZIP1 Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VZIP1Q_S64;  // ZIP1 Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VZIP1_U8;  // ZIP1 Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VZIP1Q_U8;  // ZIP1 Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VZIP1_U16;  // ZIP1 Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VZIP1Q_U16;  // ZIP1 Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VZIP1_U32;  // ZIP1 Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VZIP1Q_U32;  // ZIP1 Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VZIP1Q_U64;  // ZIP1 Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VZIP1Q_P64;  // ZIP1 Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VZIP1_F32;  // ZIP1 Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VZIP1Q_F32;  // ZIP1 Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VZIP1Q_F64;  // ZIP1 Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VZIP1_P8;  // ZIP1 Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VZIP1Q_P8;  // ZIP1 Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VZIP1_P16;  // ZIP1 Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VZIP1Q_P16;  // ZIP1 Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VZIP1_F16;  // ZIP1 Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VZIP1Q_F16;  // ZIP1 Vd.8H,Vn.8H,Vm.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_ZIP2_ASIMDPERM_ONLY:
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VZIP2_S8;  // ZIP2 Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VZIP2Q_S8;  // ZIP2 Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VZIP2_S16;  // ZIP2 Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VZIP2Q_S16;  // ZIP2 Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VZIP2_S32;  // ZIP2 Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VZIP2Q_S32;  // ZIP2 Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VZIP2Q_S64;  // ZIP2 Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VZIP2_U8;  // ZIP2 Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VZIP2Q_U8;  // ZIP2 Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VZIP2_U16;  // ZIP2 Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VZIP2Q_U16;  // ZIP2 Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VZIP2_U32;  // ZIP2 Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VZIP2Q_U32;  // ZIP2 Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VZIP2Q_U64;  // ZIP2 Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VZIP2Q_P64;  // ZIP2 Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VZIP2_F32;  // ZIP2 Vd.2S,Vn.2S,Vm.2S
		if (instr.operands[1].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VZIP2Q_F32;  // ZIP2 Vd.4S,Vn.4S,Vm.4S
		if (instr.operands[1].arrSpec == ARRSPEC_2DOUBLES)
			intrin_id = ARM64_INTRIN_VZIP2Q_F64;  // ZIP2 Vd.2D,Vn.2D,Vm.2D
		if (instr.operands[1].arrSpec == ARRSPEC_8BYTES)
			intrin_id = ARM64_INTRIN_VZIP2_P8;  // ZIP2 Vd.8B,Vn.8B,Vm.8B
		if (instr.operands[1].arrSpec == ARRSPEC_16BYTES)
			intrin_id = ARM64_INTRIN_VZIP2Q_P8;  // ZIP2 Vd.16B,Vn.16B,Vm.16B
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VZIP2_P16;  // ZIP2 Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VZIP2Q_P16;  // ZIP2 Vd.8H,Vn.8H,Vm.8H
		if (instr.operands[1].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VZIP2_F16;  // ZIP2 Vd.4H,Vn.4H,Vm.4H
		if (instr.operands[1].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VZIP2Q_F16;  // ZIP2 Vd.8H,Vn.8H,Vm.8H
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
		//		case ENC_BFMLALB_Z_ZZZ_:
		//			intrin_id = ARM64_INTRIN_VBFMLALBQ_F32; // BFMLALB Vd.4S,Vn.8H,Vm.8H
		//			add_input_reg(inputs, il, instr.operands[0]);
		//			add_input_reg(inputs, il, instr.operands[1]);
		//			add_input_reg(inputs, il, instr.operands[2]);
		//			add_output_reg(outputs, il, instr.operands[0]);
		//			break;
		//		case ENC_BFMLALB_Z_ZZZI_:
		//			if(instr.operands[0].arrSpec==ARRSPEC_4SINGLES) intrin_id =
		// ARM64_INTRIN_VBFMLALBQ_LANE_F32; // BFMLALB Vd.4S,Vn.8H,Vm.H[lane]
		//			if(instr.operands[0].arrSpec==ARRSPEC_4SINGLES) intrin_id =
		// ARM64_INTRIN_VBFMLALBQ_LANEQ_F32; // BFMLALB Vd.4S,Vn.8H,Vm.H[lane] 			add_input_reg(inputs,
		// il, instr.operands[0]); 			add_input_reg(inputs, il, instr.operands[1]);
		// add_input_reg(inputs, il, instr.operands[2]); 			add_input_lane(inputs, il,
		// instr.operands[2]); 			add_output_reg(outputs, il, instr.operands[0]); 			break; case
		// ENC_BFMLALT_Z_ZZZ_: 			intrin_id = ARM64_INTRIN_VBFMLALTQ_F32; // BFMLALT Vd.4S,Vn.8H,Vm.8H
		// add_input_reg(inputs, il, instr.operands[0]); 			add_input_reg(inputs, il,
		// instr.operands[1]); 			add_input_reg(inputs, il, instr.operands[2]);
		// add_output_reg(outputs, il, instr.operands[0]); 			break; 		case ENC_BFMLALT_Z_ZZZI_:
		//			if(instr.operands[0].arrSpec==ARRSPEC_4SINGLES) intrin_id =
		// ARM64_INTRIN_VBFMLALTQ_LANE_F32; // BFMLALT Vd.4S,Vn.8H,Vm.H[lane]
		//			if(instr.operands[0].arrSpec==ARRSPEC_4SINGLES) intrin_id =
		// ARM64_INTRIN_VBFMLALTQ_LANEQ_F32; // BFMLALT Vd.4S,Vn.8H,Vm.H[lane] 			add_input_reg(inputs,
		// il, instr.operands[0]); 			add_input_reg(inputs, il, instr.operands[1]);
		// add_input_reg(inputs, il, instr.operands[2]); 			add_input_lane(inputs, il,
		// instr.operands[2]); 			add_output_reg(outputs, il, instr.operands[0]); 			break;
	case ENC_FCMLA_Z_ZZZI_H:
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCMLA_ROT180_LANE_F16;  // FCMLA Vd.4H,Vn.4H,Vm.H[lane],#180
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCMLA_ROT180_LANEQ_F16;  // FCMLA Vd.4H,Vn.4H,Vm.H[lane],#180
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCMLAQ_ROT180_LANE_F16;  // FCMLA Vd.8H,Vn.8H,Vm.H[lane],#180
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCMLAQ_ROT180_LANEQ_F16;  // FCMLA Vd.8H,Vn.8H,Vm.H[lane],#180
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCMLA_ROT270_LANE_F16;  // FCMLA Vd.4H,Vn.4H,Vm.H[lane],#270
		if (instr.operands[0].arrSpec == ARRSPEC_4HALVES)
			intrin_id = ARM64_INTRIN_VCMLA_ROT270_LANEQ_F16;  // FCMLA Vd.4H,Vn.4H,Vm.H[lane],#270
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCMLAQ_ROT270_LANE_F16;  // FCMLA Vd.8H,Vn.8H,Vm.H[lane],#270
		if (instr.operands[0].arrSpec == ARRSPEC_8HALVES)
			intrin_id = ARM64_INTRIN_VCMLAQ_ROT270_LANEQ_F16;  // FCMLA Vd.8H,Vn.8H,Vm.H[lane],#270
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;
	case ENC_FCMLA_Z_ZZZI_S:
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCMLA_ROT180_LANE_F32;  // FCMLA Vd.2S,Vn.2S,Vm.2S[lane],#180
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCMLAQ_ROT180_LANE_F32;  // FCMLA Vd.4S,Vn.4S,Vm.S[lane],#180
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCMLAQ_ROT180_LANEQ_F32;  // FCMLA Vd.4S,Vn.4S,Vm.S[lane],#180
		if (instr.operands[0].arrSpec == ARRSPEC_2SINGLES)
			intrin_id = ARM64_INTRIN_VCMLA_ROT270_LANE_F32;  // FCMLA Vd.2S,Vn.2S,Vm.2S[lane],#270
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCMLAQ_ROT270_LANE_F32;  // FCMLA Vd.4S,Vn.4S,Vm.S[lane],#270
		if (instr.operands[0].arrSpec == ARRSPEC_4SINGLES)
			intrin_id = ARM64_INTRIN_VCMLAQ_ROT270_LANEQ_F32;  // FCMLA Vd.4S,Vn.4S,Vm.S[lane],#270
		add_input_reg(inputs, il, instr.operands[0]);
		add_input_reg(inputs, il, instr.operands[1]);
		add_input_reg(inputs, il, instr.operands[2]);
		add_input_lane(inputs, il, instr.operands[2]);
		add_output_reg(outputs, il, instr.operands[0]);
		break;

	default:
		break;
	}

	if (intrin_id != (NeonIntrinsic)ARM64_INTRIN_INVALID)
		il.AddInstruction(il.Intrinsic(outputs, intrin_id, inputs));

	return true;
}
