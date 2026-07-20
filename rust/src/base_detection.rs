use binaryninjacore_sys::*;
use std::ffi::CStr;

use crate::architecture::CoreArchitecture;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner};
use crate::string::IntoCStr;
use std::num::NonZeroU32;
use std::ptr::NonNull;

pub type BaseAddressDetectionPOISetting = BNBaseAddressDetectionPOISetting;
pub type BaseAddressDetectionConfidence = BNBaseAddressDetectionConfidence;
pub type BaseAddressDetectionPOIType = BNBaseAddressDetectionPOIType;
pub type BaseAddressDetectionAnalysisMode = BNBaseAddressDetectionAnalysisMode;

/// This is the architecture name used to use the architecture auto-detection feature.
const BASE_ADDRESS_AUTO_DETECTION_ARCH: &str = "auto detect";

pub enum BaseAddressDetectionAnalysis {
    Basic,
    ControlFlow,
    Full,
}

impl BaseAddressDetectionAnalysis {
    pub fn as_raw(&self) -> &'static CStr {
        match self {
            BaseAddressDetectionAnalysis::Basic => c"basic",
            BaseAddressDetectionAnalysis::ControlFlow => c"controlFlow",
            BaseAddressDetectionAnalysis::Full => c"full",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BaseAddressDetectionResult {
    pub scores: Vec<BaseAddressDetectionScore>,
    pub confidence: BaseAddressDetectionConfidence,
    pub last_base: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BaseAddressDetectionScore {
    pub score: usize,
    pub base_address: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BaseAddressDetectionReason {
    pub pointer: u64,
    pub poi_offset: u64,
    pub poi_type: BaseAddressDetectionPOIType,
}

impl CoreArrayProvider for BaseAddressDetectionReason {
    type Raw = BNBaseAddressDetectionReason;
    type Context = ();
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for BaseAddressDetectionReason {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        unsafe { BNFreeBaseAddressDetectionReasons(raw) }
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        unsafe {
            // SAFETY BNBaseAddressDetectionReason and BaseAddressDetectionReason
            // are transparent
            std::mem::transmute::<&BNBaseAddressDetectionReason, &BaseAddressDetectionReason>(raw)
        }
    }
}

pub struct BaseAddressDetection {
    handle: NonNull<BNBaseAddressDetection>,
}

impl BaseAddressDetection {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNBaseAddressDetection>) -> Self {
        Self { handle }
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNBaseAddressDetection {
        unsafe { &mut *self.handle.as_ptr() }
    }

    /// Indicates whether base address detection analysis was aborted early
    pub fn aborted(&self) -> bool {
        unsafe { BNIsBaseAddressDetectionAborted(self.as_raw()) }
    }

    /// Aborts base address detection analysis
    ///
    /// NOTE: Does not stop base address detection until after initial analysis has completed, and
    /// it is in the base address enumeration phase.
    pub fn abort(&self) {
        unsafe { BNAbortBaseAddressDetection(self.as_raw()) }
    }

    /// Returns a list of reasons that can be used to determine why a base
    /// address is a candidate
    pub fn get_reasons(&self, base_address: u64) -> Array<BaseAddressDetectionReason> {
        let mut count = 0;
        let reasons =
            unsafe { BNGetBaseAddressDetectionReasons(self.as_raw(), base_address, &mut count) };
        unsafe { Array::new(reasons, count, ()) }
    }

    pub fn scores(&self, max_candidates: usize) -> BaseAddressDetectionResult {
        let mut scores = vec![BNBaseAddressDetectionScore::default(); max_candidates];
        let mut confidence = BNBaseAddressDetectionConfidence::NoConfidence;
        let mut last_base = 0;
        let num_candidates = unsafe {
            BNGetBaseAddressDetectionScores(
                self.as_raw(),
                scores.as_mut_ptr(),
                scores.len(),
                &mut confidence,
                &mut last_base,
            )
        };
        scores.truncate(num_candidates);
        // SAFETY BNBaseAddressDetectionScore and BaseAddressDetectionScore
        // are transparent
        let scores = unsafe {
            std::mem::transmute::<Vec<BNBaseAddressDetectionScore>, Vec<BaseAddressDetectionScore>>(
                scores,
            )
        };
        BaseAddressDetectionResult {
            scores,
            confidence,
            last_base,
        }
    }

    /// Initial analysis and attempts to identify candidate base addresses
    ///
    /// NOTE: This operation can take a long time to complete depending on the size and complexity
    /// of the binary and the settings used.
    pub fn detect(&self, settings: &BaseAddressDetectionSettings) -> bool {
        let mut raw_settings = BaseAddressDetectionSettings::into_raw(settings);
        unsafe { BNDetectBaseAddress(self.handle.as_ptr(), &mut raw_settings) }
    }

    /// Use instruction analysis to identify candidate base addresses.
    pub fn detect_with_instruction_analysis(
        &self,
        settings: &BaseAddressDetectionInstructionAnalysisSettings,
    ) -> bool {
        let mut raw_settings = BaseAddressDetectionInstructionAnalysisSettings::into_raw(settings);
        unsafe {
            BNDetectBaseAddressWithInstructionAnalysis(self.handle.as_ptr(), &mut raw_settings)
        }
    }

    /// Sample raw binary contents to identify candidate base addresses.
    pub fn detect_with_sampling(&self, settings: &BaseAddressDetectionSamplingSettings) -> bool {
        let mut raw_settings = BaseAddressDetectionSamplingSettings::into_raw(settings);
        unsafe { BNDetectBaseAddressWithSampling(self.handle.as_ptr(), &mut raw_settings) }
    }
}

impl Drop for BaseAddressDetection {
    fn drop(&mut self) {
        unsafe { BNFreeBaseAddressDetection(self.as_raw()) }
    }
}

/// Builds the initial analysis settings for base address detection.
pub struct BaseAddressDetectionSettings {
    arch: Option<CoreArchitecture>,
    /// Analysis mode to use
    analysis: BaseAddressDetectionAnalysis,
    /// Minimum length of a string to be considered a point-of-interest
    min_string_len: u32,
    /// Byte boundary to align the base address to while brute-forcing
    alignment: NonZeroU32,
    /// Lower boundary of the base address range to test
    lower_boundary: u64,
    /// Upper boundary of the base address range to test
    upper_boundary: u64,
    /// Specifies types of points-of-interest to use for analysis
    poi_analysis: BaseAddressDetectionPOISetting,
    /// Maximum number of candidate pointers to collect per pointer cluster
    max_pointers: u32,
    /// Base address detection algorithm to use
    analysis_mode: BaseAddressDetectionAnalysisMode,
}

impl BaseAddressDetectionSettings {
    pub(crate) fn into_raw(value: &Self) -> BNBaseAddressDetectionSettings {
        let arch_name = value
            .arch
            .map(|a| a.name())
            .unwrap_or(BASE_ADDRESS_AUTO_DETECTION_ARCH.to_string());
        let c_arch_name = arch_name.to_cstr();
        BNBaseAddressDetectionSettings {
            Architecture: c_arch_name.into_raw(),
            Analysis: value.analysis.as_raw().as_ptr(),
            MinStrlen: value.min_string_len,
            Alignment: value.alignment.get(),
            LowerBoundary: value.lower_boundary,
            UpperBoundary: value.upper_boundary,
            POIAnalysis: value.poi_analysis,
            MaxPointersPerCluster: value.max_pointers,
            AnalysisMode: value.analysis_mode,
        }
    }

    pub fn arch(mut self, value: CoreArchitecture) -> Self {
        self.arch = Some(value);
        self
    }

    pub fn analysis(mut self, value: BaseAddressDetectionAnalysis) -> Self {
        self.analysis = value;
        self
    }

    pub fn min_strlen(mut self, value: u32) -> Self {
        self.min_string_len = value;
        self
    }

    pub fn alignment(mut self, value: NonZeroU32) -> Self {
        self.alignment = value;
        self
    }

    /// Specify the lower boundary of the base address range to test.
    ///
    /// NOTE: The passed `value` **must** be less than the upper boundary.
    pub fn low_boundary(mut self, value: u64) -> Self {
        assert!(
            self.upper_boundary >= value,
            "upper boundary must be greater than lower boundary"
        );
        self.lower_boundary = value;
        self
    }

    /// Specify the upper boundary of the base address range to test.
    ///
    /// NOTE: The passed `value` **must** be greater than the lower boundary.
    pub fn high_boundary(mut self, value: u64) -> Self {
        assert!(
            self.lower_boundary <= value,
            "upper boundary must be greater than lower boundary"
        );
        self.upper_boundary = value;
        self
    }

    pub fn poi_analysis(mut self, value: BaseAddressDetectionPOISetting) -> Self {
        self.poi_analysis = value;
        self
    }

    /// Specify the maximum number of candidate pointers to collect per pointer cluster.
    ///
    /// NOTE: The passed `value` **must** be at least 2.
    pub fn max_pointers(mut self, value: u32) -> Self {
        assert!(value > 2, "max pointers must be at least 2");
        self.max_pointers = value;
        self
    }

    pub fn analysis_mode(mut self, value: BaseAddressDetectionAnalysisMode) -> Self {
        self.analysis_mode = value;
        self
    }
}

impl Default for BaseAddressDetectionSettings {
    fn default() -> Self {
        BaseAddressDetectionSettings {
            arch: None,
            analysis: BaseAddressDetectionAnalysis::Full,
            min_string_len: 10,
            alignment: 1024.try_into().unwrap(),
            lower_boundary: u64::MIN,
            upper_boundary: u64::MAX,
            poi_analysis: BaseAddressDetectionPOISetting::POIAnalysisAll,
            max_pointers: 128,
            analysis_mode:
                BaseAddressDetectionAnalysisMode::InstructionAnalysisBaseAddressDetection,
        }
    }
}

/// Settings shared by each base address detection mode.
pub struct BaseAddressDetectionCommonSettings {
    arch: Option<CoreArchitecture>,
    /// Minimum length of a string to be considered a point-of-interest
    min_string_len: u32,
    /// Lower boundary of the base address range to test
    lower_boundary: u64,
    /// Upper boundary of the base address range to test
    upper_boundary: u64,
}

impl BaseAddressDetectionCommonSettings {
    fn into_raw(value: &Self) -> BNBaseAddressDetectionCommonSettings {
        let arch_name = value
            .arch
            .map(|a| a.name())
            .unwrap_or(BASE_ADDRESS_AUTO_DETECTION_ARCH.to_string());
        let c_arch_name = arch_name.to_cstr();
        BNBaseAddressDetectionCommonSettings {
            Architecture: c_arch_name.into_raw(),
            MinStrlen: value.min_string_len,
            LowerBoundary: value.lower_boundary,
            UpperBoundary: value.upper_boundary,
        }
    }

    pub fn arch(mut self, value: CoreArchitecture) -> Self {
        self.arch = Some(value);
        self
    }

    pub fn min_strlen(mut self, value: u32) -> Self {
        self.min_string_len = value;
        self
    }

    /// Specify the lower boundary of the base address range to test.
    ///
    /// NOTE: The passed `value` **must** be less than the upper boundary.
    pub fn low_boundary(mut self, value: u64) -> Self {
        assert!(
            self.upper_boundary >= value,
            "upper boundary must be greater than lower boundary"
        );
        self.lower_boundary = value;
        self
    }

    /// Specify the upper boundary of the base address range to test.
    ///
    /// NOTE: The passed `value` **must** be greater than the lower boundary.
    pub fn high_boundary(mut self, value: u64) -> Self {
        assert!(
            self.lower_boundary <= value,
            "upper boundary must be greater than lower boundary"
        );
        self.upper_boundary = value;
        self
    }
}

impl Default for BaseAddressDetectionCommonSettings {
    fn default() -> Self {
        Self {
            arch: None,
            min_string_len: 10,
            lower_boundary: u64::MIN,
            upper_boundary: u64::MAX,
        }
    }
}

/// Settings for instruction analysis base address detection.
pub struct BaseAddressDetectionInstructionAnalysisSettings {
    common: BaseAddressDetectionCommonSettings,
    /// Analysis mode to use
    analysis: BaseAddressDetectionAnalysis,
    /// Byte boundary to align the base address to while brute-forcing
    alignment: NonZeroU32,
    /// Specifies types of points-of-interest to use for analysis
    poi_analysis: BaseAddressDetectionPOISetting,
    /// Maximum number of candidate pointers to collect per pointer cluster
    max_pointers: u32,
}

impl BaseAddressDetectionInstructionAnalysisSettings {
    pub(crate) fn into_raw(value: &Self) -> BNBaseAddressDetectionInstructionAnalysisSettings {
        BNBaseAddressDetectionInstructionAnalysisSettings {
            Common: BaseAddressDetectionCommonSettings::into_raw(&value.common),
            Analysis: value.analysis.as_raw().as_ptr(),
            Alignment: value.alignment.get(),
            POIAnalysis: value.poi_analysis,
            MaxPointersPerCluster: value.max_pointers,
        }
    }

    pub fn common(mut self, value: BaseAddressDetectionCommonSettings) -> Self {
        self.common = value;
        self
    }

    pub fn arch(mut self, value: CoreArchitecture) -> Self {
        self.common = self.common.arch(value);
        self
    }

    pub fn analysis(mut self, value: BaseAddressDetectionAnalysis) -> Self {
        self.analysis = value;
        self
    }

    pub fn min_strlen(mut self, value: u32) -> Self {
        self.common = self.common.min_strlen(value);
        self
    }

    pub fn alignment(mut self, value: NonZeroU32) -> Self {
        self.alignment = value;
        self
    }

    pub fn low_boundary(mut self, value: u64) -> Self {
        self.common = self.common.low_boundary(value);
        self
    }

    pub fn high_boundary(mut self, value: u64) -> Self {
        self.common = self.common.high_boundary(value);
        self
    }

    pub fn poi_analysis(mut self, value: BaseAddressDetectionPOISetting) -> Self {
        self.poi_analysis = value;
        self
    }

    /// Specify the maximum number of candidate pointers to collect per pointer cluster.
    ///
    /// NOTE: The passed `value` **must** be at least 2.
    pub fn max_pointers(mut self, value: u32) -> Self {
        assert!(value >= 2, "max pointers must be at least 2");
        self.max_pointers = value;
        self
    }
}

impl Default for BaseAddressDetectionInstructionAnalysisSettings {
    fn default() -> Self {
        Self {
            common: BaseAddressDetectionCommonSettings::default(),
            analysis: BaseAddressDetectionAnalysis::Full,
            alignment: 1024.try_into().unwrap(),
            poi_analysis: BaseAddressDetectionPOISetting::POIAnalysisAll,
            max_pointers: 128,
        }
    }
}

/// Settings for sampling base address detection.
pub struct BaseAddressDetectionSamplingSettings {
    common: BaseAddressDetectionCommonSettings,
    /// Byte boundary to align sampled base address candidates to
    alignment: NonZeroU32,
}

impl BaseAddressDetectionSamplingSettings {
    pub(crate) fn into_raw(value: &Self) -> BNBaseAddressDetectionSamplingSettings {
        BNBaseAddressDetectionSamplingSettings {
            Common: BaseAddressDetectionCommonSettings::into_raw(&value.common),
            Alignment: value.alignment.get(),
        }
    }

    pub fn common(mut self, value: BaseAddressDetectionCommonSettings) -> Self {
        self.common = value;
        self
    }

    pub fn arch(mut self, value: CoreArchitecture) -> Self {
        self.common = self.common.arch(value);
        self
    }

    pub fn min_strlen(mut self, value: u32) -> Self {
        self.common = self.common.min_strlen(value);
        self
    }

    pub fn alignment(mut self, value: NonZeroU32) -> Self {
        self.alignment = value;
        self
    }

    pub fn low_boundary(mut self, value: u64) -> Self {
        self.common = self.common.low_boundary(value);
        self
    }

    pub fn high_boundary(mut self, value: u64) -> Self {
        self.common = self.common.high_boundary(value);
        self
    }
}

impl Default for BaseAddressDetectionSamplingSettings {
    fn default() -> Self {
        Self {
            common: BaseAddressDetectionCommonSettings::default(),
            alignment: 4096.try_into().unwrap(),
        }
    }
}
