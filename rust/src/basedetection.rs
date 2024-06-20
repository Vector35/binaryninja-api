use binaryninjacore_sys::*;

use core::{ffi, mem, ptr};

use crate::architecture::CoreArchitecture;
use crate::binaryview::{BinaryView, BinaryViewExt};
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner};

pub type BaseAddressDetectionPOISetting = BNBaseAddressDetectionPOISetting;
pub type BaseAddressDetectionConfidence = BNBaseAddressDetectionConfidence;
pub type BaseAddressDetectionPOIType = BNBaseAddressDetectionPOIType;

pub enum BaseAddressDetectionAnalysis {
    Basic,
    ControlFlow,
    Full,
}

impl BaseAddressDetectionAnalysis {
    pub fn as_raw(&self) -> &'static ffi::CStr {
        let bytes: &[u8] = match self {
            BaseAddressDetectionAnalysis::Basic => b"basic\x00",
            BaseAddressDetectionAnalysis::ControlFlow => b"controlFlow\x00",
            BaseAddressDetectionAnalysis::Full => b"full\x00",
        };
        unsafe { ffi::CStr::from_bytes_with_nul_unchecked(bytes) }
    }
}

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
        BNFreeBaseAddressDetectionReasons(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        // SAFETY BNBaseAddressDetectionReason and BaseAddressDetectionReason
        // are transparent
        mem::transmute::<&BNBaseAddressDetectionReason, &BaseAddressDetectionReason>(raw)
    }
}

/// Build the initial analysis.
///
/// * `arch` - CPU architecture of the binary (defaults to using auto-detection)
/// * `analysis` - analysis mode
/// * `min_strlen` - minimum length of a string to be considered a point-of-interest
/// * `alignment` - byte boundary to align the base address to while brute-forcing
/// * `low_boundary` - lower boundary of the base address range to test
/// * `high_boundary` - upper boundary of the base address range to test
/// * `poi_analysis` - specifies types of points-of-interest to use for analysis
/// * `max_pointers` - maximum number of candidate pointers to collect per pointer cluster
pub struct BaseAddressDetectionBuilder {
    bv: BinaryView,
    arch: Option<CoreArchitecture>,
    analysis: Option<BaseAddressDetectionAnalysis>,
    min_strlen: Option<u32>,
    alignment: Option<core::num::NonZeroU32>,
    low_boundary: Option<u64>,
    high_boundary: Option<u64>,
    poi_analysis: Option<BaseAddressDetectionPOISetting>,
    max_pointers: Option<u32>,
}

impl BaseAddressDetectionBuilder {
    pub fn new(bv: BinaryView) -> Self {
        BaseAddressDetectionBuilder {
            bv,
            arch: None,
            analysis: None,
            min_strlen: None,
            alignment: None,
            low_boundary: None,
            high_boundary: None,
            poi_analysis: None,
            max_pointers: None,
        }
    }

    pub fn arch(mut self, value: CoreArchitecture) -> Self {
        self.arch = Some(value);
        self
    }

    pub fn analysis(mut self, value: BaseAddressDetectionAnalysis) -> Self {
        self.analysis = Some(value);
        self
    }

    pub fn min_strlen(mut self, value: u32) -> Self {
        self.min_strlen = Some(value);
        self
    }

    pub fn alignment(mut self, value: core::num::NonZeroU32) -> Self {
        self.alignment = Some(value);
        self
    }

    pub fn low_boundary(mut self, value: u64) -> Self {
        if let Some(high) = self.high_boundary {
            assert!(
                high >= value,
                "upper boundary must be greater than lower boundary"
            );
        }
        self.low_boundary = Some(value);
        self
    }

    pub fn high_boundary(mut self, value: u64) -> Self {
        if let Some(low) = self.low_boundary {
            assert!(
                low <= value,
                "upper boundary must be greater than lower boundary"
            );
        }
        self.high_boundary = Some(value);
        self
    }

    pub fn poi_analysis(mut self, value: BaseAddressDetectionPOISetting) -> Self {
        self.poi_analysis = Some(value);
        self
    }

    pub fn max_pointers(mut self, value: u32) -> Self {
        assert!(value > 2, "max pointers must be at least 2");
        self.max_pointers = Some(value);
        self
    }

    /// Initial analysis and attempts to identify candidate base addresses
    ///
    /// .. note:: This operation can take a long time to complete depending on
    /// the size and complexity of the binary and the settings used
    pub fn process(self) -> Result<BaseAddressDetection, ()> {
        let arch = self.arch.or_else(|| self.bv.default_arch());
        let arch_name = arch.map(|a| a.name());
        let arch_ptr = arch_name
            .map(|a| a.as_ptr())
            .unwrap_or("\x00".as_ptr() as *const ffi::c_char);

        let analysis = self.analysis.unwrap_or(BaseAddressDetectionAnalysis::Full);
        let min_strlen = self.min_strlen.unwrap_or(10);
        let alignment = self.alignment.map(|a| a.get()).unwrap_or(1024);
        let low_boundary = self.low_boundary.unwrap_or(u64::MIN);
        let high_boundary = self.high_boundary.unwrap_or(u64::MAX);
        let poi_analysis = self
            .poi_analysis
            .unwrap_or(BaseAddressDetectionPOISetting::POIAnalysisAll);
        let max_pointers = self.max_pointers.unwrap_or(128);
        let mut settings = BNBaseAddressDetectionSettings {
            Architecture: arch_ptr,
            Analysis: analysis.as_raw().as_ptr(),
            MinStrlen: min_strlen,
            Alignment: alignment,
            LowerBoundary: low_boundary,
            UpperBoundary: high_boundary,
            POIAnalysis: poi_analysis,
            MaxPointersPerCluster: max_pointers,
        };
        let base =
            ptr::NonNull::new(unsafe { BNCreateBaseAddressDetection(self.bv.handle) }).unwrap();
        let success = unsafe { BNDetectBaseAddress(base.as_ptr(), &mut settings) };
        if success {
            Ok(unsafe { BaseAddressDetection::from_raw(base) })
        } else {
            Err(())
        }
    }
}

pub struct BaseAddressDetection {
    handle: ptr::NonNull<BNBaseAddressDetection>,
}

impl Drop for BaseAddressDetection {
    fn drop(&mut self) {
        unsafe { BNFreeBaseAddressDetection(self.as_raw()) }
    }
}

impl BaseAddressDetection {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNBaseAddressDetection>) -> Self {
        Self { handle }
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNBaseAddressDetection {
        &mut *self.handle.as_ptr()
    }

    /// Indicates whether or not base address detection analysis was aborted early
    pub fn aborted(&self) -> bool {
        unsafe { BNIsBaseAddressDetectionAborted(self.as_raw()) }
    }

    /// Aborts base address detection analysis
    ///
    /// .. note:: `abort` does not stop base address detection until after
    /// initial analysis has completed and it is in the base address enumeration
    /// phase
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
            mem::transmute::<Vec<BNBaseAddressDetectionScore>, Vec<BaseAddressDetectionScore>>(
                scores,
            )
        };
        BaseAddressDetectionResult {
            scores,
            confidence,
            last_base,
        }
    }
}
