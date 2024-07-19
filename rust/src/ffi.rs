// Copyright 2021-2024 Vector 35 Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use core::ffi;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

macro_rules! ffi_wrap {
    ($n:expr, $b:expr) => {{
        use std::panic;
        use std::process;

        panic::catch_unwind(|| $b).unwrap_or_else(|_| {
            error!("ffi callback caught panic: {}", $n);
            process::abort()
        })
    }};
}

pub trait ProgressCallback: Sized {
    type SplitProgressType: SplitProgressBuilder;
    fn progress(&mut self, progress: usize, total: usize) -> bool;

    unsafe extern "C" fn cb_progress_callback(
        ctxt: *mut ffi::c_void,
        progress: usize,
        total: usize,
    ) -> bool {
        let ctxt: &mut Self = &mut *(ctxt as *mut Self);
        ctxt.progress(progress, total)
    }
    /// Split a single progress function into proportionally sized subparts.
    /// This function takes the original progress function and returns a new function whose signature
    /// is the same but whose output is shortened to correspond to the specified subparts.
    ///
    /// The length of a subpart is proportional to the sum of all the weights.
    /// E.g. with `subpart_weights = &[ 25, 50, 25 ]`, this will return a function that calls
    /// progress_func and maps its progress to the ranges `[0..=25, 25..=75, 75..=100]`
    ///
    /// Weights of subparts, described above
    ///
    /// * `progress_func` - Original progress function (usually updates a UI)
    /// * `subpart_weights` - Weights of subparts, described above
    fn split(self, subpart_weights: &'static [usize]) -> Self::SplitProgressType;
}

pub trait SplitProgressBuilder {
    type Progress<'a>: ProgressCallback
    where
        Self: 'a;
    fn next_subpart<'a>(&'a mut self) -> Option<Self::Progress<'a>>;
}

impl<F> ProgressCallback for F
where
    F: FnMut(usize, usize) -> bool,
{
    type SplitProgressType = SplitProgress<F>;

    fn progress(&mut self, progress: usize, total: usize) -> bool {
        self(progress, total)
    }

    fn split(self, subpart_weights: &'static [usize]) -> Self::SplitProgressType {
        SplitProgress::new(self, subpart_weights)
    }
}

pub struct ProgressCallbackNop;
impl ProgressCallback for ProgressCallbackNop {
    type SplitProgressType = SplitProgressNop;

    fn progress(&mut self, _progress: usize, _total: usize) -> bool {
        unreachable!()
    }

    unsafe extern "C" fn cb_progress_callback(
        _ctxt: *mut ffi::c_void,
        _progress: usize,
        _total: usize,
    ) -> bool {
        true
    }

    fn split(self, subpart_weights: &'static [usize]) -> Self::SplitProgressType {
        SplitProgressNop(subpart_weights.len())
    }
}

pub struct SplitProgressNop(usize);
impl SplitProgressBuilder for SplitProgressNop {
    type Progress<'a> = ProgressCallbackNop;

    fn next_subpart(&mut self) -> Option<Self::Progress<'_>> {
        if self.0 == 0 {
            return None;
        }
        self.0 -= 1;
        Some(ProgressCallbackNop)
    }
}

pub struct SplitProgress<P> {
    callback: P,
    subpart_weights: &'static [usize],
    total: usize,
    progress: usize,
}

impl<P: ProgressCallback> SplitProgress<P> {
    pub fn new(callback: P, subpart_weights: &'static [usize]) -> Self {
        let total = subpart_weights.iter().sum();
        Self {
            callback,
            subpart_weights,
            total,
            progress: 0,
        }
    }

    pub fn next_subpart(&mut self) -> Option<SplitProgressInstance<'_, P>> {
        if self.subpart_weights.is_empty() {
            return None;
        }
        Some(SplitProgressInstance { progress: self })
    }
}

impl<P: ProgressCallback> SplitProgressBuilder for SplitProgress<P> {
    type Progress<'a> = SplitProgressInstance<'a, P> where Self: 'a;
    fn next_subpart<'a>(&'a mut self) -> Option<Self::Progress<'a>> {
        self.next_subpart()
    }
}

pub struct SplitProgressInstance<'a, P: ProgressCallback> {
    progress: &'a mut SplitProgress<P>,
}

impl<'a, P: ProgressCallback> Drop for SplitProgressInstance<'a, P> {
    fn drop(&mut self) {
        self.progress.progress += self.progress.subpart_weights[0];
        self.progress.subpart_weights = &self.progress.subpart_weights[1..];
    }
}

impl<'a, P: ProgressCallback> ProgressCallback for SplitProgressInstance<'a, P> {
    type SplitProgressType = SplitProgress<Self>;

    fn progress(&mut self, progress: usize, total: usize) -> bool {
        let subpart_progress = (self.progress.subpart_weights[0] * progress) / total;
        let progress = self.progress.progress + subpart_progress;
        self.progress
            .callback
            .progress(progress, self.progress.total)
    }

    fn split(self, subpart_weights: &'static [usize]) -> Self::SplitProgressType {
        SplitProgress::new(self, subpart_weights)
    }
}

pub(crate) fn time_from_bn(timestamp: u64) -> SystemTime {
    let m = Duration::from_secs(timestamp);
    UNIX_EPOCH + m
}

#[cfg(test)]
mod test {
    use std::cell::Cell;

    use super::*;

    #[test]
    fn progress_simple() {
        let progress = Cell::new(0);
        let mut callback = |p, _| {
            progress.set(p);
            true
        };
        callback.progress(0, 100);
        assert_eq!(progress.get(), 0);
        callback.progress(1, 100);
        assert_eq!(progress.get(), 1);
        callback.progress(50, 100);
        assert_eq!(progress.get(), 50);
        callback.progress(99, 100);
        assert_eq!(progress.get(), 99);
        callback.progress(100, 100);
        assert_eq!(progress.get(), 100);
    }

    #[test]
    fn progress_simple_split() {
        let progress = Cell::new(0);
        let callback = |p, _| {
            progress.set(p);
            true
        };
        let mut split = callback.split(&[25, 50, 25]);
        // 0..=25
        let mut split_instance = split.next_subpart().unwrap();
        split_instance.progress(0, 100);
        assert_eq!(progress.get(), 0);
        split_instance.progress(100, 100);
        assert_eq!(progress.get(), 25);
        drop(split_instance);

        // 25..=75
        let mut split_instance = split.next_subpart().unwrap();
        split_instance.progress(0, 100);
        assert_eq!(progress.get(), 25);
        split_instance.progress(25, 100);
        // there is no way to check for exact values, it depends on how the calculation is done,
        // at the time or writing of this test is always round down, but we just check a range because this
        // could change
        assert!((36..=37).contains(&progress.get()));
        split_instance.progress(50, 100);
        assert_eq!(progress.get(), 50);
        split_instance.progress(100, 100);
        assert_eq!(progress.get(), 75);
        drop(split_instance);

        // 75..=100
        let mut split_instance = split.next_subpart().unwrap();
        split_instance.progress(0, 100);
        assert_eq!(progress.get(), 75);
        split_instance.progress(100, 100);
        assert_eq!(progress.get(), 100);
        drop(split_instance);

        assert!(split.next_subpart().is_none());
    }

    #[test]
    fn progress_recursive_split() {
        let progress = Cell::new(0);
        let callback = |p, _| {
            progress.set(p);
            true
        };
        let mut split = callback.split(&[25, 50, 25]);
        // 0..=25
        let mut split_instance = split.next_subpart().unwrap();
        split_instance.progress(0, 100);
        assert_eq!(progress.get(), 0);
        split_instance.progress(100, 100);
        assert_eq!(progress.get(), 25);
        drop(split_instance);

        // 25..=75, will get split into two parts: 25..=50 and 50..=75
        {
            let split_instance = split.next_subpart().unwrap();
            let mut sub_split = split_instance.split(&[50, 50]);
            // 25..=50
            let mut sub_split_instance = sub_split.next_subpart().unwrap();
            sub_split_instance.progress(0, 100);
            assert_eq!(progress.get(), 25);
            sub_split_instance.progress(100, 100);
            assert_eq!(progress.get(), 50);
            drop(sub_split_instance);

            // 50..=75
            let mut sub_split_instance = sub_split.next_subpart().unwrap();
            sub_split_instance.progress(0, 100);
            assert_eq!(progress.get(), 50);
            sub_split_instance.progress(100, 100);
            assert_eq!(progress.get(), 75);
            drop(sub_split_instance);
        }

        // 75..=100
        let mut split_instance = split.next_subpart().unwrap();
        split_instance.progress(0, 100);
        assert_eq!(progress.get(), 75);
        split_instance.progress(100, 100);
        assert_eq!(progress.get(), 100);
        drop(split_instance);

        assert!(split.next_subpart().is_none());
    }
}
