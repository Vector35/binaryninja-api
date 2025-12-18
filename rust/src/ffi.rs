// Copyright 2021-2026 Vector 35 Inc.
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

use std::time::{Duration, SystemTime, UNIX_EPOCH};

macro_rules! ffi_wrap {
    ($n:expr, $b:expr) => {{
        use std::panic;
        use std::process;

        panic::catch_unwind(|| $b).unwrap_or_else(|_| {
            ::tracing::error!("ffi callback caught panic: {}", $n);
            process::abort()
        })
    }};
}

pub(crate) fn time_from_bn(timestamp: u64) -> SystemTime {
    let m = Duration::from_secs(timestamp);
    UNIX_EPOCH + m
}

#[macro_export]
macro_rules! ffi_span {
    ($name:expr, $bv:expr) => {{
        use $crate::binary_view::BinaryViewExt;
        #[allow(unused_imports)]
        use $crate::file_metadata::FileMetadata;
        ::tracing::info_span!($name, session_id = $bv.file().session_id().0).entered()
    }};
    ($name:expr) => {
        ::tracing::info_span!($name).entered()
    };
}

macro_rules! new_id_type {
    ($name:ident, $inner_type:ty) => {
        #[derive(std::fmt::Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub $inner_type);

        impl From<$inner_type> for $name {
            fn from(value: $inner_type) -> Self {
                Self(value)
            }
        }

        impl From<$name> for $inner_type {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}
