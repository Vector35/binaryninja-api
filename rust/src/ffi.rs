// Copyright 2021-2022 Vector 35 Inc.
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
