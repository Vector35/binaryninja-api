
macro_rules! ffi_wrap {
    ($n:expr, $b:expr) => {{
        use std::panic;
        use std::process;

        panic::catch_unwind(|| $b).unwrap_or_else(|_| {
            error!("ffi callback caught panic: {}", $n);
            process::abort()
        })
    }}
}

