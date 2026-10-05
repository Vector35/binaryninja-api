#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(unused)]
#![allow(clippy::all)]
#![doc(html_root_url = "https://dev-rust.binary.ninja/")]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(test)]
mod tests {
    use super::BNSymbolDemangleQueueFlags;

    #[test]
    fn symbol_demangle_queue_flags_combine() {
        let flags = BNSymbolDemangleQueueFlags::ApplyRecoveredTypes
            | BNSymbolDemangleQueueFlags::DefineRecoveredTypes;
        assert_eq!(flags.0, 3);
        assert_eq!(
            flags & BNSymbolDemangleQueueFlags::ApplyRecoveredTypes,
            BNSymbolDemangleQueueFlags::ApplyRecoveredTypes
        );
        assert_eq!(
            flags & BNSymbolDemangleQueueFlags::DefineRecoveredTypes,
            BNSymbolDemangleQueueFlags::DefineRecoveredTypes
        );
    }
}
