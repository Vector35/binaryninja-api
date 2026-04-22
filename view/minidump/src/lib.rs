use crate::view::MinidumpBinaryViewType;
use binaryninja::binary_view::register_binary_view_type;

mod view;

#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginInit() -> bool {
    binaryninja::tracing_init!("Minidump");
    register_binary_view_type(MinidumpBinaryViewType);
    true
}
