use std::str;

use log::{debug, error, info};
use minidump::{Minidump, MinidumpMemoryInfoList};

use binaryninja::binary_view::{BinaryView, BinaryViewBase, BinaryViewExt};

pub fn print_memory_information(bv: &BinaryView) {
    debug!("Printing memory information");
    if let Some(minidump_bv) = bv.parent_view() {
        if let Ok(read_buffer) = minidump_bv.read_buffer(0, minidump_bv.len() as usize) {
            if let Ok(minidump_obj) = Minidump::read(read_buffer.get_data()) {
                if let Ok(memory_info_list) = minidump_obj.get_stream::<MinidumpMemoryInfoList>() {
                    let mut memory_info_list_writer = Vec::new();
                    match memory_info_list.print(&mut memory_info_list_writer) {
                        Ok(_) => {
                            if let Ok(memory_info_str) = str::from_utf8(&memory_info_list_writer) {
                                info!("{memory_info_str}");
                            } else {
                                error!("Could not convert the memory information description from minidump into a valid string");
                            }
                        }
                        Err(_) => {
                            error!("Could not get memory information from minidump");
                        }
                    }
                } else {
                    error!(
                        "Could not parse a valid MinidumpMemoryInfoList stream from the minidump"
                    );
                }
            } else {
                error!("Could not parse a valid minidump file from the parent binary view's data buffer");
            }
        } else {
            error!("Could not read data from parent binary view");
        }
    } else {
        error!("Could not get the parent binary view");
    }
}
