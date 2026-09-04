// Copyright 2017 pdb Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::common::*;

// OFFCB:
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Slice {
    pub offset: i32, // technically a "long", but... 32 bits for life?
    pub size: u32,
}

// HDR:
//   https://github.com/Microsoft/microsoft-pdb/blob/082c5290e5aff028ae84e43affa8be717aa7af73/PDB/dbi/tpi.h#L45
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Header {
    pub version: u32,
    pub header_size: u32,
    pub minimum_index: u32,
    pub maximum_index: u32,
    pub gprec_size: u32,
    pub tpi_hash_stream: u16,
    pub tpi_hash_pad_stream: u16,
    pub hash_key_size: u32,
    pub hash_bucket_size: u32,
    pub hash_values: Slice,
    pub ti_off: Slice,
    pub hash_adj: Slice, // "offcb of hash head list, maps (hashval,ti), where ti is the head of the hashval chain."
}

impl Header {
    pub(crate) fn empty() -> Self {
        let empty_slice = Slice { offset: 0, size: 0 };

        Self {
            version: 0,
            header_size: 0,
            minimum_index: 0,
            maximum_index: 0,
            gprec_size: 0,
            tpi_hash_stream: 0,
            tpi_hash_pad_stream: 0,
            hash_key_size: 0,
            hash_bucket_size: 0,
            hash_values: empty_slice,
            ti_off: empty_slice,
            hash_adj: empty_slice,
        }
    }

    pub(crate) fn parse(buf: &mut ParseBuffer<'_>) -> Result<Self> {
        debug_assert!(buf.pos() == 0);

        if buf.is_empty() {
            // Special case when the buffer is completely empty. This indicates a missing TPI or IPI
            // stream. In this case, `ItemInformation` acts like an empty shell that never resolves
            // any types.
            return Ok(Self::empty());
        }

        let header = Self {
            version: buf.parse()?,
            header_size: buf.parse()?,
            minimum_index: buf.parse()?,
            maximum_index: buf.parse()?,
            gprec_size: buf.parse()?,
            tpi_hash_stream: buf.parse()?,
            tpi_hash_pad_stream: buf.parse()?,
            hash_key_size: buf.parse()?,
            hash_bucket_size: buf.parse()?,
            hash_values: Slice {
                offset: buf.parse()?,
                size: buf.parse()?,
            },
            ti_off: Slice {
                offset: buf.parse()?,
                size: buf.parse()?,
            },
            hash_adj: Slice {
                offset: buf.parse()?,
                size: buf.parse()?,
            },
        };

        // we read 56 bytes
        // make sure that's okay
        let bytes_read = buf.pos() as u32;
        if header.header_size < bytes_read {
            return Err(Error::InvalidTypeInformationHeader(
                "header size is impossibly small",
            ));
        } else if header.header_size > 1024 {
            return Err(Error::InvalidTypeInformationHeader(
                "header size is unreasonably large",
            ));
        }

        // consume anything else the header says belongs to the header
        buf.take((header.header_size - bytes_read) as usize)?;

        // do some final validations
        if header.minimum_index < 4096 {
            return Err(Error::InvalidTypeInformationHeader(
                "minimum type index is < 4096",
            ));
        }
        if header.maximum_index < header.minimum_index {
            return Err(Error::InvalidTypeInformationHeader(
                "maximum type index is < minimum type index",
            ));
        }

        // success
        Ok(header)
    }
}
