mod ihex;
mod srec;
mod titxt;

use binaryninja::segment::SegmentBuilder;
use ihex::*;
use srec::*;
use titxt::*;

use binaryninja::logger::Logger;
use log::LevelFilter;
use std::ops::Range;

#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginInit() -> bool {
    Logger::new("BINTXT").with_level(LevelFilter::Info).init();

    binaryninja::custom_binary_view::register_view_type(c"ti-txt", c"TI-TXT", |core| {
        TiTxtViewConstructor { core }
    });

    binaryninja::custom_binary_view::register_view_type(c"srec", c"Motorola S-record", |core| {
        SRecViewConstructor { core }
    });

    binaryninja::custom_binary_view::register_view_type(c"ihex", c"Intel HEX", |core| {
        IHexViewConstructor { core }
    });

    true
}

struct UnmergedSegment {
    address: u64,
    data: Vec<u8>,
}

impl UnmergedSegment {
    fn end(&self) -> u64 {
        self.address + u64::try_from(self.data.len()).unwrap()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct MergedSegment {
    address: u64,
    len: u64,
    data_offset: u64,
}

impl MergedSegment {
    fn address_range(&self) -> Range<u64> {
        self.address..self.end()
    }

    fn data_range(&self) -> Range<u64> {
        self.data_offset..self.data_offset + self.len
    }

    fn end(&self) -> u64 {
        self.address + self.len
    }
}

impl From<MergedSegment> for SegmentBuilder {
    fn from(segment: MergedSegment) -> Self {
        SegmentBuilder::new(segment.address_range()).parent_backing(segment.data_range())
    }
}

struct MergedSegments {
    data: Vec<u8>,
    segments: Vec<MergedSegment>,
}

fn sort_and_merge_segments(mut unmerged_data: Vec<UnmergedSegment>) -> Result<MergedSegments, ()> {
    // sort segments by address and len, so we can detect overlaps
    unmerged_data.sort_unstable_by_key(|segment| (segment.address, segment.data.len()));

    let mut data: Vec<u8> =
        Vec::with_capacity(unmerged_data.iter().map(|sector| sector.data.len()).sum());
    let mut segments: Vec<MergedSegment> = Vec::with_capacity(unmerged_data.len());
    for segment in unmerged_data.into_iter() {
        // add the data to the data poll
        let data_offset = u64::try_from(data.len()).unwrap();
        let segment_len = u64::try_from(segment.data.len()).unwrap();
        data.extend(segment.data);
        match segments.last_mut() {
            // if have a last segment and the current chunk just extend it, merge both
            Some(last) if segment.address == last.end() => last.len += segment_len,
            // the same sector overlap, then the data was defined multiple times.
            Some(last) if segment.address < last.end() => {
                log::error!("Chunks of data overlap");
                return Err(());
            }
            // otherwise just create a new segment
            _ => segments.push(MergedSegment {
                address: segment.address,
                len: segment_len,
                data_offset,
            }),
        }
    }

    Ok(MergedSegments { data, segments })
}

fn segment_from_address(segments: &[MergedSegment], offset: u64) -> Option<&MergedSegment> {
    segments
        .binary_search_by(|segment| {
            let range = segment.address_range();
            if range.contains(&offset) {
                return core::cmp::Ordering::Equal;
            }
            offset.cmp(&range.start)
        })
        .ok()
        .map(|idx| &segments[idx])
}

fn segment_after_address(segments: &[MergedSegment], offset: u64) -> u64 {
    let sector = segments.iter().find_map(|sector| {
        if sector.address >= offset {
            Some(sector.address)
        } else if sector.end() < offset {
            Some(offset)
        } else {
            None
        }
    });
    sector.unwrap_or(offset).into()
}
