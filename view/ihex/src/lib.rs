use core::cmp::Ordering;
use std::ops::Range;

use binaryninja::binaryview::*;
use binaryninja::custombinaryview::*;
use binaryninja::rc::Ref;
use binaryninja::segment::SegmentBuilder;

pub struct IHexViewConstructor {
    core: BinaryViewType,
}

impl AsRef<BinaryViewType> for IHexViewConstructor {
    fn as_ref(&self) -> &BinaryViewType {
        &self.core
    }
}

impl CustomBinaryViewType for IHexViewConstructor {
    fn create_custom_view<'builder>(
        &self,
        parent: &BinaryView,
        builder: CustomViewBuilder<'builder, Self>,
    ) -> Result<CustomView<'builder>> {
        let bytes = parent.len();
        let mut buf = vec![0; bytes];
        let bytes_read = parent.read(&mut buf, 0);
        if bytes_read != bytes {
            log::error!("IHex file is too small");
            return Err(());
        }
        let string = String::from_utf8(buf).map_err(|_| {
            log::error!("File contains invalid UTF8 characters");
        })?;
        let mut reader = ihex::Reader::new_with_options(
            &string,
            ihex::ReaderOptions {
                stop_after_first_error: true,
                stop_after_eof: true,
            },
        );
        let mut unmerged_data = vec![];
        let mut start = None;
        let mut offset = None;
        while let Some(record) = reader.next() {
            let record = record.map_err(|e| {
                log::error!("Unable to parse record: {e}");
                ()
            })?;
            match record {
                ihex::Record::EndOfFile => break,
                ihex::Record::Data {
                    offset: data_offset,
                    value,
                } => {
                    let address = match offset {
                        Some(IHexOffset::Segment(offset)) => {
                            u32::from(offset) * 16 + u32::from(data_offset)
                        }
                        Some(IHexOffset::Linear(offset)) => {
                            u32::from(offset) << 16 | u32::from(data_offset)
                        }
                        None => data_offset.into(),
                    };
                    // check if the block is just extending the previous one
                    if unmerged_data
                        .last()
                        .map(|(last_address, last_data): &(u32, Vec<u8>)| {
                            usize::try_from(*last_address).unwrap() + last_data.len()
                        })
                        == Some(usize::try_from(address).unwrap())
                    {
                        let (_last_address, last_data) = unmerged_data.last_mut().unwrap();
                        last_data.extend(value);
                    } else {
                        // otherwise just add a new block
                        unmerged_data.push((address, value));
                    }
                }
                ihex::Record::StartSegmentAddress { cs, ip } => {
                    if start.is_some() {
                        log::error!("Multiple Start Address defined");
                        return Err(());
                    }
                    start = Some(IHexStart::Segment { cs, ip });
                }
                ihex::Record::StartLinearAddress(offset) => {
                    if start.is_some() {
                        log::error!("Multiple Start Address defined");
                        return Err(());
                    }
                    start = Some(IHexStart::Linear(offset));
                }
                ihex::Record::ExtendedSegmentAddress(segment_offset) => {
                    offset = Some(IHexOffset::Segment(segment_offset))
                }
                ihex::Record::ExtendedLinearAddress(linear_offset) => {
                    offset = Some(IHexOffset::Linear(linear_offset))
                }
            }
        }
        // can't have other record after the EoF record
        if reader.next().is_some() {
            log::error!("Found record after EoF record");
            return Err(());
        }

        // condensate the blocks
        // sort blocks by address and len
        unmerged_data.sort_unstable_by(|(addr_a, data_a), (addr_b, data_b)| {
            // order by address
            match addr_a.cmp(addr_b) {
                std::cmp::Ordering::Equal => {}
                x => return x,
            };
            // if save address, put the biggest first, so it's easy to error later
            data_a.len().cmp(&data_b.len())
        });
        // make sure they don't overlap and merge then if they extend each other
        let mut data: Vec<u8> =
            Vec::with_capacity(unmerged_data.iter().map(|(_addr, chunk)| chunk.len()).sum());
        let mut segments: Vec<IHexViewSegment> = Vec::with_capacity(unmerged_data.len());
        for (chunk_addr, chunk_data) in unmerged_data.into_iter() {
            match segments.last_mut() {
                // if have a last segment and the current chunk just extend it, merge both
                Some(last) if chunk_addr == last.end() => {
                    last.len += chunk_data.len();
                }
                // the same sector overlap, then the data was defined multiple times.
                Some(last) if chunk_addr < last.end() => {
                    log::error!("Chunks of data overlap");
                    return Err(());
                }
                // otherwise just create a new segment
                _ => {
                    segments.push(IHexViewSegment {
                        address: chunk_addr,
                        len: chunk_data.len(),
                        data_offset: data.len(),
                    });
                }
            }
            data.extend(chunk_data);
        }

        let parent_bin = BinaryView::from_data(&parent.file(), &data)?;
        builder.create::<IHexView>(&parent_bin, IHexViewData { segments, start })
    }
}

impl BinaryViewTypeBase for IHexViewConstructor {
    fn is_valid_for(&self, data: &BinaryView) -> bool {
        // TODO check filename and identify the type if necessary
        //let filename = data.file().filename();
        //let filename = std::path::Path::new(filename.as_str());
        //let filetype = filename
        //    .extension()
        //    .map(|ext| match &ext.to_string_lossy() {
        //        // General-purpose:
        //        "hex" | "mcs" | "int" | "ihex" | "ihe" | "ihx" => Some(true),
        //        // Platform-specific:
        //        "h80" | "h86" | "a43" | "a90" => Some(true),
        //        // Binary or Intel hex:
        //        "obj" | "obl" | "obh" | "rom" | "eep" => Some(true),
        //        // TODO: Split, banked, or paged:
        //        //.hxl–.hxh,[8] .h00–.h15, .p00–.pff[9]
        //        _ => None,
        //    })
        //    .flatten();

        // The smallest valid record is EOF ":00000001FF", 11 bytes
        if data.len() < 11 {
            return false;
        }
        let mut first_bytes = [0u8; 11];
        let read_bytes = data.read(&mut first_bytes, 0);
        if read_bytes < 11 {
            return false;
        }

        // first byte need to be equal to ':'.
        if first_bytes[0] != b':' {
            return false;
        }

        // the next bytes can be any hex char
        if first_bytes[1..]
            .iter()
            .any(|byte| !byte.is_ascii_hexdigit())
        {
            return false;
        }

        true
    }

    fn is_deprecated(&self) -> bool {
        false
    }
}

pub struct IHexView {
    core: Ref<BinaryView>,
    segments: Vec<IHexViewSegment>,
    start: Option<IHexStart>,
}

pub struct IHexViewSegment {
    address: u32,
    len: usize,
    data_offset: usize,
}

impl IHexViewSegment {
    fn address_range(&self) -> Range<u64> {
        self.address.into()..u64::from(self.address) + u64::try_from(self.len).unwrap()
    }

    fn data_range(&self) -> Range<usize> {
        let start = self.data_offset;
        let end = start + self.len;
        start..end
    }

    fn data_range_u64(&self) -> Range<u64> {
        let range = self.data_range();
        range.start.try_into().unwrap()..range.end.try_into().unwrap()
    }

    fn end(&self) -> u32 {
        self.address + u32::try_from(self.len).unwrap()
    }
}

pub struct IHexViewData {
    segments: Vec<IHexViewSegment>,
    start: Option<IHexStart>,
}

#[derive(Clone, Copy, Debug)]
pub enum IHexStart {
    Segment { cs: u16, ip: u16 },
    Linear(u32),
}

#[derive(Clone, Copy, Debug)]
pub enum IHexOffset {
    Segment(u16),
    Linear(u16),
}

impl AsRef<BinaryView> for IHexView {
    fn as_ref(&self) -> &BinaryView {
        &self.core
    }
}

impl IHexView {
    fn sector_from_address(&self, offset: u64) -> Option<&IHexViewSegment> {
        self.segments
            .binary_search_by(|sector| {
                let range = sector.address_range();
                if range.contains(&offset) {
                    return Ordering::Equal;
                }
                offset.cmp(&range.start)
            })
            .ok()
            .map(|idx| &self.segments[idx])
    }
}

unsafe impl CustomBinaryView for IHexView {
    type Args = IHexViewData;

    fn new(handle: &BinaryView, _args: &Self::Args) -> Result<Self> {
        Ok(Self {
            core: handle.to_owned(),
            // NOTE dummy values, final values are added on init
            start: None,
            segments: vec![],
        })
    }

    fn init(&mut self, IHexViewData { start, segments }: Self::Args) -> Result<()> {
        self.start = start;
        self.segments = segments;

        for segment in self.segments.iter() {
            self.add_segment(
                SegmentBuilder::new(segment.address_range())
                    .parent_backing(segment.data_range_u64())
                    .executable(true)
                    .readable(true)
                    .contains_data(true)
                    .contains_code(true),
            );
        }
        Ok(())
    }
}

impl BinaryViewBase for IHexView {
    fn entry_point(&self) -> u64 {
        match self.start {
            Some(IHexStart::Linear(addr)) => addr.into(),
            Some(IHexStart::Segment { cs: _, ip }) => ip.into(),
            None => self.start(),
        }
    }

    fn default_endianness(&self) -> binaryninja::Endianness {
        binaryninja::Endianness::LittleEndian
    }

    fn address_size(&self) -> usize {
        4
    }

    fn offset_valid(&self, offset: u64) -> bool {
        self.sector_from_address(offset).is_some()
    }

    fn next_valid_offset_after(&self, offset: u64) -> u64 {
        let Ok(offset) = u32::try_from(offset) else {
            return offset;
        };
        let sector = self.segments.iter().find_map(|sector| {
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
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginInit() -> bool {
    binaryninja::logger::init(log::LevelFilter::Error).expect("Unable to initialize logger");
    binaryninja::custombinaryview::register_view_type(c"ihex", c"Intel HEX", |core| {
        IHexViewConstructor { core }
    });
    true
}
