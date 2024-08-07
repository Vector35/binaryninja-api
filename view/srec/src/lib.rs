use core::cmp::Ordering;
use std::ops::Range;

use binaryninja::binaryview::{BinaryView, BinaryViewBase, BinaryViewExt};
use binaryninja::custombinaryview::{
    BinaryViewType, BinaryViewTypeBase, CustomBinaryView, CustomBinaryViewType, CustomView,
    CustomViewBuilder,
};
use binaryninja::rc::Ref;
use binaryninja::segment::SegmentBuilder;
use srec::Record;

pub struct SRecViewConstructor {
    core: BinaryViewType,
}

impl AsRef<BinaryViewType> for SRecViewConstructor {
    fn as_ref(&self) -> &BinaryViewType {
        &self.core
    }
}

struct SRecParser<I> {
    reader: I,
    sectors: Vec<(u32, Vec<u8>)>,
    sector_counter: u32,
    start: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RecordLen {
    R16,
    R24,
    R32,
}

impl<I: Iterator<Item = Result<Record, srec::ReaderError>>> SRecParser<I> {
    fn parse(&mut self) -> Result<(), ()> {
        // first sector need to be the header
        let header = self.reader.next();
        let header = header
            .ok_or_else(|| {
                log::error!("Missing header record");
            })?
            .map_err(|e| {
                log::error!("Unable to parse header record: {e}");
            })?;

        let Record::S0(_header_info) = header else {
            log::error!("Invalid first record");
            return Err(());
        };

        // parse the first data record
        let second_record = self
            .reader
            .next()
            .ok_or_else(|| {
                log::error!("Missing first data record");
            })?
            .map_err(|e| {
                log::error!("Unable to parse first data record: {e}");
            })?;
        let (addr_len, first_data_addr, first_data) = match second_record {
            Record::S0(_)
            | Record::S5(_)
            | Record::S6(_)
            | Record::S7(_)
            | Record::S8(_)
            | Record::S9(_) => {
                log::error!("Invalid second record type");
                return Err(());
            }
            Record::S1(s) => (RecordLen::R16, s.address.into(), s.data),
            Record::S2(s) => (RecordLen::R24, s.address.into(), s.data),
            Record::S3(s) => (RecordLen::R32, s.address.into(), s.data),
        };
        self.sector_counter = 1;
        self.sectors.push((first_data_addr, first_data));

        // parse zero or more data after the first until hit a Count (S5, S6)
        // or Start Address (S7, S8, S9) Records
        let next = loop {
            let record = self
                .reader
                .next()
                .ok_or_else(|| {
                    log::error!("Final record can't be data");
                })?
                .map_err(|e| {
                    log::error!("Unable to parse record: {e}");
                })?;
            match record {
                Record::S0(_) => {
                    log::error!("Multiple header records");
                    return Err(());
                }
                Record::S1(s) if addr_len == RecordLen::R16 => {
                    self.add_record_data(s.address.into(), s.data)
                }
                Record::S2(s) if addr_len == RecordLen::R24 => {
                    self.add_record_data(s.address.into(), s.data)
                }
                Record::S3(s) if addr_len == RecordLen::R32 => {
                    self.add_record_data(s.address.into(), s.data)
                }
                Record::S1(_) | Record::S2(_) | Record::S3(_) => {
                    log::error!("Data record with invalid len");
                    return Err(());
                }
                other @ (Record::S5(_)
                | Record::S6(_)
                | Record::S7(_)
                | Record::S8(_)
                | Record::S9(_)) => break other,
            }
        };

        // S5/S6 is an opional last-but-one record
        let last = match next {
            Record::S0(_) | Record::S1(_) | Record::S2(_) | Record::S3(_) => {
                unreachable!()
            }
            Record::S5(s) => {
                self.check_count_record(s.into())?;
                self.reader.next()
            }
            Record::S6(s) => {
                self.check_count_record(s.into())?;
                self.reader.next()
            }
            s @ (Record::S7(_) | Record::S8(_) | Record::S9(_)) => Some(Ok(s)),
        };

        // the last record need to be S7 | S8 | S9
        let last = last
            .ok_or_else(|| {
                log::error!("Missing last record");
            })?
            .map_err(|e| {
                log::error!("Unable to parse last record: {e}");
            })?;
        match last {
            Record::S7(s) => self.start = s.into(),
            Record::S8(s) => self.start = s.into(),
            Record::S9(s) => self.start = s.into(),
            _ => {
                log::error!("Invalid last record type");
                return Err(());
            }
        }

        // can't have any record after S7 | S8 | S9
        if let Some(_s) = self.reader.next() {
            log::error!("Records found after the last");
            return Err(());
        }

        Ok(())
    }

    fn add_record_data(&mut self, address: u32, value: Vec<u8>) {
        self.sector_counter += 1;
        match self.sectors.last_mut() {
            // check if the block is just extending the previous one, merge both
            Some((last_address, last_data))
                if *last_address + u32::try_from(last_data.len()).unwrap() == address =>
            {
                last_data.extend(value);
            }
            // otherwise just add a new block
            _ => {
                self.sectors.push((address, value));
            }
        }
    }

    fn check_count_record(&self, value: u32) -> Result<(), ()> {
        if value != self.sector_counter {
            log::error!("Invalid number of records");
            Err(())
        } else {
            Ok(())
        }
    }
}

fn parse_srec(data: &str) -> Result<(Vec<u8>, SRecViewData), ()> {
    let mut parser = SRecParser {
        reader: srec::reader::read_records(&data),
        sectors: vec![],
        sector_counter: 0,
        start: 0,
    };
    parser.parse()?;

    let mut unmerged_sectors = parser.sectors;
    let start = parser.start;

    // condensate the blocks
    // sort blocks by address and len
    unmerged_sectors.sort_unstable_by(|(addr_a, data_a), (addr_b, data_b)| {
        // order by address
        match addr_a.cmp(addr_b) {
            std::cmp::Ordering::Equal => {}
            x => return x,
        };
        // if save address, put the biggest first, so it's easy to error later
        data_a.len().cmp(&data_b.len())
    });
    // make sure they don't overlap and merge then if they extend each other
    let mut data: Vec<u8> = Vec::with_capacity(
        unmerged_sectors
            .iter()
            .map(|(_addr, chunk)| chunk.len())
            .sum(),
    );
    let mut segments: Vec<SRecViewSegment> = Vec::with_capacity(unmerged_sectors.len());
    for (chunk_addr, chunk_data) in unmerged_sectors.into_iter() {
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
                segments.push(SRecViewSegment {
                    address: chunk_addr,
                    len: chunk_data.len(),
                    data_offset: data.len(),
                });
            }
        }
        data.extend(chunk_data);
    }

    Ok((data, SRecViewData { segments, start }))
}

impl CustomBinaryViewType for SRecViewConstructor {
    fn create_custom_view<'builder>(
        &self,
        parent: &BinaryView,
        builder: CustomViewBuilder<'builder, Self>,
    ) -> Result<CustomView<'builder>, ()> {
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
        let (data, regs) = parse_srec(&string)?;

        let parent_bin = BinaryView::from_data(&parent.file(), &data)?;
        builder.create::<SRecView>(&parent_bin, regs)
    }
}

impl BinaryViewTypeBase for SRecViewConstructor {
    fn is_valid_for(&self, data: &BinaryView) -> bool {
        // TODO check filename and identify the type if necessary
        //let filename = data.file().filename();
        //let filename = std::path::Path::new(filename.as_str());
        //let filetype = filename
        //    .extension()
        //    .map(|ext| match ext.to_string_lossy().as_ref() {
        //        "s19" | "s28" | "s37" | "s" | "s1" | "s2" | "s3" | "sx" | "srec" | "exo"
        //        | "mot" | "mxt" => true,
        //        _ => false,
        //    });

        // The biggest possible record line is 269
        const READ_LEN: usize = 384;
        let mut first_bytes = [0u8; READ_LEN];
        let read_bytes = data.read(&mut first_bytes, 0);
        let line = String::from_utf8_lossy(&first_bytes[0..read_bytes]);
        let first_record: Result<Record, _> = line.parse();
        // first record need to be and S0
        matches!(first_record, Ok(Record::S0(_)))
    }

    fn is_deprecated(&self) -> bool {
        false
    }
}

pub struct SRecView {
    core: Ref<BinaryView>,
    segments: Vec<SRecViewSegment>,
    start: u32,
}

pub struct SRecViewSegment {
    address: u32,
    len: usize,
    data_offset: usize,
}

impl SRecViewSegment {
    fn address_range(&self) -> Range<u64> {
        self.address.into()..u64::from(self.address) + u64::try_from(self.len).unwrap()
    }

    fn data_range(&self) -> Range<usize> {
        let start = usize::try_from(self.data_offset).unwrap();
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

pub struct SRecViewData {
    segments: Vec<SRecViewSegment>,
    start: u32,
}

impl AsRef<BinaryView> for SRecView {
    fn as_ref(&self) -> &BinaryView {
        &self.core
    }
}

impl SRecView {
    fn sector_from_address(&self, offset: u64) -> Option<&SRecViewSegment> {
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

unsafe impl CustomBinaryView for SRecView {
    type Args = SRecViewData;

    fn new(handle: &BinaryView, _args: &Self::Args) -> Result<Self, ()> {
        Ok(Self {
            core: handle.to_owned(),
            // NOTE dummy values, final values are added on init
            start: 0,
            segments: vec![],
        })
    }

    fn init(&mut self, SRecViewData { start, segments }: Self::Args) -> Result<(), ()> {
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

impl BinaryViewBase for SRecView {
    fn entry_point(&self) -> u64 {
        self.start.into()
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
    binaryninja::custombinaryview::register_view_type(c"srec", c"Motorola S-record", |core| {
        SRecViewConstructor { core }
    });
    true
}
