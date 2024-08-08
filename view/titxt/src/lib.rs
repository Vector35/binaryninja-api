use core::cmp::Ordering;
use std::ops::Range;

use binaryninja::binaryview::{BinaryView, BinaryViewBase, BinaryViewExt};
use binaryninja::custombinaryview::{
    BinaryViewType, BinaryViewTypeBase, CustomBinaryView, CustomBinaryViewType, CustomView,
    CustomViewBuilder,
};
use binaryninja::rc::Ref;
use binaryninja::segment::SegmentBuilder;

pub struct TiTxtViewConstructor {
    core: BinaryViewType,
}

impl AsRef<BinaryViewType> for TiTxtViewConstructor {
    fn as_ref(&self) -> &BinaryViewType {
        &self.core
    }
}

struct TiTxtSection {
    address: u16,
    data: Vec<u8>,
}

fn hex_to_byte(char: u8) -> Option<u8> {
    match char {
        b'0'..=b'9' => Some(char - b'0'),
        b'a'..=b'f' => Some(0xa + (char - b'a')),
        b'A'..=b'F' => Some(0xA + (char - b'A')),
        _ => None,
    }
}

fn take_address(input: &[u8]) -> Result<(u16, &[u8]), ()> {
    let [b'@', b1, b2, b3, b4, rest @ ..] = input else {
        return Err(());
    };
    let b1 = hex_to_byte(*b1).map(u16::from).ok_or(())?;
    let b2 = hex_to_byte(*b2).map(u16::from).ok_or(())?;
    let b3 = hex_to_byte(*b3).map(u16::from).ok_or(())?;
    let b4 = hex_to_byte(*b4).map(u16::from).ok_or(())?;
    let value = b1 << 12 | b2 << 8 | b3 << 4 | b4;
    Ok((value, rest))
}

fn take_byte(input: &[u8]) -> Option<(u8, &[u8])> {
    let [b1, b2, rest @ ..] = input else {
        return None;
    };
    let b1 = hex_to_byte(*b1)?;
    let b2 = hex_to_byte(*b2)?;
    let value = b1 << 4 | b2;
    Some((value, rest))
}

fn take_newline(input: &[u8]) -> Option<&[u8]> {
    match input {
        [b'\r', b'\n', rest @ ..] => Some(rest),
        [b'\n', rest @ ..] => Some(rest),
        _ => None,
    }
}

fn parse_section(input: &[u8]) -> Result<(TiTxtSection, &[u8]), ()> {
    let (address, input) =
        take_address(input).map_err(|_| log::error!("Unable to parse Address"))?;
    let mut input =
        take_newline(input).ok_or_else(|| log::error!("Unable to find Address delimiter"))?;

    // get one or more bytes
    let mut data = vec![];
    let rest = loop {
        let (byte, rest) = take_byte(input).ok_or_else(|| log::error!("Unable to parse byte"))?;
        input = rest;
        data.push(byte);

        // bytes are separated by space or new line
        if input[0] == b' ' {
            input = &input[1..];
        } else {
            let rest = take_newline(input)
                .ok_or_else(|| log::error!("Unable to find Address delimiter"))?;
            input = rest;
        }

        match input {
            // if after a byte we find a 'q', then we found the end of file
            b"q" | b"q\n" | b"q\r\n" => break &[][..],

            // end of file, but with data after
            [b'q', ..] => {
                log::error!("Found data after the end section");
                return Err(());
            }

            // found the next sector
            [b'@', ..] => break input,

            // just get the next byte
            _ => {}
        }
    };

    Ok((TiTxtSection { address, data }, rest))
}

fn parse_ti_txt(data: &[u8]) -> Result<(Vec<u8>, TiTxtViewData), ()> {
    let mut current_data = data;
    let mut unmerged_data = vec![];
    while !current_data.is_empty() {
        let (section, rest) = parse_section(current_data)?;
        current_data = rest;

        unmerged_data.push(section);
    }

    // condensate the blocks, sort blocks by address and len
    unmerged_data.sort_unstable_by_key(|sector| sector.address);

    // make sure they don't overlap and merge then if they extend each other
    let mut data: Vec<u8> =
        Vec::with_capacity(unmerged_data.iter().map(|sector| sector.data.len()).sum());
    let mut segments: Vec<TiTxtViewSegment> = Vec::with_capacity(unmerged_data.len());
    for chunk in unmerged_data.into_iter() {
        match segments.last_mut() {
            // if have a last segment and the current chunk just extend it, merge both
            Some(last) if chunk.address == last.end() => {
                last.len += chunk.data.len();
            }
            // the same sector overlap, then the data was defined multiple times.
            Some(last) if chunk.address < last.end() => {
                log::error!("Chunks of data overlap");
                return Err(());
            }
            // otherwise just create a new segment
            _ => {
                segments.push(TiTxtViewSegment {
                    address: chunk.address,
                    len: chunk.data.len(),
                    data_offset: data.len(),
                });
            }
        }
        data.extend(chunk.data);
    }

    Ok((data, TiTxtViewData { segments }))
}

impl CustomBinaryViewType for TiTxtViewConstructor {
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
        let (data, sectors) = parse_ti_txt(&buf)?;

        let parent_bin = BinaryView::from_data(&parent.file(), &data)?;
        builder.create::<TiTxtView>(&parent_bin, sectors)
    }
}

impl BinaryViewTypeBase for TiTxtViewConstructor {
    fn is_valid_for(&self, data: &BinaryView) -> bool {
        let mut first_bytes = [0u8; 16];
        let read_bytes = data.read(&mut first_bytes, 0);

        let [b'@', b1, b2, b3, b4, b'\r' | b'\n', ..] = first_bytes[0..read_bytes] else {
            return false;
        };
        b1.is_ascii_hexdigit()
            && b2.is_ascii_hexdigit()
            && b3.is_ascii_hexdigit()
            && b4.is_ascii_hexdigit()
    }

    fn is_deprecated(&self) -> bool {
        false
    }
}

pub struct TiTxtView {
    core: Ref<BinaryView>,
    segments: Vec<TiTxtViewSegment>,
}

pub struct TiTxtViewSegment {
    address: u16,
    len: usize,
    data_offset: usize,
}

impl TiTxtViewSegment {
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

    fn end(&self) -> u16 {
        self.address + u16::try_from(self.len).unwrap()
    }
}

pub struct TiTxtViewData {
    segments: Vec<TiTxtViewSegment>,
}

impl AsRef<BinaryView> for TiTxtView {
    fn as_ref(&self) -> &BinaryView {
        &self.core
    }
}

impl TiTxtView {
    fn sector_from_address(&self, offset: u64) -> Option<&TiTxtViewSegment> {
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

unsafe impl CustomBinaryView for TiTxtView {
    type Args = TiTxtViewData;

    fn new(handle: &BinaryView, _args: &Self::Args) -> Result<Self, ()> {
        Ok(Self {
            core: handle.to_owned(),
            // NOTE dummy value, final values are added on init
            segments: vec![],
        })
    }

    fn init(&mut self, TiTxtViewData { segments }: Self::Args) -> Result<(), ()> {
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

impl BinaryViewBase for TiTxtView {
    fn entry_point(&self) -> u64 {
        self.segments.first().map(|s| s.address.into()).unwrap_or(0)
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
        let Ok(offset) = u16::try_from(offset) else {
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
    binaryninja::custombinaryview::register_view_type(c"ti-txt", c"TI-TXT", |core| {
        TiTxtViewConstructor { core }
    });
    true
}
