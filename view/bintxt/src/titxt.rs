use binaryninja::binary_view::{BinaryView, BinaryViewBase, BinaryViewExt};
use binaryninja::custom_binary_view::{
    BinaryViewType, BinaryViewTypeBase, CustomBinaryView, CustomBinaryViewType, CustomView,
    CustomViewBuilder,
};
use binaryninja::rc::Ref;
use binaryninja::segment::SegmentBuilder;

use crate::{
    segment_after_address, segment_from_address, sort_and_merge_segments, MergedSegment,
    MergedSegments, UnmergedSegment,
};

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

// take 0 or more newlines
fn take_newlines(mut input: &[u8]) -> (usize, &[u8]) {
    let mut counter = 0;
    while let Some(rest) = take_newline(input) {
        input = rest;
        counter += 1;
    }
    (counter, input)
}

fn take_byte_line(input: &[u8]) -> Result<(Vec<u8>, &[u8]), ()> {
    // a line can be 16 bytes long, or less in case it's the last line
    let mut current_input = input;
    let mut bytes = Vec::with_capacity(16);

    // line need to have at least one line
    for _i in 0..16 {
        let (byte, rest) =
            take_byte(current_input).ok_or_else(|| log::error!("Unable to parse byte"))?;
        current_input = rest;
        bytes.push(byte);

        match current_input {
            // space with newline ends this line
            [b' ', b'\r', b'\n', rest @ ..] | [b' ', b'\n', rest @ ..] => return Ok((bytes, rest)),
            // bytes are separated by space
            [b' ', rest @ ..] => current_input = rest,
            // newline ends this line
            [b'\r', b'\n', rest @ ..] | [b'\n', rest @ ..] => return Ok((bytes, rest)),
            // other chars are forbidden
            _ => {
                log::error!("Invalid character on data bytes");
                return Err(());
            }
        }
    }
    // can't have more then 16 bytes
    log::error!("Bytes line is too long");
    Err(())
}

fn parse_sections(input: &[u8]) -> Result<(UnmergedSegment, &[u8]), ()> {
    // get the address part of the section
    let (address, input) =
        take_address(input).map_err(|_| log::error!("Unable to parse Address"))?;
    let mut input =
        take_newline(input).ok_or_else(|| log::error!("Unable to find Address delimiter"))?;

    // get one or more bytes
    let mut data = vec![];
    let rest = loop {
        let (line, rest) = take_byte_line(input)?;
        let line_len = line.len();
        data.extend(line);
        input = rest;

        // allow sections to be separated by multiple spaces
        let (new_lines, rest) = take_newlines(input);
        input = rest;

        match input {
            // if after a line we find a 'q', then we found the end of file
            b"q" | b"q\n" | b"q\r\n" => break &[][..],

            // end of file, but with data after
            [b'q', ..] => {
                log::error!("Found data after the end section");
                return Err(());
            }

            // found the next sector
            [b'@', ..] => break input,

            // NOTE: only the last line is allowed to be less then 16 bytes,
            // if less then 16 it's the end of a sector, so we need
            // find a new sector or end of file
            // NOTE: bytes can't be separated by multiple lines, only sections can
            _ if line_len != 16 || new_lines > 0 => {
                log::error!("Unable to find end of section");
                return Err(());
            }

            // line is followed by other line of bytes
            _ => {}
        }
    };

    let segment = UnmergedSegment {
        address: address.into(),
        data,
    };
    Ok((segment, rest))
}

fn parse_ti_txt(data: &[u8]) -> Result<MergedSegments, ()> {
    let mut current_data = data;
    let mut unmerged_segments = vec![];
    while !current_data.is_empty() {
        let (section, rest) = parse_sections(current_data)?;
        current_data = rest;

        unmerged_segments.push(section);
    }
    sort_and_merge_segments(unmerged_segments)
}

pub struct TiTxtViewConstructor {
    pub core: BinaryViewType,
}

impl AsRef<BinaryViewType> for TiTxtViewConstructor {
    fn as_ref(&self) -> &BinaryViewType {
        &self.core
    }
}

impl CustomBinaryViewType for TiTxtViewConstructor {
    fn create_custom_view<'builder>(
        &self,
        parent: &BinaryView,
        builder: CustomViewBuilder<'builder, Self>,
    ) -> Result<CustomView<'builder>, ()> {
        let bytes = parent.len() as usize;
        let mut buf = vec![0; bytes];
        let bytes_read = parent.read(&mut buf, 0);
        if bytes_read != bytes {
            log::error!("IHex file is too small");
            return Err(());
        }
        let sectors = parse_ti_txt(&buf)?;

        let parent_bin = BinaryView::from_data(&parent.file(), &sectors.data)?;
        builder.create::<TiTxtView>(&parent_bin, sectors.segments)
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
    segments: Vec<MergedSegment>,
}

impl AsRef<BinaryView> for TiTxtView {
    fn as_ref(&self) -> &BinaryView {
        &self.core
    }
}

unsafe impl CustomBinaryView for TiTxtView {
    type Args = Vec<MergedSegment>;

    fn new(handle: &BinaryView, _args: &Self::Args) -> Result<Self, ()> {
        Ok(Self {
            core: handle.to_owned(),
            // NOTE dummy value, final values are added on init
            segments: vec![],
        })
    }

    fn init(&mut self, segments: Self::Args) -> Result<(), ()> {
        self.segments = segments;

        for segment in self.segments.iter() {
            self.add_segment(
                SegmentBuilder::from(*segment)
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
        // NOTE: TI TXT don't have any entry point information
        self.segments.first().map(|s| s.address.into()).unwrap_or(0)
    }

    fn default_endianness(&self) -> binaryninja::Endianness {
        binaryninja::Endianness::LittleEndian
    }

    fn address_size(&self) -> usize {
        4
    }

    fn offset_valid(&self, offset: u64) -> bool {
        segment_from_address(&self.segments, offset).is_some()
    }

    fn next_valid_offset_after(&self, offset: u64) -> u64 {
        segment_after_address(&self.segments, offset)
    }
}
