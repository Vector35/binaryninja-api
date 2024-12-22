use crate::segment_after_address;
use crate::segment_from_address;
use crate::sort_and_merge_segments;
use crate::MergedSegment;
use crate::UnmergedSegment;
use binaryninja::binary_view::*;
use binaryninja::custom_binary_view::*;
use binaryninja::platform::Platform;
use binaryninja::rc::Ref;
use binaryninja::segment::SegmentBuilder;
use binaryninja::settings::{QueryOptions, Settings};
use ihex::Record;

fn parse_ihex(string: &str) -> Result<(Vec<u8>, IHexViewData)> {
    let mut reader = ihex::Reader::new(&string);
    let mut unmerged_data: Vec<UnmergedSegment> = vec![];
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
                        u64::from(offset) * 16 + u64::from(data_offset)
                    }
                    Some(IHexOffset::Linear(offset)) => {
                        u64::from(offset) << 16 | u64::from(data_offset)
                    }
                    None => data_offset.into(),
                };
                // check if the block is just extending the previous one
                match unmerged_data.last_mut() {
                    // check if the block is just extending the previous one, merge both
                    Some(last) if last.end() == address => last.data.extend(value),
                    // otherwise just add a new block
                    _ => unmerged_data.push(UnmergedSegment {
                        address,
                        data: value,
                    }),
                }
            }
            ihex::Record::StartSegmentAddress { cs, ip } => {
                if start.is_some() {
                    log::error!("Multiple Start Address defined");
                    return Err(());
                }
                start = Some(IHexStart::Segment { _cs: cs, ip });
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

    let merged = sort_and_merge_segments(unmerged_data)?;
    Ok((
        merged.data,
        IHexViewData {
            segments: merged.segments,
            start,
        },
    ))
}

pub struct IHexViewConstructor {
    pub core: BinaryViewType,
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
        let bytes = parent.len() as usize;
        let mut buf = vec![0; bytes];
        let bytes_read = parent.read(&mut buf, 0);
        if bytes_read != bytes {
            log::error!("IHex file is too small");
            return Err(());
        }
        let string = String::from_utf8(buf).map_err(|_| {
            log::error!("File contains invalid UTF8 characters");
        })?;

        let (data, segments) = parse_ihex(&string)?;

        let parent_bin = BinaryView::from_data(&parent.file(), &data)?;
        builder.create::<IHexView>(&parent_bin, segments)
    }
}

impl BinaryViewTypeBase for IHexViewConstructor {
    fn is_valid_for(&self, data: &BinaryView) -> bool {
        // TODO check filename and identify the type if necessary
        //let filename = data.file().filename();
        //let filename = std::path::Path::new(filename.as_str());
        //let filetype = filename
        //    .extension()
        //    .map(|ext| match ext.to_string_lossy().as_ref() {
        //        // General-purpose:
        //        "hex" | "mcs" | "int" | "ihex" | "ihe" | "ihx" => true,
        //        // Platform-specific:
        //        "h80" | "h86" | "a43" | "a90" => Some(true),
        //        // Binary or Intel hex:
        //        "obj" | "obl" | "obh" | "rom" | "eep" => true,
        //        // TODO: Split, banked, or paged:
        //        //.hxl–.hxh,[8] .h00–.h15, .p00–.pff[9]
        //        _ => false,
        //    });

        // The biggest possible record is data record with 255 bytes: 268 bytes
        let mut first_bytes = [0u8; 384];
        let read_bytes = data.read(&mut first_bytes, 0);
        let data = String::from_utf8_lossy(&first_bytes[0..read_bytes]);
        let Some(line) = data.lines().next() else {
            return false;
        };
        Record::from_record_string(line).is_ok()
    }

    fn is_deprecated(&self) -> bool {
        false
    }

    fn load_settings_for_data(&self, data: &BinaryView) -> Option<Ref<Settings>> {
        self.default_load_settings_for_data(&data).map(|s| {
            s.update_bool_property("loader.platform", "readOnly", false);
            s.update_bool_property("loader.imageBase", "readOnly", false);
            s.update_bool_property("loader.segments", "readOnly", false);
            s
        })
    }
}

pub struct IHexView {
    core: Ref<BinaryView>,
    segments: Vec<MergedSegment>,
    start: Option<IHexStart>,
}

pub struct IHexViewData {
    segments: Vec<MergedSegment>,
    start: Option<IHexStart>,
}

#[derive(Clone, Copy, Debug)]
enum IHexStart {
    Segment { _cs: u16, ip: u16 },
    Linear(u32),
}

#[derive(Clone, Copy, Debug)]
enum IHexOffset {
    Segment(u16),
    Linear(u16),
}

impl AsRef<BinaryView> for IHexView {
    fn as_ref(&self) -> &BinaryView {
        &self.core
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
                SegmentBuilder::from(*segment)
                    .executable(true)
                    .readable(true)
                    .contains_data(true)
                    .contains_code(true),
            );
        }

        // TODO: Because we detached from the raw view this setting will never be set.
        let mut settings_query_opts = QueryOptions::new_with_view(&self.core);
        let _ = self.core.load_settings(self.type_name()).map(|s| {
            let platform_name = s.get_string_with_opts("loader.platform", &mut settings_query_opts);
            if let Some(platform) = Platform::by_name(platform_name) {
                self.set_default_platform(&platform);
            }
        });

        Ok(())
    }
}

impl BinaryViewBase for IHexView {
    fn entry_point(&self) -> u64 {
        match self.start {
            Some(IHexStart::Linear(addr)) => addr.into(),
            Some(IHexStart::Segment { _cs, ip }) => ip.into(),
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
        segment_from_address(&self.segments, offset).is_some()
    }

    fn next_valid_offset_after(&self, offset: u64) -> u64 {
        segment_after_address(&self.segments, offset)
    }
}
