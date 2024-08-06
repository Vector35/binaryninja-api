use core::cmp::Ordering;

use binaryninja::binaryview::*;
use binaryninja::custombinaryview::*;
use binaryninja::rc::Ref;
use binaryninja::section::SectionBuilder;
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
                    match offset {
                        Some(IHexOffset::Linear(_)) => {
                            log::error!("Mixing ExtendedSegmentAddress and ExtendedLinearAddress");
                            return Err(());
                        }
                        Some(IHexOffset::Segment(_)) | None => {}
                    }
                    offset = Some(IHexOffset::Segment(segment_offset))
                }
                ihex::Record::ExtendedLinearAddress(linear_offset) => {
                    match offset {
                        // can't mix linear and segment offsets
                        Some(IHexOffset::Segment(_)) => {
                            log::error!("Mixing ExtendedSegmentAddress and ExtendedLinearAddress");
                            return Err(());
                        }
                        Some(IHexOffset::Linear(_)) | None => {}
                    }
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
            match addr_a.cmp(addr_b) {
                std::cmp::Ordering::Equal => {}
                x => return x,
            };
            data_a.len().cmp(&data_b.len())
        });
        // make sure they don't overlap and merge then if they extend each other
        let mut data: Vec<IHexChunk> = Vec::with_capacity(unmerged_data.len());
        for (chunk_addr, chunk_data) in unmerged_data.into_iter() {
            if let Some(last) = data.last_mut() {
                let chunk_addr = usize::try_from(chunk_addr).unwrap();
                let last_addr = usize::try_from(last.address).unwrap();
                let chunk_range = chunk_addr..chunk_addr + chunk_data.len();
                let last_range = last_addr..last_addr + last.data.len();
                // if the current chunk just extend the last chunk, merge both
                if chunk_range.start == last_range.end {
                    last.data.extend(chunk_data);
                    continue;
                };
                // the same chucks overlap, then the data was defined multiple times.
                if last_range.contains(&chunk_range.start) || last_range.contains(&chunk_range.end)
                {
                    log::error!("Chunks of data overlap");
                    return Err(());
                }
            }
            data.push(IHexChunk {
                address: chunk_addr,
                data: chunk_data,
            });
        }
        builder.create::<IHexView>(parent, IHexViewData { data, start })
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
    data: Vec<IHexChunk>,
    start: Option<IHexStart>,
}

pub struct IHexViewData {
    data: Vec<IHexChunk>,
    start: Option<IHexStart>,
}

#[derive(Clone, Debug)]
pub struct IHexChunk {
    address: u32,
    data: Vec<u8>,
}

impl IHexChunk {
    pub fn end(&self) -> u32 {
        self.address + u32::try_from(self.data.len()).unwrap()
    }
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
    fn chunk_from_address(&self, offset: u32) -> Option<usize> {
        self.data
            .binary_search_by(|chunk| {
                let range = chunk.address..chunk.address + u32::try_from(chunk.data.len()).unwrap();
                if range.contains(&offset) {
                    return Ordering::Equal;
                }
                offset.cmp(&range.start)
            })
            .ok()
    }
}

unsafe impl CustomBinaryView for IHexView {
    type Args = IHexViewData;

    fn new(handle: &BinaryView, _args: &Self::Args) -> Result<Self> {
        Ok(Self {
            core: handle.to_owned(),
            // NOTE dummy values, final values are added on init
            data: vec![],
            start: None,
        })
    }

    fn init(&mut self, IHexViewData { data, start }: Self::Args) -> Result<()> {
        self.data = data;
        self.start = start;
        //TODO this will cause a Segmentation Fault
        //for chunk in self.data.iter() {
        //    self.add_segment(
        //        SegmentBuilder::new(chunk.address.into()..chunk.end().into())
        //            .executable(true)
        //            .readable(true)
        //            .contains_data(true)
        //            .contains_code(true),
        //    );
        //}
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
        self.core.default_endianness()
    }

    fn address_size(&self) -> usize {
        4
    }

    fn start(&self) -> u64 {
        self.data
            .first()
            .map(|chunk| chunk.address.into())
            .unwrap_or(0)
    }

    fn read(&self, buf: &mut [u8], offset: u64) -> usize {
        let Ok(offset) = u32::try_from(offset) else {
            return 0;
        };
        let Some(chunk_idx) = self.chunk_from_address(offset) else {
            return 0;
        };

        let chunk = &self.data[chunk_idx];
        let chunk_data_offset = usize::try_from(offset - chunk.address).unwrap();
        let chunk_data = &chunk.data[chunk_data_offset..];

        let copy_len = chunk_data.len().min(buf.len());
        buf[..copy_len].copy_from_slice(&chunk_data[..copy_len]);
        copy_len
    }

    fn offset_valid(&self, offset: u64) -> bool {
        let Ok(offset) = u32::try_from(offset) else {
            return false;
        };
        self.chunk_from_address(offset).is_some()
    }

    fn len(&self) -> usize {
        match (self.data.first(), self.data.last()) {
            (Some(first), Some(last)) => (last.end() - first.address).try_into().unwrap(),
            (Some(single), None) | (None, Some(single)) => single.data.len(),
            (None, None) => 0,
        }
    }

    fn next_valid_offset_after(&self, offset: u64) -> u64 {
        let Ok(offset) = u32::try_from(offset) else {
            return offset;
        };
        let chunk = self.data.iter().find_map(|chunk| {
            if chunk.address >= offset {
                Some(chunk.address)
            } else if chunk.end() < offset {
                Some(offset)
            } else {
                None
            }
        });
        chunk.unwrap_or(offset).into()
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
