#[cfg(test)]
mod test;

pub mod til;
pub use til::{TILSection, TILTypeInfo};

use std::fmt::Debug;
use std::io::{BufRead, Read, Seek, SeekFrom};
use std::num::NonZeroU64;

use serde::Deserialize;

use anyhow::{anyhow, ensure, Result};

#[derive(Debug, Clone, Copy)]
pub struct IDBParser<I: BufRead + Seek> {
    input: I,
    header: IDBHeader,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TILOffset(NonZeroU64);

impl<I: BufRead + Seek> IDBParser<I> {
    pub fn new(mut input: I) -> Result<Self> {
        let header = IDBHeader::read(&mut input)?;
        Ok(Self { input, header })
    }

    pub fn til_section(&self) -> Option<TILOffset> {
        self.header.til_offset.map(TILOffset)
    }

    pub fn read_til_section(&mut self, til: TILOffset) -> Result<TILSection> {
        self.input.seek(SeekFrom::Start(til.0.get()))?;
        let section_header = IDBSectionHeader::read(&self.header, &mut self.input)?;
        // makes sure the reader doesn't go out-of-bounds
        let mut input = Read::take(&mut self.input, section_header.len);
        let result = TILSection::read(&mut input, section_header.compress)?;

        // TODO seems its normal to have a few extra bytes at the end of the sector, maybe
        // because of the compressions stuff, anyway verify that
        ensure!(
            input.limit() <= 16,
            "Sector have more data then expected, left {} bytes",
            input.limit()
        );
        Ok(result)
    }

    #[cfg(test)]
    pub(crate) fn decompress_til_section(
        &mut self,
        til: TILOffset,
        output: &mut impl std::io::Write,
    ) -> Result<()> {
        self.input.seek(SeekFrom::Start(til.0.get()))?;
        let section_header = IDBSectionHeader::read(&self.header, &mut self.input)?;
        // makes sure the reader doesn't go out-of-bounds
        let mut input = Read::take(&mut self.input, section_header.len);
        TILSection::decompress(&mut input, output, section_header.compress)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum IDBMagic {
    IDA0,
    IDA1,
    IDA2,
}

impl TryFrom<[u8; 4]> for IDBMagic {
    type Error = anyhow::Error;

    fn try_from(value: [u8; 4]) -> Result<Self, Self::Error> {
        match &value {
            b"IDA0" => Ok(IDBMagic::IDA0),
            b"IDA1" => Ok(IDBMagic::IDA1),
            b"IDA2" => Ok(IDBMagic::IDA2),
            _ => Err(anyhow!("Invalid IDB Magic number")),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum IDBVersion {
    V1,
    V4,
    V5,
    V6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct IDBHeader {
    version: IDBVersion,
    id0_offset: Option<NonZeroU64>,
    id1_offset: Option<NonZeroU64>,
    nam_offset: Option<NonZeroU64>,
    til_offset: Option<NonZeroU64>,
    checksums: [u32; 3],
    unk0_checksum: u32,
    data: IDBHeaderVersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum IDBHeaderVersion {
    V1 {
        seg_offset: Option<NonZeroU64>,
    },
    V4 {
        seg_offset: Option<NonZeroU64>,
    },
    V5 {
        unk16: u32,
        unk1_checksum: u32,
    },
    V6 {
        unk16: u32,
        id2_offset: Option<NonZeroU64>,
        unk1_checksum: u32,
    },
}

#[derive(Debug, Clone, Copy)]
struct IDBSectionHeader {
    compress: IDBSectionCompression,
    len: u64,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
enum IDBSectionCompression {
    None = 0,
    Zlib = 2,
}

impl TryFrom<u8> for IDBSectionCompression {
    type Error = ();

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            2 => Ok(Self::Zlib),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Deserialize)]
struct IDBHeaderRaw {
    magic: [u8; 4],
    _padding_0: u16,
    offsets: [u32; 5],
    signature: u32,
    version: u16,
    // more, depending on the version
}

impl IDBHeader {
    pub fn read<I: BufRead + Seek>(input: &mut I) -> Result<Self> {
        let header_raw: IDBHeaderRaw = bincode::deserialize_from(&mut *input)?;
        let _magic = IDBMagic::try_from(header_raw.magic)?;
        ensure!(
            header_raw.signature == 0xAABB_CCDD,
            "Invalid header signature {:#x}",
            header_raw.signature
        );
        match header_raw.version {
            1 => Self::read_v1(&header_raw, input),
            4 => Self::read_v4(&header_raw, input),
            5 => Self::read_v5(&header_raw, input),
            6 => Self::read_v6(&header_raw, input),
            v => return Err(anyhow!("Unable to parse version `{v}`")),
        }
    }

    fn read_v1<I: Read + Seek>(header_raw: &IDBHeaderRaw, input: I) -> Result<Self> {
        #[derive(Debug, Deserialize)]
        struct V1Raw {
            id2_offset: u32,
            checksums: [u32; 3],
            unk30_zeroed: u32,
            unk33_checksum: u32,
            unk38_zeroed: [u8; 6],
        }

        let v1_raw: V1Raw = bincode::deserialize_from(input)?;
        ensure!(v1_raw.unk30_zeroed == 0, "unk30 not zeroed");
        ensure!(v1_raw.id2_offset == 0, "id2 in V1 is not zeroed");
        ensure!(v1_raw.unk38_zeroed == [0; 6], "unk38 is not zeroed");

        Ok(Self {
            version: IDBVersion::V1,
            id0_offset: NonZeroU64::new(header_raw.offsets[0].into()),
            id1_offset: NonZeroU64::new(header_raw.offsets[1].into()),
            nam_offset: NonZeroU64::new(header_raw.offsets[2].into()),
            til_offset: NonZeroU64::new(header_raw.offsets[4].into()),
            checksums: v1_raw.checksums,
            unk0_checksum: v1_raw.unk33_checksum,
            data: IDBHeaderVersion::V1 {
                seg_offset: NonZeroU64::new(header_raw.offsets[3].into()),
            },
        })
    }

    fn read_v4<I: Read + Seek>(header_raw: &IDBHeaderRaw, input: I) -> Result<Self> {
        #[derive(Debug, Deserialize)]
        struct V4Raw {
            id2_offset: u32,
            checksums: [u32; 3],
            unk30_zeroed: u32,
            unk33_checksum: u32,
            unk38_zeroed: [u8; 8],
            unk40_v5c: u32,
            unk44_zeroed: [u8; 8],
            _unk4c: [u8; 16],
            unk5c_zeroed: [[u8; 16]; 8],
        }

        let v4_raw: V4Raw = bincode::deserialize_from(input)?;

        ensure!(v4_raw.unk30_zeroed == 0, "unk30 not zeroed");
        ensure!(v4_raw.id2_offset == 0, "id2 in V4 is not zeroed");
        ensure!(v4_raw.unk38_zeroed == [0; 8], "unk38 is not zeroed");
        ensure!(v4_raw.unk40_v5c == 0x5c, "unk40 is not 0x5C");
        ensure!(v4_raw.unk44_zeroed == [0; 8], "unk44 is not zeroed");
        ensure!(v4_raw.unk5c_zeroed == [[0; 16]; 8], "unk5c is not zeroed");

        Ok(Self {
            version: IDBVersion::V4,
            id0_offset: NonZeroU64::new(header_raw.offsets[0].into()),
            id1_offset: NonZeroU64::new(header_raw.offsets[1].into()),
            nam_offset: NonZeroU64::new(header_raw.offsets[2].into()),
            til_offset: NonZeroU64::new(header_raw.offsets[4].into()),
            checksums: v4_raw.checksums,
            unk0_checksum: v4_raw.unk33_checksum,
            data: IDBHeaderVersion::V4 {
                seg_offset: NonZeroU64::new(header_raw.offsets[3].into()),
            },
        })
    }

    fn read_v5(header_raw: &IDBHeaderRaw, input: impl Read) -> Result<Self> {
        #[derive(Debug, Deserialize)]
        struct V5Raw {
            nam_offset: u64,
            seg_offset_zeroed: u64,
            til_offset: u64,
            initial_checksums: [u32; 3],
            unk4_zeroed: u32,
            unk_checksum: u32,
            id2_offset_zeroed: u64,
            final_checksum: u32,
            unk0_v7c: u32,
            unk1_zeroed: [u8; 16],
            _unk2: [u8; 16],
            unk3_zeroed: [[u8; 16]; 8],
        }
        let v5_raw: V5Raw = bincode::deserialize_from(input)?;
        let id0_offset =
            u64::from_le(u64::from(header_raw.offsets[1]) << 32 | u64::from(header_raw.offsets[0]));
        let id1_offset =
            u64::from_le(u64::from(header_raw.offsets[3]) << 32 | u64::from(header_raw.offsets[2]));

        // TODO Final checksum is always zero on v5?

        ensure!(v5_raw.unk4_zeroed == 0, "unk4 not zeroed");
        ensure!(v5_raw.id2_offset_zeroed == 0, "id2 in V5 is not zeroed");
        ensure!(v5_raw.seg_offset_zeroed == 0, "seg in V5 is not zeroed");
        ensure!(v5_raw.unk0_v7c == 0x7C, "unk0 not 0x7C");
        ensure!(v5_raw.unk1_zeroed == [0; 16], "unk1 is not zeroed");
        ensure!(v5_raw.unk3_zeroed == [[0; 16]; 8], "unk3 is not zeroed");

        Ok(Self {
            version: IDBVersion::V5,
            id0_offset: NonZeroU64::new(id0_offset),
            id1_offset: NonZeroU64::new(id1_offset),
            nam_offset: NonZeroU64::new(v5_raw.nam_offset),
            til_offset: NonZeroU64::new(v5_raw.til_offset),
            checksums: v5_raw.initial_checksums,
            unk0_checksum: v5_raw.unk_checksum,
            data: IDBHeaderVersion::V5 {
                unk16: header_raw.offsets[4],
                unk1_checksum: v5_raw.final_checksum,
            },
        })
    }

    fn read_v6(header_raw: &IDBHeaderRaw, input: impl Read) -> Result<Self> {
        #[derive(Debug, Deserialize)]
        struct V6Raw {
            nam_offset: u64,
            seg_offset_zeroed: u64,
            til_offset: u64,
            initial_checksums: [u32; 3],
            unk4_zeroed: [u8; 4],
            unk5_checksum: u32,
            id2_offset: u64,
            final_checksum: u32,
            unk0_v7c: u32,
            unk1_zeroed: [u8; 16],
            _unk2: [u8; 16],
            unk3_zeroed: [[u8; 16]; 8],
        }
        let v6_raw: V6Raw = bincode::deserialize_from(input)?;
        let id0_offset =
            u64::from_le(u64::from(header_raw.offsets[1]) << 32 | u64::from(header_raw.offsets[0]));
        let id1_offset =
            u64::from_le(u64::from(header_raw.offsets[3]) << 32 | u64::from(header_raw.offsets[2]));

        ensure!(v6_raw.unk4_zeroed == [0; 4], "unk4 not zeroed");
        ensure!(v6_raw.seg_offset_zeroed == 0, "seg in V6 is not zeroed");
        ensure!(v6_raw.unk0_v7c == 0x7C, "unk0 not 0x7C");
        ensure!(v6_raw.unk1_zeroed == [0; 16], "unk1 is not zeroed");
        ensure!(v6_raw.unk3_zeroed == [[0; 16]; 8], "unk3 is not zeroed");

        Ok(Self {
            version: IDBVersion::V6,
            id0_offset: NonZeroU64::new(id0_offset),
            id1_offset: NonZeroU64::new(id1_offset),
            nam_offset: NonZeroU64::new(v6_raw.nam_offset),
            til_offset: NonZeroU64::new(v6_raw.til_offset),
            checksums: v6_raw.initial_checksums,
            unk0_checksum: v6_raw.unk5_checksum,
            data: IDBHeaderVersion::V6 {
                unk16: header_raw.offsets[4],
                id2_offset: NonZeroU64::new(v6_raw.id2_offset),
                unk1_checksum: v6_raw.final_checksum,
            },
        })
    }
}

impl IDBSectionHeader {
    pub fn read<I: BufRead>(header: &IDBHeader, input: I) -> Result<Self> {
        match header.version {
            crate::IDBVersion::V1 | crate::IDBVersion::V4 => {
                #[derive(Debug, Deserialize)]
                struct Section32Raw {
                    compress: u8,
                    len: u32,
                }
                let header: Section32Raw = bincode::deserialize_from(input)?;
                Ok(IDBSectionHeader {
                    compress: header
                        .compress
                        .try_into()
                        .map_err(|_| anyhow!("Invalid compression code"))?,
                    len: header.len.into(),
                })
            }
            crate::IDBVersion::V5 | crate::IDBVersion::V6 => {
                #[derive(Debug, Deserialize)]
                struct Section64Raw {
                    compress: u8,
                    len: u64,
                }
                let header: Section64Raw = bincode::deserialize_from(input)?;
                Ok(IDBSectionHeader {
                    compress: header
                        .compress
                        .try_into()
                        .map_err(|_| anyhow!("Invalid compression code"))?,
                    len: header.len,
                })
            }
        }
    }
}

fn read_bytes_len_u8<I: Read>(mut input: I) -> Result<Vec<u8>> {
    let mut len = [0];
    input.read_exact(&mut len)?;
    let mut bytes = vec![0u8; len[0].into()];
    input.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn read_string_len_u8<I: Read>(input: I) -> Result<String> {
    let bytes = read_bytes_len_u8(input)?;
    Ok(String::from_utf8(bytes)?)
}

#[cfg(test)]
fn write_string_len_u8<O: std::io::Write>(mut output: O, value: &str) -> Result<()> {
    output.write_all(&[u8::try_from(value.len()).unwrap()])?;
    Ok(output.write_all(value.as_bytes())?)
}

fn read_c_string_raw<I: BufRead>(mut input: I) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![];
    input.read_until(b'\x00', &mut buf)?;
    // last char need to be \x00 or we found a EoF
    if buf.pop() != Some(b'\x00') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "Unexpected EoF on CStr",
        ));
    }
    Ok(buf)
}

fn read_c_string<I: BufRead>(input: &mut I) -> std::io::Result<String> {
    let buf = read_c_string_raw(input)?;
    Ok(String::from_utf8_lossy(&buf).to_string())
}

fn read_c_string_vec<I: BufRead>(input: &mut I) -> std::io::Result<Vec<String>> {
    let buf = read_c_string_raw(input)?;
    if buf.is_empty() {
        return Ok(vec![]);
    }

    let mut result = vec![];
    // NOTE never 0 because this came from a CStr
    let mut len = buf[0] - 1;
    // NOTE zero len (buf[0] == 1) string is allowed
    let mut current = &buf[1..];
    loop {
        if usize::from(len) > current.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid len on Vec of CStr",
            ));
        }
        let (value, rest) = current.split_at(len.into());
        result.push(String::from_utf8_lossy(value).to_string());
        if rest.is_empty() {
            break;
        }
        len = rest[0] - 1;
        current = &rest[1..];
    }
    Ok(result)
}
