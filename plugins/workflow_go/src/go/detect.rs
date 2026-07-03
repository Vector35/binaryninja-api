use binaryninja::binary_view::{BinaryView, BinaryViewBase};

/// Magic that marks the start of the buildinfo blob, embedded by the Go linker
/// since go1.13. Followed by the pointer size, flags, and the version string.
/// Source: <https://go.dev/src/debug/buildinfo/buildinfo.go>
const BUILDINFO_MAGIC: &[u8; 14] = b"\xff Go buildinf:";

/// Section names that hold the pclntab, by object format: `.gopclntab` on ELF,
/// `__gopclntab` on Mach-O. The `.data.rel.ro` variant appears on some
/// position-independent ELF builds. PE has no dedicated section (see the scan).
const PCLNTAB_SECTIONS: &[&str] = &[".gopclntab", "__gopclntab", ".data.rel.ro.gopclntab"];

/// Section names that hold the buildinfo blob: `.go.buildinfo` on ELF,
/// `__go_buildinfo` on Mach-O. As with the pclntab, PE embeds it without a
/// dedicated section.
const BUILDINFO_SECTIONS: &[&str] = &[".go.buildinfo", "__go_buildinfo"];

const FLAGS_VERSION_MASK: u8 = 0x2;

/// pclntab header magics, mapped to the Go version range that produces them.
const MAGICS: [(u32, &str); 4] = [
    (0xFFFF_FFFB, "go1.2 -- 1.15"),
    (0xFFFF_FFFA, "go1.16 -- 1.17"),
    (0xFFFF_FFF0, "go1.18 -- 1.19"),
    (0xFFFF_FFF1, "go1.20+"),
];

/// Sanity cap on the decoded version string length (e.g. "go1.22.2").
const MAX_VERSION_LEN: u64 = 128;

/// A uvarint encodes at most 10 bytes for a u64; the 10th holds a single bit.
const UVARINT_MAX_BYTES: usize = 9;

/// Outcome of Go detection for a binary.
pub struct GoInfo {
    /// Whether the binary is a Go binary.
    pub is_go: bool,
    /// Whether a valid pclntab was located.
    pub has_pclntab: bool,
    /// Exact Go version (from buildinfo) or a version range (from the pclntab magic).
    pub version: String,
}

/// Detects Go binaries and extracts version information from their embedded
/// metadata: the pclntab header and the buildinfo blob.
///
/// The pclntab is located by section name on ELF/Mach-O, and by scanning section
/// contents on PE (where it is embedded in .rdata or .text with no dedicated
/// section).
pub struct GoDetector {}

impl GoDetector {
    /// Apply the identification of golang binary
    pub fn analyze(bv: &BinaryView) -> GoInfo {
        let pclntab_magic = Self::find_pclntab_magic(bv);
        let has_pclntab = pclntab_magic.is_some();
        let build_version = Self::read_buildinfo_version(bv);

        // Prefer the exact version from buildinfo; fall back to the pclntab range.
        let version = build_version
            .clone()
            .or_else(|| pclntab_magic.map(Self::version_bucket))
            .unwrap_or_else(|| "unknown".to_string());

        // A valid pclntab or a buildinfo blob is proof the binary is Go.
        let is_go = has_pclntab || build_version.is_some();

        GoInfo {
            is_go,
            has_pclntab,
            version,
        }
    }

    /// Locates the pclntab header magic: known section names first, then a
    /// content scan of every section (covers PE, and renamed sections).
    fn find_pclntab_magic(bv: &BinaryView) -> Option<u32> {
        for name in PCLNTAB_SECTIONS {
            if let Some(sec) = bv.section_by_name(*name)
                && let Some(m) = Self::check_magic_at(bv, sec.start())
            {
                return Some(m);
            }
        }
        for sec in &bv.sections() {
            if let Some(m) = Self::scan_section(bv, sec.start(), sec.end()) {
                return Some(m);
            }
        }
        None
    }

    /// Validates a pclntab header at `addr`: known magic (either endianness),
    /// two zero padding bytes, and a sane pointer size.
    fn check_magic_at(bv: &BinaryView, addr: u64) -> Option<u32> {
        let mut buf = [0u8; 8];
        if bv.read(&mut buf, addr) != 8 || buf[4] != 0 || buf[5] != 0 {
            return None;
        }
        if buf[7] != 4 && buf[7] != 8 {
            return None;
        }
        let word = [buf[0], buf[1], buf[2], buf[3]];
        [u32::from_le_bytes(word), u32::from_be_bytes(word)]
            .into_iter()
            .find(|m| MAGICS.iter().any(|&(x, _)| x == *m))
    }

    /// Scans a section byte-by-byte for a valid pclntab header. A cheap
    /// in-buffer pre-filter avoids a `read` call per offset.
    fn scan_section(bv: &BinaryView, start: u64, end: u64) -> Option<u32> {
        const CHUNK: usize = 0x10000; // read window size
        const HEADER_LEN: usize = 8; // magic(4) + pad(2) + quantum(1) + ptr_size(1)

        // magic bytes to look for, derived from MAGICS (single source of truth)
        let needles: [[u8; 4]; 4] = MAGICS.map(|(magic, _)| u32::to_le_bytes(magic));

        let mut buf = vec![0u8; CHUNK];
        let mut addr = start;

        while addr < end {
            let want = ((end - addr) as usize).min(CHUNK);
            let n = bv.read(&mut buf[..want], addr);
            if n < HEADER_LEN {
                break;
            }

            // the header may be unaligned, so check every offset in the chunk
            for i in 0..=n - HEADER_LEN {
                let magic = &buf[i..i + 4];
                let padding = buf[i + 4] == 0 && buf[i + 5] == 0; // two zero pad bytes
                let ptr_size_ok = buf[i + 7] == 4 || buf[i + 7] == 8; // 32- or 64-bit

                if !(padding && ptr_size_ok && needles.iter().any(|m| m == magic)) {
                    continue;
                }

                // cheap pre-filter passed: confirm with a clean re-read (endianness)
                if let Some(mg) = Self::check_magic_at(bv, addr + i as u64) {
                    return Some(mg);
                }
            }

            // advance, overlapping by HEADER_LEN-1 so a header split across chunks isn't missed
            addr += (n - (HEADER_LEN - 1)) as u64;
        }
        None
    }

    fn version_bucket(m: u32) -> String {
        MAGICS
            .iter()
            .find(|&&(x, _)| x == m)
            .map(|&(_, s)| s.to_string())
            .unwrap_or_else(|| "go (unknown version)".to_string())
    }

    fn read_buildinfo_version(bv: &BinaryView) -> Option<String> {
        for name in BUILDINFO_SECTIONS {
            if let Some(sec) = bv.section_by_name(*name)
                && let Some(v) = Self::parse_buildinfo(bv, sec.start())
            {
                return Some(v);
            }
        }
        None
    }

    /// Parses the buildinfo blob. Two formats exist: inline (go1.18+), where the
    /// version is a varint-length-prefixed string at offset 32, and the older
    /// pointer format, where offset 16 holds a pointer to a Go string header.
    fn parse_buildinfo(bv: &BinaryView, addr: u64) -> Option<String> {
        let mut hdr = [0u8; 64];
        if bv.read(&mut hdr, addr) < 32 || &hdr[..14] != BUILDINFO_MAGIC {
            return None;
        }

        let ptr_size = hdr[14] as usize;
        let flags = hdr[15];

        if flags & FLAGS_VERSION_MASK != 0 {
            let (len, consumed) = Self::uvarint(&hdr[32..])?;
            let start = 32 + consumed;
            let mut buf = vec![0u8; start + len as usize];
            if (bv.read(&mut buf, addr) as u64) < start as u64 + len {
                return None;
            }
            String::from_utf8(buf[start..start + len as usize].to_vec()).ok()
        } else {
            let big_endian = flags & 0x1 != 0;
            let ver_hdr = Self::read_ptr(bv, addr + 16, ptr_size, big_endian)?;
            Self::read_go_string(bv, ver_hdr, ptr_size, big_endian)
        }
    }

    fn read_ptr(bv: &BinaryView, addr: u64, ptr_size: usize, big_endian: bool) -> Option<u64> {
        let mut buf = [0u8; 8];
        if bv.read(&mut buf[..ptr_size], addr) != ptr_size {
            return None;
        }
        let mut val = 0u64;
        for i in 0..ptr_size {
            let idx = if big_endian { ptr_size - 1 - i } else { i };
            val |= u64::from(buf[idx]) << (8 * i);
        }
        Some(val)
    }

    /// Reads a Go string ({data ptr, len}) at the given header address.
    fn read_go_string(
        bv: &BinaryView,
        hdr: u64,
        ptr_size: usize,
        big_endian: bool,
    ) -> Option<String> {
        let data = Self::read_ptr(bv, hdr, ptr_size, big_endian)?;
        let len = Self::read_ptr(bv, hdr + ptr_size as u64, ptr_size, big_endian)?;
        if len == 0 || len > MAX_VERSION_LEN {
            return None;
        }
        let mut buf = vec![0u8; len as usize];
        if bv.read(&mut buf, data) != len as usize {
            return None;
        }
        String::from_utf8(buf).ok()
    }

    /// Decodes an unsigned LEB128 varint, returning (value, bytes consumed).
    ///
    /// Each byte carries 7 value bits in its low bits; the high bit (0x80) means
    /// "more bytes follow". The final byte has the high bit clear. A u64 value needs at
    /// most 10 bytes, and on the 10th only a single bit is valid, so anything past
    /// that is rejected as overflow.
    fn uvarint(buf: &[u8]) -> Option<(u64, usize)> {
        let mut value = 0u64;
        let mut shift = 0u32;

        for (i, &byte) in buf.iter().enumerate() {
            let is_last = byte < 0x80;
            if is_last {
                // overflow: value wider than an u64
                if i > UVARINT_MAX_BYTES || (i == UVARINT_MAX_BYTES && byte > 1) {
                    return None;
                }
                return Some((value | (u64::from(byte) << shift), i + 1));
            }
            // strip the continuation bit, accumulate the 7 payload bits
            value |= u64::from(byte & 0x7f) << shift;
            shift += 7;
        }

        None
    }
}
