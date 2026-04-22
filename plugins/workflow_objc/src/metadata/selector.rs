use crate::Error;
use binaryninja::binary_view::{BinaryView, BinaryViewBase as _};

pub struct Selector {
    pub name: String,
    pub addr: u64,
}

impl Selector {
    pub fn from_address(bv: &BinaryView, addr: u64) -> Result<Self, Error> {
        let name = if bv.offset_valid(addr) {
            // Read the selector name from the binary view
            read_cstring(bv, addr, 500)
        } else {
            // Look for the `sel_` symbols that ObjCProcessor adds to represent selectors
            // whose backing regions have not yet been loaded into the view.
            bv.symbol_by_address(addr)
                .and_then(|sym| sym.raw_name().to_str().ok().map(|name| name.to_owned()))
                .filter(|name| name.starts_with("sel_"))
                .map(|name| name["sel_".len()..].to_string())
        }
        .ok_or(Error::InvalidSelector { address: addr })?;
        Ok(Selector { name, addr })
    }

    /// Returns true if this selector belongs to the `init` method family.
    ///
    /// Per the ObjC ARC spec, a selector is in the init family if it starts with
    /// "init" and the next character is either uppercase or absent (e.g. `init`,
    /// `initWithFrame:`, but NOT `initialize` or `initials`).
    pub fn is_init_family(&self) -> bool {
        if let Some(rest) = self.name.strip_prefix("init") {
            rest.is_empty() || rest.starts_with(|c: char| c.is_ascii_uppercase() || c == ':')
        } else {
            false
        }
    }

    pub fn argument_labels(&self) -> Vec<String> {
        if !self.name.contains(':') {
            return vec![];
        }

        self.name
            .split(':')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect()
    }
}

// Read a null-terminated string from the view
fn read_cstring(bv: &BinaryView, address: u64, max_len: usize) -> Option<String> {
    let mut buffer = vec![0u8; max_len];
    let bytes_read = bv.read(&mut buffer, address);
    if bytes_read == 0 {
        return None;
    }

    // Find the null terminator
    let null_pos = buffer.iter().position(|&b| b == 0).unwrap_or(bytes_read);
    buffer.truncate(null_pos);

    String::from_utf8(buffer).ok()
}
