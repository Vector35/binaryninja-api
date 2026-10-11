use binaryninjacore_sys::BNDetectSearchMode;
use serde_derive::{Deserialize, Serialize};

use crate::string::{BnString, IntoCStr};

/// The parser a [`SearchQuery`] pattern is read with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SearchType {
    /// Try FlexHex, then YARA hex, then regex, then a raw string.
    #[default]
    Auto,
    /// Hex bytes with `??` and nibble wildcards, ex. "42 2e ?? 6?".
    FlexHex,
    /// A YARA hex string, with jumps, alternation and negation.
    Yara,
    /// A byte-level regular expression.
    Regex,
    /// A literal string.
    Raw,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SearchQuery {
    /// ex. "42 2e 64 65 ?? 75 67 24"
    pattern: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    start: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    end: Option<u64>,
    #[serde(rename = "ignoreCase")]
    ignore_case: bool,
    raw: bool,
    overlap: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    align: Option<u64>,
    /// Force a parser for the pattern; the core auto-detects one when unset.
    #[serde(rename = "searchType", skip_serializing_if = "Option::is_none")]
    search_type: Option<SearchType>,
}

impl SearchQuery {
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            ..Default::default()
        }
    }

    /// Set the starting address for the search
    pub fn start(mut self, addr: u64) -> Self {
        self.start = Some(addr);
        self
    }

    /// Set the ending address for the search (inclusive)
    pub fn end(mut self, addr: u64) -> Self {
        self.end = Some(addr);
        self
    }

    /// Set whether to interpret the pattern as a raw string
    pub fn raw(mut self, raw: bool) -> Self {
        self.raw = raw;
        self
    }

    /// Set whether to perform case-insensitive matching
    pub fn ignore_case(mut self, ignore_case: bool) -> Self {
        self.ignore_case = ignore_case;
        self
    }

    /// Set whether to allow matches to overlap
    pub fn overlap(mut self, overlap: bool) -> Self {
        self.overlap = overlap;
        self
    }

    /// Set the alignment of matches (must be a power of 2)
    pub fn align(mut self, align: u64) -> Self {
        // Validate that align is a power of 2
        if align != 0 && (align & (align - 1)) == 0 {
            self.align = Some(align);
        }
        self
    }

    /// Force the parser the pattern is read with. With an explicit type, a
    /// pattern that type can't parse is an error rather than falling through
    /// to another type.
    pub fn search_type(mut self, search_type: SearchType) -> Self {
        self.search_type = Some(search_type);
        self
    }
}

impl SearchQuery {
    /// The name of the parser the core would read the pattern with, ex.
    /// "FlexHex" or "Regex", or the core's error message when the pattern
    /// doesn't parse.
    pub fn detect_mode(&self) -> Result<String, String> {
        let query = self.to_json().to_cstr();
        let mode = unsafe { BnString::into_string(BNDetectSearchMode(query.as_ptr())) };
        match mode.strip_prefix("Error: ") {
            Some(err) => Err(err.to_owned()),
            None => Ok(mode),
        }
    }

    /// Serialize the query to a JSON string
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("failed to serialize search query")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_query_builder() {
        let query = SearchQuery::new("test pattern")
            .start(0x1000)
            .end(0x2000)
            .raw(true)
            .ignore_case(true)
            .overlap(false)
            .align(16);

        assert_eq!(query.pattern, "test pattern");
        assert_eq!(query.start, Some(0x1000));
        assert_eq!(query.end, Some(0x2000));
        assert!(query.raw);
        assert!(query.ignore_case);
        assert!(!query.overlap);
        assert_eq!(query.align, Some(16));
    }

    #[test]
    fn test_search_query_json() {
        let query = SearchQuery::new("test").start(0x1000).align(8);

        let json = query.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["pattern"], "test");
        assert_eq!(parsed["start"], 4096);
        assert_eq!(parsed["align"], 8);
        assert!(!parsed.as_object().unwrap().contains_key("end"));
        assert!(!parsed.as_object().unwrap().contains_key("searchType"));
    }

    #[test]
    fn test_search_query_search_type_json() {
        for (search_type, name) in [
            (SearchType::Auto, "auto"),
            (SearchType::FlexHex, "flexhex"),
            (SearchType::Yara, "yara"),
            (SearchType::Regex, "regex"),
            (SearchType::Raw, "raw"),
        ] {
            let json = SearchQuery::new("test").search_type(search_type).to_json();
            let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed["searchType"], name);
        }
    }
}
