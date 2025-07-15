use serde_derive::{Deserialize, Serialize};

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
}

impl SearchQuery {
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
    }
}
