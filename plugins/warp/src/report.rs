use binaryninja::interaction::{Form, FormInputField};
use minijinja::Environment;
use serde::Serialize;
use warp::chunk::{Chunk, ChunkKind};
use warp::r#type::guid::TypeGUID;
use warp::WarpFile;

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum ReportKindField {
    None,
    #[default]
    Html,
    Markdown,
    Json,
}

impl ReportKindField {
    pub fn to_field(&self) -> FormInputField {
        FormInputField::Choice {
            prompt: "Generated Report".to_string(),
            choices: vec![
                "None".to_string(),
                "HTML".to_string(),
                "Markdown".to_string(),
                "JSON".to_string(),
            ],
            default: Some(match self {
                Self::None => 0,
                Self::Html => 1,
                Self::Markdown => 2,
                Self::Json => 3,
            }),
            value: 0,
        }
    }

    pub fn from_form(form: &Form) -> Option<Self> {
        let field = form.get_field_with_name("Generated Report")?;
        let field_value = field.try_value_index()?;
        match field_value {
            3 => Some(Self::Json),
            2 => Some(Self::Markdown),
            1 => Some(Self::Html),
            _ => Some(Self::None),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReportGenerator {
    environment: Environment<'static>,
}

impl ReportGenerator {
    pub fn new() -> Self {
        let mut environment = Environment::new();
        // Remove trailing lines for blocks, this is required for Markdown tables.
        environment.set_trim_blocks(true);
        minijinja_embed::load_templates!(&mut environment);
        Self { environment }
    }

    pub fn report(&self, kind: &ReportKindField, file: &WarpFile) -> Option<String> {
        match kind {
            ReportKindField::None => None,
            ReportKindField::Html => self.html_report(file),
            ReportKindField::Markdown => self.markdown_report(file),
            ReportKindField::Json => self.json_report(file),
        }
    }

    pub fn report_extension(&self, kind: &ReportKindField) -> Option<&'static str> {
        match kind {
            ReportKindField::None => None,
            ReportKindField::Html => Some("html"),
            ReportKindField::Markdown => Some("md"),
            ReportKindField::Json => Some("json"),
        }
    }

    pub fn html_report(&self, file: &WarpFile) -> Option<String> {
        let data = FileReportData::new(file);
        let tmpl = self.environment.get_template("file.html").ok()?;
        tmpl.render(data).ok()
    }

    pub fn markdown_report(&self, file: &WarpFile) -> Option<String> {
        let data = FileReportData::new(file);
        let tmpl = self.environment.get_template("file.md").ok()?;
        tmpl.render(data).ok()
    }

    pub fn json_report(&self, file: &WarpFile) -> Option<String> {
        let data = FileReportData::new(file);
        let tmpl = self.environment.get_template("file.json").ok()?;
        tmpl.render(data).ok()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FileReportData {
    pub title: String,
    // pub header: WarpFileHeader,
    pub chunks: Vec<ChunkReportData>,
}

impl FileReportData {
    pub fn new(file: &WarpFile) -> Self {
        Self {
            title: "Warp File Report".to_string(),
            // header: file.header.clone(),
            chunks: file
                .chunks
                .iter()
                .map(|chunk| ChunkReportData::new(chunk))
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ChunkReportData {
    pub title: String,
    // pub header: ChunkHeader,
    pub target: String,
    pub total_item_count: usize,
    /// View into a (possible subset) of chunk items.
    pub item_view: Vec<ItemReportData>,
}

impl ChunkReportData {
    pub fn new(chunk: &Chunk) -> Self {
        // TODO: Set a limit for the number of items so we dont construct 10000000 items in the report.
        let items: Vec<_> = match &chunk.kind {
            ChunkKind::Signature(sc) => sc
                .raw_functions()
                .map(|f| ItemReportData {
                    name: f.symbol().and_then(|s| s.name().map(|n| n.to_string())),
                    guid: f.guid().to_string(),
                    note: None,
                })
                .collect(),
            ChunkKind::Type(tc) => tc
                .raw_types()
                .map(|t| ItemReportData {
                    name: t.type_().and_then(|s| s.name().map(|n| n.to_string())),
                    guid: TypeGUID::from(t.guid()).to_string(),
                    note: None,
                })
                .collect(),
        };

        let chunk_type = match &chunk.kind {
            ChunkKind::Signature(_) => "Signature".to_string(),
            ChunkKind::Type(_) => "Type".to_string(),
        };

        let size_in_kb = chunk.header.size as f64 / 1024.0;
        let formatted_size = format!("{:.1}kb", size_in_kb);

        // For the target show the platform, or the architecture if available.
        let target = chunk
            .header
            .target
            .platform
            .clone()
            .or_else(|| chunk.header.target.architecture.clone())
            .unwrap_or_else(|| "None".to_string());

        Self {
            title: format!("{} Chunk ({})", chunk_type, formatted_size),
            target,
            // header: chunk.header.clone(),
            total_item_count: items.len(),
            item_view: items,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ItemReportData {
    pub guid: String,
    pub name: Option<String>,
    pub note: Option<String>,
}
