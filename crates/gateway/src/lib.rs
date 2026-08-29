pub mod backend;
pub mod control;
pub mod entity;
pub mod integrity;
pub mod key_cipher;
pub mod managed;
pub mod multipart_staging;
pub mod object;
pub mod plugin_registry;
pub mod read_spool;
pub mod record;
pub mod s3_error;
mod s3_safety;
pub mod server;
pub mod service_storage;
pub mod sigv4;
pub mod store;
pub mod transaction;
pub mod workspace_storage;

use plugin_registry::PluginRegistry;
use s4_wasm_runtime::FilterEngine;
use std::sync::Arc;

pub struct Gateway {
    pub engine: Arc<FilterEngine>,
    pub plugins: Option<Arc<PluginRegistry>>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Format {
    Jsonl,
    Json,
    Csv,
    Tsv,
    Text,
}

impl Format {
    pub fn as_str(&self) -> &str {
        match self {
            Format::Jsonl => "jsonl",
            Format::Json => "json",
            Format::Csv => "csv",
            Format::Tsv => "tsv",
            Format::Text => "text",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "jsonl" => Some(Self::Jsonl),
            "json" => Some(Self::Json),
            "csv" => Some(Self::Csv),
            "tsv" => Some(Self::Tsv),
            "text" => Some(Self::Text),
            _ => None,
        }
    }
}

impl Gateway {
    pub fn new(component_bytes: &[u8]) -> anyhow::Result<Self> {
        let engine = FilterEngine::new(component_bytes)?;
        Ok(Self {
            engine: Arc::new(engine),
            plugins: None,
        })
    }

    pub fn with_registry(engine: FilterEngine, plugins: Arc<PluginRegistry>) -> Self {
        Self {
            engine: Arc::new(engine),
            plugins: Some(plugins),
        }
    }

    pub fn pipeline_snapshot(&self) -> Option<plugin_registry::PipelineSnapshot> {
        self.plugins.as_ref().map(|plugins| plugins.snapshot())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_parse_valid() {
        assert_eq!(Format::parse("jsonl"), Some(Format::Jsonl));
        assert_eq!(Format::parse("json"), Some(Format::Json));
        assert_eq!(Format::parse("csv"), Some(Format::Csv));
        assert_eq!(Format::parse("tsv"), Some(Format::Tsv));
    }

    #[test]
    fn format_parse_invalid() {
        assert_eq!(Format::parse("pdf"), None);
    }
}
