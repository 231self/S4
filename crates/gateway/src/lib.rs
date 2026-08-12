pub mod control;
pub mod entity;
pub mod plugin_registry;
pub mod s3_error;
pub mod server;
pub mod service_storage;
pub mod store;

use plugin_registry::PluginRegistry;
use s4_error::{S4Error, codes};
use s4_wasm_runtime::FilterEngine;
use std::sync::Arc;

pub struct Gateway {
    pub engine: FilterEngine,
    pub plugins: Option<Arc<PluginRegistry>>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Format {
    Jsonl,
    Json,
    Csv,
    Text,
}

impl Format {
    pub fn as_str(&self) -> &str {
        match self {
            Format::Jsonl => "jsonl",
            Format::Json => "json",
            Format::Csv => "csv",
            Format::Text => "text",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "jsonl" => Some(Self::Jsonl),
            "json" => Some(Self::Json),
            "csv" => Some(Self::Csv),
            "text" => Some(Self::Text),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct TransformOutput {
    pub bytes: Vec<u8>,
    pub records_processed: usize,
}

impl Gateway {
    pub fn new(component_bytes: &[u8]) -> anyhow::Result<Self> {
        let engine = FilterEngine::new(component_bytes)?;
        Ok(Self {
            engine,
            plugins: None,
        })
    }

    pub fn with_registry(engine: FilterEngine, plugins: Arc<PluginRegistry>) -> Self {
        Self {
            engine,
            plugins: Some(plugins),
        }
    }

    pub fn process(
        &self,
        input: &[u8],
        format: Format,
        content_type: &str,
        public_key_pem: Option<&str>,
        stable_key: Option<&[u8]>,
        stable_fields: Option<&str>,
    ) -> Result<TransformOutput, S4Error> {
        let records = split_records(input, format)?;
        let record_count = records.len();

        let transformed = if let Some(ref plugins) = self.plugins {
            plugins
                .process_all(
                    format,
                    content_type,
                    public_key_pem,
                    stable_key,
                    stable_fields,
                    &records,
                )
                .map_err(|e| S4Error::new(codes::INTERNAL, e.to_string()))?
        } else {
            let session = s4_wasm_runtime::Session {
                format: format.as_str().to_string(),
                content_type: content_type.to_string(),
                policy_version: 1,
                public_key_pem: public_key_pem.map(|s| s.to_string()),
                stable_key: stable_key.map(|k| k.to_vec()),
                stable_fields: stable_fields.map(|s| s.to_string()),
            };
            self.engine.run_session(&session, &records)?
        };

        let mut output = Vec::new();
        for (i, record_bytes) in transformed.iter().enumerate() {
            output.extend_from_slice(record_bytes);
            if (i + 1 < transformed.len() && needs_newline(format))
                || (i + 1 == transformed.len() && needs_newline(format))
            {
                output.push(b'\n');
            }
        }

        Ok(TransformOutput {
            bytes: output,
            records_processed: record_count,
        })
    }
}

pub fn split_records(input: &[u8], format: Format) -> Result<Vec<Vec<u8>>, S4Error> {
    match format {
        Format::Jsonl => split_lines(input),
        Format::Text => split_lines(input),
        Format::Json => {
            let s = std::str::from_utf8(input)
                .map_err(|e| S4Error::new(codes::DECODE_ENCODING, e.to_string()))?;
            Ok(vec![s.as_bytes().to_vec()])
        }
        Format::Csv => split_csv_records(input),
    }
}

fn split_lines(input: &[u8]) -> Result<Vec<Vec<u8>>, S4Error> {
    let s = std::str::from_utf8(input)
        .map_err(|e| S4Error::new(codes::DECODE_ENCODING, e.to_string()))?;
    let records: Vec<Vec<u8>> = s
        .lines()
        .map(|l| l.as_bytes().to_vec())
        .filter(|b| !is_empty_or_whitespace(b))
        .collect();
    if records.is_empty() {
        Ok(vec![s.as_bytes().to_vec()])
    } else {
        Ok(records)
    }
}

fn split_csv_records(input: &[u8]) -> Result<Vec<Vec<u8>>, S4Error> {
    let s = std::str::from_utf8(input)
        .map_err(|e| S4Error::new(codes::DECODE_ENCODING, e.to_string()))?;
    let mut records = Vec::new();
    let mut current = Vec::new();
    let mut in_quotes = false;

    for ch in s.chars() {
        current.push(ch as u8);
        if ch == '"' {
            in_quotes = !in_quotes;
        }
        if ch == '\n' && !in_quotes {
            let record: Vec<u8> = std::mem::take(&mut current);
            let record = std::str::from_utf8(&record)
                .map_err(|e| S4Error::new(codes::DECODE_CSV, e.to_string()))?;
            let trimmed = record.trim_end_matches('\n');
            if !trimmed.is_empty() {
                records.push(trimmed.as_bytes().to_vec());
            }
        }
    }

    if !current.is_empty() {
        let record = std::str::from_utf8(&current)
            .map_err(|e| S4Error::new(codes::DECODE_CSV, e.to_string()))?;
        let trimmed = record.trim();
        if !trimmed.is_empty() {
            records.push(trimmed.as_bytes().to_vec());
        }
    }

    if records.is_empty() {
        return Err(S4Error::new(codes::DECODE_CSV, "no CSV records found"));
    }
    Ok(records)
}

fn is_empty_or_whitespace(b: &[u8]) -> bool {
    std::str::from_utf8(b)
        .map(|s| s.trim().is_empty())
        .unwrap_or(false)
}

fn needs_newline(format: Format) -> bool {
    matches!(format, Format::Jsonl | Format::Text | Format::Csv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_jsonl_to_records() {
        let input = b"{\"a\":1}\n{\"b\":2}\n{\"c\":3}\n";
        let records = split_records(input, Format::Jsonl).unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0], b"{\"a\":1}");
        assert_eq!(records[2], b"{\"c\":3}");
    }

    #[test]
    fn split_json_single_record() {
        let input = b"{\"key\": \"value\"}";
        let records = split_records(input, Format::Json).unwrap();
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn split_csv_with_quoted_newlines() {
        let input = b"col1,col2\n\"a\nb\",c\nd,e\n";
        let records = split_records(input, Format::Csv).unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0], b"col1,col2");
        assert_eq!(records[1], b"\"a\nb\",c");
        assert_eq!(records[2], b"d,e");
    }

    #[test]
    fn split_lines_empty_input_is_single_record() {
        let input = b"   ";
        let records = split_records(input, Format::Text).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0], b"   ");
    }

    #[test]
    fn format_parse_valid() {
        assert_eq!(Format::parse("jsonl"), Some(Format::Jsonl));
        assert_eq!(Format::parse("json"), Some(Format::Json));
        assert_eq!(Format::parse("csv"), Some(Format::Csv));
    }

    #[test]
    fn format_parse_invalid() {
        assert_eq!(Format::parse("pdf"), None);
    }
}
