pub mod backend;
pub mod control;
pub mod entity;
pub mod integrity;
pub mod key_cipher;
pub mod object;
pub mod plugin_registry;
pub mod record;
pub mod s3_error;
pub mod server;
pub mod service_storage;
pub mod sigv4;
pub mod store;
pub mod transaction;

use bytes::Bytes;
use plugin_registry::{PipelineSession, PluginRegistry};
use s4_error::S4Error;
use s4_wasm_runtime::{CancellationToken, ExecutorConfig, FilterEngine, WasmExecutor};
use std::sync::Arc;

pub struct Gateway {
    pub engine: Arc<FilterEngine>,
    pub plugins: Option<Arc<PluginRegistry>>,
    fallback_executor: Option<Arc<WasmExecutor>>,
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

#[derive(Debug)]
pub struct TransformOutput {
    pub bytes: Vec<u8>,
    pub records_processed: usize,
}

impl Gateway {
    pub fn new(component_bytes: &[u8]) -> anyhow::Result<Self> {
        let engine = FilterEngine::new(component_bytes)?;
        Ok(Self {
            engine: Arc::new(engine),
            plugins: None,
            fallback_executor: Some(Arc::new(WasmExecutor::new(ExecutorConfig::default())?)),
        })
    }

    pub fn with_registry(engine: FilterEngine, plugins: Arc<PluginRegistry>) -> Self {
        Self {
            engine: Arc::new(engine),
            plugins: Some(plugins),
            fallback_executor: None,
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
            plugins.process_all(
                format,
                content_type,
                public_key_pem,
                stable_key,
                stable_fields,
                &records,
            )?
        } else {
            let session = s4_wasm_runtime::Session {
                format: format.as_str().to_string(),
                content_type: content_type.to_string(),
                policy_version: 1,
                public_key_pem: public_key_pem.map(|s| s.to_string()),
                stable_key: stable_key.map(|k| k.to_vec()),
                stable_fields: stable_fields.map(|s| s.to_string()),
            };
            let executor = self
                .fallback_executor
                .as_ref()
                .expect("gateway without a registry must own a Wasm executor");
            let engine = Arc::clone(&self.engine);
            let reservation = engine.guest_memory_limit();
            let cancellation = CancellationToken::new();
            let task_cancellation = cancellation.clone();
            executor.execute(reservation, &cancellation, move || {
                let filter = engine.start_session_with_cancellation(&session, task_cancellation)?;
                let mut pipeline = PipelineSession::from_filter("default", filter);
                let mut output = Vec::new();
                for payload in records {
                    if let Some(record) =
                        pipeline.process(record::Record::new(Bytes::from(payload), Bytes::new()))?
                    {
                        output.push(record.payload.to_vec());
                    }
                }
                output.extend(
                    pipeline
                        .finish()?
                        .into_iter()
                        .map(|record| record.payload.to_vec()),
                );
                Ok::<_, S4Error>(output)
            })??
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

    pub fn pipeline_snapshot(&self) -> Option<plugin_registry::PipelineSnapshot> {
        self.plugins.as_ref().map(|plugins| plugins.snapshot())
    }
}

pub fn split_records(input: &[u8], format: Format) -> Result<Vec<Vec<u8>>, S4Error> {
    let decoded = record::decode_all(input, format, record::DecoderLimits::default())?;
    let mut records: Vec<Vec<u8>> = decoded
        .into_iter()
        .map(|record| record.payload.to_vec())
        .collect();

    if matches!(format, Format::Text | Format::Jsonl | Format::Tsv) {
        records.retain(|record| !is_empty_or_whitespace(record));
        if records.is_empty() {
            records.push(input.to_vec());
        }
    }
    Ok(records)
}

fn is_empty_or_whitespace(b: &[u8]) -> bool {
    std::str::from_utf8(b)
        .map(|s| s.trim().is_empty())
        .unwrap_or(false)
}

fn needs_newline(format: Format) -> bool {
    matches!(
        format,
        Format::Jsonl | Format::Text | Format::Csv | Format::Tsv
    )
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
        assert_eq!(Format::parse("tsv"), Some(Format::Tsv));
    }

    #[test]
    fn format_parse_invalid() {
        assert_eq!(Format::parse("pdf"), None);
    }
}
