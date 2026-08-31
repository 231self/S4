//! Shared streaming-processing helper for gateway integration tests.
//!
//! Phase 12 removed the legacy whole-object batch API (`Gateway::process`,
//! `split_records`, `PluginRegistry::process_all`, `record::decode_all`).
//! These helpers push in-memory fixtures through the same bounded
//! `RecordDecoder` + `StreamingPipelineSession` path the S3 handlers use, so
//! the tests keep exercising real production infrastructure.
#![allow(dead_code)]

use s4_error::S4Error;
use s4_gateway::Format;
use s4_gateway::plugin_registry::PluginRegistry;
use s4_gateway::record::{DecoderLimits, Record, RecordDecoder};
use s4_wasm_runtime::CancellationToken;

/// Process `input` through the registry's streaming pipeline, preserving the
/// original record separators. Returns the complete transformed bytes.
pub async fn stream_process_async(
    registry: &PluginRegistry,
    input: &[u8],
    format: Format,
    content_type: &str,
    public_key_pem: Option<&str>,
    stable_key: Option<&[u8]>,
    stable_fields: Option<&str>,
) -> Result<Vec<u8>, S4Error> {
    let limits = DecoderLimits::default();
    Ok(stream_chunked_counted_async(
        registry,
        input,
        format,
        content_type,
        public_key_pem,
        stable_key,
        stable_fields,
        limits.max_source_frame_bytes,
    )
    .await?
    .0)
}

/// Like [`stream_process_async`] but feeds the input in `frame_bytes` frames.
/// Chunk invariance makes the result independent of the chosen frame size.
#[allow(clippy::too_many_arguments)]
pub async fn stream_chunked_async(
    registry: &PluginRegistry,
    input: &[u8],
    format: Format,
    content_type: &str,
    public_key_pem: Option<&str>,
    stable_key: Option<&[u8]>,
    stable_fields: Option<&str>,
    frame_bytes: usize,
) -> Result<Vec<u8>, S4Error> {
    Ok(stream_chunked_counted_async(
        registry,
        input,
        format,
        content_type,
        public_key_pem,
        stable_key,
        stable_fields,
        frame_bytes,
    )
    .await?
    .0)
}

/// Core helper: streams `input` in `frame_bytes` frames through the decoder
/// and pipeline, returning the transformed bytes and the decoded record count.
#[allow(clippy::too_many_arguments)]
pub async fn stream_chunked_counted_async(
    registry: &PluginRegistry,
    input: &[u8],
    format: Format,
    content_type: &str,
    public_key_pem: Option<&str>,
    stable_key: Option<&[u8]>,
    stable_fields: Option<&str>,
    frame_bytes: usize,
) -> Result<(Vec<u8>, usize), S4Error> {
    let session = s4_wasm_runtime::Session {
        format: format.as_str().to_string(),
        content_type: content_type.to_string(),
        policy_version: 0,
        operation: s4_wasm_runtime::Operation::Write,
        config_json: None,
        public_key_pem: public_key_pem.map(str::to_string),
        stable_key: stable_key.map(<[u8]>::to_vec),
        stable_fields: stable_fields.map(str::to_string),
    };
    let snapshot = registry.snapshot();
    let cancellation = CancellationToken::new();
    let mut pipeline = snapshot
        .start_streaming_session(session, cancellation)
        .await?;
    let limits = DecoderLimits {
        max_source_frame_bytes: frame_bytes.max(1),
        ..DecoderLimits::default()
    };
    let mut decoder = RecordDecoder::new(format, limits)?;
    let mut output = Vec::new();
    let mut records = 0usize;
    let mut extend = |record: Record| {
        output.extend_from_slice(&record.payload);
        output.extend_from_slice(&record.separator);
    };
    for chunk in input.chunks(frame_bytes.max(1)) {
        decoder.push(chunk)?;
        while let Some(record) = decoder.next_record()? {
            records += 1;
            if let Some(record) = pipeline.process(record).await? {
                extend(record);
            }
        }
    }
    decoder.finish()?;
    while let Some(record) = decoder.next_record()? {
        records += 1;
        if let Some(record) = pipeline.process(record).await? {
            extend(record);
        }
    }
    for record in pipeline.finish().await? {
        extend(record);
    }
    Ok((output, records))
}

/// Synchronous wrapper of [`stream_process_async`] for proptest and non-async
/// tests. Runs on its own current-thread Tokio runtime so the executor-based
/// streaming session can be driven.
pub fn stream_process(
    registry: &PluginRegistry,
    input: &[u8],
    format: Format,
    content_type: &str,
    public_key_pem: Option<&str>,
    stable_key: Option<&[u8]>,
    stable_fields: Option<&str>,
) -> Result<Vec<u8>, S4Error> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test tokio runtime");
    runtime.block_on(stream_process_async(
        registry,
        input,
        format,
        content_type,
        public_key_pem,
        stable_key,
        stable_fields,
    ))
}

/// Synchronous [`stream_process`] that also reports the decoded record count.
pub fn stream_process_counted(
    registry: &PluginRegistry,
    input: &[u8],
    format: Format,
    content_type: &str,
) -> Result<(Vec<u8>, usize), S4Error> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test tokio runtime");
    runtime.block_on(stream_chunked_counted_async(
        registry,
        input,
        format,
        content_type,
        None,
        None,
        None,
        DecoderLimits::default().max_source_frame_bytes,
    ))
}

/// Synchronous [`stream_chunked_async`] for proptest chunk-invariance checks.
pub fn stream_chunked(
    registry: &PluginRegistry,
    input: &[u8],
    format: Format,
    content_type: &str,
    frame_bytes: usize,
) -> Result<Vec<u8>, S4Error> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test tokio runtime");
    runtime.block_on(stream_chunked_async(
        registry,
        input,
        format,
        content_type,
        None,
        None,
        None,
        frame_bytes,
    ))
}
