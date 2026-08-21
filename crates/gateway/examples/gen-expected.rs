use s4_gateway::Format;
use s4_gateway::plugin_registry::PluginRegistry;
use s4_gateway::record::{DecoderLimits, RecordDecoder};
use s4_wasm_runtime::CancellationToken;
use std::fs;
use std::path::PathBuf;

fn main() {
    let component = fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("components")
            .join("pii-default.component.wasm"),
    )
    .expect("component not found; run `just build-filters` first");
    let registry = PluginRegistry::new();
    registry.import("pii-default", &component).unwrap();
    let snapshot = registry.snapshot();

    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("pii");

    let specs: &[(&str, &str, Format, &str)] = &[
        (
            "perf/large-corpus-500.jsonl",
            "perf/large-corpus-500.expected.jsonl",
            Format::Jsonl,
            "application/x-ndjson",
        ),
        (
            "real-world/cloudtrail.jsonl",
            "real-world/cloudtrail.expected.jsonl",
            Format::Jsonl,
            "application/x-ndjson",
        ),
        (
            "real-world/app-logs.jsonl",
            "real-world/app-logs.expected.jsonl",
            Format::Jsonl,
            "application/x-ndjson",
        ),
        (
            "adversarial/empty-records.jsonl",
            "adversarial/empty-records.expected.jsonl",
            Format::Jsonl,
            "application/x-ndjson",
        ),
        (
            "adversarial/injection-attempts.jsonl",
            "adversarial/injection-attempts.expected.jsonl",
            Format::Jsonl,
            "application/x-ndjson",
        ),
    ];

    for &(input_rel, output_rel, fmt, ct) in specs {
        let input_path = base.join(input_rel);
        let output_path = base.join(output_rel);
        let input = fs::read(&input_path).unwrap();
        let output = stream_process(&snapshot, &input, fmt, ct);
        fs::write(&output_path, &output).unwrap();
        let processed: String = String::from_utf8_lossy(&output).to_string();
        let redactions = processed.matches("[REDACTED_").count();
        let records = processed
            .as_bytes()
            .iter()
            .filter(|byte| **byte == b'\n')
            .count();
        eprintln!(
            "{input_rel}: {records} records, {redactions} redactions, {}B out",
            output.len()
        );
    }
}

/// Stream a bounded in-memory fixture through the same decoder + persistent
/// pipeline session the gateway uses for single PUTs.
fn stream_process(
    snapshot: &s4_gateway::plugin_registry::PipelineSnapshot,
    input: &[u8],
    format: Format,
    content_type: &str,
) -> Vec<u8> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime
        .block_on(async move {
            let session = s4_wasm_runtime::Session {
                format: format.as_str().to_string(),
                content_type: content_type.to_string(),
                policy_version: 0,
                ..Default::default()
            };
            let cancellation = CancellationToken::new();
            let mut pipeline = snapshot
                .clone()
                .start_streaming_session(session, cancellation)
                .await?;
            let limits = DecoderLimits {
                max_source_frame_bytes: input.len().max(1),
                ..DecoderLimits::default()
            };
            let mut decoder = RecordDecoder::new(format, limits)?;
            let mut output = Vec::new();
            for chunk in input.chunks(limits.max_source_frame_bytes) {
                decoder.push(chunk)?;
                while let Some(record) = decoder.next_record()? {
                    if let Some(record) = pipeline.process(record).await? {
                        output.extend_from_slice(&record.payload);
                        output.extend_from_slice(&record.separator);
                    }
                }
            }
            decoder.finish()?;
            while let Some(record) = decoder.next_record()? {
                if let Some(record) = pipeline.process(record).await? {
                    output.extend_from_slice(&record.payload);
                    output.extend_from_slice(&record.separator);
                }
            }
            for record in pipeline.finish().await? {
                output.extend_from_slice(&record.payload);
                output.extend_from_slice(&record.separator);
            }
            Ok::<_, s4_error::S4Error>(output)
        })
        .expect("fixture pipeline must succeed")
}
