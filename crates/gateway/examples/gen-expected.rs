use s4_gateway::{Format, Gateway};
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
    let gateway = Gateway::new(&component).expect("gateway failed");

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
        let output = gateway.process(&input, fmt, ct, None, None, None).unwrap();
        fs::write(&output_path, &output.bytes).unwrap();
        let processed: String = String::from_utf8_lossy(&output.bytes).to_string();
        let redactions = processed.matches("[REDACTED_").count();
        eprintln!(
            "{input_rel}: {} records, {} redactions, {}B out",
            output.records_processed,
            redactions,
            output.bytes.len()
        );
    }
}
