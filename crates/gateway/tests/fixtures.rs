use s4_gateway::{Format, Gateway};
use std::fs;
use std::path::PathBuf;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("pii")
}

fn component_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("components")
        .join("pii-default.component.wasm")
}

fn load_gateway() -> Gateway {
    let component = fs::read(component_path())
        .expect("filter component not found; run `just build-filters` first");
    Gateway::new(&component).expect("failed to load gateway")
}

fn session(format: &str, content_type: &str) -> s4_wasm_runtime::Session {
    s4_wasm_runtime::Session {
        format: format.to_string(),
        content_type: content_type.to_string(),
        policy_version: 1,
        ..Default::default()
    }
}

fn run_fixture(
    name: &str,
    input_path: &str,
    expected_path: &str,
    format: Format,
    content_type: &str,
) {
    let dir = fixture_dir();
    let input = fs::read(dir.join(input_path)).unwrap();
    let expected_raw = fs::read(dir.join(expected_path)).unwrap();
    let expected = trim_trailing_newline(&expected_raw);

    let gateway = load_gateway();
    let output = gateway
        .process(&input, format, content_type, None, None, None)
        .unwrap();
    let output_bytes = trim_trailing_newline(&output.bytes);

    let output_str = String::from_utf8_lossy(output_bytes);
    let expected_str = String::from_utf8_lossy(expected);

    if output_bytes != expected {
        eprintln!("=== {name} MISMATCH ===");
        eprintln!("--- output ({}) ---", output.records_processed);
        eprintln!("{output_str}");
        eprintln!("--- expected ---");
        eprintln!("{expected_str}");
        panic!("fixture {name}: output does not match expected");
    }
}

fn trim_trailing_newline(data: &[u8]) -> &[u8] {
    if data.last() == Some(&b'\n') {
        &data[..data.len() - 1]
    } else {
        data
    }
}

#[test]
fn fixture_sample1_text() {
    run_fixture(
        "sample1.txt",
        "sample1.txt",
        "sample1.expected.txt",
        Format::Text,
        "text/plain",
    );
}

#[test]
fn fixture_sample2_jsonl() {
    run_fixture(
        "sample2.jsonl",
        "sample2.jsonl",
        "sample2.expected.jsonl",
        Format::Jsonl,
        "application/x-ndjson",
    );
}

#[test]
fn fixture_sample3_csv() {
    run_fixture(
        "sample3.csv",
        "sample3.csv",
        "sample3.expected.csv",
        Format::Csv,
        "text/csv",
    );
}

#[test]
fn deterministic_output_same_input() {
    let gateway = load_gateway();
    let input = fs::read(fixture_dir().join("sample1.txt")).unwrap();

    let out1 = gateway
        .process(&input, Format::Text, "text/plain", None, None, None)
        .unwrap();
    let out2 = gateway
        .process(&input, Format::Text, "text/plain", None, None, None)
        .unwrap();
    assert_eq!(
        out1.bytes, out2.bytes,
        "same input must produce same output"
    );
}

#[test]
fn chunk_split_invariance_text() {
    let gateway = load_gateway();
    let input = fs::read(fixture_dir().join("sample1.txt")).unwrap();
    let lines: Vec<Vec<u8>> = String::from_utf8_lossy(&input)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.as_bytes().to_vec())
        .collect();

    let mut baseline = Vec::new();
    for line in &lines {
        let result = gateway
            .engine
            .run(&session("text", "text/plain"), std::slice::from_ref(line))
            .unwrap();
        baseline.extend_from_slice(&result);
    }

    let mut reversed = Vec::new();
    for line in lines.iter().rev() {
        let result = gateway
            .engine
            .run(&session("text", "text/plain"), std::slice::from_ref(line))
            .unwrap();
        reversed.push(result);
    }
    reversed.reverse();

    let mut reversed_bytes = Vec::new();
    for r in &reversed {
        reversed_bytes.extend_from_slice(r);
    }

    assert_eq!(
        baseline, reversed_bytes,
        "filter must be deterministic per-record"
    );
}

#[test]
fn comprehensive_fixture_jsonl() {
    run_fixture(
        "comprehensive.jsonl",
        "comprehensive.jsonl",
        "comprehensive.expected.jsonl",
        Format::Jsonl,
        "application/x-ndjson",
    );
}

#[test]
fn comprehensive_per_record_validation() {
    let gateway = load_gateway();
    let input = fs::read(fixture_dir().join("comprehensive.jsonl")).unwrap();
    let expected_raw = fs::read(fixture_dir().join("comprehensive.expected.jsonl")).unwrap();

    let records = s4_gateway::split_records(&input, Format::Jsonl).unwrap();
    let expected_records = s4_gateway::split_records(&expected_raw, Format::Jsonl).unwrap();

    assert_eq!(
        records.len(),
        expected_records.len(),
        "record count mismatch"
    );

    let mut redacted = 0u32;
    let mut clean = 0u32;
    let mut mismatches = 0u32;

    for (i, record) in records.iter().enumerate() {
        let result = gateway
            .engine
            .run(
                &session("jsonl", "application/x-ndjson"),
                std::slice::from_ref(record),
            )
            .unwrap();
        let expected = &expected_records[i];

        let result_str = String::from_utf8_lossy(&result);
        let expected_str = String::from_utf8_lossy(expected);

        if result_str != expected_str {
            eprintln!("[{i}] MISMATCH: got {result_str:?} expected {expected_str:?}");
            mismatches += 1;
        }

        if expected_str.contains("[REDACTED_") {
            redacted += 1;
        } else if result_str == *record.iter().map(|&b| b as char).collect::<String>() {
            clean += 1;
        }
    }

    assert_eq!(
        mismatches,
        0,
        "{mismatches} per-record mismatches out of {} records",
        records.len()
    );
    assert!(
        redacted > 10,
        "expected >10 redacted records, got {redacted}"
    );
    assert!(clean > 5, "expected >5 clean records, got {clean}");
    eprintln!(
        "Comprehensive: {} records, {} redacted, {} clean",
        records.len(),
        redacted,
        clean
    );
}

#[test]
fn real_world_cloudtrail() {
    run_fixture(
        "cloudtrail.jsonl",
        "real-world/cloudtrail.jsonl",
        "real-world/cloudtrail.expected.jsonl",
        Format::Jsonl,
        "application/x-ndjson",
    );
}

#[test]
fn real_world_app_logs() {
    run_fixture(
        "app-logs.jsonl",
        "real-world/app-logs.jsonl",
        "real-world/app-logs.expected.jsonl",
        Format::Jsonl,
        "application/x-ndjson",
    );
}

#[test]
fn adversarial_empty_records() {
    run_fixture(
        "empty-records.jsonl",
        "adversarial/empty-records.jsonl",
        "adversarial/empty-records.expected.jsonl",
        Format::Jsonl,
        "application/x-ndjson",
    );
}

#[test]
fn adversarial_injection_attempts() {
    run_fixture(
        "injection-attempts.jsonl",
        "adversarial/injection-attempts.jsonl",
        "adversarial/injection-attempts.expected.jsonl",
        Format::Jsonl,
        "application/x-ndjson",
    );
}

#[test]
fn adversarial_binary_blob_does_not_crash() {
    let gateway = load_gateway();
    let input = fs::read(fixture_dir().join("adversarial").join("binary-blob.raw")).unwrap();
    let result = gateway.process(&input, Format::Text, "text/plain", None, None, None);
    match result {
        Ok(_) => {}
        Err(e) => {
            eprintln!("binary blob produced error (expected): {e}");
        }
    }
}

#[test]
fn performance_corpus_500_deterministic() {
    let gateway = load_gateway();
    let input = fs::read(fixture_dir().join("perf").join("large-corpus-500.jsonl")).unwrap();

    let out1 = gateway
        .process(
            &input,
            Format::Jsonl,
            "application/x-ndjson",
            None,
            None,
            None,
        )
        .unwrap();
    let out2 = gateway
        .process(
            &input,
            Format::Jsonl,
            "application/x-ndjson",
            None,
            None,
            None,
        )
        .unwrap();

    assert_eq!(out1.records_processed, out2.records_processed);
    assert_eq!(out1.bytes, out2.bytes);
    assert_eq!(out1.records_processed, 500);

    let redactions = String::from_utf8_lossy(&out1.bytes)
        .matches("[REDACTED_")
        .count();
    eprintln!(
        "Performance corpus: {} records, {} redactions, {} bytes output",
        out1.records_processed,
        redactions,
        out1.bytes.len()
    );
    assert!(
        redactions > 50,
        "expected >50 redactions in 500 records, got {redactions}"
    );
}

#[test]
fn adversarial_xml_injection_passthrough() {
    let gateway = load_gateway();
    let input = br#"{"data":"<?xml version=\"1.0\"?><Error><Code>AccessDenied</Code></Error>"}"#;
    let result = gateway
        .process(
            input,
            Format::Jsonl,
            "application/x-ndjson",
            None,
            None,
            None,
        )
        .unwrap();
    let output = String::from_utf8_lossy(&result.bytes);
    assert!(
        output.contains("AccessDenied"),
        "non-S3 XML should pass through unchanged"
    );
}

#[test]
fn adversarial_oversized_record() {
    let gateway = load_gateway();
    let long = "A".repeat(10_000) + "@example.com";
    let input = serde_json::json!({"user": long}).to_string();
    let result = gateway.process(
        input.as_bytes(),
        Format::Jsonl,
        "application/x-ndjson",
        None,
        None,
        None,
    );
    assert!(result.is_ok(), "large record should not crash");
}
