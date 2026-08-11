#[test]
fn corpus_host_repro() {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = dir
        .join("../..")
        .join("tests/fixtures/pii/perf/large-corpus-500.jsonl");
    let data = std::fs::read(path).unwrap();
    let text = String::from_utf8_lossy(&data);
    let redactions = pii_shared::redact_pii(&text).matches("[REDACTED_").count();
    assert!(redactions > 50, "expected >50 redactions, got {redactions}");
}
