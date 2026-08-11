use proptest::prelude::*;
use s4_gateway::{Format, Gateway, split_records};
use std::fs;
use std::path::PathBuf;

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

proptest! {
    #[test]
    fn deterministic_output(
        input in prop::collection::vec(any::<u8>(), 0..1024),
    ) {
        let gateway = load_gateway();
        let out1 = gateway.process(&input, Format::Text, "text/plain", None, None, None);
        let out2 = gateway.process(&input, Format::Text, "text/plain", None, None, None);
        match (out1, out2) {
            (Ok(o1), Ok(o2)) => {
                assert_eq!(o1.records_processed, o2.records_processed);
                assert_eq!(o1.bytes, o2.bytes);
            }
            (Err(_), Err(_)) => {}
            _ => panic!("determinism violated: one call succeeded, the other failed"),
        }
    }

    #[test]
    fn record_split_invariance(
        input in prop::string::string_regex("([[:ascii:]]{0,200}\n){0,5}").unwrap(),
    ) {
        let gateway = load_gateway();
        let bytes = input.as_bytes().to_vec();

        let Ok(records) = split_records(&bytes, Format::Text) else {
            return Ok(());
        };
        if records.is_empty() {
            return Ok(());
        }

        let full_result = gateway.process(&bytes, Format::Text, "text/plain", None, None, None).ok();

        let mut per_record = Vec::new();
        for record in &records {
            let r = gateway.engine.run(
                &s4_wasm_runtime::Session {
                    format: "text".to_string(),
                    content_type: "text/plain".to_string(),
                    policy_version: records.len() as u64,
                    ..Default::default()
                },
                std::slice::from_ref(record),
            );
            if let Ok(result) = r {
                per_record.extend_from_slice(&result);
                per_record.push(b'\n');
            }
        }

        if let Some(full) = full_result {
            let full_str = String::from_utf8_lossy(&full.bytes);
            let rec_str = String::from_utf8_lossy(&per_record);
            assert_eq!(
                full_str.trim(),
                rec_str.trim(),
                "full must match per-record using split_records logic"
            );
        }
    }

    #[test]
    fn format_detection_no_crash(
        input in prop::collection::vec(any::<u8>(), 0..2048),
    ) {
        let gateway = load_gateway();
        let _ = gateway.process(&input, Format::Text, "text/plain", None, None, None);
        let _ = gateway.process(&input, Format::Jsonl, "application/x-ndjson", None, None, None);
        let _ = gateway.process(&input, Format::Json, "application/json", None, None, None);
        let _ = gateway.process(&input, Format::Csv, "text/csv", None, None, None);
    }
}
