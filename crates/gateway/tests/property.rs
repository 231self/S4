mod common;

use proptest::prelude::*;
use s4_gateway::Format;
use s4_gateway::plugin_registry::PluginRegistry;
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

fn component_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("components")
        .join("pii-default.component.wasm")
}

fn registry() -> &'static PluginRegistry {
    static REGISTRY: OnceLock<PluginRegistry> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        let component = fs::read(component_path())
            .expect("filter component not found; run `just build-filters` first");
        let registry = PluginRegistry::new();
        registry.import("pii-default", &component).unwrap();
        registry
    })
}

proptest! {
    #[test]
    fn deterministic_output(
        input in prop::collection::vec(any::<u8>(), 0..1024),
    ) {
        let registry = registry();
        let out1 = common::stream_process(registry, &input, Format::Text, "text/plain", None, None, None);
        let out2 = common::stream_process(registry, &input, Format::Text, "text/plain", None, None, None);
        match (out1, out2) {
            (Ok(o1), Ok(o2)) => {
                assert_eq!(o1, o2);
            }
            (Err(_), Err(_)) => {}
            _ => panic!("determinism violated: one call succeeded, the other failed"),
        }
    }

    #[test]
    fn record_split_invariance(
        input in prop::string::string_regex("([[:ascii:]]{0,200}\n){0,5}").unwrap(),
    ) {
        let registry = registry();
        let bytes = input.as_bytes().to_vec();

        let Ok(full) = common::stream_chunked(registry, &bytes, Format::Text, "text/plain", bytes.len().max(1)) else {
            return Ok(());
        };
        let Ok(split) = common::stream_chunked(registry, &bytes, Format::Text, "text/plain", 3) else {
            return Ok(());
        };
        prop_assert_eq!(
            full,
            split,
            "streaming output must be invariant under transport frame splits"
        );
    }

    #[test]
    fn format_detection_no_crash(
        input in prop::collection::vec(any::<u8>(), 0..2048),
    ) {
        let registry = registry();
        let _ = common::stream_process(registry, &input, Format::Text, "text/plain", None, None, None);
        let _ = common::stream_process(registry, &input, Format::Jsonl, "application/x-ndjson", None, None, None);
        let _ = common::stream_process(registry, &input, Format::Json, "application/json", None, None, None);
        let _ = common::stream_process(registry, &input, Format::Csv, "text/csv", None, None, None);
    }
}
