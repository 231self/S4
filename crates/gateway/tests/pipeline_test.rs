use s4_gateway::plugin_registry::PluginRegistry;
use s4_gateway::{Format, Gateway};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

fn component_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("components")
        .join(name)
}

fn read_component(name: &str) -> Vec<u8> {
    fs::read(component_path(name))
        .unwrap_or_else(|_| panic!("component not found: {name}; run `just build-filters` first"))
}

fn gateway_with_registry() -> Gateway {
    let engine = s4_wasm_runtime::FilterEngine::new(&read_component("noop.component.wasm"))
        .expect("failed to load noop engine");
    Gateway::with_registry(engine, Arc::new(PluginRegistry::new()))
}

#[test]
fn noop_passes_records_through_unchanged() {
    let gateway = gateway_with_registry();
    let registry = gateway.plugins.as_ref().unwrap().clone();
    registry
        .import("noop", &read_component("noop.component.wasm"))
        .unwrap();

    let input = b"alice@example.com 123-45-6789\nhello world\n";
    let output = gateway
        .process(input, Format::Text, "text/plain", None, None, None)
        .unwrap();

    assert_eq!(output.records_processed, 2);
    assert_eq!(output.bytes, input);
}

fn registry_with(components: &[&str]) -> PluginRegistry {
    let registry = PluginRegistry::new();
    for (i, name) in components.iter().enumerate() {
        registry
            .import(name, &read_component(&format!("{name}.component.wasm")))
            .unwrap_or_else(|e| panic!("failed to import {name}: {e}"));
        let _ = i;
    }
    registry
}

fn process_with(gateway: &Gateway, input: &[u8], format: Format) -> Vec<u8> {
    let mut bytes = gateway
        .process(input, format, "text/plain", None, None, None)
        .unwrap()
        .bytes;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    bytes
}

#[test]
fn email_detect_redacts_only_emails() {
    let engine =
        s4_wasm_runtime::FilterEngine::new(&read_component("email-detect.component.wasm")).unwrap();
    let gateway = Gateway::with_registry(engine, Arc::new(registry_with(&["email-detect"])));

    let input = b"alice@test.com SSN 123-45-6789 card 5500005555555559";
    let output = process_with(&gateway, input, Format::Text);
    assert_eq!(
        String::from_utf8_lossy(&output),
        "[REDACTED_EMAIL] SSN 123-45-6789 card 5500005555555559"
    );
}

#[test]
fn ssn_detect_redacts_only_ssns() {
    let engine =
        s4_wasm_runtime::FilterEngine::new(&read_component("ssn-detect.component.wasm")).unwrap();
    let gateway = Gateway::with_registry(engine, Arc::new(registry_with(&["ssn-detect"])));

    let input = b"alice@test.com SSN 123-45-6789 card 5500005555555559";
    let output = process_with(&gateway, input, Format::Text);
    assert_eq!(
        String::from_utf8_lossy(&output),
        "alice@test.com SSN [REDACTED_SSN] card 5500005555555559"
    );
}

#[test]
fn card_detect_redacts_only_cards() {
    let engine =
        s4_wasm_runtime::FilterEngine::new(&read_component("card-detect.component.wasm")).unwrap();
    let gateway = Gateway::with_registry(engine, Arc::new(registry_with(&["card-detect"])));

    let input = b"alice@test.com SSN 123-45-6789 card 5500005555555559";
    let output = process_with(&gateway, input, Format::Text);
    assert_eq!(
        String::from_utf8_lossy(&output),
        "alice@test.com SSN 123-45-6789 card [REDACTED_CARD]"
    );
}

#[test]
fn modular_pipeline_matches_pii_default() {
    let modular = {
        let engine =
            s4_wasm_runtime::FilterEngine::new(&read_component("email-detect.component.wasm"))
                .unwrap();
        let registry = registry_with(&["email-detect", "ssn-detect", "card-detect"]);
        Gateway::with_registry(engine, Arc::new(registry))
    };
    let combined = {
        let engine =
            s4_wasm_runtime::FilterEngine::new(&read_component("pii-default.component.wasm"))
                .unwrap();
        let registry = registry_with(&["pii-default"]);
        Gateway::with_registry(engine, Arc::new(registry))
    };

    let cases: &[&[u8]] = &[
        b"alice@test.com SSN 123-45-6789 card 5500005555555559",
        b"Card 4111 1111 1111 1111 here and bob@x.io",
        b"078051120 123456789 378282246310005",
        b"plain text with no pii\n",
        b"Bad SSN 000-12-3456 Bad card 1234567890123",
    ];

    for case in cases {
        let a = process_with(&modular, case, Format::Text);
        let b = process_with(&combined, case, Format::Text);
        assert_eq!(
            a, b,
            "modular pipeline diverged from pii-default for {case:?}"
        );
    }
}

#[test]
fn disabled_plugins_are_skipped() {
    let engine =
        s4_wasm_runtime::FilterEngine::new(&read_component("email-detect.component.wasm")).unwrap();
    let registry = registry_with(&["email-detect"]);
    let info = registry.list().remove(0);
    registry.set_enabled(&info.id, false).unwrap();

    let gateway = Gateway::with_registry(engine, Arc::new(registry));
    let input = b"alice@test.com SSN 123-45-6789";
    let output = process_with(&gateway, input, Format::Text);
    assert_eq!(
        output, input,
        "disabled plugin must pass records through raw"
    );
}

#[test]
fn full_pipeline_composition_noop_detect_encrypt() {
    // The plan's core flow: noop → email-detect → ssn-detect → card-detect
    // → envelope-encrypt, in a single ordered registry.
    let engine =
        s4_wasm_runtime::FilterEngine::new(&read_component("envelope-encrypt.component.wasm"))
            .unwrap();
    let registry = registry_with(&[
        "noop",
        "email-detect",
        "ssn-detect",
        "card-detect",
        "envelope-encrypt",
    ]);
    let gateway = Gateway::with_registry(engine, Arc::new(registry));

    let input = b"alice@example.com SSN 123-45-6789 card 4111111111111111";
    // No public key: the encrypt plugin redacts (upstream detects already
    // redacted, so the encrypt plugin's own detection is a no-op fallback).
    let out = process_with(&gateway, input, Format::Text);
    let s = String::from_utf8_lossy(&out);
    assert_eq!(
        s,
        "[REDACTED_EMAIL] SSN [REDACTED_SSN] card [REDACTED_CARD]"
    );
}
