mod common;

use s4_gateway::Format;
use s4_gateway::plugin_registry::PluginRegistry;
use std::fs;
use std::path::PathBuf;

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

fn registry_with(components: &[&str]) -> PluginRegistry {
    let registry = PluginRegistry::new();
    for name in components {
        registry
            .import(name, &read_component(&format!("{name}.component.wasm")))
            .unwrap_or_else(|e| panic!("failed to import {name}: {e}"));
    }
    registry
}

fn process_with(registry: &PluginRegistry, input: &[u8], format: Format) -> Vec<u8> {
    let mut bytes =
        common::stream_process(registry, input, format, "text/plain", None, None, None).unwrap();
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    bytes
}

#[test]
fn noop_passes_records_through_unchanged() {
    let registry = registry_with(&["noop"]);

    let input = b"alice@example.com 123-45-6789\nhello world\n";
    let output = common::stream_process(
        &registry,
        input,
        Format::Text,
        "text/plain",
        None,
        None,
        None,
    )
    .unwrap();

    assert_eq!(output, input);
}

#[test]
fn email_detect_redacts_only_emails() {
    let registry = registry_with(&["email-detect"]);

    let input = b"alice@test.com SSN 123-45-6789 card 5500005555555559";
    let output = process_with(&registry, input, Format::Text);
    assert_eq!(
        String::from_utf8_lossy(&output),
        "[REDACTED_EMAIL] SSN 123-45-6789 card 5500005555555559"
    );
}

#[test]
fn ssn_detect_redacts_only_ssns() {
    let registry = registry_with(&["ssn-detect"]);

    let input = b"alice@test.com SSN 123-45-6789 card 5500005555555559";
    let output = process_with(&registry, input, Format::Text);
    assert_eq!(
        String::from_utf8_lossy(&output),
        "alice@test.com SSN [REDACTED_SSN] card 5500005555555559"
    );
}

#[test]
fn card_detect_redacts_only_cards() {
    let registry = registry_with(&["card-detect"]);

    let input = b"alice@test.com SSN 123-45-6789 card 5500005555555559";
    let output = process_with(&registry, input, Format::Text);
    assert_eq!(
        String::from_utf8_lossy(&output),
        "alice@test.com SSN 123-45-6789 card [REDACTED_CARD]"
    );
}

#[test]
fn modular_pipeline_matches_pii_default() {
    let modular = registry_with(&["email-detect", "ssn-detect", "card-detect"]);
    let combined = registry_with(&["pii-default"]);

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
    let registry = registry_with(&["email-detect"]);
    let info = registry.list().remove(0);
    registry.set_enabled(&info.id, false).unwrap();

    let input = b"alice@test.com SSN 123-45-6789";
    let output = process_with(&registry, input, Format::Text);
    assert_eq!(
        output, input,
        "disabled plugin must pass records through raw"
    );
}

#[test]
fn full_pipeline_composition_noop_detect_encrypt() {
    // The plan's core flow: noop → email-detect → ssn-detect → card-detect
    // → envelope-encrypt, in a single ordered registry.
    let registry = registry_with(&[
        "noop",
        "email-detect",
        "ssn-detect",
        "card-detect",
        "envelope-encrypt",
    ]);

    let input = b"alice@example.com SSN 123-45-6789 card 4111111111111111";
    // No public key: the encrypt plugin redacts (upstream detects already
    // redacted, so the encrypt plugin's own detection is a no-op fallback).
    let out = process_with(&registry, input, Format::Text);
    let s = String::from_utf8_lossy(&out);
    assert_eq!(
        s,
        "[REDACTED_EMAIL] SSN [REDACTED_SSN] card [REDACTED_CARD]"
    );
}
