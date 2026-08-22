//! Stable (deterministic) encryption tests: same input → same ciphertext,
//! decryptable by the client holding the derived key, isolated across keys.

use aes_siv::Aes256SivAead;
use aes_siv::aead::{Aead, KeyInit};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use hmac::{Hmac, Mac};
use s4_gateway::Format;
use s4_gateway::plugin_registry::PluginRegistry;
use sha2::Sha256;
use std::fs;
use std::path::PathBuf;

mod common;

fn component(name: &str) -> Vec<u8> {
    fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("components")
            .join(name),
    )
    .unwrap_or_else(|_| panic!("component not found: {name}; run `just build-filters` first"))
}

fn stable_key(secret: &str) -> Vec<u8> {
    type HmacSha256 = Hmac<Sha256>;
    let mut out = Vec::with_capacity(64);
    for i in 1..=2u8 {
        let mut mac =
            <HmacSha256 as hmac::Mac>::new_from_slice(secret.as_bytes()).expect("hmac key");
        mac.update(b"s4-stable-encrypt");
        mac.update(&[i]);
        out.extend_from_slice(&mac.finalize().into_bytes());
    }
    out
}

fn registry() -> PluginRegistry {
    let registry = PluginRegistry::new();
    registry
        .import(
            "stable-encrypt",
            &component("stable-encrypt.component.wasm"),
        )
        .unwrap();
    registry
}

fn run(
    registry: &PluginRegistry,
    input: &[u8],
    key: Option<&[u8]>,
    fields: Option<&str>,
) -> Vec<u8> {
    common::stream_process(
        registry,
        input,
        Format::Jsonl,
        "application/x-ndjson",
        None,
        key,
        fields,
    )
    .unwrap()
}

fn decrypt(value: &str, key: &[u8]) -> String {
    let cipher = Aes256SivAead::new_from_slice(key).unwrap();
    let nonce = aes_siv::aead::generic_array::GenericArray::clone_from_slice(&[0u8; 16]);
    let ct = B64.decode(value).unwrap();
    String::from_utf8(cipher.decrypt(&nonce, ct.as_ref()).unwrap()).unwrap()
}

const INPUT: &[u8] =
    b"{\"email\":\"alice@x.com\",\"name\":\"Alice\"}\n{\"email\":\"bob@x.com\",\"name\":\"Bob\"}\n";

#[test]
fn stable_encryption_is_deterministic() {
    let registry = registry();
    let key = stable_key("s4s_testsecret");
    let a = run(&registry, INPUT, Some(&key), Some("email"));
    let b = run(&registry, INPUT, Some(&key), Some("email"));
    assert_eq!(a, b, "same key + input must produce identical output");
}

#[test]
fn stable_encryption_roundtrips_and_preserves_other_fields() {
    let registry = registry();
    let key = stable_key("s4s_testsecret");
    let out = run(&registry, INPUT, Some(&key), Some("email"));
    let out_str = String::from_utf8_lossy(&out);

    assert!(!out_str.contains("alice@x.com"), "plaintext email leaked");

    let records: Vec<serde_json::Value> = out_str
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(records.len(), 2);

    assert_eq!(
        decrypt(records[0]["email"].as_str().unwrap(), &key),
        "alice@x.com"
    );
    assert_eq!(
        decrypt(records[1]["email"].as_str().unwrap(), &key),
        "bob@x.com"
    );
    assert_eq!(
        records[0]["name"], "Alice",
        "non-tagged field must be unchanged"
    );
    assert_eq!(
        records[1]["name"], "Bob",
        "non-tagged field must be unchanged"
    );
}

#[test]
fn different_keys_produce_different_ciphertext() {
    let registry = registry();
    let k1 = stable_key("s4s_secret_one");
    let k2 = stable_key("s4s_secret_two");
    let a = run(&registry, INPUT, Some(&k1), Some("email"));
    let b = run(&registry, INPUT, Some(&k2), Some("email"));
    assert_ne!(a, b, "different tenants must not share ciphertext");
}

#[test]
fn no_fields_no_encryption() {
    let registry = registry();
    let key = stable_key("s4s_testsecret");
    let out = run(&registry, INPUT, Some(&key), None);
    assert_eq!(
        out, INPUT,
        "without tagged fields the record must pass through"
    );
}

#[test]
fn no_key_no_encryption() {
    let registry = registry();
    let out = run(&registry, INPUT, None, Some("email"));
    assert_eq!(
        out, INPUT,
        "without a stable key the record must pass through"
    );
}

#[test]
fn non_json_records_pass_through() {
    let registry = registry();
    let key = stable_key("s4s_testsecret");
    let input = b"plain text line\nanother line\n";
    let out = run(&registry, input, Some(&key), Some("email"));
    assert_eq!(out, input);
}

#[test]
fn unknown_tagged_field_is_skipped() {
    let registry = registry();
    let key = stable_key("s4s_testsecret");
    let out = run(&registry, INPUT, Some(&key), Some("does_not_exist"));
    assert_eq!(out, INPUT);
}
