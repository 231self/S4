//! Deterministic (stable) encryption filter plugin.
//!
//! Encrypts explicitly tagged JSON fields with AES-SIV, so the same input
//! always produces the same ciphertext — enabling JOINs and dedup across
//! datasets. The 32-byte key is derived host-side from the API key secret
//! (`Context.stable-key`); fields to encrypt are listed in
//! `Context.stable-fields` (comma-separated top-level JSON field names).
//!
//! Deterministic encryption reveals value equality — only tag fields that
//! are safe to expose as join keys (e.g. `user_id`, `email`), never secrets.

#[cfg(target_arch = "wasm32")]
mod guest {
    use std::cell::RefCell;

    use aes_siv::Aes256SivAead;
    use aes_siv::aead::{Aead, KeyInit};
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;

    wit_bindgen::generate!({
        world: "filter",
        path: "../../wit/s4-filter/world.wit",
    });

    thread_local! {
        static KEY: RefCell<Option<[u8; 64]>> = const { RefCell::new(None) };
        static FIELDS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    }

    fn stable_encrypt_value(cipher: &Aes256SivAead, value: &str) -> Result<String, String> {
        // Zero nonce makes AES-SIV deterministic (keyed only).
        let nonce = aes_siv::aead::generic_array::GenericArray::clone_from_slice(&[0u8; 16]);
        let ct = cipher
            .encrypt(&nonce, value.as_bytes())
            .map_err(|e| format!("AES-SIV encrypt failed: {e}"))?;
        Ok(B64.encode(ct))
    }

    fn transform_record(payload: &[u8]) -> Result<Vec<u8>, String> {
        let has_key = KEY.with(|k| k.borrow().is_some());
        let fields = FIELDS.with(|f| f.borrow().clone());
        if !has_key || fields.is_empty() {
            return Ok(payload.to_vec());
        }

        let text = std::str::from_utf8(payload).map_err(|e| e.to_string())?;
        let mut value: serde_json::Value = match serde_json::from_str(text) {
            Ok(v) => v,
            Err(_) => return Ok(payload.to_vec()),
        };
        if !value.is_object() {
            return Ok(payload.to_vec());
        }

        let key = KEY.with(|k| k.borrow().expect("key checked"));
        let cipher = Aes256SivAead::new_from_slice(&key).map_err(|e| e.to_string())?;

        let obj = value.as_object_mut().expect("checked object");
        let mut changed = false;
        for field in &fields {
            if let Some(serde_json::Value::String(s)) = obj.get_mut(field) {
                let encrypted = stable_encrypt_value(&cipher, s)?;
                *s = encrypted;
                changed = true;
            }
        }
        if changed {
            serde_json::to_vec(&value).map_err(|e| e.to_string())
        } else {
            Ok(payload.to_vec())
        }
    }

    struct StableEncrypt;

    impl Guest for StableEncrypt {
        fn begin(context: Context) -> Result<(), String> {
            let key: Option<[u8; 64]> = match context.stable_key {
                Some(bytes) if bytes.len() >= 64 => {
                    let mut arr = [0u8; 64];
                    arr.copy_from_slice(&bytes[..64]);
                    Some(arr)
                }
                _ => None,
            };
            let fields: Vec<String> = context
                .stable_fields
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            KEY.with(|k| *k.borrow_mut() = key);
            FIELDS.with(|f| *f.borrow_mut() = fields);
            Ok(())
        }

        fn transform(payload: Vec<u8>) -> Result<Decision, String> {
            Ok(Decision::Emit(transform_record(&payload)?))
        }

        fn finish() -> Result<Vec<u8>, String> {
            Ok(Vec::new())
        }
    }

    export!(StableEncrypt);
}
