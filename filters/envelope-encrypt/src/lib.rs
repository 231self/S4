//! Envelope encryption filter plugin.
//!
//! For every PII span detected in a record: generate a fresh 256-bit DEK,
//! wrap it with RSA-OAEP using the client's public key (X.509 cert or SPKI
//! PEM from `Context.public-key-pem`), encrypt the field with AES-256-GCM,
//! and replace the field with a JSON envelope:
//!
//! ```json
//! {"alg":"RSA-OAEP/AES-256-GCM","iv":"<b64>","enc_dek":"<b64>","ct":"<b64>","tag":"<b64>"}
//! ```
//!
//! When no public key is configured, falls back to redaction (`[REDACTED_*]`).
//! Randomness comes from `Context.entropy-seed` (a fresh 32-byte host seed per
//! session) seeding a ChaCha20 CSPRNG — no host imports required.

#[cfg(target_arch = "wasm32")]
mod guest {
    use std::cell::RefCell;

    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;
    use pii_shared::find_all_spans;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use rand_core::{CryptoRng, RngCore};
    use rsa::Oaep;
    use rsa::RsaPublicKey;
    use rsa::pkcs8::DecodePublicKey;
    use sha2::Sha256;

    wit_bindgen::generate!({
        world: "filter",
        path: "../../wit/s4-filter/world.wit",
    });

    thread_local! {
        static KEY: RefCell<Option<RsaPublicKey>> = const { RefCell::new(None) };
        static RNG: RefCell<Option<ChaCha20Rng>> = const { RefCell::new(None) };
    }

    fn parse_public_key(pem: &str) -> Result<Option<RsaPublicKey>, String> {
        if pem.trim().is_empty() {
            return Ok(None);
        }
        if let Ok(key) = RsaPublicKey::from_public_key_pem(pem) {
            return Ok(Some(key));
        }
        // Not an SPKI PEM — try an X.509 certificate.
        let (_, pem) = x509_parser::pem::parse_x509_pem(pem.as_bytes())
            .map_err(|e| format!("invalid public key or X.509 certificate: {e}"))?;
        let cert = pem
            .parse_x509()
            .map_err(|e| format!("certificate parse failed: {e}"))?;
        let spki = cert.public_key().raw;
        let key = RsaPublicKey::from_public_key_der(spki)
            .map_err(|e| format!("certificate does not carry an RSA key: {e}"))?;
        Ok(Some(key))
    }

    fn encrypt_field(field: &str, marker: &str) -> Result<String, String> {
        let (iv, enc_dek, ct_full) = RNG.with(|r| {
            let mut guard = r.borrow_mut();
            let rng = guard
                .as_mut()
                .ok_or_else(|| "no entropy seed".to_string())?;
            let mut dek = [0u8; 32];
            let mut iv = [0u8; 12];
            rng.fill_bytes(&mut dek);
            rng.fill_bytes(&mut iv);

            let key = KEY
                .with(|k| k.borrow().clone())
                .ok_or_else(|| "no public key".to_string())?;
            let enc_dek = key
                .encrypt(rng, Oaep::new::<Sha256>(), &dek)
                .map_err(|e| format!("RSA-OAEP wrap failed: {e}"))?;

            let cipher =
                Aes256Gcm::new_from_slice(&dek).map_err(|e| format!("AES key init failed: {e}"))?;
            let ct = cipher
                .encrypt(Nonce::from_slice(&iv), field.as_bytes())
                .map_err(|e| format!("AES-GCM encrypt failed: {e}"))?;
            Ok::<([u8; 12], Vec<u8>, Vec<u8>), String>((iv, enc_dek, ct))
        })?;

        if ct_full.len() < 16 {
            return Err(format!("ciphertext too short to carry a tag for {marker}"));
        }
        let split = ct_full.len() - 16;
        let ct = &ct_full[..split];
        let tag = &ct_full[split..];

        let envelope = serde_json::json!({
            "alg": "RSA-OAEP/AES-256-GCM",
            "iv": B64.encode(iv),
            "enc_dek": B64.encode(enc_dek),
            "ct": B64.encode(ct),
            "tag": B64.encode(tag),
        });
        Ok(envelope.to_string())
    }

    fn transform_record(payload: &[u8]) -> Result<Vec<u8>, String> {
        let text = std::str::from_utf8(payload).map_err(|e| e.to_string())?;
        let has_key = KEY.with(|k| k.borrow().is_some());

        if !has_key {
            return Ok(pii_shared::redact_pii(text).into_bytes());
        }

        let mut spans = find_all_spans(text);
        if spans.is_empty() {
            return Ok(payload.to_vec());
        }
        spans.sort_by_key(|(start, end, _)| (*start, *end));

        let mut output = String::with_capacity(text.len());
        let mut pos = 0;
        for (start, end, marker) in spans {
            if start < pos {
                continue;
            }
            output.push_str(&text[pos..start]);
            let field = &text[start..end];
            match encrypt_field(field, marker) {
                Ok(envelope) => output.push_str(&envelope),
                Err(e) => {
                    // Never leak plaintext: redact on any crypto failure.
                    let _ = e;
                    output.push_str(marker);
                }
            }
            pos = end;
        }
        output.push_str(&text[pos..]);
        Ok(output.into_bytes())
    }

    struct EnvelopeEncrypt;

    impl Guest for EnvelopeEncrypt {
        fn begin(context: Context) -> Result<(), String> {
            let key = match context.public_key_pem {
                Some(pem) => parse_public_key(&pem)?,
                None => None,
            };
            let seed: Option<[u8; 32]> = match context.entropy_seed {
                Some(bytes) if bytes.len() >= 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes[..32]);
                    Some(arr)
                }
                _ => None,
            };

            KEY.with(|k| *k.borrow_mut() = key);
            RNG.with(|r| *r.borrow_mut() = seed.map(ChaCha20Rng::from_seed));

            if KEY.with(|k| k.borrow().is_some()) && !RNG.with(|r| r.borrow().is_some()) {
                return Err(
                    "public key provided but no entropy seed from host — refusing to encrypt"
                        .to_string(),
                );
            }
            Ok(())
        }

        fn transform(payload: Vec<u8>) -> Result<Decision, String> {
            Ok(Decision::Emit(transform_record(&payload)?))
        }

        fn finish() -> Result<Vec<u8>, String> {
            Ok(Vec::new())
        }
    }

    // Silence unused warning for the CryptoRng import in non-encrypt paths.
    #[allow(dead_code)]
    fn _assert_crypto_rng(_rng: &mut ChaCha20Rng) {
        fn requires_crypto<R: CryptoRng + RngCore>() {}
        requires_crypto::<ChaCha20Rng>();
    }

    export!(EnvelopeEncrypt);
}
