//! Envelope encryption for API key secrets.
//!
//! The gateway never stores plaintext API key secrets. Each secret is
//! encrypted with a fresh 256-bit data key (DEK) using AES-256-GCM, and the
//! DEK itself is wrapped by a [`KeyWrapping`] implementation so the master
//! key can live elsewhere (operator-provided `S4_SECRET_KEK`, or a KMS key in
//! a follow-up). Decryption only happens in memory, on demand, to recompute a
//! SigV4 signature.
//!
//! Envelope formats:
//! - `v1:{base64(wrapped_dek)}:{base64(nonce)}:{base64(ciphertext+tag)}`
//! - `v2:{base64(wrapped_dek)}:{base64(nonce)}:{base64(ciphertext+tag)}`
//!
//! v2 authenticates the API key identity as AES-GCM additional authenticated
//! data (AAD), preventing an encrypted secret from being moved to another key.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use rand::RngCore;
use rand::rngs::OsRng;
use std::fmt::Debug;
use std::sync::Arc;
use tracing::warn;

const LEGACY_ENVELOPE_VERSION: &str = "v1";
const ENVELOPE_VERSION: &str = "v2";
const AAD_DOMAIN: &[u8] = b"s4.api-key.secret.v2\0";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;

/// Wraps (encrypts) and unwraps (decrypts) the per-secret data key (DEK).
///
/// The OSS self-host binary uses [`LocalKeyWrapping`] with an operator
/// provided KEK. A KMS-backed implementation (AWS KMS `GenerateDataKey` /
/// `Decrypt`) can be added behind this trait so the gateway never holds the
/// master key.
pub trait KeyWrapping: Send + Sync + Debug {
    fn wrap(&self, dek: &[u8]) -> Result<Vec<u8>>;
    fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>>;
}

/// Wraps the DEK with a static 256-bit KEK using AES-256-GCM. The per-wrap
/// nonce is prepended to the ciphertext so the blob is self-describing.
#[derive(Debug)]
pub struct LocalKeyWrapping {
    kek: [u8; KEY_LEN],
}

impl LocalKeyWrapping {
    /// Read the KEK from `S4_SECRET_KEK` (base64, 32 bytes).
    pub fn from_env() -> Result<Option<Self>> {
        match std::env::var("S4_SECRET_KEK") {
            Ok(v) => {
                let kek = B64
                    .decode(v.trim())
                    .context("S4_SECRET_KEK must be base64")?;
                let kek: [u8; KEY_LEN] = kek
                    .try_into()
                    .map_err(|_| anyhow!("S4_SECRET_KEK must decode to 32 bytes"))?;
                Ok(Some(Self { kek }))
            }
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(e) => Err(e).context("failed to read S4_SECRET_KEK"),
        }
    }

    /// A KEK supplied directly (tests, key material from elsewhere).
    pub fn with_kek(kek: [u8; KEY_LEN]) -> Self {
        Self { kek }
    }

    /// A random in-memory KEK. Used when no KEK is configured: secrets cannot
    /// be decrypted after a restart (SigV4 verification is lost; hash-based
    /// SDK auth still works).
    pub fn ephemeral() -> Self {
        let mut kek = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut kek);
        Self { kek }
    }
}

impl KeyWrapping for LocalKeyWrapping {
    fn wrap(&self, dek: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let cipher = Aes256Gcm::new_from_slice(&self.kek).map_err(anyhow::Error::msg)?;
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), dek)
            .map_err(|_| anyhow!("DEK wrap failed"))?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>> {
        if wrapped.len() < NONCE_LEN {
            return Err(anyhow!("wrapped DEK too short"));
        }
        let (nonce, ct) = wrapped.split_at(NONCE_LEN);
        let cipher = Aes256Gcm::new_from_slice(&self.kek).map_err(anyhow::Error::msg)?;
        cipher
            .decrypt(Nonce::from_slice(nonce), ct)
            .map_err(|_| anyhow!("DEK unwrap failed"))
    }
}

/// Resolve the OSS self-host wrapping: `S4_SECRET_KEK` if set, otherwise an
/// ephemeral key with a warning that SigV4 verification will not survive a
/// restart. KMS/Vault wrappers are injected by callers that construct their
/// own [`KeyWrapping`] and pass it to `build_state`.
pub fn default_wrapping() -> Result<Arc<dyn KeyWrapping>> {
    match LocalKeyWrapping::from_env()? {
        Some(wrapping) => Ok(Arc::new(wrapping)),
        None => {
            warn!(
                "S4_SECRET_KEK is not set; API key secrets use an ephemeral key and SigV4 verification will not survive a restart"
            );
            Ok(Arc::new(LocalKeyWrapping::ephemeral()))
        }
    }
}

/// Encrypts and decrypts API key secrets at rest (envelope encryption).
#[derive(Debug)]
pub struct SecretCipher {
    wrapping: Arc<dyn KeyWrapping>,
}

impl SecretCipher {
    pub fn new(wrapping: Arc<dyn KeyWrapping>) -> Self {
        Self { wrapping }
    }

    /// Encrypt `secret`, returning a v2 envelope bound to `key_id`.
    pub fn encrypt(&self, key_id: &str, secret: &str) -> Result<String> {
        self.encrypt_with_version(ENVELOPE_VERSION, key_id, secret)
    }

    fn encrypt_with_version(&self, version: &str, key_id: &str, secret: &str) -> Result<String> {
        let mut dek = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut dek);
        let wrapped = self.wrapping.wrap(&dek)?;
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let cipher = Aes256Gcm::new_from_slice(&dek).map_err(anyhow::Error::msg)?;
        let ct = if version == ENVELOPE_VERSION {
            let aad = envelope_aad(key_id);
            cipher.encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: secret.as_bytes(),
                    aad: &aad,
                },
            )
        } else {
            cipher.encrypt(Nonce::from_slice(&nonce), secret.as_bytes())
        }
        .map_err(|_| anyhow!("secret encryption failed"))?;
        Ok(format!(
            "{version}:{}:{}:{}",
            B64.encode(wrapped),
            B64.encode(nonce),
            B64.encode(ct)
        ))
    }

    /// Decrypt a v1 or v2 envelope. v2 must match `key_id`'s AAD binding.
    pub fn decrypt(&self, key_id: &str, blob: &str) -> Option<String> {
        let parts: Vec<&str> = blob.splitn(4, ':').collect();
        if parts.len() != 4
            || (parts[0] != ENVELOPE_VERSION && parts[0] != LEGACY_ENVELOPE_VERSION)
        {
            return None;
        }
        let wrapped = B64.decode(parts[1]).ok()?;
        let nonce = B64.decode(parts[2]).ok()?;
        if nonce.len() != NONCE_LEN {
            return None;
        }
        let ct = B64.decode(parts[3]).ok()?;
        let dek = self.wrapping.unwrap(&wrapped).ok()?;
        let cipher = Aes256Gcm::new_from_slice(&dek).ok()?;
        let plaintext = if parts[0] == ENVELOPE_VERSION {
            let aad = envelope_aad(key_id);
            cipher.decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ct.as_ref(),
                    aad: &aad,
                },
            )
        } else {
            cipher.decrypt(Nonce::from_slice(&nonce), ct.as_ref())
        };
        plaintext
            .ok()
            .and_then(|p| String::from_utf8(p).ok())
    }

    pub fn is_legacy_envelope(blob: &str) -> bool {
        blob.starts_with("v1:")
    }

    #[cfg(test)]
    pub(crate) fn encrypt_v1(&self, secret: &str) -> Result<String> {
        self.encrypt_with_version(LEGACY_ENVELOPE_VERSION, "", secret)
    }
}

fn envelope_aad(key_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + key_id.len());
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(key_id.as_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    // env mutations must be serialized across tests.
    static ENV_LOCK: StdMutex<()> = StdMutex::new(());

    fn cipher_with_kek(kek: u8) -> SecretCipher {
        SecretCipher::new(Arc::new(LocalKeyWrapping::with_kek([kek; KEY_LEN])))
    }

    #[test]
    fn v2_roundtrip_local_kek() {
        let cipher = cipher_with_kek(7);
        let blob = cipher
            .encrypt("s4_key_identity", "s4s_secret_value_1234")
            .unwrap();
        assert!(blob.starts_with("v2:"));
        assert_eq!(
            cipher.decrypt("s4_key_identity", &blob).as_deref(),
            Some("s4s_secret_value_1234")
        );
    }

    #[test]
    fn v1_envelope_remains_compatible() {
        let cipher = cipher_with_kek(7);
        let blob = cipher.encrypt_v1("legacy-secret").unwrap();

        assert!(SecretCipher::is_legacy_envelope(&blob));
        assert_eq!(
            cipher.decrypt("any-key-id", &blob).as_deref(),
            Some("legacy-secret")
        );
    }

    #[test]
    fn v2_wrong_identity_fails() {
        let cipher = cipher_with_kek(7);
        let blob = cipher.encrypt("key-a", "secret").unwrap();

        assert_eq!(cipher.decrypt("key-b", &blob), None);
    }

    #[test]
    fn swapped_v2_envelopes_fail() {
        let cipher = cipher_with_kek(7);
        let envelope_a = cipher.encrypt("key-a", "secret-a").unwrap();
        let envelope_b = cipher.encrypt("key-b", "secret-b").unwrap();

        assert_eq!(cipher.decrypt("key-a", &envelope_b), None);
        assert_eq!(cipher.decrypt("key-b", &envelope_a), None);
    }

    #[test]
    fn tampered_v2_ciphertext_fails() {
        let cipher = cipher_with_kek(7);
        let blob = cipher.encrypt("key-a", "secret").unwrap();
        let mut parts: Vec<String> = blob.split(':').map(|s| s.to_string()).collect();
        let ct = B64.decode(&parts[3]).unwrap();
        let mut tampered = ct.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        parts[3] = B64.encode(tampered);
        assert_eq!(cipher.decrypt("key-a", &parts.join(":")), None);
    }

    #[test]
    fn wrong_kek_fails() {
        let blob = cipher_with_kek(7).encrypt("key-a", "secret").unwrap();
        let other = cipher_with_kek(9);
        assert_eq!(other.decrypt("key-a", &blob), None);
    }

    #[test]
    fn malformed_blob_returns_none() {
        let cipher = cipher_with_kek(7);
        assert_eq!(cipher.decrypt("key-a", "v1:not-base64:abc"), None);
        assert_eq!(cipher.decrypt("key-a", "v9:abc:def:ghi"), None);
        assert_eq!(cipher.decrypt("key-a", ""), None);
    }

    #[test]
    fn malformed_nonce_returns_none() {
        let cipher = cipher_with_kek(7);
        let blob = cipher.encrypt("key-a", "secret").unwrap();
        let mut parts: Vec<String> = blob.split(':').map(str::to_string).collect();
        parts[2] = B64.encode([0u8; NONCE_LEN - 1]);

        assert_eq!(cipher.decrypt("key-a", &parts.join(":")), None);
    }

    #[test]
    fn env_kek_parses() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("S4_SECRET_KEK", B64.encode([3u8; KEY_LEN])) };
        let w = LocalKeyWrapping::from_env()
            .expect("no env error")
            .expect("Some");
        let cipher = SecretCipher::new(Arc::new(w));
        let blob = cipher.encrypt("key-a", "x").unwrap();
        assert_eq!(cipher.decrypt("key-a", &blob).as_deref(), Some("x"));
    }

    #[test]
    fn env_kek_rejects_short_key() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("S4_SECRET_KEK", B64.encode([1u8; 8])) };
        assert!(LocalKeyWrapping::from_env().is_err());
    }
}
