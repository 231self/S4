use anyhow::Context;
use async_trait::async_trait;
use bytes::Bytes;
use rsa::RsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use sea_orm::sea_query::Expr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, Set,
    SqlxPostgresConnector,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use uuid::Uuid;

use crate::entity::api_key;
use crate::entity::mcp_token;
use crate::key_cipher::SecretCipher;

pub const MAX_CREDENTIAL_LABEL_BYTES: usize = 128;
pub const MAX_CREDENTIAL_TTL_SECONDS: u64 = 365 * 24 * 60 * 60;
pub const MAX_PUBLIC_KEY_PEM_BYTES: usize = 16 * 1024;
const MIN_RSA_PUBLIC_KEY_BITS: usize = 2048;
const MAX_RSA_PUBLIC_KEY_BITS: usize = 4096;

#[derive(Debug, Clone)]
pub struct StoredObject {
    pub data: Bytes,
    pub content_type: String,
    pub etag: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiKey {
    pub key_id: String,
    pub secret_hash: String,
    #[serde(default)]
    pub secret_encrypted: Option<String>,
    pub user_id: String,
    pub label: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub public_key_pem: Option<String>,
}

/// MCP bearer token (`s4m_...`). The full token is the credential; only its
/// SHA-256 hash is stored.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct McpToken {
    pub token_hash: String,
    pub user_id: String,
    pub label: String,
    pub created_at: String,
    pub expires_at: Option<String>,
}

#[derive(Debug)]
pub struct MemoryStore {
    objects: RwLock<HashMap<String, StoredObject>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self {
            objects: RwLock::new(HashMap::new()),
        }
    }

    fn object_key(bucket: &str, key: &str) -> String {
        format!("{}/{}", bucket, key)
    }

    pub fn put(
        &self,
        bucket: &str,
        key: &str,
        data: impl Into<Bytes>,
        content_type: &str,
    ) -> StoredObject {
        let etag = format!("\"{}\"", Uuid::new_v4());
        let obj = StoredObject {
            data: data.into(),
            content_type: content_type.to_string(),
            etag: etag.clone(),
        };
        self.objects
            .write()
            .unwrap()
            .insert(Self::object_key(bucket, key), obj.clone());
        obj
    }

    pub fn get(&self, bucket: &str, key: &str) -> Option<StoredObject> {
        self.objects
            .read()
            .unwrap()
            .get(&Self::object_key(bucket, key))
            .cloned()
    }

    pub fn head(&self, bucket: &str, key: &str) -> Option<StoredObject> {
        self.objects
            .read()
            .unwrap()
            .get(&Self::object_key(bucket, key))
            .map(|object| StoredObject {
                data: Bytes::new(),
                content_type: object.content_type.clone(),
                etag: object.etag.clone(),
            })
    }

    pub fn metadata(&self, bucket: &str, key: &str) -> Option<(usize, String, String)> {
        self.objects
            .read()
            .unwrap()
            .get(&Self::object_key(bucket, key))
            .map(|object| {
                (
                    object.data.len(),
                    object.content_type.clone(),
                    object.etag.clone(),
                )
            })
    }

    pub fn delete(&self, bucket: &str, key: &str) -> bool {
        self.objects
            .write()
            .unwrap()
            .remove(&Self::object_key(bucket, key))
            .is_some()
    }

    pub fn list_keys(&self) -> Vec<String> {
        self.objects.read().unwrap().keys().cloned().collect()
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct KeyStore {
    keys: RwLock<HashMap<String, ApiKey>>,
    mcp_tokens: RwLock<HashMap<String, McpToken>>,
    cipher: Option<Arc<SecretCipher>>,
}

impl KeyStore {
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
            mcp_tokens: RwLock::new(HashMap::new()),
            cipher: None,
        }
    }

    /// A keystore that can also encrypt/decrypt secrets for SigV4 verification.
    pub fn with_cipher(cipher: Arc<SecretCipher>) -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
            mcp_tokens: RwLock::new(HashMap::new()),
            cipher: Some(cipher),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PostgresKeyStore {
    db: DatabaseConnection,
    cipher: Option<Arc<SecretCipher>>,
}

impl PostgresKeyStore {
    pub fn new(pool: sqlx::PgPool) -> Self {
        let db = SqlxPostgresConnector::from_sqlx_postgres_pool(pool);
        Self { db, cipher: None }
    }

    pub fn with_cipher(pool: sqlx::PgPool, cipher: Arc<SecretCipher>) -> Self {
        let db = SqlxPostgresConnector::from_sqlx_postgres_pool(pool);
        Self {
            db,
            cipher: Some(cipher),
        }
    }
}

/// Persistence for API keys. In-memory (`KeyStore`) or Postgres-backed
/// (`PostgresKeyStore`); selected by the presence of `DATABASE_URL`.
#[async_trait]
pub trait KeyRepository: Send + Sync {
    /// Create and persist a key, then return the plaintext secret and committed
    /// metadata. The secret is hashed (SHA-256) before storage and never
    /// returned when persistence fails.
    async fn create_key(
        &self,
        user_id: &str,
        label: &str,
        expires_in: u64,
        public_key_pem: Option<String>,
    ) -> anyhow::Result<(String, ApiKey)>;

    async fn set_public_key(
        &self,
        key_id: &str,
        user_id: &str,
        public_key_pem: &str,
    ) -> anyhow::Result<bool>;

    async fn get_key(&self, key_id: &str) -> anyhow::Result<Option<ApiKey>>;

    /// Decrypt the stored plaintext secret for `key_id` (used to verify SigV4
    /// signatures). Returns `None` for legacy keys that only have a hash.
    async fn decrypt_secret(&self, key_id: &str) -> anyhow::Result<Option<String>>;

    /// Validate an access key/secret pair and return the owning user id plus
    /// the API key's public key PEM (used by the encryption pipeline).
    async fn resolve_credentials(
        &self,
        access_key: &str,
        secret_key: &str,
    ) -> anyhow::Result<Option<(String, Option<String>)>>;

    /// Keys for a user, with the secret hash stripped.
    async fn list_for_user(&self, user_id: &str) -> anyhow::Result<Vec<ApiKey>>;

    async fn delete_key(&self, key_id: &str, user_id: &str) -> anyhow::Result<bool>;

    /// Create an MCP bearer token (`s4m_...`) and return the plaintext token
    /// (shown once). Only its SHA-256 hash is stored.
    async fn create_mcp_token(
        &self,
        user_id: &str,
        label: &str,
        expires_in: u64,
    ) -> anyhow::Result<(String, McpToken)>;

    /// Validate an MCP bearer token and return the owning user id.
    async fn resolve_mcp_token(&self, token: &str) -> anyhow::Result<Option<String>>;

    /// MCP tokens for a user (hashes only).
    async fn list_mcp_tokens(&self, user_id: &str) -> anyhow::Result<Vec<McpToken>>;

    async fn delete_mcp_token(&self, token_hash: &str, user_id: &str) -> anyhow::Result<bool>;
}

pub fn canonicalize_credential_label(label: &str) -> anyhow::Result<String> {
    if label.chars().any(char::is_control) {
        anyhow::bail!("credential label must not contain control characters");
    }
    let label = label.trim();
    if label.is_empty() {
        anyhow::bail!("credential label must not be empty");
    }
    if label.len() > MAX_CREDENTIAL_LABEL_BYTES {
        anyhow::bail!("credential label must not exceed {MAX_CREDENTIAL_LABEL_BYTES} UTF-8 bytes");
    }
    Ok(label.to_string())
}

pub fn validate_credential_ttl(expires_in: u64) -> anyhow::Result<()> {
    if expires_in > MAX_CREDENTIAL_TTL_SECONDS {
        anyhow::bail!(
            "credential expiry must be 0 or at most {MAX_CREDENTIAL_TTL_SECONDS} seconds"
        );
    }
    Ok(())
}

pub fn canonicalize_public_key_pem(public_key_pem: &str) -> anyhow::Result<String> {
    if public_key_pem.len() > MAX_PUBLIC_KEY_PEM_BYTES {
        anyhow::bail!("public key PEM must not exceed {MAX_PUBLIC_KEY_PEM_BYTES} bytes");
    }
    let public_key_pem = public_key_pem.trim();
    if public_key_pem.is_empty() {
        anyhow::bail!("public key PEM must not be empty");
    }

    let key = match RsaPublicKey::from_public_key_pem(public_key_pem) {
        Ok(key) => key,
        Err(_) => {
            let (_, pem) =
                x509_parser::pem::parse_x509_pem(public_key_pem.as_bytes()).map_err(|_| {
                    anyhow::anyhow!(
                        "public key PEM must contain an RSA public key or X.509 certificate"
                    )
                })?;
            let certificate = pem.parse_x509().map_err(|_| {
                anyhow::anyhow!("public key PEM must contain a valid X.509 certificate")
            })?;
            RsaPublicKey::from_public_key_der(certificate.public_key().raw)
                .map_err(|_| anyhow::anyhow!("X.509 certificate must contain an RSA public key"))?
        }
    };
    let bits = key.n().bits();
    if !(MIN_RSA_PUBLIC_KEY_BITS..=MAX_RSA_PUBLIC_KEY_BITS).contains(&bits) {
        anyhow::bail!(
            "RSA public key must be between {MIN_RSA_PUBLIC_KEY_BITS} and {MAX_RSA_PUBLIC_KEY_BITS} bits"
        );
    }
    Ok(public_key_pem.to_string())
}

#[allow(clippy::too_many_arguments)]
fn build_api_key(
    key_id: &str,
    user_id: &str,
    label: &str,
    secret_hash: String,
    secret_encrypted: Option<String>,
    created_at: String,
    expires_at: Option<String>,
    public_key_pem: Option<String>,
) -> ApiKey {
    ApiKey {
        key_id: key_id.to_string(),
        secret_hash,
        secret_encrypted,
        user_id: user_id.to_string(),
        label: label.to_string(),
        created_at,
        expires_at,
        public_key_pem,
    }
}

fn generate_api_key(
    user_id: &str,
    label: &str,
    expires_in: u64,
    public_key_pem: Option<String>,
    cipher: Option<&SecretCipher>,
) -> anyhow::Result<(ApiKey, String)> {
    let label = canonicalize_credential_label(label)?;
    validate_credential_ttl(expires_in)?;
    let public_key_pem = public_key_pem
        .as_deref()
        .map(canonicalize_public_key_pem)
        .transpose()?;
    let key_id = format!("s4_{}", Uuid::new_v4().to_string().replace('-', ""));
    let secret = format!("s4s_{}", Uuid::new_v4().to_string().replace('-', ""));
    let secret_hash = sha256_hash(&secret);
    let secret_encrypted = match cipher {
        Some(cipher) => Some(
            cipher
                .encrypt(&key_id, &secret)
                .context("API key secret encryption failed")?,
        ),
        None => {
            tracing::warn!(
                "secret encryption is not configured; key {key_id} supports header authentication only"
            );
            None
        }
    };
    let now = chrono_now().parse::<u64>().unwrap_or(0);
    let expires_at = if expires_in > 0 {
        Some(
            now.checked_add(expires_in)
                .context("API key expiry overflow")?
                .to_string(),
        )
    } else {
        None
    };
    let api_key = build_api_key(
        &key_id,
        user_id,
        &label,
        secret_hash,
        secret_encrypted,
        chrono_now(),
        expires_at,
        public_key_pem,
    );
    Ok((api_key, secret))
}

fn generate_mcp_token(
    user_id: &str,
    label: &str,
    expires_in: u64,
) -> anyhow::Result<(McpToken, String)> {
    let label = canonicalize_credential_label(label)?;
    validate_credential_ttl(expires_in)?;
    let token = format!("s4m_{}", Uuid::new_v4().to_string().replace('-', ""));
    let now = chrono_now().parse::<u64>().unwrap_or(0);
    let expires_at = if expires_in > 0 {
        Some(
            now.checked_add(expires_in)
                .context("MCP token expiry overflow")?
                .to_string(),
        )
    } else {
        None
    };
    Ok((
        McpToken {
            token_hash: sha256_hash(&token),
            user_id: user_id.to_string(),
            label,
            created_at: chrono_now(),
            expires_at,
        },
        token,
    ))
}

fn decrypt_verified_secret(
    cipher: &SecretCipher,
    key_id: &str,
    secret_hash: &str,
    blob: &str,
) -> anyhow::Result<Option<(String, Option<String>)>> {
    let Some(secret) = cipher.decrypt_result(key_id, blob)? else {
        return Ok(None);
    };
    if sha256_hash(&secret) != secret_hash {
        tracing::warn!(
            key_id = key_id,
            "decrypted API key secret failed hash verification"
        );
        return Ok(None);
    }
    let rewrapped = if SecretCipher::is_legacy_envelope(blob) {
        Some(
            cipher
                .encrypt(key_id, &secret)
                .context("legacy API key secret rewrap encryption failed")?,
        )
    } else {
        None
    };
    Ok(Some((secret, rewrapped)))
}

fn compare_and_swap_envelope(
    keys: &RwLock<HashMap<String, ApiKey>>,
    key_id: &str,
    expected: &str,
    replacement: String,
) -> anyhow::Result<bool> {
    let mut keys = keys
        .write()
        .map_err(|_| anyhow::anyhow!("KeyStore API key lock poisoned"))?;
    let Some(key) = keys.get_mut(key_id) else {
        return Ok(false);
    };
    if key.secret_encrypted.as_deref() != Some(expected) {
        return Ok(false);
    }
    key.secret_encrypted = Some(replacement);
    Ok(true)
}

#[derive(Debug, PartialEq, Eq)]
enum EnvelopeUpdate {
    Replaced,
    AlreadyRewrapped,
}

fn key_has_matching_v2_secret(
    cipher: &SecretCipher,
    key: &ApiKey,
    key_id: &str,
    secret_hash: &str,
    secret: &str,
) -> anyhow::Result<bool> {
    if key.key_id != key_id || key.secret_hash != secret_hash {
        return Ok(false);
    }
    let Some(blob) = key.secret_encrypted.as_deref() else {
        return Ok(false);
    };
    if !blob.starts_with("v2:") {
        return Ok(false);
    }
    Ok(decrypt_verified_secret(cipher, key_id, secret_hash, blob)?
        .is_some_and(|(current, rewrapped)| rewrapped.is_none() && current == secret))
}

fn replace_or_accept_rewrapped_envelope(
    keys: &RwLock<HashMap<String, ApiKey>>,
    cipher: &SecretCipher,
    key_id: &str,
    secret_hash: &str,
    secret: &str,
    expected: &str,
    replacement: String,
) -> anyhow::Result<Option<EnvelopeUpdate>> {
    if compare_and_swap_envelope(keys, key_id, expected, replacement)? {
        return Ok(Some(EnvelopeUpdate::Replaced));
    }
    let keys = keys
        .read()
        .map_err(|_| anyhow::anyhow!("KeyStore API key lock poisoned"))?;
    let Some(current) = keys.get(key_id) else {
        return Ok(None);
    };
    Ok(
        key_has_matching_v2_secret(cipher, current, key_id, secret_hash, secret)?
            .then_some(EnvelopeUpdate::AlreadyRewrapped),
    )
}

fn set_public_key_in(
    keys: &RwLock<HashMap<String, ApiKey>>,
    key_id: &str,
    user_id: &str,
    public_key_pem: &str,
) -> anyhow::Result<bool> {
    let mut keys = keys
        .write()
        .map_err(|_| anyhow::anyhow!("KeyStore API key lock poisoned"))?;
    if let Some(k) = keys.get_mut(key_id)
        && k.user_id == user_id
    {
        k.public_key_pem = Some(public_key_pem.to_string());
        return Ok(true);
    }
    Ok(false)
}

fn get_key_in(
    keys: &RwLock<HashMap<String, ApiKey>>,
    key_id: &str,
) -> anyhow::Result<Option<ApiKey>> {
    Ok(keys
        .read()
        .map_err(|_| anyhow::anyhow!("KeyStore API key lock poisoned"))?
        .get(key_id)
        .cloned())
}

fn resolve_credentials_in(
    keys: &RwLock<HashMap<String, ApiKey>>,
    access_key: &str,
    secret_key: &str,
) -> anyhow::Result<Option<(String, Option<String>)>> {
    let keys = keys
        .read()
        .map_err(|_| anyhow::anyhow!("KeyStore API key lock poisoned"))?;
    let Some(key) = keys.get(access_key) else {
        return Ok(None);
    };
    if key.secret_hash != sha256_hash(secret_key) {
        return Ok(None);
    }
    if is_expired(key.expires_at.as_deref()) {
        return Ok(None);
    }
    Ok(Some((key.user_id.clone(), key.public_key_pem.clone())))
}

fn list_for_user_in(
    keys: &RwLock<HashMap<String, ApiKey>>,
    user_id: &str,
) -> anyhow::Result<Vec<ApiKey>> {
    Ok(keys
        .read()
        .map_err(|_| anyhow::anyhow!("KeyStore API key lock poisoned"))?
        .values()
        .filter(|k| k.user_id == user_id)
        .map(|k| {
            build_api_key(
                &k.key_id,
                &k.user_id,
                &k.label,
                String::new(),
                None,
                k.created_at.clone(),
                k.expires_at.clone(),
                k.public_key_pem.clone(),
            )
        })
        .collect())
}

fn delete_key_in(
    keys: &RwLock<HashMap<String, ApiKey>>,
    key_id: &str,
    user_id: &str,
) -> anyhow::Result<bool> {
    let mut keys = keys
        .write()
        .map_err(|_| anyhow::anyhow!("KeyStore API key lock poisoned"))?;
    if let Some(k) = keys.get(key_id)
        && k.user_id == user_id
    {
        keys.remove(key_id);
        return Ok(true);
    }
    Ok(false)
}

#[async_trait]
impl KeyRepository for KeyStore {
    async fn create_key(
        &self,
        user_id: &str,
        label: &str,
        expires_in: u64,
        public_key_pem: Option<String>,
    ) -> anyhow::Result<(String, ApiKey)> {
        let (api_key, secret) = generate_api_key(
            user_id,
            label,
            expires_in,
            public_key_pem,
            self.cipher.as_deref(),
        )?;
        let key_id = api_key.key_id.clone();
        let committed = api_key.clone();
        self.keys
            .write()
            .map_err(|_| anyhow::anyhow!("KeyStore API key lock poisoned"))?
            .insert(key_id.clone(), api_key);
        Ok((secret, committed))
    }

    async fn set_public_key(
        &self,
        key_id: &str,
        user_id: &str,
        public_key_pem: &str,
    ) -> anyhow::Result<bool> {
        let public_key_pem = canonicalize_public_key_pem(public_key_pem)?;
        set_public_key_in(&self.keys, key_id, user_id, &public_key_pem)
    }

    async fn get_key(&self, key_id: &str) -> anyhow::Result<Option<ApiKey>> {
        get_key_in(&self.keys, key_id)
    }

    async fn decrypt_secret(&self, key_id: &str) -> anyhow::Result<Option<String>> {
        let Some(cipher) = self.cipher.as_deref() else {
            return Ok(None);
        };
        let (secret_hash, blob) = {
            let keys = self
                .keys
                .read()
                .map_err(|_| anyhow::anyhow!("KeyStore API key lock poisoned"))?;
            let Some(key) = keys.get(key_id) else {
                return Ok(None);
            };
            let Some(blob) = key.secret_encrypted.clone() else {
                return Ok(None);
            };
            (key.secret_hash.clone(), blob)
        };
        let Some((secret, rewrapped)) =
            decrypt_verified_secret(cipher, key_id, &secret_hash, &blob)?
        else {
            return Ok(None);
        };
        if let Some(rewrapped) = rewrapped {
            let Some(_) = replace_or_accept_rewrapped_envelope(
                &self.keys,
                cipher,
                key_id,
                &secret_hash,
                &secret,
                &blob,
                rewrapped,
            )?
            else {
                return Ok(None);
            };
        }
        Ok(Some(secret))
    }

    async fn resolve_credentials(
        &self,
        access_key: &str,
        secret_key: &str,
    ) -> anyhow::Result<Option<(String, Option<String>)>> {
        resolve_credentials_in(&self.keys, access_key, secret_key)
    }

    async fn list_for_user(&self, user_id: &str) -> anyhow::Result<Vec<ApiKey>> {
        list_for_user_in(&self.keys, user_id)
    }

    async fn delete_key(&self, key_id: &str, user_id: &str) -> anyhow::Result<bool> {
        delete_key_in(&self.keys, key_id, user_id)
    }

    async fn create_mcp_token(
        &self,
        user_id: &str,
        label: &str,
        expires_in: u64,
    ) -> anyhow::Result<(String, McpToken)> {
        let (mcp, token) = generate_mcp_token(user_id, label, expires_in)?;
        self.mcp_tokens
            .write()
            .map_err(|_| anyhow::anyhow!("KeyStore MCP token lock poisoned"))?
            .insert(mcp.token_hash.clone(), mcp.clone());
        Ok((token, mcp))
    }

    async fn resolve_mcp_token(&self, token: &str) -> anyhow::Result<Option<String>> {
        let hash = sha256_hash(token);
        let tokens = self
            .mcp_tokens
            .read()
            .map_err(|_| anyhow::anyhow!("KeyStore MCP token lock poisoned"))?;
        let Some(t) = tokens.get(&hash) else {
            return Ok(None);
        };
        if is_expired(t.expires_at.as_deref()) {
            return Ok(None);
        }
        Ok(Some(t.user_id.clone()))
    }

    async fn list_mcp_tokens(&self, user_id: &str) -> anyhow::Result<Vec<McpToken>> {
        Ok(self
            .mcp_tokens
            .read()
            .map_err(|_| anyhow::anyhow!("KeyStore MCP token lock poisoned"))?
            .values()
            .filter(|t| t.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn delete_mcp_token(&self, token_hash: &str, user_id: &str) -> anyhow::Result<bool> {
        let mut tokens = self
            .mcp_tokens
            .write()
            .map_err(|_| anyhow::anyhow!("KeyStore MCP token lock poisoned"))?;
        if let Some(t) = tokens.get(token_hash)
            && t.user_id == user_id
        {
            tokens.remove(token_hash);
            return Ok(true);
        }
        Ok(false)
    }
}

/// Persistent key store backed by a JSON file (e.g. `~/.config/s4/keys.json`).
///
/// Loads the file once at construction and rewrites it atomically (0600 on
/// unix) after every mutation, so API keys survive gateway restarts without
/// Postgres. This is the default in local mode (`AUTH_DISABLED=true` without
/// `DATABASE_URL`), or opt in explicitly with `MASKURA_KEYS_FILE`.
#[derive(Debug)]
pub struct FileKeyStore {
    keys: RwLock<HashMap<String, ApiKey>>,
    mcp_tokens: RwLock<HashMap<String, McpToken>>,
    // Every mutation shares one snapshot file. Writers take this lock first,
    // then acquire keys before mcp_tokens whenever both maps are needed.
    mutation_lock: Mutex<()>,
    #[cfg(test)]
    persist_hook: Mutex<Option<PersistTestHook>>,
    path: PathBuf,
    cipher: Option<Arc<SecretCipher>>,
}

#[cfg(test)]
#[derive(Debug)]
struct PersistTestHook {
    entered: std::sync::mpsc::SyncSender<()>,
    resume: std::sync::mpsc::Receiver<()>,
}

impl FileKeyStore {
    pub fn new(path: PathBuf) -> anyhow::Result<Self> {
        let (keys, mcp_tokens) = load_file_store(&path)?;
        ensure_file_store_parent(&path)?;
        Ok(Self {
            keys: RwLock::new(keys),
            mcp_tokens: RwLock::new(mcp_tokens),
            mutation_lock: Mutex::new(()),
            #[cfg(test)]
            persist_hook: Mutex::new(None),
            path,
            cipher: None,
        })
    }

    pub fn with_cipher(path: PathBuf, cipher: Arc<SecretCipher>) -> anyhow::Result<Self> {
        let (keys, mcp_tokens) = load_file_store(&path)?;
        ensure_file_store_parent(&path)?;
        Ok(Self {
            keys: RwLock::new(keys),
            mcp_tokens: RwLock::new(mcp_tokens),
            mutation_lock: Mutex::new(()),
            #[cfg(test)]
            persist_hook: Mutex::new(None),
            path,
            cipher: Some(cipher),
        })
    }

    /// Default location for the local-mode keys file.
    pub fn default_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("s4")
            .join("keys.json")
    }

    /// Atomically write a caller-locked key snapshot to disk (0600 on unix).
    fn persist_snapshot(
        &self,
        keys: &HashMap<String, ApiKey>,
        mcp_tokens: &HashMap<String, McpToken>,
    ) -> anyhow::Result<()> {
        #[cfg(test)]
        if let Some(hook) = self
            .persist_hook
            .lock()
            .map_err(|_| anyhow::anyhow!("FileKeyStore persist hook lock poisoned"))?
            .take()
        {
            hook.entered.send(()).unwrap();
            hook.resume.recv().unwrap();
        }
        #[derive(serde::Serialize)]
        struct Persisted<'a> {
            keys: &'a HashMap<String, ApiKey>,
            mcp_tokens: &'a HashMap<String, McpToken>,
        }
        let data = Persisted { keys, mcp_tokens };
        let json = serde_json::to_string_pretty(&data)?;
        ensure_file_store_parent(&self.path)?;
        let mut tmp_name = self.path.as_os_str().to_os_string();
        tmp_name.push(".tmp");
        let tmp = PathBuf::from(tmp_name);
        let mut options = std::fs::OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(json.as_bytes())?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, &self.path)?;
        // Rename commits the snapshot. No error may escape after this point or
        // callers would roll back memory while disk contains the new state.
        #[cfg(unix)]
        {
            let parent = self
                .path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            if std::fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .is_err()
            {
                tracing::warn!("FileKeyStore parent directory sync failed after committed rename");
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn persist(&self) -> anyhow::Result<()> {
        let keys = self
            .keys
            .read()
            .map_err(|_| anyhow::anyhow!("FileKeyStore API key lock poisoned"))?;
        let mcp_tokens = self
            .mcp_tokens
            .read()
            .map_err(|_| anyhow::anyhow!("FileKeyStore MCP token lock poisoned"))?;
        self.persist_snapshot(&keys, &mcp_tokens)
    }
}

fn ensure_file_store_parent(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).context("FileKeyStore parent directory creation failed")?;
    }
    Ok(())
}

#[async_trait]
impl KeyRepository for FileKeyStore {
    async fn create_key(
        &self,
        user_id: &str,
        label: &str,
        expires_in: u64,
        public_key_pem: Option<String>,
    ) -> anyhow::Result<(String, ApiKey)> {
        let (api_key, secret) = generate_api_key(
            user_id,
            label,
            expires_in,
            public_key_pem,
            self.cipher.as_deref(),
        )?;
        let _mutation_guard = self
            .mutation_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("FileKeyStore mutation lock poisoned"))?;
        let key_id = api_key.key_id.clone();
        let inserted = api_key.clone();
        let mut keys = self
            .keys
            .write()
            .map_err(|_| anyhow::anyhow!("FileKeyStore API key lock poisoned"))?;
        let mcp_tokens = self
            .mcp_tokens
            .read()
            .map_err(|_| anyhow::anyhow!("FileKeyStore MCP token lock poisoned"))?
            .clone();
        let previous = keys.insert(key_id.clone(), api_key);
        if let Err(error) = self.persist_snapshot(&keys, &mcp_tokens) {
            if keys.get(&key_id) == Some(&inserted) {
                if let Some(previous) = previous {
                    keys.insert(key_id.clone(), previous);
                } else {
                    keys.remove(&key_id);
                }
            }
            return Err(error.context("FileKeyStore persist failed"));
        }
        Ok((secret, inserted))
    }

    async fn set_public_key(
        &self,
        key_id: &str,
        user_id: &str,
        public_key_pem: &str,
    ) -> anyhow::Result<bool> {
        let public_key_pem = canonicalize_public_key_pem(public_key_pem)?;
        let _mutation_guard = self
            .mutation_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("FileKeyStore mutation lock poisoned"))?;
        let mut keys = self
            .keys
            .write()
            .map_err(|_| anyhow::anyhow!("FileKeyStore API key lock poisoned"))?;
        let mcp_tokens = self
            .mcp_tokens
            .read()
            .map_err(|_| anyhow::anyhow!("FileKeyStore MCP token lock poisoned"))?
            .clone();
        let Some(key) = keys.get_mut(key_id) else {
            return Ok(false);
        };
        if key.user_id != user_id {
            return Ok(false);
        }
        let previous = key.public_key_pem.replace(public_key_pem.clone());
        if let Err(error) = self.persist_snapshot(&keys, &mcp_tokens) {
            if let Some(key) = keys.get_mut(key_id)
                && key.user_id == user_id
                && key.public_key_pem.as_deref() == Some(public_key_pem.as_str())
            {
                key.public_key_pem = previous;
            }
            return Err(error.context("FileKeyStore public key persist failed"));
        }
        Ok(true)
    }

    async fn get_key(&self, key_id: &str) -> anyhow::Result<Option<ApiKey>> {
        get_key_in(&self.keys, key_id)
    }

    async fn decrypt_secret(&self, key_id: &str) -> anyhow::Result<Option<String>> {
        let Some(cipher) = self.cipher.as_deref() else {
            return Ok(None);
        };
        let (secret_hash, blob) = {
            let keys = self
                .keys
                .read()
                .map_err(|_| anyhow::anyhow!("FileKeyStore API key lock poisoned"))?;
            let Some(key) = keys.get(key_id) else {
                return Ok(None);
            };
            let Some(blob) = key.secret_encrypted.clone() else {
                return Ok(None);
            };
            (key.secret_hash.clone(), blob)
        };
        let Some((secret, rewrapped)) =
            decrypt_verified_secret(cipher, key_id, &secret_hash, &blob)?
        else {
            return Ok(None);
        };
        if let Some(rewrapped) = rewrapped {
            let _mutation_guard = self
                .mutation_lock
                .lock()
                .map_err(|_| anyhow::anyhow!("FileKeyStore mutation lock poisoned"))?;
            let mut keys = self
                .keys
                .write()
                .map_err(|_| anyhow::anyhow!("FileKeyStore API key lock poisoned"))?;
            let mcp_tokens = self
                .mcp_tokens
                .read()
                .map_err(|_| anyhow::anyhow!("FileKeyStore MCP token lock poisoned"))?
                .clone();
            let update = if let Some(key) = keys.get_mut(key_id) {
                if key.secret_encrypted.as_deref() == Some(blob.as_str()) {
                    key.secret_encrypted = Some(rewrapped.clone());
                    Some(EnvelopeUpdate::Replaced)
                } else if key_has_matching_v2_secret(cipher, key, key_id, &secret_hash, &secret)? {
                    Some(EnvelopeUpdate::AlreadyRewrapped)
                } else {
                    None
                }
            } else {
                None
            };
            let Some(update) = update else {
                return Ok(None);
            };
            match update {
                EnvelopeUpdate::Replaced => {
                    if let Err(error) = self.persist_snapshot(&keys, &mcp_tokens) {
                        if let Some(key) = keys.get_mut(key_id)
                            && key.secret_encrypted.as_deref() == Some(rewrapped.as_str())
                        {
                            key.secret_encrypted = Some(blob);
                        }
                        return Err(
                            error.context("FileKeyStore legacy secret rewrap persist failed")
                        );
                    }
                }
                EnvelopeUpdate::AlreadyRewrapped => {}
            }
        }
        Ok(Some(secret))
    }

    async fn resolve_credentials(
        &self,
        access_key: &str,
        secret_key: &str,
    ) -> anyhow::Result<Option<(String, Option<String>)>> {
        resolve_credentials_in(&self.keys, access_key, secret_key)
    }

    async fn list_for_user(&self, user_id: &str) -> anyhow::Result<Vec<ApiKey>> {
        list_for_user_in(&self.keys, user_id)
    }

    async fn delete_key(&self, key_id: &str, user_id: &str) -> anyhow::Result<bool> {
        let _mutation_guard = self
            .mutation_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("FileKeyStore mutation lock poisoned"))?;
        let mut keys = self
            .keys
            .write()
            .map_err(|_| anyhow::anyhow!("FileKeyStore API key lock poisoned"))?;
        let mcp_tokens = self
            .mcp_tokens
            .read()
            .map_err(|_| anyhow::anyhow!("FileKeyStore MCP token lock poisoned"))?
            .clone();
        let Some(key) = keys.get(key_id) else {
            return Ok(false);
        };
        if key.user_id != user_id {
            return Ok(false);
        }
        let removed = keys.remove(key_id).expect("key existence checked");
        if let Err(error) = self.persist_snapshot(&keys, &mcp_tokens) {
            keys.insert(key_id.to_string(), removed);
            return Err(error.context("FileKeyStore key deletion persist failed"));
        }
        Ok(true)
    }

    async fn create_mcp_token(
        &self,
        user_id: &str,
        label: &str,
        expires_in: u64,
    ) -> anyhow::Result<(String, McpToken)> {
        let (mcp, token) = generate_mcp_token(user_id, label, expires_in)?;
        let token_hash = mcp.token_hash.clone();
        let _mutation_guard = self
            .mutation_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("FileKeyStore mutation lock poisoned"))?;
        let keys = self
            .keys
            .read()
            .map_err(|_| anyhow::anyhow!("FileKeyStore API key lock poisoned"))?
            .clone();
        let inserted = mcp.clone();
        let mut tokens = self
            .mcp_tokens
            .write()
            .map_err(|_| anyhow::anyhow!("FileKeyStore MCP token lock poisoned"))?;
        let previous = tokens.insert(token_hash.clone(), mcp);
        if let Err(error) = self.persist_snapshot(&keys, &tokens) {
            if tokens.get(&token_hash) == Some(&inserted) {
                if let Some(previous) = previous {
                    tokens.insert(token_hash.clone(), previous);
                } else {
                    tokens.remove(&token_hash);
                }
            }
            return Err(error.context("FileKeyStore MCP token creation persist failed"));
        }
        Ok((token, inserted))
    }

    async fn resolve_mcp_token(&self, token: &str) -> anyhow::Result<Option<String>> {
        let hash = sha256_hash(token);
        let tokens = self
            .mcp_tokens
            .read()
            .map_err(|_| anyhow::anyhow!("FileKeyStore MCP token lock poisoned"))?;
        let Some(t) = tokens.get(&hash) else {
            return Ok(None);
        };
        if is_expired(t.expires_at.as_deref()) {
            return Ok(None);
        }
        Ok(Some(t.user_id.clone()))
    }

    async fn list_mcp_tokens(&self, user_id: &str) -> anyhow::Result<Vec<McpToken>> {
        Ok(self
            .mcp_tokens
            .read()
            .map_err(|_| anyhow::anyhow!("FileKeyStore MCP token lock poisoned"))?
            .values()
            .filter(|t| t.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn delete_mcp_token(&self, token_hash: &str, user_id: &str) -> anyhow::Result<bool> {
        let _mutation_guard = self
            .mutation_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("FileKeyStore mutation lock poisoned"))?;
        let keys = self
            .keys
            .read()
            .map_err(|_| anyhow::anyhow!("FileKeyStore API key lock poisoned"))?
            .clone();
        let mut tokens = self
            .mcp_tokens
            .write()
            .map_err(|_| anyhow::anyhow!("FileKeyStore MCP token lock poisoned"))?;
        let Some(token) = tokens.get(token_hash) else {
            return Ok(false);
        };
        if token.user_id != user_id {
            return Ok(false);
        }
        let removed = tokens.remove(token_hash).expect("token existence checked");
        if let Err(error) = self.persist_snapshot(&keys, &tokens) {
            tokens.insert(token_hash.to_string(), removed);
            return Err(error.context("FileKeyStore MCP token deletion persist failed"));
        }
        Ok(true)
    }
}

impl From<api_key::Model> for ApiKey {
    fn from(m: api_key::Model) -> Self {
        build_api_key(
            &m.key_id,
            &m.user_id,
            &m.label,
            m.secret_hash,
            m.secret_encrypted,
            m.created_at.timestamp().to_string(),
            m.expires_at.map(|e| e.to_string()),
            m.public_key_pem,
        )
    }
}

async fn fetch_key(db: &DatabaseConnection, key_id: &str) -> anyhow::Result<Option<ApiKey>> {
    Ok(api_key::Entity::find()
        .filter(api_key::Column::KeyId.eq(key_id.to_string()))
        .one(db)
        .await
        .context("Postgres API key lookup failed")?
        .map(Into::into))
}

#[async_trait]
impl KeyRepository for PostgresKeyStore {
    async fn create_key(
        &self,
        user_id: &str,
        label: &str,
        expires_in: u64,
        public_key_pem: Option<String>,
    ) -> anyhow::Result<(String, ApiKey)> {
        let (api_key, secret) = generate_api_key(
            user_id,
            label,
            expires_in,
            public_key_pem,
            self.cipher.as_deref(),
        )?;
        let expires_at = api_key
            .expires_at
            .as_deref()
            .map(str::parse::<i64>)
            .transpose()
            .context("API key expiry is outside the Postgres timestamp range")?;
        let model = api_key::ActiveModel {
            user_id: Set(api_key.user_id.clone()),
            key_id: Set(api_key.key_id.clone()),
            secret_hash: Set(api_key.secret_hash.clone()),
            secret_encrypted: Set(api_key.secret_encrypted.clone()),
            label: Set(api_key.label.clone()),
            expires_at: Set(expires_at),
            public_key_pem: Set(api_key.public_key_pem.clone()),
            ..Default::default()
        };
        let inserted = model
            .insert(&self.db)
            .await
            .context("Postgres API key insert failed")?;
        Ok((secret, inserted.into()))
    }

    async fn set_public_key(
        &self,
        key_id: &str,
        user_id: &str,
        public_key_pem: &str,
    ) -> anyhow::Result<bool> {
        let public_key_pem = canonicalize_public_key_pem(public_key_pem)?;
        let result = api_key::Entity::update_many()
            .col_expr(
                api_key::Column::PublicKeyPem,
                Expr::value(Some(public_key_pem)),
            )
            .filter(api_key::Column::KeyId.eq(key_id.to_string()))
            .filter(api_key::Column::UserId.eq(user_id.to_string()))
            .exec(&self.db)
            .await
            .context("Postgres public key update failed")?;
        match result.rows_affected {
            0 => Ok(false),
            1 => Ok(true),
            rows => anyhow::bail!("Postgres public key update affected {rows} rows"),
        }
    }

    async fn get_key(&self, key_id: &str) -> anyhow::Result<Option<ApiKey>> {
        fetch_key(&self.db, key_id).await
    }

    async fn decrypt_secret(&self, key_id: &str) -> anyhow::Result<Option<String>> {
        let Some(cipher) = self.cipher.as_deref() else {
            return Ok(None);
        };
        let Some(key) = fetch_key(&self.db, key_id).await? else {
            return Ok(None);
        };
        let Some(blob) = key.secret_encrypted.clone() else {
            return Ok(None);
        };
        let Some((secret, rewrapped)) =
            decrypt_verified_secret(cipher, key_id, &key.secret_hash, &blob)?
        else {
            return Ok(None);
        };
        if let Some(rewrapped) = rewrapped {
            let result = api_key::Entity::update_many()
                .col_expr(
                    api_key::Column::SecretEncrypted,
                    Expr::value(Some(rewrapped)),
                )
                .filter(api_key::Column::KeyId.eq(key_id.to_string()))
                .filter(api_key::Column::SecretEncrypted.eq(blob.clone()))
                .exec(&self.db)
                .await;
            let reread = match result {
                Ok(update) if update.rows_affected == 1 => false,
                Ok(update) if update.rows_affected == 0 => true,
                Ok(update) => anyhow::bail!(
                    "Postgres legacy secret rewrap affected {} rows",
                    update.rows_affected
                ),
                Err(error) => {
                    let current = fetch_key(&self.db, key_id).await?;
                    if let Some(current) = current.as_ref()
                        && key_has_matching_v2_secret(
                            cipher,
                            current,
                            key_id,
                            &key.secret_hash,
                            &secret,
                        )?
                    {
                        return Ok(Some(secret));
                    }
                    return Err(
                        anyhow::Error::new(error).context("Postgres legacy secret rewrap failed")
                    );
                }
            };
            if reread {
                let Some(current) = fetch_key(&self.db, key_id).await? else {
                    return Ok(None);
                };
                if !key_has_matching_v2_secret(cipher, &current, key_id, &key.secret_hash, &secret)?
                {
                    return Ok(None);
                }
            }
        }
        Ok(Some(secret))
    }

    async fn resolve_credentials(
        &self,
        access_key: &str,
        secret_key: &str,
    ) -> anyhow::Result<Option<(String, Option<String>)>> {
        let Some(key) = fetch_key(&self.db, access_key).await? else {
            return Ok(None);
        };
        if key.secret_hash != sha256_hash(secret_key) {
            return Ok(None);
        }
        if is_expired(key.expires_at.as_deref()) {
            return Ok(None);
        }
        Ok(Some((key.user_id, key.public_key_pem)))
    }

    async fn list_for_user(&self, user_id: &str) -> anyhow::Result<Vec<ApiKey>> {
        let rows = api_key::Entity::find()
            .filter(api_key::Column::UserId.eq(user_id.to_string()))
            .order_by_desc(api_key::Column::CreatedAt)
            .all(&self.db)
            .await
            .context("Postgres API key list failed")?;
        Ok(rows
            .into_iter()
            .map(|m| {
                let mut k: ApiKey = m.into();
                k.secret_hash = String::new();
                k.secret_encrypted = None;
                k
            })
            .collect())
    }

    async fn delete_key(&self, key_id: &str, user_id: &str) -> anyhow::Result<bool> {
        let result = api_key::Entity::delete_many()
            .filter(api_key::Column::KeyId.eq(key_id.to_string()))
            .filter(api_key::Column::UserId.eq(user_id.to_string()))
            .exec(&self.db)
            .await
            .context("Postgres API key delete failed")?;
        match result.rows_affected {
            0 => Ok(false),
            1 => Ok(true),
            rows => anyhow::bail!("Postgres API key delete affected {rows} rows"),
        }
    }

    async fn create_mcp_token(
        &self,
        user_id: &str,
        label: &str,
        expires_in: u64,
    ) -> anyhow::Result<(String, McpToken)> {
        let (mcp, token) = generate_mcp_token(user_id, label, expires_in)?;
        let expires_at = mcp
            .expires_at
            .as_deref()
            .map(str::parse::<i64>)
            .transpose()
            .context("MCP token expiry is outside the Postgres timestamp range")?;
        let model = mcp_token::ActiveModel {
            user_id: Set(mcp.user_id.clone()),
            token_hash: Set(mcp.token_hash.clone()),
            label: Set(mcp.label.clone()),
            expires_at: Set(expires_at),
            ..Default::default()
        };
        let inserted = model
            .insert(&self.db)
            .await
            .context("Postgres MCP token insert failed")?;
        Ok((
            token,
            McpToken {
                token_hash: inserted.token_hash,
                user_id: inserted.user_id,
                label: inserted.label,
                created_at: inserted.created_at.to_string(),
                expires_at: inserted.expires_at.map(|value| value.to_string()),
            },
        ))
    }

    async fn resolve_mcp_token(&self, token: &str) -> anyhow::Result<Option<String>> {
        let hash = sha256_hash(token);
        let row = mcp_token::Entity::find()
            .filter(mcp_token::Column::TokenHash.eq(hash))
            .one(&self.db)
            .await
            .context("Postgres MCP token lookup failed")?;
        let Some(row) = row else {
            return Ok(None);
        };
        if is_expired(row.expires_at.as_ref().map(|e| e.to_string()).as_deref()) {
            return Ok(None);
        }
        Ok(Some(row.user_id))
    }

    async fn list_mcp_tokens(&self, user_id: &str) -> anyhow::Result<Vec<McpToken>> {
        let rows = mcp_token::Entity::find()
            .filter(mcp_token::Column::UserId.eq(user_id.to_string()))
            .order_by_desc(mcp_token::Column::CreatedAt)
            .all(&self.db)
            .await
            .context("Postgres MCP token list failed")?;
        Ok(rows
            .into_iter()
            .map(|m| McpToken {
                token_hash: m.token_hash,
                user_id: m.user_id,
                label: m.label,
                created_at: m.created_at.to_string(),
                expires_at: m.expires_at.map(|e| e.to_string()),
            })
            .collect())
    }

    async fn delete_mcp_token(&self, token_hash: &str, user_id: &str) -> anyhow::Result<bool> {
        let result = mcp_token::Entity::delete_many()
            .filter(mcp_token::Column::TokenHash.eq(token_hash.to_string()))
            .filter(mcp_token::Column::UserId.eq(user_id.to_string()))
            .exec(&self.db)
            .await
            .context("Postgres MCP token delete failed")?;
        match result.rows_affected {
            0 => Ok(false),
            1 => Ok(true),
            rows => anyhow::bail!("Postgres MCP token delete affected {rows} rows"),
        }
    }
}

/// Load a persisted FileKeyStore payload (keys + mcp_tokens), tolerating the
/// legacy keys-only JSON shape.
fn load_file_store(
    path: &Path,
) -> anyhow::Result<(HashMap<String, ApiKey>, HashMap<String, McpToken>)> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Persisted {
        #[serde(default)]
        keys: HashMap<String, ApiKey>,
        #[serde(default)]
        mcp_tokens: HashMap<String, McpToken>,
    }
    let payload = match std::fs::read_to_string(path) {
        Ok(payload) => payload,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((HashMap::new(), HashMap::new()));
        }
        Err(error) => return Err(error).context("FileKeyStore snapshot read failed"),
    };
    if let Ok(data) = serde_json::from_str::<Persisted>(&payload) {
        return Ok((data.keys, data.mcp_tokens));
    }
    // Legacy shape: bare keys map.
    let keys = serde_json::from_str::<HashMap<String, ApiKey>>(&payload)
        .context("FileKeyStore snapshot is invalid as current and legacy formats")?;
    Ok((keys, HashMap::new()))
}

fn is_expired(expires_at: Option<&str>) -> bool {
    if let Some(exp) = expires_at {
        let now = chrono_now().parse::<u64>().unwrap_or(0);
        return exp.parse::<u64>().map_or(true, |ts| now >= ts);
    }
    false
}

impl Default for KeyStore {
    fn default() -> Self {
        Self::new()
    }
}

pub fn sha256_hash(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    format!("{:x}", h.finalize())
}

fn chrono_now() -> String {
    use std::time::SystemTime;
    let ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{}", ts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_cipher::{KeyWrapping, LocalKeyWrapping};

    const TEST_PUBLIC_KEY_PEM: &str = include_str!("../../../tests/fixtures/pii/crypto/pub.pem");
    const TEST_CERTIFICATE_PEM: &str = include_str!("../../../tests/fixtures/pii/crypto/cert.pem");
    const TEST_RSA_1024_PUBLIC_KEY_PEM: &str =
        include_str!("../../../tests/fixtures/pii/crypto/rsa-1024-public.pem");
    const TEST_RSA_4096_PUBLIC_KEY_PEM: &str =
        include_str!("../../../tests/fixtures/pii/crypto/rsa-4096-public.pem");

    #[derive(Debug)]
    struct FailingKeyWrapping;

    impl KeyWrapping for FailingKeyWrapping {
        fn wrap(&self, _dek: &[u8]) -> anyhow::Result<Vec<u8>> {
            Err(anyhow::anyhow!("intentional wrap failure"))
        }

        fn unwrap(&self, _wrapped: &[u8]) -> anyhow::Result<Vec<u8>> {
            Err(anyhow::anyhow!("intentional unwrap failure"))
        }
    }

    #[derive(Debug)]
    struct FailingUnwrapKeyWrapping(LocalKeyWrapping);

    impl KeyWrapping for FailingUnwrapKeyWrapping {
        fn wrap(&self, dek: &[u8]) -> anyhow::Result<Vec<u8>> {
            self.0.wrap(dek)
        }

        fn unwrap(&self, _wrapped: &[u8]) -> anyhow::Result<Vec<u8>> {
            Err(anyhow::anyhow!("intentional unwrap failure"))
        }
    }

    #[derive(Debug)]
    struct FailingWrapKeyWrapping(LocalKeyWrapping);

    impl KeyWrapping for FailingWrapKeyWrapping {
        fn wrap(&self, _dek: &[u8]) -> anyhow::Result<Vec<u8>> {
            Err(anyhow::anyhow!("intentional wrap failure"))
        }

        fn unwrap(&self, wrapped: &[u8]) -> anyhow::Result<Vec<u8>> {
            self.0.unwrap(wrapped)
        }
    }

    fn test_cipher() -> Arc<SecretCipher> {
        Arc::new(SecretCipher::new(Arc::new(LocalKeyWrapping::with_kek(
            [7u8; 32],
        ))))
    }

    fn failing_cipher() -> Arc<SecretCipher> {
        Arc::new(SecretCipher::new(Arc::new(FailingKeyWrapping)))
    }

    #[test]
    fn credential_labels_and_ttls_are_canonical_and_bounded() {
        assert_eq!(
            canonicalize_credential_label("  production key  ").unwrap(),
            "production key"
        );
        assert_eq!(
            canonicalize_credential_label(&"a".repeat(MAX_CREDENTIAL_LABEL_BYTES)).unwrap(),
            "a".repeat(MAX_CREDENTIAL_LABEL_BYTES)
        );
        for invalid in [
            " ".to_string(),
            "control\nlabel".to_string(),
            "a".repeat(MAX_CREDENTIAL_LABEL_BYTES + 1),
            "é".repeat((MAX_CREDENTIAL_LABEL_BYTES / 2) + 1),
        ] {
            assert!(canonicalize_credential_label(&invalid).is_err());
        }
        assert!(validate_credential_ttl(0).is_ok());
        assert!(validate_credential_ttl(MAX_CREDENTIAL_TTL_SECONDS).is_ok());
        assert!(validate_credential_ttl(MAX_CREDENTIAL_TTL_SECONDS + 1).is_err());
    }

    #[test]
    fn public_key_validation_matches_filter_formats_and_bounds() {
        assert_eq!(
            canonicalize_public_key_pem(TEST_PUBLIC_KEY_PEM).unwrap(),
            TEST_PUBLIC_KEY_PEM.trim()
        );
        assert_eq!(
            canonicalize_public_key_pem(TEST_CERTIFICATE_PEM).unwrap(),
            TEST_CERTIFICATE_PEM.trim()
        );
        assert!(canonicalize_public_key_pem("not a PEM").is_err());
        assert!(canonicalize_public_key_pem(TEST_RSA_1024_PUBLIC_KEY_PEM).is_err());
        assert!(canonicalize_public_key_pem(TEST_RSA_4096_PUBLIC_KEY_PEM).is_ok());
        assert!(canonicalize_public_key_pem(&"x".repeat(MAX_PUBLIC_KEY_PEM_BYTES + 1)).is_err());
    }

    #[test]
    fn malformed_expiry_fails_closed() {
        assert!(is_expired(Some("-1")));
        assert!(is_expired(Some("not-a-timestamp")));
    }

    #[tokio::test]
    async fn api_key_creation_enforces_input_boundaries() {
        let store = KeyStore::new();
        assert!(
            store
                .create_key(
                    "u1",
                    "  bounded  ",
                    MAX_CREDENTIAL_TTL_SECONDS,
                    Some(TEST_CERTIFICATE_PEM.to_string()),
                )
                .await
                .is_ok()
        );
        let stored = store.list_for_user("u1").await.unwrap();
        assert_eq!(stored[0].label, "bounded");
        assert_eq!(
            stored[0].public_key_pem.as_deref(),
            Some(TEST_CERTIFICATE_PEM.trim())
        );
        assert!(
            store
                .create_key("u1", "too long", MAX_CREDENTIAL_TTL_SECONDS + 1, None)
                .await
                .is_err()
        );

        let (token, mcp) = store
            .create_mcp_token("u1", "  agent  ", MAX_CREDENTIAL_TTL_SECONDS)
            .await
            .unwrap();
        assert!(token.starts_with("s4m_"));
        assert_eq!(mcp.label, "agent");
        assert!(mcp.expires_at.is_some());
        assert!(
            store
                .create_mcp_token("u1", "agent", MAX_CREDENTIAL_TTL_SECONDS + 1)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn in_memory_key_roundtrip() {
        let store = KeyStore::new();
        let (secret, created) = store.create_key("u1", "test", 0, None).await.unwrap();
        let key_id = created.key_id;
        let (uid, pk) = store
            .resolve_credentials(&key_id, &secret)
            .await
            .unwrap()
            .expect("valid credentials should resolve");
        assert_eq!(uid, "u1");
        assert!(pk.is_none());
        assert!(
            store
                .get_key(&key_id)
                .await
                .unwrap()
                .unwrap()
                .secret_encrypted
                .is_none(),
            "a store without a cipher may create a hash-only key"
        );
        assert!(
            store
                .resolve_credentials(&key_id, "nope")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .resolve_credentials("missing", &secret)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn configured_cipher_failure_does_not_create_in_memory_key() {
        let store = KeyStore::with_cipher(failing_cipher());

        let error = store
            .create_key("u1", "encryption-error", 0, None)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("secret encryption failed"));
        assert!(store.keys.read().unwrap().is_empty());
    }

    #[tokio::test]
    async fn wrapping_provider_unwrap_failure_is_a_repository_error() {
        let cipher = Arc::new(SecretCipher::new(Arc::new(FailingUnwrapKeyWrapping(
            LocalKeyWrapping::with_kek([7; 32]),
        ))));
        let store = KeyStore::with_cipher(cipher);
        let (_, created) = store
            .create_key("u1", "unwrap-failure", 0, None)
            .await
            .unwrap();

        let error = store.decrypt_secret(&created.key_id).await.unwrap_err();
        assert!(error.to_string().contains("wrapping provider failed"));
    }

    #[tokio::test]
    async fn legacy_rewrap_encryption_failure_is_a_repository_error() {
        let key_id = "s4_legacy";
        let secret = "s4s_legacy";
        let legacy = test_cipher().encrypt_v1(secret).unwrap();
        let cipher = Arc::new(SecretCipher::new(Arc::new(FailingWrapKeyWrapping(
            LocalKeyWrapping::with_kek([7; 32]),
        ))));
        let store = KeyStore {
            keys: RwLock::new(HashMap::from([(
                key_id.to_string(),
                build_api_key(
                    key_id,
                    "u1",
                    "legacy",
                    sha256_hash(secret),
                    Some(legacy),
                    chrono_now(),
                    None,
                    None,
                ),
            )])),
            mcp_tokens: RwLock::new(HashMap::new()),
            cipher: Some(cipher),
        };

        let error = store.decrypt_secret(key_id).await.unwrap_err();
        assert!(error.to_string().contains("rewrap encryption failed"));
    }

    #[test]
    fn already_rewrapped_same_secret_is_accepted_without_overwrite() {
        let cipher = test_cipher();
        let key_id = "key-a";
        let secret = "secret-a";
        let secret_hash = sha256_hash(secret);
        let legacy = cipher.encrypt_v1(secret).unwrap();
        let current_v2 = cipher.encrypt(key_id, secret).unwrap();
        let losing_rewrap = cipher.encrypt(key_id, secret).unwrap();
        let keys = RwLock::new(HashMap::from([(
            key_id.to_string(),
            build_api_key(
                key_id,
                "u1",
                "race",
                secret_hash.clone(),
                Some(current_v2.clone()),
                chrono_now(),
                None,
                None,
            ),
        )]));

        let result = replace_or_accept_rewrapped_envelope(
            &keys,
            &cipher,
            key_id,
            &secret_hash,
            secret,
            &legacy,
            losing_rewrap,
        );

        assert_eq!(result.unwrap(), Some(EnvelopeUpdate::AlreadyRewrapped));
        assert_eq!(
            keys.read().unwrap()[key_id].secret_encrypted.as_deref(),
            Some(current_v2.as_str())
        );
    }

    #[test]
    fn concurrent_different_v2_secret_is_rejected_without_overwrite() {
        let cipher = test_cipher();
        let key_id = "key-a";
        let secret = "secret-a";
        let secret_hash = sha256_hash(secret);
        let legacy = cipher.encrypt_v1(secret).unwrap();
        let current_v2 = cipher.encrypt(key_id, "different-secret").unwrap();
        let losing_rewrap = cipher.encrypt(key_id, secret).unwrap();
        let keys = RwLock::new(HashMap::from([(
            key_id.to_string(),
            build_api_key(
                key_id,
                "u1",
                "race",
                secret_hash.clone(),
                Some(current_v2.clone()),
                chrono_now(),
                None,
                None,
            ),
        )]));

        let result = replace_or_accept_rewrapped_envelope(
            &keys,
            &cipher,
            key_id,
            &secret_hash,
            secret,
            &legacy,
            losing_rewrap,
        );

        assert_eq!(result.unwrap(), None);
        assert_eq!(
            keys.read().unwrap()[key_id].secret_encrypted.as_deref(),
            Some(current_v2.as_str())
        );
    }

    #[tokio::test]
    async fn in_memory_api_key_operations_return_lock_errors() {
        let store = Arc::new(KeyStore::with_cipher(test_cipher()));
        let poisoner = store.clone();
        let _ = std::thread::spawn(move || {
            let _keys = poisoner.keys.write().unwrap();
            panic!("poison API key lock");
        })
        .join();

        assert!(store.get_key("missing").await.is_err());
        assert!(store.decrypt_secret("missing").await.is_err());
        assert!(store.list_for_user("u1").await.is_err());
        assert!(
            store
                .resolve_credentials("missing", "secret")
                .await
                .is_err()
        );
        assert!(store.delete_key("missing", "u1").await.is_err());
        assert!(store.create_key("u1", "lock-error", 0, None).await.is_err());
    }

    #[tokio::test]
    async fn in_memory_mcp_operations_return_lock_errors() {
        let store = Arc::new(KeyStore::new());
        let poisoner = store.clone();
        let _ = std::thread::spawn(move || {
            let _tokens = poisoner.mcp_tokens.write().unwrap();
            panic!("poison MCP token lock");
        })
        .join();

        assert!(store.resolve_mcp_token("s4m_missing").await.is_err());
        assert!(store.list_mcp_tokens("u1").await.is_err());
        assert!(store.create_mcp_token("u1", "lock-error", 0).await.is_err());
        assert!(store.delete_mcp_token(&"a".repeat(64), "u1").await.is_err());
    }

    #[tokio::test]
    async fn newly_generated_encrypted_secret_uses_v2() {
        let cipher = test_cipher();
        let store = KeyStore::with_cipher(cipher);
        let (secret, created) = store.create_key("u1", "v2", 0, None).await.unwrap();
        let key_id = created.key_id;

        let key = store.get_key(&key_id).await.unwrap().expect("key exists");
        assert!(
            key.secret_encrypted
                .as_deref()
                .is_some_and(|blob| blob.starts_with("v2:"))
        );
        assert_eq!(
            store.decrypt_secret(&key_id).await.unwrap().as_deref(),
            Some(secret.as_str())
        );
    }

    #[tokio::test]
    async fn in_memory_v1_secret_is_verified_and_rewrapped() {
        let cipher = test_cipher();
        let store = KeyStore::with_cipher(cipher.clone());
        let (secret, created) = store.create_key("u1", "legacy", 0, None).await.unwrap();
        let key_id = created.key_id;
        let legacy = cipher.encrypt_v1(&secret).unwrap();
        store
            .keys
            .write()
            .unwrap()
            .get_mut(&key_id)
            .unwrap()
            .secret_encrypted = Some(legacy);

        assert_eq!(
            store.decrypt_secret(&key_id).await.unwrap().as_deref(),
            Some(secret.as_str())
        );
        let rewrapped = store
            .get_key(&key_id)
            .await
            .unwrap()
            .unwrap()
            .secret_encrypted
            .unwrap();
        assert!(rewrapped.starts_with("v2:"));
        assert_eq!(
            cipher.decrypt(&key_id, &rewrapped).as_deref(),
            Some(secret.as_str())
        );
    }

    #[tokio::test]
    async fn hash_mismatch_never_returns_or_rewraps_secret() {
        let cipher = test_cipher();
        let store = KeyStore::with_cipher(cipher.clone());
        let (secret, created) = store.create_key("u1", "legacy", 0, None).await.unwrap();
        let key_id = created.key_id;
        let legacy = cipher.encrypt_v1(&secret).unwrap();
        {
            let mut keys = store.keys.write().unwrap();
            let key = keys.get_mut(&key_id).unwrap();
            key.secret_hash = sha256_hash("different-secret");
            key.secret_encrypted = Some(legacy.clone());
        }

        assert_eq!(store.decrypt_secret(&key_id).await.unwrap(), None);
        assert_eq!(
            store
                .get_key(&key_id)
                .await
                .unwrap()
                .unwrap()
                .secret_encrypted,
            Some(legacy)
        );
    }

    #[tokio::test]
    async fn swapped_v2_store_envelopes_are_rejected() {
        let cipher = test_cipher();
        let store = KeyStore::with_cipher(cipher);
        let (_, key_a) = store.create_key("u1", "a", 0, None).await.unwrap();
        let (_, key_b) = store.create_key("u1", "b", 0, None).await.unwrap();
        let key_a = key_a.key_id;
        let key_b = key_b.key_id;
        {
            let mut keys = store.keys.write().unwrap();
            let envelope_a = keys[&key_a].secret_encrypted.clone();
            let envelope_b = keys[&key_b].secret_encrypted.clone();
            keys.get_mut(&key_a).unwrap().secret_encrypted = envelope_b;
            keys.get_mut(&key_b).unwrap().secret_encrypted = envelope_a;
        }

        assert_eq!(store.decrypt_secret(&key_a).await.unwrap(), None);
        assert_eq!(store.decrypt_secret(&key_b).await.unwrap(), None);
    }

    #[tokio::test]
    async fn in_memory_expiry_rejects() {
        let store = KeyStore::new();
        let (secret, created) = store.create_key("u1", "exp", 1, None).await.unwrap();
        let key_id = created.key_id;
        // expiry is now+1s; sleep 1.2s to force it
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        assert!(
            store
                .resolve_credentials(&key_id, &secret)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn in_memory_public_key_and_delete() {
        let store = KeyStore::new();
        let (_, created) = store.create_key("u1", "enc", 0, None).await.unwrap();
        let key_id = created.key_id;
        assert!(
            store
                .set_public_key(&key_id, "u1", TEST_PUBLIC_KEY_PEM)
                .await
                .unwrap()
        );
        assert!(
            !store
                .set_public_key(&key_id, "u2", TEST_CERTIFICATE_PEM)
                .await
                .unwrap()
        );
        let key = store.get_key(&key_id).await.unwrap().expect("key exists");
        assert_eq!(
            key.public_key_pem.as_deref(),
            Some(TEST_PUBLIC_KEY_PEM.trim())
        );
        let keys = store.list_for_user("u1").await.unwrap();
        assert_eq!(keys.len(), 1);
        assert!(keys[0].secret_hash.is_empty());
        assert!(store.delete_key(&key_id, "u1").await.unwrap());
        assert!(store.get_key(&key_id).await.unwrap().is_none());
    }

    fn temp_keys_file() -> PathBuf {
        let path = std::env::temp_dir().join(format!("maskura-file-keys-{}.json", Uuid::new_v4()));
        let _ = std::fs::remove_file(&path);
        path
    }

    fn pause_next_persist(
        store: &FileKeyStore,
    ) -> (
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::SyncSender<()>,
    ) {
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
        let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel(1);
        *store.persist_hook.lock().unwrap() = Some(PersistTestHook {
            entered: entered_tx,
            resume: resume_rx,
        });
        (entered_rx, resume_tx)
    }

    #[tokio::test]
    async fn file_store_rejects_corrupt_snapshot_without_overwriting_it() {
        let path = temp_keys_file();
        let payload = b"{not-valid-json";
        std::fs::write(&path, payload).unwrap();

        let error = FileKeyStore::new(path.clone()).unwrap_err();

        assert!(error.to_string().contains("invalid as current and legacy"));
        assert_eq!(std::fs::read(&path).unwrap(), payload);
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn file_store_rejects_unreadable_snapshot_path_without_overwriting_it() {
        let path = temp_keys_file();
        std::fs::create_dir_all(&path).unwrap();
        let marker = path.join("marker");
        std::fs::write(&marker, "unchanged").unwrap();

        let error = FileKeyStore::new(path.clone()).unwrap_err();

        assert!(error.to_string().contains("snapshot read failed"));
        assert_eq!(std::fs::read_to_string(marker).unwrap(), "unchanged");
        std::fs::remove_dir_all(path).unwrap();
    }

    #[tokio::test]
    async fn file_store_loads_legacy_bare_key_map() {
        let path = temp_keys_file();
        let key = build_api_key(
            "s4_legacy",
            "u1",
            "legacy",
            sha256_hash("secret"),
            None,
            chrono_now(),
            None,
            None,
        );
        std::fs::write(
            &path,
            serde_json::to_vec(&HashMap::from([(key.key_id.clone(), key.clone())])).unwrap(),
        )
        .unwrap();

        let store = FileKeyStore::new(path.clone()).unwrap();

        assert_eq!(store.get_key(&key.key_id).await.unwrap(), Some(key));
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn file_store_creation_establishes_snapshot_parent_directory() {
        let root = std::env::temp_dir().join(format!("maskura-file-parent-{}", Uuid::new_v4()));
        let path = root.join("nested").join("keys.json");
        assert!(!root.exists());

        let store = FileKeyStore::new(path.clone()).unwrap();

        assert!(path.parent().unwrap().is_dir());
        assert!(store.list_for_user("u1").await.unwrap().is_empty());
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn file_readers_never_observe_failed_persisted_mutations() {
        let parent =
            std::env::temp_dir().join(format!("maskura-file-visibility-{}", Uuid::new_v4()));
        let durable_parent = parent.with_extension("durable");
        std::fs::create_dir_all(&parent).unwrap();
        let path = parent.join("keys.json");
        let store = Arc::new(FileKeyStore::new(path.clone()).unwrap());
        let (secret, created) = store.create_key("u1", "persisted", 0, None).await.unwrap();
        let key_id = created.key_id;
        let token = store
            .create_mcp_token("u1", "persisted", 0)
            .await
            .unwrap()
            .0;
        let token_hash = sha256_hash(&token);
        std::fs::rename(&parent, &durable_parent).unwrap();
        std::fs::write(&parent, "not a directory").unwrap();

        let (entered, resume) = pause_next_persist(&store);
        let create_store = store.clone();
        let create =
            tokio::spawn(async move { create_store.create_key("u1", "tentative", 0, None).await });
        entered
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        let read_store = store.clone();
        let read = tokio::spawn(async move { read_store.list_for_user("u1").await });
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        assert!(!read.is_finished(), "API key creation must remain hidden");
        resume.send(()).unwrap();
        assert!(create.await.unwrap().is_err());
        assert_eq!(read.await.unwrap().unwrap().len(), 1);

        let (entered, resume) = pause_next_persist(&store);
        let set_store = store.clone();
        let set_key = key_id.clone();
        let set = tokio::spawn(async move {
            set_store
                .set_public_key(&set_key, "u1", TEST_PUBLIC_KEY_PEM)
                .await
        });
        entered
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        let read_store = store.clone();
        let read_key = key_id.clone();
        let read = tokio::spawn(async move { read_store.get_key(&read_key).await });
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        assert!(!read.is_finished(), "public key update must remain hidden");
        resume.send(()).unwrap();
        assert!(set.await.unwrap().is_err());
        assert!(
            read.await
                .unwrap()
                .unwrap()
                .unwrap()
                .public_key_pem
                .is_none()
        );

        let (entered, resume) = pause_next_persist(&store);
        let delete_store = store.clone();
        let delete_key = key_id.clone();
        let delete = tokio::spawn(async move { delete_store.delete_key(&delete_key, "u1").await });
        entered
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        let read_store = store.clone();
        let read_key = key_id.clone();
        let read_secret = secret.clone();
        let read = tokio::spawn(async move {
            read_store
                .resolve_credentials(&read_key, &read_secret)
                .await
        });
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        assert!(!read.is_finished(), "API key deletion must remain hidden");
        resume.send(()).unwrap();
        assert!(delete.await.unwrap().is_err());
        assert!(read.await.unwrap().unwrap().is_some());

        let (entered, resume) = pause_next_persist(&store);
        let create_store = store.clone();
        let create =
            tokio::spawn(async move { create_store.create_mcp_token("u1", "tentative", 0).await });
        entered
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        let read_store = store.clone();
        let read = tokio::spawn(async move { read_store.list_mcp_tokens("u1").await });
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        assert!(!read.is_finished(), "MCP token creation must remain hidden");
        resume.send(()).unwrap();
        assert!(create.await.unwrap().is_err());
        assert_eq!(read.await.unwrap().unwrap().len(), 1);

        let (entered, resume) = pause_next_persist(&store);
        let delete_store = store.clone();
        let delete_hash = token_hash.clone();
        let delete =
            tokio::spawn(async move { delete_store.delete_mcp_token(&delete_hash, "u1").await });
        entered
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        let read_store = store.clone();
        let read_token = token.clone();
        let read = tokio::spawn(async move { read_store.resolve_mcp_token(&read_token).await });
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        assert!(!read.is_finished(), "MCP token deletion must remain hidden");
        resume.send(()).unwrap();
        assert!(delete.await.unwrap().is_err());
        assert_eq!(read.await.unwrap().unwrap().as_deref(), Some("u1"));

        std::fs::remove_file(&parent).unwrap();
        std::fs::rename(&durable_parent, &parent).unwrap();
        drop(store);
        let restarted = FileKeyStore::new(path).unwrap();
        assert!(
            restarted
                .resolve_credentials(&key_id, &secret)
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            restarted
                .resolve_mcp_token(&token)
                .await
                .unwrap()
                .as_deref(),
            Some("u1")
        );
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[tokio::test]
    async fn file_key_store_persists_across_restarts() {
        let path = temp_keys_file();
        let store = FileKeyStore::new(path.clone()).unwrap();
        let (secret, created) = store.create_key("u1", "persist", 0, None).await.unwrap();
        let key_id = created.key_id;
        drop(store);

        // A fresh store on the same path must see the same key.
        let reloaded = FileKeyStore::new(path.clone()).unwrap();
        let (uid, _pk) = reloaded
            .resolve_credentials(&key_id, &secret)
            .await
            .unwrap()
            .expect("credentials survive a restart");
        assert_eq!(uid, "u1");
        assert!(reloaded.list_for_user("u1").await.unwrap().len() == 1);
        assert!(reloaded.delete_key(&key_id, "u1").await.unwrap());
        drop(reloaded);

        let empty = FileKeyStore::new(path).unwrap();
        assert!(empty.get_key(&key_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn file_key_store_rolls_back_key_when_persist_fails() {
        let blocking_parent = temp_keys_file();
        std::fs::create_dir_all(&blocking_parent).unwrap();
        let path = blocking_parent.join("keys.json");
        let store = FileKeyStore::new(path).unwrap();
        std::fs::remove_dir_all(&blocking_parent).unwrap();
        std::fs::write(&blocking_parent, "not a directory").unwrap();

        let error = store
            .create_key("u1", "persist-error", 0, None)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("persist failed"));
        assert!(store.keys.read().unwrap().is_empty());
        std::fs::remove_file(blocking_parent).unwrap();
    }

    #[tokio::test]
    async fn file_key_store_rolls_back_public_key_when_persist_fails_and_restart_keeps_old_value() {
        let parent = std::env::temp_dir().join(format!("maskura-file-keys-{}", Uuid::new_v4()));
        let durable_parent = parent.with_extension("durable");
        std::fs::create_dir_all(&parent).unwrap();
        let path = parent.join("keys.json");
        let store = FileKeyStore::new(path.clone()).unwrap();
        let (_, created) = store
            .create_key(
                "u1",
                "persisted-public-key",
                0,
                Some(TEST_PUBLIC_KEY_PEM.to_string()),
            )
            .await
            .unwrap();
        let key_id = created.key_id;
        std::fs::rename(&parent, &durable_parent).unwrap();
        std::fs::write(&parent, "not a directory").unwrap();

        let error = store
            .set_public_key(&key_id, "u1", TEST_CERTIFICATE_PEM)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("public key persist failed"));
        assert_eq!(
            store
                .get_key(&key_id)
                .await
                .unwrap()
                .unwrap()
                .public_key_pem
                .as_deref(),
            Some(TEST_PUBLIC_KEY_PEM.trim())
        );
        std::fs::remove_file(&parent).unwrap();
        std::fs::rename(&durable_parent, &parent).unwrap();
        drop(store);

        let restarted = FileKeyStore::new(path).unwrap();
        assert_eq!(
            restarted
                .get_key(&key_id)
                .await
                .unwrap()
                .unwrap()
                .public_key_pem
                .as_deref(),
            Some(TEST_PUBLIC_KEY_PEM.trim())
        );
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[tokio::test]
    async fn file_key_store_rolls_back_key_delete_when_persist_fails() {
        let parent = std::env::temp_dir().join(format!("maskura-file-keys-{}", Uuid::new_v4()));
        let durable_parent = parent.with_extension("durable");
        std::fs::create_dir_all(&parent).unwrap();
        let path = parent.join("keys.json");
        let store = FileKeyStore::new(path.clone()).unwrap();
        let (secret, created) = store.create_key("u1", "delete", 0, None).await.unwrap();
        let key_id = created.key_id;
        std::fs::rename(&parent, &durable_parent).unwrap();
        std::fs::write(&parent, "not a directory").unwrap();

        assert!(store.delete_key(&key_id, "u1").await.is_err());
        assert!(
            store
                .resolve_credentials(&key_id, &secret)
                .await
                .unwrap()
                .is_some()
        );
        std::fs::remove_file(&parent).unwrap();
        std::fs::rename(&durable_parent, &parent).unwrap();
        drop(store);

        let restarted = FileKeyStore::new(path).unwrap();
        assert!(
            restarted
                .resolve_credentials(&key_id, &secret)
                .await
                .unwrap()
                .is_some(),
            "failed revocation must not be acknowledged only in memory"
        );
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[tokio::test]
    async fn file_key_store_rolls_back_mcp_mutations_when_persist_fails() {
        let parent = std::env::temp_dir().join(format!("maskura-file-keys-{}", Uuid::new_v4()));
        let durable_parent = parent.with_extension("durable");
        std::fs::create_dir_all(&parent).unwrap();
        let path = parent.join("keys.json");
        let store = FileKeyStore::new(path.clone()).unwrap();
        let persisted_token = store
            .create_mcp_token("u1", "persisted", 0)
            .await
            .unwrap()
            .0;
        let persisted_hash = sha256_hash(&persisted_token);
        std::fs::rename(&parent, &durable_parent).unwrap();
        std::fs::write(&parent, "not a directory").unwrap();

        assert!(store.create_mcp_token("u1", "rejected", 0).await.is_err());
        assert!(store.delete_mcp_token(&persisted_hash, "u1").await.is_err());
        assert_eq!(
            store
                .resolve_mcp_token(&persisted_token)
                .await
                .unwrap()
                .as_deref(),
            Some("u1")
        );
        std::fs::remove_file(&parent).unwrap();
        std::fs::rename(&durable_parent, &parent).unwrap();
        drop(store);

        let restarted = FileKeyStore::new(path).unwrap();
        assert_eq!(
            restarted
                .resolve_mcp_token(&persisted_token)
                .await
                .unwrap()
                .as_deref(),
            Some("u1")
        );
        assert_eq!(restarted.list_mcp_tokens("u1").await.unwrap().len(), 1);
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn file_key_store_serializes_public_key_set_before_successful_delete() {
        let path = temp_keys_file();
        let store = Arc::new(FileKeyStore::new(path.clone()).unwrap());
        let (secret, created) = store.create_key("u1", "race", 0, None).await.unwrap();
        let key_id = created.key_id;
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
        let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel(1);
        *store.persist_hook.lock().unwrap() = Some(PersistTestHook {
            entered: entered_tx,
            resume: resume_rx,
        });

        let set_store = store.clone();
        let set_key = key_id.clone();
        let set_task = tokio::spawn(async move {
            set_store
                .set_public_key(&set_key, "u1", TEST_PUBLIC_KEY_PEM)
                .await
        });
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        let delete_store = store.clone();
        let delete_key = key_id.clone();
        let delete_task =
            tokio::spawn(async move { delete_store.delete_key(&delete_key, "u1").await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            !delete_task.is_finished(),
            "delete must wait for the in-flight snapshot"
        );

        resume_tx.send(()).unwrap();
        assert!(set_task.await.unwrap().unwrap());
        assert!(delete_task.await.unwrap().unwrap());
        assert!(
            store
                .resolve_credentials(&key_id, &secret)
                .await
                .unwrap()
                .is_none()
        );
        drop(store);

        let restarted = FileKeyStore::new(path.clone()).unwrap();
        assert!(
            restarted
                .resolve_credentials(&key_id, &secret)
                .await
                .unwrap()
                .is_none(),
            "a successfully revoked key must never reappear after restart"
        );
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn file_key_store_serializes_api_key_and_mcp_creation_snapshots() {
        let path = temp_keys_file();
        let store = Arc::new(FileKeyStore::new(path.clone()).unwrap());
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
        let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel(1);
        *store.persist_hook.lock().unwrap() = Some(PersistTestHook {
            entered: entered_tx,
            resume: resume_rx,
        });

        let key_store = store.clone();
        let key_task =
            tokio::spawn(async move { key_store.create_key("u1", "concurrent", 0, None).await });
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        let mcp_store = store.clone();
        let mcp_task = tokio::spawn(async move {
            mcp_store
                .create_mcp_token("u1", "concurrent-token", 0)
                .await
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            !mcp_task.is_finished(),
            "MCP creation must wait for the API key snapshot"
        );

        resume_tx.send(()).unwrap();
        let (secret, created) = key_task.await.unwrap().unwrap();
        let key_id = created.key_id;
        let token = mcp_task.await.unwrap().unwrap().0;
        drop(store);

        let restarted = FileKeyStore::new(path.clone()).unwrap();
        assert!(
            restarted
                .resolve_credentials(&key_id, &secret)
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            restarted
                .resolve_mcp_token(&token)
                .await
                .unwrap()
                .as_deref(),
            Some("u1")
        );
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn file_key_store_serializes_secret_rewrap_and_mcp_creation() {
        let path = temp_keys_file();
        let cipher = test_cipher();
        let store = Arc::new(FileKeyStore::with_cipher(path.clone(), cipher.clone()).unwrap());
        let (secret, created) = store.create_key("u1", "legacy", 0, None).await.unwrap();
        let key_id = created.key_id;
        let legacy = cipher.encrypt_v1(&secret).unwrap();
        store
            .keys
            .write()
            .unwrap()
            .get_mut(&key_id)
            .unwrap()
            .secret_encrypted = Some(legacy);
        store.persist().unwrap();
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
        let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel(1);
        *store.persist_hook.lock().unwrap() = Some(PersistTestHook {
            entered: entered_tx,
            resume: resume_rx,
        });

        let rewrap_store = store.clone();
        let rewrap_key = key_id.clone();
        let rewrap_task =
            tokio::spawn(async move { rewrap_store.decrypt_secret(&rewrap_key).await });
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        let mcp_store = store.clone();
        let mcp_task =
            tokio::spawn(async move { mcp_store.create_mcp_token("u1", "after-rewrap", 0).await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            !mcp_task.is_finished(),
            "MCP creation must wait for the rewrap snapshot"
        );

        resume_tx.send(()).unwrap();
        assert_eq!(
            rewrap_task.await.unwrap().unwrap().as_deref(),
            Some(secret.as_str())
        );
        let token = mcp_task.await.unwrap().unwrap().0;
        drop(store);

        let restarted = FileKeyStore::with_cipher(path.clone(), cipher).unwrap();
        assert_eq!(
            restarted.decrypt_secret(&key_id).await.unwrap().as_deref(),
            Some(secret.as_str())
        );
        assert_eq!(
            restarted
                .resolve_mcp_token(&token)
                .await
                .unwrap()
                .as_deref(),
            Some("u1")
        );
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn file_key_store_mcp_delete_does_not_self_deadlock_and_persists() {
        let path = temp_keys_file();
        let store = FileKeyStore::new(path.clone()).unwrap();
        let token = store.create_mcp_token("u1", "delete", 0).await.unwrap().0;
        let token_hash = sha256_hash(&token);

        assert!(
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                store.delete_mcp_token(&token_hash, "u1")
            )
            .await
            .expect("MCP delete must not deadlock")
            .unwrap()
        );
        drop(store);

        let restarted = FileKeyStore::new(path.clone()).unwrap();
        assert!(restarted.resolve_mcp_token(&token).await.unwrap().is_none());
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn configured_cipher_failure_does_not_create_or_persist_file_key() {
        let path = temp_keys_file();
        let store = FileKeyStore::with_cipher(path.clone(), failing_cipher()).unwrap();

        let error = store
            .create_key("u1", "encryption-error", 0, None)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("secret encryption failed"));
        assert!(store.keys.read().unwrap().is_empty());
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn postgres_create_key_propagates_insert_error() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(50))
            .connect_lazy("postgresql://postgres:postgres@127.0.0.1:1/maskura")
            .unwrap();
        let store = PostgresKeyStore::new(pool);

        let error = store
            .create_key("u1", "database-error", 0, None)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("Postgres API key insert failed"));

        let error = store
            .create_mcp_token("u1", "database-error", 0)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Postgres MCP token insert failed")
        );
    }

    #[tokio::test]
    async fn postgres_set_public_key_propagates_update_error() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(50))
            .connect_lazy("postgresql://postgres:postgres@127.0.0.1:1/maskura")
            .unwrap();
        let store = PostgresKeyStore::new(pool);

        let error = store
            .set_public_key("missing-key", "u1", TEST_PUBLIC_KEY_PEM)
            .await
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("Postgres public key update failed")
        );
    }

    #[tokio::test]
    async fn postgres_reads_lists_resolves_and_deletes_propagate_database_errors() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(50))
            .connect_lazy("postgresql://postgres:postgres@127.0.0.1:1/maskura")
            .unwrap();
        let store = PostgresKeyStore::with_cipher(pool, test_cipher());

        assert!(
            store
                .get_key("s4_missing")
                .await
                .unwrap_err()
                .to_string()
                .contains("Postgres API key lookup failed")
        );
        assert!(
            store
                .decrypt_secret("s4_missing")
                .await
                .unwrap_err()
                .to_string()
                .contains("Postgres API key lookup failed")
        );
        assert!(
            store
                .resolve_credentials("s4_missing", "s4s_missing")
                .await
                .unwrap_err()
                .to_string()
                .contains("Postgres API key lookup failed")
        );
        assert!(
            store
                .list_for_user("u1")
                .await
                .unwrap_err()
                .to_string()
                .contains("Postgres API key list failed")
        );
        assert!(
            store
                .delete_key("s4_missing", "u1")
                .await
                .unwrap_err()
                .to_string()
                .contains("Postgres API key delete failed")
        );
        assert!(
            store
                .resolve_mcp_token("s4m_missing")
                .await
                .unwrap_err()
                .to_string()
                .contains("Postgres MCP token lookup failed")
        );
        assert!(
            store
                .list_mcp_tokens("u1")
                .await
                .unwrap_err()
                .to_string()
                .contains("Postgres MCP token list failed")
        );
        assert!(
            store
                .delete_mcp_token(&"a".repeat(64), "u1")
                .await
                .unwrap_err()
                .to_string()
                .contains("Postgres MCP token delete failed")
        );
    }

    #[tokio::test]
    async fn postgres_configured_cipher_failure_prevents_insert() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(50))
            .connect_lazy("postgresql://postgres:postgres@127.0.0.1:1/maskura")
            .unwrap();
        let store = PostgresKeyStore::with_cipher(pool, failing_cipher());

        let error = store
            .create_key("u1", "encryption-error", 0, None)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("secret encryption failed"));
    }

    #[tokio::test]
    async fn file_key_store_persists_public_key_and_expiry() {
        let path = temp_keys_file();
        let store = FileKeyStore::new(path.clone()).unwrap();
        let (_, created) = store.create_key("u1", "enc", 3600, None).await.unwrap();
        let key_id = created.key_id;
        assert!(
            store
                .set_public_key(&key_id, "u1", TEST_PUBLIC_KEY_PEM)
                .await
                .unwrap()
        );
        assert!(
            !store
                .set_public_key(&key_id, "u2", TEST_CERTIFICATE_PEM)
                .await
                .unwrap()
        );
        drop(store);

        let reloaded = FileKeyStore::new(path).unwrap();
        let key = reloaded
            .get_key(&key_id)
            .await
            .unwrap()
            .expect("key exists");
        assert_eq!(
            key.public_key_pem.as_deref(),
            Some(TEST_PUBLIC_KEY_PEM.trim())
        );
        assert!(key.expires_at.is_some());
    }

    #[tokio::test]
    async fn file_key_store_persists_v1_rewrap() {
        let path = temp_keys_file();
        let cipher = test_cipher();
        let store = FileKeyStore::with_cipher(path.clone(), cipher.clone()).unwrap();
        let (secret, created) = store.create_key("u1", "legacy", 0, None).await.unwrap();
        let key_id = created.key_id;
        let legacy = cipher.encrypt_v1(&secret).unwrap();
        store
            .keys
            .write()
            .unwrap()
            .get_mut(&key_id)
            .unwrap()
            .secret_encrypted = Some(legacy);
        store.persist().unwrap();

        assert_eq!(
            store.decrypt_secret(&key_id).await.unwrap().as_deref(),
            Some(secret.as_str())
        );
        drop(store);

        let reloaded = FileKeyStore::with_cipher(path.clone(), cipher).unwrap();
        let envelope = reloaded
            .get_key(&key_id)
            .await
            .unwrap()
            .unwrap()
            .secret_encrypted
            .unwrap();
        assert!(envelope.starts_with("v2:"));
        assert_eq!(
            reloaded.decrypt_secret(&key_id).await.unwrap().as_deref(),
            Some(secret.as_str())
        );
        let _ = std::fs::remove_file(path);
    }
}
