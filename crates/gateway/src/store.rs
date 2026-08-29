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
use std::path::PathBuf;
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
    /// Create and persist a key, then return the plaintext `(key_id, secret)`.
    /// The secret is hashed (SHA-256) before storage and never returned when
    /// persistence fails.
    async fn create_key(
        &self,
        user_id: &str,
        label: &str,
        expires_in: u64,
        public_key_pem: Option<String>,
    ) -> anyhow::Result<(String, String)>;

    async fn set_public_key(
        &self,
        key_id: &str,
        user_id: &str,
        public_key_pem: &str,
    ) -> anyhow::Result<bool>;

    async fn get_key(&self, key_id: &str) -> Option<ApiKey>;

    /// Decrypt the stored plaintext secret for `key_id` (used to verify SigV4
    /// signatures). Returns `None` for legacy keys that only have a hash.
    async fn decrypt_secret(&self, key_id: &str) -> Option<String>;

    /// Validate an access key/secret pair and return the owning user id plus
    /// the API key's public key PEM (used by the encryption pipeline).
    async fn resolve_credentials(
        &self,
        access_key: &str,
        secret_key: &str,
    ) -> Option<(String, Option<String>)>;

    /// Keys for a user, with the secret hash stripped.
    async fn list_for_user(&self, user_id: &str) -> Vec<ApiKey>;

    async fn delete_key(&self, key_id: &str, user_id: &str) -> bool;

    /// Create an MCP bearer token (`s4m_...`) and return the plaintext token
    /// (shown once). Only its SHA-256 hash is stored.
    async fn create_mcp_token(
        &self,
        user_id: &str,
        label: &str,
        expires_in: u64,
    ) -> anyhow::Result<(String, McpToken)>;

    /// Validate an MCP bearer token and return the owning user id.
    async fn resolve_mcp_token(&self, token: &str) -> Option<String>;

    /// MCP tokens for a user (hashes only).
    async fn list_mcp_tokens(&self, user_id: &str) -> Vec<McpToken>;

    async fn delete_mcp_token(&self, token_hash: &str, user_id: &str) -> bool;
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
) -> Option<(String, Option<String>)> {
    let secret = cipher.decrypt(key_id, blob)?;
    if sha256_hash(&secret) != secret_hash {
        tracing::warn!(
            key_id = key_id,
            "decrypted API key secret failed hash verification"
        );
        return None;
    }
    let rewrapped = if SecretCipher::is_legacy_envelope(blob) {
        Some(cipher.encrypt(key_id, &secret).ok()?)
    } else {
        None
    };
    Some((secret, rewrapped))
}

fn compare_and_swap_envelope(
    keys: &RwLock<HashMap<String, ApiKey>>,
    key_id: &str,
    expected: &str,
    replacement: String,
) -> bool {
    let mut keys = keys.write().unwrap();
    let Some(key) = keys.get_mut(key_id) else {
        return false;
    };
    if key.secret_encrypted.as_deref() != Some(expected) {
        return false;
    }
    key.secret_encrypted = Some(replacement);
    true
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
) -> bool {
    if key.key_id != key_id || key.secret_hash != secret_hash {
        return false;
    }
    let Some(blob) = key.secret_encrypted.as_deref() else {
        return false;
    };
    if !blob.starts_with("v2:") {
        return false;
    }
    decrypt_verified_secret(cipher, key_id, secret_hash, blob)
        .is_some_and(|(current, rewrapped)| rewrapped.is_none() && current == secret)
}

fn replace_or_accept_rewrapped_envelope(
    keys: &RwLock<HashMap<String, ApiKey>>,
    cipher: &SecretCipher,
    key_id: &str,
    secret_hash: &str,
    secret: &str,
    expected: &str,
    replacement: String,
) -> Option<EnvelopeUpdate> {
    if compare_and_swap_envelope(keys, key_id, expected, replacement) {
        return Some(EnvelopeUpdate::Replaced);
    }
    let current = keys.read().ok()?.get(key_id)?.clone();
    key_has_matching_v2_secret(cipher, &current, key_id, secret_hash, secret)
        .then_some(EnvelopeUpdate::AlreadyRewrapped)
}

fn set_public_key_in(
    keys: &RwLock<HashMap<String, ApiKey>>,
    key_id: &str,
    user_id: &str,
    public_key_pem: &str,
) -> bool {
    let mut keys = keys.write().unwrap();
    if let Some(k) = keys.get_mut(key_id)
        && k.user_id == user_id
    {
        k.public_key_pem = Some(public_key_pem.to_string());
        return true;
    }
    false
}

fn get_key_in(keys: &RwLock<HashMap<String, ApiKey>>, key_id: &str) -> Option<ApiKey> {
    keys.read().unwrap().get(key_id).cloned()
}

fn resolve_credentials_in(
    keys: &RwLock<HashMap<String, ApiKey>>,
    access_key: &str,
    secret_key: &str,
) -> Option<(String, Option<String>)> {
    let keys = keys.read().unwrap();
    let key = keys.get(access_key)?;
    if key.secret_hash != sha256_hash(secret_key) {
        return None;
    }
    if is_expired(key.expires_at.as_deref()) {
        return None;
    }
    Some((key.user_id.clone(), key.public_key_pem.clone()))
}

fn list_for_user_in(keys: &RwLock<HashMap<String, ApiKey>>, user_id: &str) -> Vec<ApiKey> {
    keys.read()
        .unwrap()
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
        .collect()
}

fn delete_key_in(keys: &RwLock<HashMap<String, ApiKey>>, key_id: &str, user_id: &str) -> bool {
    let mut keys = keys.write().unwrap();
    if let Some(k) = keys.get(key_id)
        && k.user_id == user_id
    {
        keys.remove(key_id);
        return true;
    }
    false
}

#[async_trait]
impl KeyRepository for KeyStore {
    async fn create_key(
        &self,
        user_id: &str,
        label: &str,
        expires_in: u64,
        public_key_pem: Option<String>,
    ) -> anyhow::Result<(String, String)> {
        let (api_key, secret) = generate_api_key(
            user_id,
            label,
            expires_in,
            public_key_pem,
            self.cipher.as_deref(),
        )?;
        let key_id = api_key.key_id.clone();
        self.keys
            .write()
            .map_err(|_| anyhow::anyhow!("KeyStore API key lock poisoned"))?
            .insert(key_id.clone(), api_key);
        Ok((key_id, secret))
    }

    async fn set_public_key(
        &self,
        key_id: &str,
        user_id: &str,
        public_key_pem: &str,
    ) -> anyhow::Result<bool> {
        let public_key_pem = canonicalize_public_key_pem(public_key_pem)?;
        Ok(set_public_key_in(
            &self.keys,
            key_id,
            user_id,
            &public_key_pem,
        ))
    }

    async fn get_key(&self, key_id: &str) -> Option<ApiKey> {
        get_key_in(&self.keys, key_id)
    }

    async fn decrypt_secret(&self, key_id: &str) -> Option<String> {
        let cipher = self.cipher.as_deref()?;
        let (secret_hash, blob) = {
            let keys = self.keys.read().unwrap();
            let key = keys.get(key_id)?;
            (key.secret_hash.clone(), key.secret_encrypted.clone()?)
        };
        let (secret, rewrapped) = decrypt_verified_secret(cipher, key_id, &secret_hash, &blob)?;
        if let Some(rewrapped) = rewrapped {
            replace_or_accept_rewrapped_envelope(
                &self.keys,
                cipher,
                key_id,
                &secret_hash,
                &secret,
                &blob,
                rewrapped,
            )?;
        }
        Some(secret)
    }

    async fn resolve_credentials(
        &self,
        access_key: &str,
        secret_key: &str,
    ) -> Option<(String, Option<String>)> {
        resolve_credentials_in(&self.keys, access_key, secret_key)
    }

    async fn list_for_user(&self, user_id: &str) -> Vec<ApiKey> {
        list_for_user_in(&self.keys, user_id)
    }

    async fn delete_key(&self, key_id: &str, user_id: &str) -> bool {
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

    async fn resolve_mcp_token(&self, token: &str) -> Option<String> {
        let hash = sha256_hash(token);
        let tokens = self.mcp_tokens.read().unwrap();
        let t = tokens.get(&hash)?;
        if is_expired(t.expires_at.as_deref()) {
            return None;
        }
        Some(t.user_id.clone())
    }

    async fn list_mcp_tokens(&self, user_id: &str) -> Vec<McpToken> {
        self.mcp_tokens
            .read()
            .unwrap()
            .values()
            .filter(|t| t.user_id == user_id)
            .cloned()
            .collect()
    }

    async fn delete_mcp_token(&self, token_hash: &str, user_id: &str) -> bool {
        let mut tokens = self.mcp_tokens.write().unwrap();
        if let Some(t) = tokens.get(token_hash)
            && t.user_id == user_id
        {
            tokens.remove(token_hash);
            return true;
        }
        false
    }
}

/// Persistent key store backed by a JSON file (e.g. `~/.config/s4/keys.json`).
///
/// Loads the file once at construction and rewrites it atomically (0600 on
/// unix) after every mutation, so API keys survive gateway restarts without
/// Postgres. This is the default in local mode (`AUTH_DISABLED=true` without
/// `DATABASE_URL`), or opt in explicitly with `S4_KEYS_FILE`.
#[derive(Debug)]
pub struct FileKeyStore {
    keys: RwLock<HashMap<String, ApiKey>>,
    mcp_tokens: RwLock<HashMap<String, McpToken>>,
    // Every state mutation shares one snapshot file and must commit in order.
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
    pub fn new(path: PathBuf) -> Self {
        let (keys, mcp_tokens) = load_file_store(&path);
        Self {
            keys: RwLock::new(keys),
            mcp_tokens: RwLock::new(mcp_tokens),
            mutation_lock: Mutex::new(()),
            #[cfg(test)]
            persist_hook: Mutex::new(None),
            path,
            cipher: None,
        }
    }

    pub fn with_cipher(path: PathBuf, cipher: Arc<SecretCipher>) -> Self {
        let (keys, mcp_tokens) = load_file_store(&path);
        Self {
            keys: RwLock::new(keys),
            mcp_tokens: RwLock::new(mcp_tokens),
            mutation_lock: Mutex::new(()),
            #[cfg(test)]
            persist_hook: Mutex::new(None),
            path,
            cipher: Some(cipher),
        }
    }

    /// Default location for the local-mode keys file.
    pub fn default_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("s4")
            .join("keys.json")
    }

    /// Atomically write the current key set to disk (0600 on unix).
    fn persist(&self) -> anyhow::Result<()> {
        #[cfg(test)]
        if let Some(hook) = self.persist_hook.lock().unwrap().take() {
            hook.entered.send(()).unwrap();
            hook.resume.recv().unwrap();
        }
        #[derive(serde::Serialize)]
        struct Persisted {
            keys: HashMap<String, ApiKey>,
            mcp_tokens: HashMap<String, McpToken>,
        }
        let data = Persisted {
            keys: self
                .keys
                .read()
                .map_err(|_| anyhow::anyhow!("FileKeyStore API key lock poisoned"))?
                .clone(),
            mcp_tokens: self
                .mcp_tokens
                .read()
                .map_err(|_| anyhow::anyhow!("FileKeyStore MCP token lock poisoned"))?
                .clone(),
        };
        let json = serde_json::to_string_pretty(&data)?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut tmp_name = self.path.as_os_str().to_os_string();
        tmp_name.push(".tmp");
        let tmp = PathBuf::from(tmp_name);
        std::fs::write(&tmp, json)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

#[async_trait]
impl KeyRepository for FileKeyStore {
    async fn create_key(
        &self,
        user_id: &str,
        label: &str,
        expires_in: u64,
        public_key_pem: Option<String>,
    ) -> anyhow::Result<(String, String)> {
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
        let previous = self
            .keys
            .write()
            .map_err(|_| anyhow::anyhow!("FileKeyStore API key lock poisoned"))?
            .insert(key_id.clone(), api_key);
        if let Err(error) = self.persist() {
            let mut keys = self.keys.write().map_err(|_| {
                anyhow::anyhow!(
                    "FileKeyStore persist failed and API key rollback lock was poisoned: {error}"
                )
            })?;
            if keys.get(&key_id) == Some(&inserted) {
                if let Some(previous) = previous {
                    keys.insert(key_id, previous);
                } else {
                    keys.remove(&key_id);
                }
            }
            return Err(error.context("FileKeyStore persist failed"));
        }
        Ok((key_id, secret))
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
        let previous = {
            let mut keys = self
                .keys
                .write()
                .map_err(|_| anyhow::anyhow!("FileKeyStore API key lock poisoned"))?;
            let Some(key) = keys.get_mut(key_id) else {
                return Ok(false);
            };
            if key.user_id != user_id {
                return Ok(false);
            }
            key.public_key_pem.replace(public_key_pem.clone())
        };
        if let Err(error) = self.persist() {
            let mut keys = self.keys.write().map_err(|_| {
                anyhow::anyhow!(
                    "FileKeyStore public key persist failed and rollback lock was poisoned: {error}"
                )
            })?;
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

    async fn get_key(&self, key_id: &str) -> Option<ApiKey> {
        get_key_in(&self.keys, key_id)
    }

    async fn decrypt_secret(&self, key_id: &str) -> Option<String> {
        let cipher = self.cipher.as_deref()?;
        let (secret_hash, blob) = {
            let keys = self.keys.read().unwrap();
            let key = keys.get(key_id)?;
            (key.secret_hash.clone(), key.secret_encrypted.clone()?)
        };
        let (secret, rewrapped) = decrypt_verified_secret(cipher, key_id, &secret_hash, &blob)?;
        if let Some(rewrapped) = rewrapped {
            let _mutation_guard = self.mutation_lock.lock().ok()?;
            match replace_or_accept_rewrapped_envelope(
                &self.keys,
                cipher,
                key_id,
                &secret_hash,
                &secret,
                &blob,
                rewrapped.clone(),
            )? {
                EnvelopeUpdate::Replaced => {
                    if self.persist().is_err() {
                        let _ = compare_and_swap_envelope(&self.keys, key_id, &rewrapped, blob);
                        tracing::warn!("FileKeyStore legacy secret rewrap persist failed");
                        return None;
                    }
                }
                EnvelopeUpdate::AlreadyRewrapped => {}
            }
        }
        Some(secret)
    }

    async fn resolve_credentials(
        &self,
        access_key: &str,
        secret_key: &str,
    ) -> Option<(String, Option<String>)> {
        resolve_credentials_in(&self.keys, access_key, secret_key)
    }

    async fn list_for_user(&self, user_id: &str) -> Vec<ApiKey> {
        list_for_user_in(&self.keys, user_id)
    }

    async fn delete_key(&self, key_id: &str, user_id: &str) -> bool {
        let Ok(_mutation_guard) = self.mutation_lock.lock() else {
            tracing::warn!("FileKeyStore mutation lock poisoned");
            return false;
        };
        let removed = {
            let mut keys = self.keys.write().unwrap();
            let Some(key) = keys.get(key_id) else {
                return false;
            };
            if key.user_id != user_id {
                return false;
            }
            keys.remove(key_id).expect("key existence checked")
        };
        if self.persist().is_err() {
            self.keys
                .write()
                .unwrap()
                .entry(key_id.to_string())
                .or_insert(removed);
            tracing::warn!("FileKeyStore key deletion persist failed");
            return false;
        }
        true
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
        let inserted = mcp.clone();
        let previous = self
            .mcp_tokens
            .write()
            .map_err(|_| anyhow::anyhow!("FileKeyStore MCP token lock poisoned"))?
            .insert(token_hash.clone(), mcp);
        if let Err(error) = self.persist() {
            let mut tokens = self.mcp_tokens.write().map_err(|_| {
                anyhow::anyhow!(
                    "FileKeyStore MCP token persist failed and rollback lock was poisoned: {error}"
                )
            })?;
            if tokens.get(&token_hash) == Some(&inserted) {
                if let Some(previous) = previous {
                    tokens.insert(token_hash, previous);
                } else {
                    tokens.remove(&token_hash);
                }
            }
            return Err(error.context("FileKeyStore MCP token creation persist failed"));
        }
        Ok((token, inserted))
    }

    async fn resolve_mcp_token(&self, token: &str) -> Option<String> {
        let hash = sha256_hash(token);
        let tokens = self.mcp_tokens.read().unwrap();
        let t = tokens.get(&hash)?;
        if is_expired(t.expires_at.as_deref()) {
            return None;
        }
        Some(t.user_id.clone())
    }

    async fn list_mcp_tokens(&self, user_id: &str) -> Vec<McpToken> {
        self.mcp_tokens
            .read()
            .unwrap()
            .values()
            .filter(|t| t.user_id == user_id)
            .cloned()
            .collect()
    }

    async fn delete_mcp_token(&self, token_hash: &str, user_id: &str) -> bool {
        let Ok(_mutation_guard) = self.mutation_lock.lock() else {
            tracing::warn!("FileKeyStore mutation lock poisoned");
            return false;
        };
        let removed = {
            let mut tokens = self.mcp_tokens.write().unwrap();
            let Some(token) = tokens.get(token_hash) else {
                return false;
            };
            if token.user_id != user_id {
                return false;
            }
            tokens.remove(token_hash).expect("token existence checked")
        };
        if self.persist().is_err() {
            self.mcp_tokens
                .write()
                .unwrap()
                .entry(token_hash.to_string())
                .or_insert(removed);
            tracing::warn!("FileKeyStore MCP token deletion persist failed");
            return false;
        }
        true
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

async fn fetch_key(db: &DatabaseConnection, key_id: &str) -> Option<ApiKey> {
    api_key::Entity::find()
        .filter(api_key::Column::KeyId.eq(key_id.to_string()))
        .one(db)
        .await
        .ok()
        .flatten()
        .map(Into::into)
}

#[async_trait]
impl KeyRepository for PostgresKeyStore {
    async fn create_key(
        &self,
        user_id: &str,
        label: &str,
        expires_in: u64,
        public_key_pem: Option<String>,
    ) -> anyhow::Result<(String, String)> {
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
        model
            .insert(&self.db)
            .await
            .context("Postgres API key insert failed")?;
        Ok((api_key.key_id, secret))
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
        Ok(result.rows_affected == 1)
    }

    async fn get_key(&self, key_id: &str) -> Option<ApiKey> {
        fetch_key(&self.db, key_id).await
    }

    async fn decrypt_secret(&self, key_id: &str) -> Option<String> {
        let cipher = self.cipher.as_deref()?;
        let key = fetch_key(&self.db, key_id).await?;
        let blob = key.secret_encrypted?;
        let (secret, rewrapped) = decrypt_verified_secret(cipher, key_id, &key.secret_hash, &blob)?;
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
                Ok(update) => {
                    tracing::warn!(
                        key_id = key_id,
                        rows_affected = update.rows_affected,
                        "Postgres legacy secret rewrap updated multiple rows"
                    );
                    return None;
                }
                Err(error) => {
                    tracing::warn!(
                        key_id = key_id,
                        "Postgres legacy secret rewrap failed; checking current envelope: {error}"
                    );
                    true
                }
            };
            if reread {
                let current = fetch_key(&self.db, key_id).await?;
                if !key_has_matching_v2_secret(cipher, &current, key_id, &key.secret_hash, &secret)
                {
                    return None;
                }
            }
        }
        Some(secret)
    }

    async fn resolve_credentials(
        &self,
        access_key: &str,
        secret_key: &str,
    ) -> Option<(String, Option<String>)> {
        let key = fetch_key(&self.db, access_key).await?;
        if key.secret_hash != sha256_hash(secret_key) {
            return None;
        }
        if is_expired(key.expires_at.as_deref()) {
            return None;
        }
        Some((key.user_id, key.public_key_pem))
    }

    async fn list_for_user(&self, user_id: &str) -> Vec<ApiKey> {
        match api_key::Entity::find()
            .filter(api_key::Column::UserId.eq(user_id.to_string()))
            .order_by_desc(api_key::Column::CreatedAt)
            .all(&self.db)
            .await
        {
            Ok(rows) => rows
                .into_iter()
                .map(|m| {
                    let mut k: ApiKey = m.into();
                    k.secret_hash = String::new();
                    k.secret_encrypted = None;
                    k
                })
                .collect(),
            Err(e) => {
                tracing::warn!("list_for_user failed: {e}");
                Vec::new()
            }
        }
    }

    async fn delete_key(&self, key_id: &str, user_id: &str) -> bool {
        let result = api_key::Entity::delete_many()
            .filter(api_key::Column::KeyId.eq(key_id.to_string()))
            .filter(api_key::Column::UserId.eq(user_id.to_string()))
            .exec(&self.db)
            .await;
        matches!(result, Ok(r) if r.rows_affected == 1)
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

    async fn resolve_mcp_token(&self, token: &str) -> Option<String> {
        let hash = sha256_hash(token);
        let row = mcp_token::Entity::find()
            .filter(mcp_token::Column::TokenHash.eq(hash))
            .one(&self.db)
            .await
            .ok()?;
        let row = row?;
        if is_expired(row.expires_at.as_ref().map(|e| e.to_string()).as_deref()) {
            return None;
        }
        Some(row.user_id)
    }

    async fn list_mcp_tokens(&self, user_id: &str) -> Vec<McpToken> {
        match mcp_token::Entity::find()
            .filter(mcp_token::Column::UserId.eq(user_id.to_string()))
            .order_by_desc(mcp_token::Column::CreatedAt)
            .all(&self.db)
            .await
        {
            Ok(rows) => rows
                .into_iter()
                .map(|m| McpToken {
                    token_hash: m.token_hash,
                    user_id: m.user_id,
                    label: m.label,
                    created_at: m.created_at.to_string(),
                    expires_at: m.expires_at.map(|e| e.to_string()),
                })
                .collect(),
            Err(e) => {
                tracing::warn!("list_mcp_tokens failed: {e}");
                Vec::new()
            }
        }
    }

    async fn delete_mcp_token(&self, token_hash: &str, user_id: &str) -> bool {
        let result = mcp_token::Entity::delete_many()
            .filter(mcp_token::Column::TokenHash.eq(token_hash.to_string()))
            .filter(mcp_token::Column::UserId.eq(user_id.to_string()))
            .exec(&self.db)
            .await;
        matches!(result, Ok(r) if r.rows_affected == 1)
    }
}

/// Load a persisted FileKeyStore payload (keys + mcp_tokens), tolerating the
/// legacy keys-only JSON shape.
fn load_file_store(path: &PathBuf) -> (HashMap<String, ApiKey>, HashMap<String, McpToken>) {
    #[derive(serde::Deserialize)]
    struct Persisted {
        keys: Option<HashMap<String, ApiKey>>,
        mcp_tokens: Option<HashMap<String, McpToken>>,
    }
    let Some(s) = std::fs::read_to_string(path).ok() else {
        return (HashMap::new(), HashMap::new());
    };
    if let Ok(data) = serde_json::from_str::<Persisted>(&s) {
        return (
            data.keys.unwrap_or_default(),
            data.mcp_tokens.unwrap_or_default(),
        );
    }
    // Legacy shape: bare keys map.
    let keys: HashMap<String, ApiKey> = serde_json::from_str(&s).unwrap_or_default();
    (keys, HashMap::new())
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
    use rand::rngs::OsRng;
    use rsa::pkcs8::{EncodePublicKey, LineEnding};

    const TEST_PUBLIC_KEY_PEM: &str = include_str!("../../../tests/fixtures/pii/crypto/pub.pem");
    const TEST_CERTIFICATE_PEM: &str = include_str!("../../../tests/fixtures/pii/crypto/cert.pem");

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

    fn test_cipher() -> Arc<SecretCipher> {
        Arc::new(SecretCipher::new(Arc::new(LocalKeyWrapping::with_kek(
            [7u8; 32],
        ))))
    }

    fn failing_cipher() -> Arc<SecretCipher> {
        Arc::new(SecretCipher::new(Arc::new(FailingKeyWrapping)))
    }

    fn generated_public_key_pem(bits: usize) -> String {
        rsa::RsaPrivateKey::new(&mut OsRng, bits)
            .unwrap()
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap()
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
        assert!(canonicalize_public_key_pem(&generated_public_key_pem(1024)).is_err());
        assert!(canonicalize_public_key_pem(&generated_public_key_pem(4096)).is_ok());
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
        let stored = store.list_for_user("u1").await;
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
        let (key_id, secret) = store.create_key("u1", "test", 0, None).await.unwrap();
        let (uid, pk) = store
            .resolve_credentials(&key_id, &secret)
            .await
            .expect("valid credentials should resolve");
        assert_eq!(uid, "u1");
        assert!(pk.is_none());
        assert!(
            store
                .get_key(&key_id)
                .await
                .unwrap()
                .secret_encrypted
                .is_none(),
            "a store without a cipher may create a hash-only key"
        );
        assert!(store.resolve_credentials(&key_id, "nope").await.is_none());
        assert!(
            store
                .resolve_credentials("missing", &secret)
                .await
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

        assert_eq!(result, Some(EnvelopeUpdate::AlreadyRewrapped));
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

        assert_eq!(result, None);
        assert_eq!(
            keys.read().unwrap()[key_id].secret_encrypted.as_deref(),
            Some(current_v2.as_str())
        );
    }

    #[tokio::test]
    async fn in_memory_create_key_returns_lock_error() {
        let store = Arc::new(KeyStore::new());
        let poisoner = store.clone();
        let _ = std::thread::spawn(move || {
            let _keys = poisoner.keys.write().unwrap();
            panic!("poison API key lock");
        })
        .join();

        let error = store
            .create_key("u1", "lock-error", 0, None)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("lock poisoned"));
    }

    #[tokio::test]
    async fn newly_generated_encrypted_secret_uses_v2() {
        let cipher = test_cipher();
        let store = KeyStore::with_cipher(cipher);
        let (key_id, secret) = store.create_key("u1", "v2", 0, None).await.unwrap();

        let key = store.get_key(&key_id).await.expect("key exists");
        assert!(
            key.secret_encrypted
                .as_deref()
                .is_some_and(|blob| blob.starts_with("v2:"))
        );
        assert_eq!(
            store.decrypt_secret(&key_id).await.as_deref(),
            Some(secret.as_str())
        );
    }

    #[tokio::test]
    async fn in_memory_v1_secret_is_verified_and_rewrapped() {
        let cipher = test_cipher();
        let store = KeyStore::with_cipher(cipher.clone());
        let (key_id, secret) = store.create_key("u1", "legacy", 0, None).await.unwrap();
        let legacy = cipher.encrypt_v1(&secret).unwrap();
        store
            .keys
            .write()
            .unwrap()
            .get_mut(&key_id)
            .unwrap()
            .secret_encrypted = Some(legacy);

        assert_eq!(
            store.decrypt_secret(&key_id).await.as_deref(),
            Some(secret.as_str())
        );
        let rewrapped = store
            .get_key(&key_id)
            .await
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
        let (key_id, secret) = store.create_key("u1", "legacy", 0, None).await.unwrap();
        let legacy = cipher.encrypt_v1(&secret).unwrap();
        {
            let mut keys = store.keys.write().unwrap();
            let key = keys.get_mut(&key_id).unwrap();
            key.secret_hash = sha256_hash("different-secret");
            key.secret_encrypted = Some(legacy.clone());
        }

        assert_eq!(store.decrypt_secret(&key_id).await, None);
        assert_eq!(
            store.get_key(&key_id).await.unwrap().secret_encrypted,
            Some(legacy)
        );
    }

    #[tokio::test]
    async fn swapped_v2_store_envelopes_are_rejected() {
        let cipher = test_cipher();
        let store = KeyStore::with_cipher(cipher);
        let (key_a, _) = store.create_key("u1", "a", 0, None).await.unwrap();
        let (key_b, _) = store.create_key("u1", "b", 0, None).await.unwrap();
        {
            let mut keys = store.keys.write().unwrap();
            let envelope_a = keys[&key_a].secret_encrypted.clone();
            let envelope_b = keys[&key_b].secret_encrypted.clone();
            keys.get_mut(&key_a).unwrap().secret_encrypted = envelope_b;
            keys.get_mut(&key_b).unwrap().secret_encrypted = envelope_a;
        }

        assert_eq!(store.decrypt_secret(&key_a).await, None);
        assert_eq!(store.decrypt_secret(&key_b).await, None);
    }

    #[tokio::test]
    async fn in_memory_expiry_rejects() {
        let store = KeyStore::new();
        let (key_id, secret) = store.create_key("u1", "exp", 1, None).await.unwrap();
        // expiry is now+1s; sleep 1.2s to force it
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        assert!(store.resolve_credentials(&key_id, &secret).await.is_none());
    }

    #[tokio::test]
    async fn in_memory_public_key_and_delete() {
        let store = KeyStore::new();
        let (key_id, _secret) = store.create_key("u1", "enc", 0, None).await.unwrap();
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
        let key = store.get_key(&key_id).await.expect("key exists");
        assert_eq!(
            key.public_key_pem.as_deref(),
            Some(TEST_PUBLIC_KEY_PEM.trim())
        );
        let keys = store.list_for_user("u1").await;
        assert_eq!(keys.len(), 1);
        assert!(keys[0].secret_hash.is_empty());
        assert!(store.delete_key(&key_id, "u1").await);
        assert!(store.get_key(&key_id).await.is_none());
    }

    fn temp_keys_file() -> PathBuf {
        let path = std::env::temp_dir().join(format!("s4-file-keys-{}.json", Uuid::new_v4()));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[tokio::test]
    async fn file_key_store_persists_across_restarts() {
        let path = temp_keys_file();
        let store = FileKeyStore::new(path.clone());
        let (key_id, secret) = store.create_key("u1", "persist", 0, None).await.unwrap();
        drop(store);

        // A fresh store on the same path must see the same key.
        let reloaded = FileKeyStore::new(path.clone());
        let (uid, _pk) = reloaded
            .resolve_credentials(&key_id, &secret)
            .await
            .expect("credentials survive a restart");
        assert_eq!(uid, "u1");
        assert!(reloaded.list_for_user("u1").await.len() == 1);
        assert!(reloaded.delete_key(&key_id, "u1").await);
        drop(reloaded);

        let empty = FileKeyStore::new(path);
        assert!(empty.get_key(&key_id).await.is_none());
    }

    #[tokio::test]
    async fn file_key_store_rolls_back_key_when_persist_fails() {
        let blocking_parent = temp_keys_file();
        std::fs::write(&blocking_parent, "not a directory").unwrap();
        let store = FileKeyStore::new(blocking_parent.join("keys.json"));

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
        let parent = std::env::temp_dir().join(format!("s4-file-keys-{}", Uuid::new_v4()));
        let durable_parent = parent.with_extension("durable");
        std::fs::create_dir_all(&parent).unwrap();
        let path = parent.join("keys.json");
        let store = FileKeyStore::new(path.clone());
        let (key_id, _) = store
            .create_key(
                "u1",
                "persisted-public-key",
                0,
                Some(TEST_PUBLIC_KEY_PEM.to_string()),
            )
            .await
            .unwrap();
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
                .public_key_pem
                .as_deref(),
            Some(TEST_PUBLIC_KEY_PEM.trim())
        );
        std::fs::remove_file(&parent).unwrap();
        std::fs::rename(&durable_parent, &parent).unwrap();
        drop(store);

        let restarted = FileKeyStore::new(path);
        assert_eq!(
            restarted
                .get_key(&key_id)
                .await
                .unwrap()
                .public_key_pem
                .as_deref(),
            Some(TEST_PUBLIC_KEY_PEM.trim())
        );
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[tokio::test]
    async fn file_key_store_rolls_back_key_delete_when_persist_fails() {
        let parent = std::env::temp_dir().join(format!("s4-file-keys-{}", Uuid::new_v4()));
        let durable_parent = parent.with_extension("durable");
        std::fs::create_dir_all(&parent).unwrap();
        let path = parent.join("keys.json");
        let store = FileKeyStore::new(path.clone());
        let (key_id, secret) = store.create_key("u1", "delete", 0, None).await.unwrap();
        std::fs::rename(&parent, &durable_parent).unwrap();
        std::fs::write(&parent, "not a directory").unwrap();

        assert!(!store.delete_key(&key_id, "u1").await);
        assert!(store.resolve_credentials(&key_id, &secret).await.is_some());
        std::fs::remove_file(&parent).unwrap();
        std::fs::rename(&durable_parent, &parent).unwrap();
        drop(store);

        let restarted = FileKeyStore::new(path);
        assert!(
            restarted
                .resolve_credentials(&key_id, &secret)
                .await
                .is_some(),
            "failed revocation must not be acknowledged only in memory"
        );
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[tokio::test]
    async fn file_key_store_rolls_back_mcp_mutations_when_persist_fails() {
        let parent = std::env::temp_dir().join(format!("s4-file-keys-{}", Uuid::new_v4()));
        let durable_parent = parent.with_extension("durable");
        std::fs::create_dir_all(&parent).unwrap();
        let path = parent.join("keys.json");
        let store = FileKeyStore::new(path.clone());
        let persisted_token = store
            .create_mcp_token("u1", "persisted", 0)
            .await
            .unwrap()
            .0;
        let persisted_hash = sha256_hash(&persisted_token);
        std::fs::rename(&parent, &durable_parent).unwrap();
        std::fs::write(&parent, "not a directory").unwrap();

        assert!(store.create_mcp_token("u1", "rejected", 0).await.is_err());
        assert!(!store.delete_mcp_token(&persisted_hash, "u1").await);
        assert_eq!(
            store.resolve_mcp_token(&persisted_token).await.as_deref(),
            Some("u1")
        );
        std::fs::remove_file(&parent).unwrap();
        std::fs::rename(&durable_parent, &parent).unwrap();
        drop(store);

        let restarted = FileKeyStore::new(path);
        assert_eq!(
            restarted
                .resolve_mcp_token(&persisted_token)
                .await
                .as_deref(),
            Some("u1")
        );
        assert_eq!(restarted.list_mcp_tokens("u1").await.len(), 1);
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn file_key_store_serializes_public_key_set_before_successful_delete() {
        let path = temp_keys_file();
        let store = Arc::new(FileKeyStore::new(path.clone()));
        let (key_id, secret) = store.create_key("u1", "race", 0, None).await.unwrap();
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
        assert!(delete_task.await.unwrap());
        assert!(store.resolve_credentials(&key_id, &secret).await.is_none());
        drop(store);

        let restarted = FileKeyStore::new(path.clone());
        assert!(
            restarted
                .resolve_credentials(&key_id, &secret)
                .await
                .is_none(),
            "a successfully revoked key must never reappear after restart"
        );
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn file_key_store_serializes_api_key_and_mcp_creation_snapshots() {
        let path = temp_keys_file();
        let store = Arc::new(FileKeyStore::new(path.clone()));
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
        let (key_id, secret) = key_task.await.unwrap().unwrap();
        let token = mcp_task.await.unwrap().unwrap().0;
        drop(store);

        let restarted = FileKeyStore::new(path.clone());
        assert!(
            restarted
                .resolve_credentials(&key_id, &secret)
                .await
                .is_some()
        );
        assert_eq!(
            restarted.resolve_mcp_token(&token).await.as_deref(),
            Some("u1")
        );
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn file_key_store_serializes_secret_rewrap_and_mcp_creation() {
        let path = temp_keys_file();
        let cipher = test_cipher();
        let store = Arc::new(FileKeyStore::with_cipher(path.clone(), cipher.clone()));
        let (key_id, secret) = store.create_key("u1", "legacy", 0, None).await.unwrap();
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
        assert_eq!(rewrap_task.await.unwrap().as_deref(), Some(secret.as_str()));
        let token = mcp_task.await.unwrap().unwrap().0;
        drop(store);

        let restarted = FileKeyStore::with_cipher(path.clone(), cipher);
        assert_eq!(
            restarted.decrypt_secret(&key_id).await.as_deref(),
            Some(secret.as_str())
        );
        assert_eq!(
            restarted.resolve_mcp_token(&token).await.as_deref(),
            Some("u1")
        );
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn file_key_store_mcp_delete_does_not_self_deadlock_and_persists() {
        let path = temp_keys_file();
        let store = FileKeyStore::new(path.clone());
        let token = store.create_mcp_token("u1", "delete", 0).await.unwrap().0;
        let token_hash = sha256_hash(&token);

        assert!(
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                store.delete_mcp_token(&token_hash, "u1")
            )
            .await
            .expect("MCP delete must not deadlock")
        );
        drop(store);

        let restarted = FileKeyStore::new(path.clone());
        assert!(restarted.resolve_mcp_token(&token).await.is_none());
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn configured_cipher_failure_does_not_create_or_persist_file_key() {
        let path = temp_keys_file();
        let store = FileKeyStore::with_cipher(path.clone(), failing_cipher());

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
            .connect_lazy("postgresql://postgres:postgres@127.0.0.1:1/s4")
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
            .connect_lazy("postgresql://postgres:postgres@127.0.0.1:1/s4")
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
    async fn postgres_configured_cipher_failure_prevents_insert() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(50))
            .connect_lazy("postgresql://postgres:postgres@127.0.0.1:1/s4")
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
        let store = FileKeyStore::new(path.clone());
        let (key_id, _secret) = store.create_key("u1", "enc", 3600, None).await.unwrap();
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

        let reloaded = FileKeyStore::new(path);
        let key = reloaded.get_key(&key_id).await.expect("key exists");
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
        let store = FileKeyStore::with_cipher(path.clone(), cipher.clone());
        let (key_id, secret) = store.create_key("u1", "legacy", 0, None).await.unwrap();
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
            store.decrypt_secret(&key_id).await.as_deref(),
            Some(secret.as_str())
        );
        drop(store);

        let reloaded = FileKeyStore::with_cipher(path.clone(), cipher);
        let envelope = reloaded
            .get_key(&key_id)
            .await
            .unwrap()
            .secret_encrypted
            .unwrap();
        assert!(envelope.starts_with("v2:"));
        assert_eq!(
            reloaded.decrypt_secret(&key_id).await.as_deref(),
            Some(secret.as_str())
        );
        let _ = std::fs::remove_file(path);
    }
}
