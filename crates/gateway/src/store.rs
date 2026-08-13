use async_trait::async_trait;
use sea_orm::sea_query::Expr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, Set,
    SqlxPostgresConnector,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

use crate::entity::api_key;
use crate::entity::mcp_token;
use crate::key_cipher::SecretCipher;

#[derive(Debug, Clone)]
pub struct StoredObject {
    pub data: Vec<u8>,
    pub content_type: String,
    pub etag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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

    pub fn put(&self, bucket: &str, key: &str, data: Vec<u8>, content_type: &str) -> StoredObject {
        let etag = format!("\"{}\"", Uuid::new_v4());
        let obj = StoredObject {
            data,
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
        self.get(bucket, key)
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
    /// Create a key and return the plaintext `(key_id, secret)`. The secret
    /// is hashed (SHA-256) before storage and never recoverable afterwards.
    async fn create_key(
        &self,
        user_id: &str,
        label: &str,
        expires_in: u64,
        public_key_pem: Option<String>,
    ) -> (String, String);

    async fn set_public_key(&self, key_id: &str, user_id: &str, public_key_pem: &str) -> bool;

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
    async fn create_mcp_token(&self, user_id: &str, label: &str, expires_in: u64) -> String;

    /// Validate an MCP bearer token and return the owning user id.
    async fn resolve_mcp_token(&self, token: &str) -> Option<String>;

    /// MCP tokens for a user (hashes only).
    async fn list_mcp_tokens(&self, user_id: &str) -> Vec<McpToken>;

    async fn delete_mcp_token(&self, token_hash: &str, user_id: &str) -> bool;
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
) -> (ApiKey, String) {
    let key_id = format!("s4_{}", Uuid::new_v4().to_string().replace('-', ""));
    let secret = format!("s4s_{}", Uuid::new_v4().to_string().replace('-', ""));
    let secret_hash = sha256_hash(&secret);
    let secret_encrypted = cipher.and_then(|c| c.encrypt(&secret).ok()).or_else(|| {
        tracing::warn!("secret encryption unavailable; key {key_id} will not support SigV4");
        None
    });
    let now = chrono_now().parse::<u64>().unwrap_or(0);
    let expires_at = if expires_in > 0 {
        Some(format!("{}", now + expires_in))
    } else {
        None
    };
    let api_key = build_api_key(
        &key_id,
        user_id,
        label,
        secret_hash,
        secret_encrypted,
        chrono_now(),
        expires_at,
        public_key_pem,
    );
    (api_key, secret)
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
    ) -> (String, String) {
        let (api_key, secret) = generate_api_key(
            user_id,
            label,
            expires_in,
            public_key_pem,
            self.cipher.as_deref(),
        );
        let key_id = api_key.key_id.clone();
        self.keys.write().unwrap().insert(key_id.clone(), api_key);
        (key_id, secret)
    }

    async fn set_public_key(&self, key_id: &str, user_id: &str, public_key_pem: &str) -> bool {
        set_public_key_in(&self.keys, key_id, user_id, public_key_pem)
    }

    async fn get_key(&self, key_id: &str) -> Option<ApiKey> {
        get_key_in(&self.keys, key_id)
    }

    async fn decrypt_secret(&self, key_id: &str) -> Option<String> {
        let cipher = self.cipher.as_deref()?;
        let blob = self
            .keys
            .read()
            .unwrap()
            .get(key_id)?
            .secret_encrypted
            .clone()?;
        cipher.decrypt(&blob)
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

    async fn create_mcp_token(&self, user_id: &str, label: &str, expires_in: u64) -> String {
        let token = format!("s4m_{}", Uuid::new_v4().to_string().replace('-', ""));
        let now = chrono_now().parse::<u64>().unwrap_or(0);
        let token_hash = sha256_hash(&token);
        let mcp = McpToken {
            token_hash: token_hash.clone(),
            user_id: user_id.to_string(),
            label: label.to_string(),
            created_at: chrono_now(),
            expires_at: if expires_in > 0 {
                Some(format!("{}", now + expires_in))
            } else {
                None
            },
        };
        self.mcp_tokens.write().unwrap().insert(token_hash, mcp);
        token
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
    path: PathBuf,
    cipher: Option<Arc<SecretCipher>>,
}

impl FileKeyStore {
    pub fn new(path: PathBuf) -> Self {
        let (keys, mcp_tokens) = load_file_store(&path);
        Self {
            keys: RwLock::new(keys),
            mcp_tokens: RwLock::new(mcp_tokens),
            path,
            cipher: None,
        }
    }

    pub fn with_cipher(path: PathBuf, cipher: Arc<SecretCipher>) -> Self {
        let (keys, mcp_tokens) = load_file_store(&path);
        Self {
            keys: RwLock::new(keys),
            mcp_tokens: RwLock::new(mcp_tokens),
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
        #[derive(serde::Serialize)]
        struct Persisted {
            keys: HashMap<String, ApiKey>,
            mcp_tokens: HashMap<String, McpToken>,
        }
        let data = Persisted {
            keys: self.keys.read().unwrap().clone(),
            mcp_tokens: self.mcp_tokens.read().unwrap().clone(),
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
    ) -> (String, String) {
        let (api_key, secret) = generate_api_key(
            user_id,
            label,
            expires_in,
            public_key_pem,
            self.cipher.as_deref(),
        );
        let key_id = api_key.key_id.clone();
        self.keys.write().unwrap().insert(key_id.clone(), api_key);
        self.persist()
            .unwrap_or_else(|e| tracing::warn!("FileKeyStore persist failed: {e}"));
        (key_id, secret)
    }

    async fn set_public_key(&self, key_id: &str, user_id: &str, public_key_pem: &str) -> bool {
        let ok = set_public_key_in(&self.keys, key_id, user_id, public_key_pem);
        if ok {
            self.persist()
                .unwrap_or_else(|e| tracing::warn!("FileKeyStore persist failed: {e}"));
        }
        ok
    }

    async fn get_key(&self, key_id: &str) -> Option<ApiKey> {
        get_key_in(&self.keys, key_id)
    }

    async fn decrypt_secret(&self, key_id: &str) -> Option<String> {
        let cipher = self.cipher.as_deref()?;
        let blob = self
            .keys
            .read()
            .unwrap()
            .get(key_id)?
            .secret_encrypted
            .clone()?;
        cipher.decrypt(&blob)
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
        let ok = delete_key_in(&self.keys, key_id, user_id);
        if ok {
            self.persist()
                .unwrap_or_else(|e| tracing::warn!("FileKeyStore persist failed: {e}"));
        }
        ok
    }

    async fn create_mcp_token(&self, user_id: &str, label: &str, expires_in: u64) -> String {
        let token = format!("s4m_{}", Uuid::new_v4().to_string().replace('-', ""));
        let now = chrono_now().parse::<u64>().unwrap_or(0);
        let token_hash = sha256_hash(&token);
        let mcp = McpToken {
            token_hash: token_hash.clone(),
            user_id: user_id.to_string(),
            label: label.to_string(),
            created_at: chrono_now(),
            expires_at: if expires_in > 0 {
                Some(format!("{}", now + expires_in))
            } else {
                None
            },
        };
        self.mcp_tokens.write().unwrap().insert(token_hash, mcp);
        self.persist()
            .unwrap_or_else(|e| tracing::warn!("FileKeyStore persist failed: {e}"));
        token
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
            self.persist()
                .unwrap_or_else(|e| tracing::warn!("FileKeyStore persist failed: {e}"));
            return true;
        }
        false
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
    ) -> (String, String) {
        let (api_key, secret) = generate_api_key(
            user_id,
            label,
            expires_in,
            public_key_pem,
            self.cipher.as_deref(),
        );
        let model = api_key::ActiveModel {
            user_id: Set(api_key.user_id.clone()),
            key_id: Set(api_key.key_id.clone()),
            secret_hash: Set(api_key.secret_hash.clone()),
            secret_encrypted: Set(api_key.secret_encrypted.clone()),
            label: Set(api_key.label.clone()),
            expires_at: Set(api_key.expires_at.as_ref().and_then(|e| e.parse().ok())),
            public_key_pem: Set(api_key.public_key_pem.clone()),
            ..Default::default()
        };
        let _ = model.insert(&self.db).await;
        (api_key.key_id, secret)
    }

    async fn set_public_key(&self, key_id: &str, user_id: &str, public_key_pem: &str) -> bool {
        let result = api_key::Entity::update_many()
            .col_expr(
                api_key::Column::PublicKeyPem,
                Expr::value(Some(public_key_pem.to_string())),
            )
            .filter(api_key::Column::KeyId.eq(key_id.to_string()))
            .filter(api_key::Column::UserId.eq(user_id.to_string()))
            .exec(&self.db)
            .await;
        matches!(result, Ok(r) if r.rows_affected == 1)
    }

    async fn get_key(&self, key_id: &str) -> Option<ApiKey> {
        fetch_key(&self.db, key_id).await
    }

    async fn decrypt_secret(&self, key_id: &str) -> Option<String> {
        let cipher = self.cipher.as_deref()?;
        let blob = fetch_key(&self.db, key_id).await?.secret_encrypted?;
        cipher.decrypt(&blob)
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

    async fn create_mcp_token(&self, user_id: &str, label: &str, expires_in: u64) -> String {
        let token = format!("s4m_{}", Uuid::new_v4().to_string().replace('-', ""));
        let now = chrono_now().parse::<u64>().unwrap_or(0);
        let token_hash = sha256_hash(&token);
        let model = mcp_token::ActiveModel {
            user_id: Set(user_id.to_string()),
            token_hash: Set(token_hash),
            label: Set(label.to_string()),
            expires_at: Set(if expires_in > 0 {
                Some((now + expires_in) as i64)
            } else {
                None
            }),
            ..Default::default()
        };
        let _ = model.insert(&self.db).await;
        token
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
        if exp.parse::<u64>().is_ok_and(|ts| now >= ts) {
            return true;
        }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    #[serde(default)]
    pub backend_type: String, // "aws_role", "s3_compatible", or empty (none)
    #[serde(default)]
    pub role_arn: String,
    #[serde(default)]
    pub external_id: String,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub access_key: String,
    #[serde(default)]
    pub secret_key: String,
    #[serde(default)]
    pub region: String,
}

impl BackendConfig {
    pub fn is_configured(&self) -> bool {
        !self.backend_type.is_empty()
    }
}

#[derive(Debug)]
pub struct BackendRegistry {
    backends: RwLock<HashMap<String, BackendConfig>>,
}

impl BackendRegistry {
    pub fn new() -> Self {
        Self {
            backends: RwLock::new(HashMap::new()),
        }
    }

    pub fn set(&self, user_id: &str, config: BackendConfig) {
        self.backends
            .write()
            .unwrap()
            .insert(user_id.to_string(), config);
    }

    pub fn get(&self, user_id: &str) -> Option<BackendConfig> {
        self.backends.read().unwrap().get(user_id).cloned()
    }

    pub fn generate_external_id(&self, user_id: &str) -> String {
        format!("s4_ext_{}", sha256_hash(user_id))
    }
}

impl Default for BackendRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn in_memory_key_roundtrip() {
        let store = KeyStore::new();
        let (key_id, secret) = store.create_key("u1", "test", 0, None).await;
        let (uid, pk) = store
            .resolve_credentials(&key_id, &secret)
            .await
            .expect("valid credentials should resolve");
        assert_eq!(uid, "u1");
        assert!(pk.is_none());
        assert!(store.resolve_credentials(&key_id, "nope").await.is_none());
        assert!(
            store
                .resolve_credentials("missing", &secret)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn in_memory_expiry_rejects() {
        let store = KeyStore::new();
        let (key_id, secret) = store.create_key("u1", "exp", 1, None).await;
        // expiry is now+1s; sleep 1.2s to force it
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        assert!(store.resolve_credentials(&key_id, &secret).await.is_none());
    }

    #[tokio::test]
    async fn in_memory_public_key_and_delete() {
        let store = KeyStore::new();
        let (key_id, _secret) = store.create_key("u1", "enc", 0, None).await;
        assert!(store.set_public_key(&key_id, "u1", "pem").await);
        assert!(!store.set_public_key(&key_id, "u2", "pem").await);
        let key = store.get_key(&key_id).await.expect("key exists");
        assert_eq!(key.public_key_pem.as_deref(), Some("pem"));
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
        let (key_id, secret) = store.create_key("u1", "persist", 0, None).await;
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
    async fn file_key_store_persists_public_key_and_expiry() {
        let path = temp_keys_file();
        let store = FileKeyStore::new(path.clone());
        let (key_id, _secret) = store.create_key("u1", "enc", 3600, None).await;
        assert!(store.set_public_key(&key_id, "u1", "pem").await);
        assert!(!store.set_public_key(&key_id, "u2", "pem").await);
        drop(store);

        let reloaded = FileKeyStore::new(path);
        let key = reloaded.get_key(&key_id).await.expect("key exists");
        assert_eq!(key.public_key_pem.as_deref(), Some("pem"));
        assert!(key.expires_at.is_some());
    }
}
