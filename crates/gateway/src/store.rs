use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;
use uuid::Uuid;

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
    pub user_id: String,
    pub workspace_id: Option<String>,
    pub label: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub public_key_pem: Option<String>,
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
}

impl KeyStore {
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PostgresKeyStore {
    pool: sqlx::PgPool,
}

impl PostgresKeyStore {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
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
        workspace_id: Option<String>,
    ) -> (String, String);

    async fn set_public_key(&self, key_id: &str, user_id: &str, public_key_pem: &str) -> bool;

    async fn get_key(&self, key_id: &str) -> Option<ApiKey>;

    /// Validate an access key/secret pair and return the owning user id,
    /// the API key's public key PEM, and the workspace id if scoped.
    async fn resolve_credentials(
        &self,
        access_key: &str,
        secret_key: &str,
    ) -> Option<(String, Option<String>, Option<String>)>;

    /// Keys for a user, with the secret hash stripped.
    async fn list_for_user(&self, user_id: &str) -> Vec<ApiKey>;

    async fn delete_key(&self, key_id: &str, user_id: &str) -> bool;
}

#[allow(clippy::too_many_arguments)]
fn build_api_key(
    key_id: &str,
    user_id: &str,
    label: &str,
    secret_hash: String,
    created_at: String,
    expires_at: Option<String>,
    public_key_pem: Option<String>,
    workspace_id: Option<String>,
) -> ApiKey {
    ApiKey {
        key_id: key_id.to_string(),
        secret_hash,
        user_id: user_id.to_string(),
        workspace_id,
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
    workspace_id: Option<String>,
) -> (ApiKey, String) {
    let key_id = format!("s4_{}", Uuid::new_v4().to_string().replace('-', ""));
    let secret = format!("s4s_{}", Uuid::new_v4().to_string().replace('-', ""));
    let secret_hash = sha256_hash(&secret);
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
        chrono_now(),
        expires_at,
        public_key_pem,
        workspace_id,
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
) -> Option<(String, Option<String>, Option<String>)> {
    let keys = keys.read().unwrap();
    let key = keys.get(access_key)?;
    if key.secret_hash != sha256_hash(secret_key) {
        return None;
    }
    if is_expired(key.expires_at.as_deref()) {
        return None;
    }
    Some((
        key.user_id.clone(),
        key.public_key_pem.clone(),
        key.workspace_id.clone(),
    ))
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
                k.created_at.clone(),
                k.expires_at.clone(),
                k.public_key_pem.clone(),
                k.workspace_id.clone(),
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
        workspace_id: Option<String>,
    ) -> (String, String) {
        let (api_key, secret) =
            generate_api_key(user_id, label, expires_in, public_key_pem, workspace_id);
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

    async fn resolve_credentials(
        &self,
        access_key: &str,
        secret_key: &str,
    ) -> Option<(String, Option<String>, Option<String>)> {
        resolve_credentials_in(&self.keys, access_key, secret_key)
    }

    async fn list_for_user(&self, user_id: &str) -> Vec<ApiKey> {
        list_for_user_in(&self.keys, user_id)
    }

    async fn delete_key(&self, key_id: &str, user_id: &str) -> bool {
        delete_key_in(&self.keys, key_id, user_id)
    }
}

#[derive(Debug)]
pub struct FileKeyStore {
    keys: RwLock<HashMap<String, ApiKey>>,
    path: PathBuf,
}

impl FileKeyStore {
    pub fn new(path: PathBuf) -> Self {
        let keys = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        Self {
            keys: RwLock::new(keys),
            path,
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
        let data = self.keys.read().unwrap();
        let json = serde_json::to_string_pretty(&*data)?;
        drop(data);
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
        workspace_id: Option<String>,
    ) -> (String, String) {
        let (api_key, secret) =
            generate_api_key(user_id, label, expires_in, public_key_pem, workspace_id);
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

    async fn resolve_credentials(
        &self,
        access_key: &str,
        secret_key: &str,
    ) -> Option<(String, Option<String>, Option<String>)> {
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
}

#[derive(sqlx::FromRow)]
struct KeyRow {
    key_id: String,
    secret_hash: String,
    user_id: String,
    workspace_id: Option<String>,
    label: String,
    created_at: sqlx::types::chrono::DateTime<sqlx::types::chrono::Utc>,
    expires_at: Option<i64>,
    public_key_pem: Option<String>,
}

impl From<KeyRow> for ApiKey {
    fn from(r: KeyRow) -> Self {
        build_api_key(
            &r.key_id,
            &r.user_id,
            &r.label,
            r.secret_hash,
            r.created_at.timestamp().to_string(),
            r.expires_at.map(|e| e.to_string()),
            r.public_key_pem,
            r.workspace_id,
        )
    }
}

const KEY_COLUMNS: &str =
    "key_id, secret_hash, user_id, workspace_id, label, created_at, expires_at, public_key_pem";

async fn fetch_key(pool: &sqlx::PgPool, key_id: &str) -> Option<ApiKey> {
    sqlx::query_as::<_, KeyRow>(&format!(
        "SELECT {KEY_COLUMNS} FROM api_keys WHERE key_id = $1"
    ))
    .bind(key_id)
    .fetch_optional(pool)
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
        workspace_id: Option<String>,
    ) -> (String, String) {
        let key_id = format!("s4_{}", Uuid::new_v4().to_string().replace('-', ""));
        let secret = format!("s4s_{}", Uuid::new_v4().to_string().replace('-', ""));
        let secret_hash = sha256_hash(&secret);
        let now = chrono_now().parse::<u64>().unwrap_or(0);
        let expires_at = (expires_in > 0).then_some((now + expires_in) as i64);

        let _ = sqlx::query(
            "INSERT INTO api_keys (user_id, workspace_id, key_id, secret_hash, label, expires_at, public_key_pem) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(user_id)
        .bind(&workspace_id)
        .bind(&key_id)
        .bind(&secret_hash)
        .bind(label)
        .bind(expires_at)
        .bind(&public_key_pem)
        .execute(&self.pool)
        .await;
        (key_id, secret)
    }

    async fn set_public_key(&self, key_id: &str, user_id: &str, public_key_pem: &str) -> bool {
        let result = sqlx::query(
            "UPDATE api_keys SET public_key_pem = $3 WHERE key_id = $1 AND user_id = $2",
        )
        .bind(key_id)
        .bind(user_id)
        .bind(public_key_pem)
        .execute(&self.pool)
        .await;
        matches!(result, Ok(r) if r.rows_affected() == 1)
    }

    async fn get_key(&self, key_id: &str) -> Option<ApiKey> {
        fetch_key(&self.pool, key_id).await
    }

    async fn resolve_credentials(
        &self,
        access_key: &str,
        secret_key: &str,
    ) -> Option<(String, Option<String>, Option<String>)> {
        let key = fetch_key(&self.pool, access_key).await?;
        if key.secret_hash != sha256_hash(secret_key) {
            return None;
        }
        if is_expired(key.expires_at.as_deref()) {
            return None;
        }
        Some((key.user_id, key.public_key_pem, key.workspace_id))
    }

    async fn list_for_user(&self, user_id: &str) -> Vec<ApiKey> {
        match sqlx::query_as::<_, KeyRow>(&format!(
            "SELECT {KEY_COLUMNS} FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC"
        ))
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        {
            Ok(rows) => rows
                .into_iter()
                .map(|r| {
                    let mut k: ApiKey = r.into();
                    k.secret_hash = String::new();
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
        let result = sqlx::query("DELETE FROM api_keys WHERE key_id = $1 AND user_id = $2")
            .bind(key_id)
            .bind(user_id)
            .execute(&self.pool)
            .await;
        matches!(result, Ok(r) if r.rows_affected() == 1)
    }
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

fn sha256_hash(s: &str) -> String {
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
        let (key_id, secret) = store.create_key("u1", "test", 0, None, None).await;
        let (uid, pk, _ws) = store
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
        let (key_id, secret) = store.create_key("u1", "exp", 1, None, None).await;
        // expiry is now+1s; sleep 1.2s to force it
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        assert!(store.resolve_credentials(&key_id, &secret).await.is_none());
    }

    #[tokio::test]
    async fn in_memory_public_key_and_delete() {
        let store = KeyStore::new();
        let (key_id, _secret) = store.create_key("u1", "enc", 0, None, None).await;
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
        let (key_id, secret) = store.create_key("u1", "persist", 0, None, None).await;
        drop(store);

        // A fresh store on the same path must see the same key.
        let reloaded = FileKeyStore::new(path.clone());
        let (uid, _pk, _ws) = reloaded
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
        let (key_id, _secret) = store.create_key("u1", "enc", 3600, None, None).await;
        assert!(store.set_public_key(&key_id, "u1", "pem").await);
        assert!(!store.set_public_key(&key_id, "u2", "pem").await);
        drop(store);

        let reloaded = FileKeyStore::new(path);
        let key = reloaded.get_key(&key_id).await.expect("key exists");
        assert_eq!(key.public_key_pem.as_deref(), Some("pem"));
        assert!(key.expires_at.is_some());
    }
}
