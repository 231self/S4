use aws_sdk_s3::Client;
use aws_sdk_s3::config::{Credentials, Region};
use aws_sdk_s3::primitives::ByteStream;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::{delete, get, head, post, put},
};
use s4_gateway::plugin_registry::PluginRegistry;
use s4_gateway::s3_error;
use s4_gateway::service_storage::{ServiceStorage, parse_service_backends};
use s4_gateway::store::{
    BackendConfig, BackendRegistry, FileKeyStore, KeyRepository, KeyStore, MemoryStore,
    PostgresKeyStore,
};
use s4_gateway::{Format, Gateway};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tower_http::cors::CorsLayer;
use tracing::{info, warn};
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;

#[derive(Clone)]
struct WorkspaceCounters {
    write_count: Arc<AtomicU64>,
    read_count: Arc<AtomicU64>,
    bytes_processed: Arc<AtomicU64>,
}

impl WorkspaceCounters {
    fn new() -> Self {
        Self {
            write_count: Arc::new(AtomicU64::new(0)),
            read_count: Arc::new(AtomicU64::new(0)),
            bytes_processed: Arc::new(AtomicU64::new(0)),
        }
    }
}

/// Per-workspace (fallback per-user) usage metering.
/// The meter key is workspace_id if scoped, or user_id otherwise.
#[derive(Clone)]
struct WorkspaceMeter {
    counters: Arc<RwLock<HashMap<String, WorkspaceCounters>>>,
}

impl WorkspaceMeter {
    fn new() -> Self {
        Self {
            counters: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn get_or_create(&self, dimension: &str) -> WorkspaceCounters {
        let map = self.counters.read().unwrap();
        if let Some(c) = map.get(dimension) {
            return c.clone();
        }
        drop(map);
        let mut map = self.counters.write().unwrap();
        map.entry(dimension.to_string())
            .or_insert_with(WorkspaceCounters::new)
            .clone()
    }

    fn track_write(&self, dimension: &str, bytes: u64) {
        let c = self.get_or_create(dimension);
        c.write_count.fetch_add(1, Ordering::Relaxed);
        c.bytes_processed.fetch_add(bytes, Ordering::Relaxed);
    }

    fn track_read(&self, dimension: &str) {
        let c = self.get_or_create(dimension);
        c.read_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Snapshot all counters, keyed by dimension.
    fn snapshot(&self) -> HashMap<String, WorkspaceCounters> {
        self.counters.read().unwrap().clone()
    }

    /// Atomically drain all counters, returning the previous totals per dimension.
    fn drain(&self) -> HashMap<String, (u64, u64, u64)> {
        let map = self.counters.read().unwrap();
        let dims: Vec<String> = map.keys().cloned().collect();
        let mut result = HashMap::new();
        for dim in &dims {
            let c = map.get(dim).cloned();
            if let Some(c) = c {
                let w = c.write_count.swap(0, Ordering::Relaxed);
                let r = c.read_count.swap(0, Ordering::Relaxed);
                let b = c.bytes_processed.swap(0, Ordering::Relaxed);
                if w > 0 || r > 0 || b > 0 {
                    result.insert(dim.clone(), (w, r, b));
                }
            }
        }
        result
    }
}

#[derive(Clone)]
struct AppState {
    gateway: Arc<Gateway>,
    store: Arc<MemoryStore>,
    keys: Arc<dyn KeyRepository>,
    backends: Arc<BackendRegistry>,
    plugins: Arc<PluginRegistry>,
    service_storage: Arc<ServiceStorage>,
    s3_client: Option<Client>,
    supabase_url: String,
    jwt_decoder: Option<Arc<jsonwebtoken::DecodingKey>>,
    auth_disabled: bool,
    pool: Option<sqlx::PgPool>,
    meter: WorkspaceMeter,
}

struct Auth {
    user_id: String,
    workspace_id: Option<String>,
    public_key_pem: Option<String>,
    stable_key: Option<Vec<u8>>,
    permissions: String,
}

fn auth_has(auth: &Auth, perm: &str) -> bool {
    auth.permissions.split(',').any(|p| p.trim() == perm)
}

/// Derive the deterministic-encryption key for an API key secret:
/// two 32-byte HMAC-SHA256 outputs (`"s4-stable-encrypt"` + counter) giving
/// the 64-byte key AES-256-SIV requires. The plugin receives only this
/// derived key, never the raw secret.
fn derive_stable_key(secret: &str) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut out = Vec::with_capacity(64);
    for i in 1..=2u8 {
        let mut mac =
            HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
        mac.update(b"s4-stable-encrypt");
        mac.update(&[i]);
        out.extend_from_slice(&mac.finalize().into_bytes());
    }
    out
}

#[derive(Serialize, ToSchema)]
struct ApiKeyResponse {
    key_id: String,
    secret: String,
    label: String,
    created_at: String,
    expires_at: Option<String>,
    public_key_pem: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct ListKeyResponse {
    key_id: String,
    label: String,
    created_at: String,
    expires_at: Option<String>,
    public_key_pem: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct ObjectResponse {
    key: String,
    size: usize,
}

#[derive(Deserialize, ToSchema)]
struct CreateKeyRequest {
    label: String,
    #[serde(default)]
    expires_in: u64,
    #[serde(default)]
    public_key_pem: Option<String>,
    #[serde(default)]
    workspace_id: Option<String>,
}

#[derive(Deserialize, ToSchema)]
struct DeleteKeyRequest {
    key_id: String,
}

#[derive(serde::Deserialize, Default)]
struct S3Query {
    uploads: Option<String>,
    #[serde(rename = "uploadId")]
    upload_id: Option<String>,
    #[serde(rename = "partNumber")]
    #[allow(dead_code)]
    part_number: Option<String>,
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "S4 Gateway API",
        version = "0.3.3",
        description = "Pluggable processing gateway for S3-compatible storage. Manage plugins and API keys, proxy S3 requests through a Wasm plugin pipeline."
    ),
    paths(get_keys, create_key, delete_key, list_objects),
    components(schemas(ApiKeyResponse, ListKeyResponse, CreateKeyRequest, DeleteKeyRequest, ObjectResponse)),
    tags(
        (name = "keys", description = "API key management"),
        (name = "objects", description = "Object store listing")
    )
)]
struct ApiDoc;

fn detect_format(headers: &HeaderMap) -> Format {
    let ct = headers
        .get("Content-Type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("text/plain");
    match ct {
        "application/x-ndjson" | "application/jsonlines" => Format::Jsonl,
        "application/json" => Format::Json,
        "text/csv" => Format::Csv,
        _ => Format::Text,
    }
}

async fn get_user_s3_client(state: &AppState, auth: &Auth) -> Option<Client> {
    if let Some(ref s3) = state.s3_client {
        return Some(s3.clone());
    }
    let cfg = auth
        .workspace_id
        .as_deref()
        .and_then(|ws| state.backends.get(ws))
        .or_else(|| state.backends.get(&auth.user_id))?;
    if !cfg.is_configured() || cfg.endpoint.is_empty() {
        return None;
    }
    let creds = Credentials::new(&cfg.access_key, &cfg.secret_key, None, None, "s4-backend");
    let region = if cfg.region.is_empty() {
        "us-east-1".to_string()
    } else {
        cfg.region.clone()
    };
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(Region::new(region))
        .endpoint_url(&cfg.endpoint)
        .credentials_provider(creds)
        .load()
        .await;
    Some(Client::new(&config))
}

async fn authenticate(
    headers: &HeaderMap,
    keys: &Arc<dyn KeyRepository>,
    state: &AppState,
) -> Option<Auth> {
    let auth = headers.get("Authorization").and_then(|v| v.to_str().ok());
    match auth {
        Some(a) if a.starts_with("AWS4-") => Some(Auth {
            user_id: "system".to_string(),
            workspace_id: None,
            public_key_pem: None,
            stable_key: None,
            permissions: "read,write,delete".to_string(),
        }),
        Some(a) if a.starts_with("Bearer ") => {
            let token = &a[7..];
            if let Some((ak, sk)) = token.split_once(':') {
                let (user_id, public_key_pem, workspace_id, permissions) =
                    keys.resolve_credentials(ak, sk).await?;
                return Some(Auth {
                    user_id,
                    workspace_id,
                    public_key_pem,
                    stable_key: Some(derive_stable_key(sk)),
                    permissions,
                });
            }
            if state.jwt_decoder.is_some() {
                let uid = get_user_id(headers, state);
                if uid != "demo-user" {
                    return Some(Auth {
                        user_id: uid,
                        workspace_id: None,
                        public_key_pem: None,
                        stable_key: None,
                        permissions: "read,write,delete".to_string(),
                    });
                }
            }
            return None;
        }
        _ => None,
    };
    let ak = headers
        .get("x-s4-access-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let sk = headers
        .get("x-s4-secret-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if let Some((user_id, public_key_pem, workspace_id, permissions)) =
        keys.resolve_credentials(ak, sk).await
    {
        return Some(Auth {
            user_id,
            workspace_id,
            public_key_pem,
            stable_key: Some(derive_stable_key(sk)),
            permissions,
        });
    }
    if state.auth_disabled {
        return Some(Auth {
            user_id: "demo-user".to_string(),
            workspace_id: None,
            public_key_pem: None,
            stable_key: None,
            permissions: "read,write,delete".to_string(),
        });
    }
    None
}

fn get_user_id(headers: &HeaderMap, state: &AppState) -> String {
    match get_user_claims(headers, state) {
        Some(claims) => claims
            .get("sub")
            .and_then(|v| v.as_str())
            .unwrap_or("demo-user")
            .to_string(),
        None => "demo-user".to_string(),
    }
}

/// Decode and validate the Supabase JWT, returning its claims.
fn get_user_claims(headers: &HeaderMap, state: &AppState) -> Option<serde_json::Value> {
    let auth = headers.get("Authorization").and_then(|v| v.to_str().ok());
    let token = match auth {
        Some(a) if a.starts_with("Bearer ") => &a[7..],
        _ => return None,
    };

    let key = state.jwt_decoder.as_ref()?;
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.set_issuer(&[&format!("{}/auth/v1", state.supabase_url)]);
    validation.validate_exp = true;
    match jsonwebtoken::decode::<serde_json::Value>(token, key, &validation) {
        Ok(data) => Some(data.claims),
        Err(e) => {
            warn!("JWT validation failed: {e}");
            None
        }
    }
}

async fn get_me(State(state): State<Arc<AppState>>, headers: HeaderMap) -> impl IntoResponse {
    let user_id = get_user_id(&headers, &state);
    let (email, provider) = match get_user_claims(&headers, &state) {
        Some(claims) => (
            claims
                .get("email")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            claims
                .get("app_metadata")
                .and_then(|m| m.get("provider"))
                .and_then(|v| v.as_str())
                .unwrap_or("email")
                .to_string(),
        ),
        None => (String::new(), "demo".to_string()),
    };
    let keys = state.keys.list_for_user(&user_id).await;
    Json(serde_json::json!({
        "user_id": user_id,
        "email": email,
        "provider": provider,
        "keys": keys.len(),
    }))
}

fn s3_xml_ok(xml: String) -> axum::response::Response {
    axum::response::Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/xml")
        .body(axum::body::Body::from(xml))
        .unwrap()
}

async fn list_workspaces(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let user_id = get_user_id(&headers, &state);
    let pool = match &state.pool {
        Some(p) => p,
        None => return Json(serde_json::json!({ "workspaces": [] })),
    };

    let rows = sqlx::query(
        "SELECT w.id::text, w.name, w.slug, wm.role \
         FROM workspaces w JOIN workspace_members wm ON w.id = wm.workspace_id \
         WHERE wm.user_id = $1 ORDER BY w.created_at DESC",
    )
    .bind(&user_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let workspaces: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            use sqlx::Row;
            serde_json::json!({
                "id": r.get::<String, _>(0),
                "name": r.get::<&str, _>(1),
                "slug": r.get::<&str, _>(2),
                "role": r.get::<&str, _>(3)
            })
        })
        .collect();

    Json(serde_json::json!({ "workspaces": workspaces }))
}

async fn create_workspace(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let user_id = get_user_id(&headers, &state);
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("My Workspace");
    let slug = body
        .get("slug")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_lowercase())
        .unwrap_or_else(|| name.to_lowercase().replace(' ', "-"));

    let pool = match &state.pool {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, "DATABASE_URL not configured").into_response(),
    };

    let row = sqlx::query("INSERT INTO workspaces (name, slug) VALUES ($1, $2) RETURNING id::text")
        .bind(name)
        .bind(&slug)
        .fetch_one(pool)
        .await;

    let ws_id: String = match row {
        Ok(r) => {
            use sqlx::Row;
            r.get(0)
        }
        Err(e) => return (StatusCode::CONFLICT, format!("{}", e)).into_response(),
    };

    let _ = sqlx::query(
        "INSERT INTO workspace_members (workspace_id, user_id, role) VALUES ($1::uuid, $2, 'owner')",
    )
    .bind(&ws_id)
    .bind(&user_id)
    .execute(pool)
    .await;

    Json(serde_json::json!({ "id": ws_id, "name": name, "slug": slug, "role": "owner" }))
        .into_response()
}

async fn delete_workspace(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(ws_id): Path<String>,
) -> impl IntoResponse {
    let user_id = get_user_id(&headers, &state);
    let pool = match &state.pool {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, "DATABASE_URL not configured").into_response(),
    };

    let result = sqlx::query(
        "DELETE FROM workspaces w USING workspace_members wm \
         WHERE w.id::text = $1 AND wm.workspace_id = w.id AND wm.user_id = $2 AND wm.role = 'owner'",
    )
    .bind(&ws_id)
    .bind(&user_id)
    .execute(pool)
    .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => StatusCode::NO_CONTENT.into_response(),
        Ok(_) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response(),
    }
}

async fn get_usage(State(state): State<Arc<AppState>>, headers: HeaderMap) -> impl IntoResponse {
    let user_id = get_user_id(&headers, &state);
    // Live in-memory counters: sum across all dimensions
    let snapshot = state.meter.snapshot();
    let (live_writes, live_reads, live_bytes): (u64, u64, u64) =
        snapshot.values().fold((0, 0, 0), |acc, c| {
            (
                acc.0 + c.write_count.load(Ordering::Relaxed),
                acc.1 + c.read_count.load(Ordering::Relaxed),
                acc.2 + c.bytes_processed.load(Ordering::Relaxed),
            )
        });
    let pool = match &state.pool {
        Some(p) => p,
        None => {
            return Json(serde_json::json!({
                "usage": {
                    "write_count": live_writes,
                    "read_count": live_reads,
                    "gb_processed": live_bytes as f64 / 1_000_000_000.0,
                    "live": true
                }
            }));
        }
    };

    let row = sqlx::query(
        "SELECT coalesce(sum(write_count), 0)::bigint, \
                coalesce(sum(read_count), 0)::bigint, \
                coalesce(sum(gb_processed), 0.0)::double precision \
         FROM usage_records ur \
         JOIN workspace_members wm ON ur.workspace_id = wm.workspace_id \
         WHERE wm.user_id = $1 \
         AND ur.period_start >= date_trunc('month', now())",
    )
    .bind(&user_id)
    .fetch_one(pool)
    .await;

    let (db_writes, db_reads, db_gb): (i64, i64, f64) = match row {
        Ok(r) => {
            use sqlx::Row;
            (r.get(0), r.get(1), r.get(2))
        }
        Err(_) => (0, 0, 0.0),
    };

    Json(serde_json::json!({
        "usage": {
            "write_count": db_writes,
            "read_count": db_reads,
            "gb_processed": db_gb,
            "live": {
                "write_count": live_writes,
                "read_count": live_reads,
                "gb_processed": live_bytes as f64 / 1_000_000_000.0,
            }
        }
    }))
}

async fn s3_put(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let Some(auth) = authenticate(&headers, &state.keys, &state).await else {
        return s3_error::access_denied(&key);
    };
    if !auth_has(&auth, "write") {
        return s3_error::access_denied(&key);
    }
    let dim = auth.workspace_id.as_deref().unwrap_or(&auth.user_id);
    let uid = &auth.user_id;

    state.meter.track_write(dim, body.len() as u64);

    let format = detect_format(&headers);
    let stable_fields = headers
        .get("x-s4-stable-fields")
        .and_then(|v| v.to_str().ok());
    let output = match state.gateway.process(
        &body,
        format,
        "text/plain",
        auth.public_key_pem.as_deref(),
        auth.stable_key.as_deref(),
        stable_fields,
    ) {
        Ok(o) => o,
        Err(e) => {
            warn!("filter failed for /{bucket}/{key}: {e}");
            return s3_error::internal_error(&key, &e.to_string());
        }
    };

    if let Some(backend_url) = headers
        .get("x-s4-backend-url")
        .and_then(|v| v.to_str().ok())
    {
        match reqwest::Client::new()
            .put(backend_url)
            .body(output.bytes.clone())
            .send()
            .await
        {
            Ok(_) => {
                info!(
                    "PUT /{bucket}/{key} -> presigned URL ({} records, user={})",
                    output.records_processed, uid
                );
                StatusCode::OK.into_response()
            }
            Err(e) => {
                warn!("backend put failed: {e}");
                s3_error::internal_error(&key, &e.to_string())
            }
        }
    } else if let Some(s3) = get_user_s3_client(&state, &auth).await {
        match s3
            .put_object()
            .bucket(&bucket)
            .key(&key)
            .body(ByteStream::from(output.bytes))
            .send()
            .await
        {
            Ok(_) => {
                info!(
                    "PUT /{bucket}/{key} -> S3 ({} records, user={})",
                    output.records_processed, uid
                );
                StatusCode::OK.into_response()
            }
            Err(e) => {
                warn!("upstream put failed: {e}");
                s3_error::internal_error(&key, &e.to_string())
            }
        }
    } else if !state.service_storage.is_empty() {
        match state
            .service_storage
            .put(
                &format!("{}/{}", bucket, key),
                output.bytes.to_vec(),
                "text/plain",
            )
            .await
        {
            Ok(()) => {
                info!(
                    "PUT /{bucket}/{key} -> service storage ({} records, user={})",
                    output.records_processed, uid
                );
                StatusCode::OK.into_response()
            }
            Err(e) => {
                warn!("service storage put failed: {e}");
                s3_error::internal_error(&key, &e.to_string())
            }
        }
    } else {
        let obj = state.store.put(&bucket, &key, output.bytes, "text/plain");
        info!(
            "PUT /{bucket}/{key} -> memory ({} records, {} bytes, user={})",
            output.records_processed,
            obj.data.len(),
            uid
        );
        let mut resp = axum::response::Response::builder().status(StatusCode::OK);
        resp = resp.header("ETag", &obj.etag);
        resp.body(axum::body::Body::empty()).unwrap()
    }
}

async fn s3_get(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let Some(_auth) = authenticate(&headers, &state.keys, &state).await else {
        return s3_error::access_denied(&key);
    };
    if !auth_has(&_auth, "read") {
        return s3_error::access_denied(&key);
    }

    let dim = _auth.workspace_id.as_deref().unwrap_or(&_auth.user_id);
    state.meter.track_read(dim);

    if let Some(backend_url) = headers
        .get("x-s4-backend-url")
        .and_then(|v| v.to_str().ok())
    {
        match reqwest::get(backend_url).await {
            Ok(resp) => {
                let status = resp.status();
                let ct = resp
                    .headers()
                    .get("content-type")
                    .map(|v| v.to_str().unwrap_or("application/octet-stream").to_string());
                let body_bytes = resp.bytes().await.unwrap_or_default();
                let mut builder = axum::response::Response::builder()
                    .status(StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::OK));
                if let Some(ct_val) = ct {
                    builder = builder.header("Content-Type", ct_val);
                }
                builder = builder.header("Content-Length", body_bytes.len().to_string());
                builder.body(axum::body::Body::from(body_bytes)).unwrap()
            }
            Err(e) => {
                warn!("backend get failed: {e}");
                s3_error::internal_error(&key, &e.to_string())
            }
        }
    } else if let Some(ref s3) = state.s3_client {
        let mut req = s3.get_object().bucket(&bucket).key(&key);
        if let Some(range) = headers.get("Range").and_then(|v| v.to_str().ok()) {
            req = req.range(range);
        }
        match req.send().await {
            Ok(output) => {
                let data = output.body.collect().await;
                match data {
                    Ok(bytes) => {
                        let bytes = bytes.into_bytes();
                        let mut resp = axum::response::Response::builder().status(StatusCode::OK);
                        if let Some(etag) = output.e_tag.as_deref() {
                            resp = resp.header("ETag", etag);
                        }
                        if let Some(ct) = output.content_type.as_deref() {
                            resp = resp.header("Content-Type", ct);
                        }
                        if let Some(cl) = output.content_length {
                            resp = resp.header("Content-Length", cl.to_string());
                        }
                        resp.body(axum::body::Body::from(bytes)).unwrap()
                    }
                    Err(e) => s3_error::internal_error(&key, &e.to_string()),
                }
            }
            Err(e) => {
                if e.to_string().contains("NotFound") {
                    s3_error::no_such_key(&key)
                } else {
                    s3_error::internal_error(&key, &e.to_string())
                }
            }
        }
    } else if !state.service_storage.is_empty() {
        match state
            .service_storage
            .get(&format!("{}/{}", bucket, key))
            .await
        {
            Some((data, content_type)) => {
                let mut resp = axum::response::Response::builder().status(StatusCode::OK);
                resp = resp.header("Content-Type", content_type);
                resp = resp.header("Content-Length", data.len().to_string());
                resp.body(axum::body::Body::from(data)).unwrap()
            }
            None => s3_error::no_such_key(&key),
        }
    } else {
        match state.store.get(&bucket, &key) {
            Some(obj) => {
                let mut resp = axum::response::Response::builder().status(StatusCode::OK);
                resp = resp.header("ETag", &obj.etag);
                resp = resp.header("Content-Type", &obj.content_type);
                resp = resp.header("Content-Length", obj.data.len().to_string());
                resp.body(axum::body::Body::from(obj.data)).unwrap()
            }
            None => s3_error::no_such_key(&key),
        }
    }
}

async fn s3_head(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let Some(_auth) = authenticate(&headers, &state.keys, &state).await else {
        return s3_error::access_denied(&key);
    };
    if !auth_has(&_auth, "read") {
        return s3_error::access_denied(&key);
    }

    let dim = _auth.workspace_id.as_deref().unwrap_or(&_auth.user_id);
    state.meter.track_read(dim);

    if let Some(ref s3) = state.s3_client {
        match s3.head_object().bucket(&bucket).key(&key).send().await {
            Ok(output) => {
                let mut resp = axum::response::Response::builder().status(StatusCode::OK);
                if let Some(etag) = output.e_tag.as_deref() {
                    resp = resp.header("ETag", etag);
                }
                if let Some(ct) = output.content_type.as_deref() {
                    resp = resp.header("Content-Type", ct);
                }
                if let Some(cl) = output.content_length {
                    resp = resp.header("Content-Length", cl.to_string());
                }
                resp.body(axum::body::Body::empty()).unwrap()
            }
            Err(e) => {
                if e.to_string().contains("NotFound") {
                    s3_error::no_such_key(&key)
                } else {
                    s3_error::internal_error(&key, &e.to_string())
                }
            }
        }
    } else {
        match state.store.head(&bucket, &key) {
            Some(obj) => {
                let mut resp = axum::response::Response::builder().status(StatusCode::OK);
                resp = resp.header("ETag", &obj.etag);
                resp = resp.header("Content-Type", &obj.content_type);
                resp = resp.header("Content-Length", obj.data.len().to_string());
                resp.body(axum::body::Body::empty()).unwrap()
            }
            None => s3_error::no_such_key(&key),
        }
    }
}

async fn s3_delete(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let Some(auth) = authenticate(&headers, &state.keys, &state).await else {
        return s3_error::access_denied(&key);
    };
    if !auth_has(&auth, "write") {
        return s3_error::access_denied(&key);
    }
    info!("DELETE /{bucket}/{key} user={}", auth.user_id);

    let dim = auth.workspace_id.as_deref().unwrap_or(&auth.user_id);
    state.meter.track_write(dim, 0);

    if let Some(ref s3) = state.s3_client {
        match s3.delete_object().bucket(&bucket).key(&key).send().await {
            Ok(_) => StatusCode::NO_CONTENT.into_response(),
            Err(e) => s3_error::internal_error(&key, &e.to_string()),
        }
    } else {
        state.store.delete(&bucket, &key);
        StatusCode::NO_CONTENT.into_response()
    }
}

async fn s3_post(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<S3Query>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let Some(auth) = authenticate(&headers, &state.keys, &state).await else {
        return s3_error::access_denied(&key);
    };
    if !auth_has(&auth, "write") {
        return s3_error::access_denied(&key);
    }
    info!("POST /{bucket}/{key} user={}", auth.user_id);

    let dim = auth.workspace_id.as_deref().unwrap_or(&auth.user_id);
    state.meter.track_write(dim, body.len() as u64);

    if params.uploads.is_some() {
        return s3_mp_create(&bucket, &key).await;
    }
    if params.upload_id.is_some() {
        return s3_mp_complete(&bucket, &key, &params, body).await;
    }
    s3_error::not_implemented(&key)
}

async fn s3_mp_create(bucket: &str, key: &str) -> axum::response::Response {
    let upload_id = uuid::Uuid::new_v4().to_string();
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><InitiateMultipartUploadResult><Bucket>{bucket}</Bucket><Key>{key}</Key><UploadId>{upload_id}</UploadId></InitiateMultipartUploadResult>"#
    );
    s3_xml_ok(xml)
}

async fn s3_mp_complete(
    bucket: &str,
    key: &str,
    _params: &S3Query,
    _body: axum::body::Bytes,
) -> axum::response::Response {
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUploadResult><Bucket>{bucket}</Bucket><Key>{key}</Key></CompleteMultipartUploadResult>"#
    );
    s3_xml_ok(xml)
}

fn dashboard_html() -> String {
    let html = include_str!("../static/dashboard.html");
    let auth_disabled = std::env::var("AUTH_DISABLED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let supabase_url =
        std::env::var("SUPABASE_URL").unwrap_or_else(|_| "http://127.0.0.1:54321".to_string());
    let anon_key = std::env::var("SUPABASE_ANON_KEY")
        .unwrap_or_else(|_| "sb_publishable_ACJWlzQHlZjBrEguHvfOxg_3BJgxAaH".to_string());
    let has_supabase = anon_key.starts_with("sb_");

    let supabase_script = if has_supabase {
        format!(
            "<script src=\"https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/dist/umd/supabase.min.js\"></script>\n<script>var supabase = window.supabase.createClient('{supabase_url}', '{anon_key}');\nvar HAS_SUPABASE = true;</script>"
        )
    } else {
        "<script>var HAS_SUPABASE = false;</script>".to_string()
    };

    // Local mode (AUTH_DISABLED=true): skip the auth modal entirely, go
    // straight into the dashboard as the local demo user.
    let boot = if auth_disabled || !has_supabase {
        "isDemo = true; onAuthReady();".to_string()
    } else {
        "supabase.auth.getSession().then(function(r) { if (r.data.session) { session = r.data.session; sessionToken = session.access_token; onAuthReady(); } });".to_string()
    };

    let auth_flag = format!(
        "<script>var AUTH_DISABLED = {};</script>",
        if auth_disabled { "true" } else { "false" }
    );

    html.replace("<!--SUPABASE-->", &format!("{auth_flag}{supabase_script}"))
        .replace("/*BOOT*/", &boot)
}

async fn health() -> impl IntoResponse {
    "ok"
}

/// List API keys for the authenticated user
#[utoipa::path(
    get,
    path = "/dashboard/api/keys",
    responses((status = 200, description = "API keys", body = Vec<ListKeyResponse>)),
    tag = "keys"
)]
async fn get_keys(State(state): State<Arc<AppState>>, headers: HeaderMap) -> impl IntoResponse {
    let uid = get_user_id(&headers, &state);
    let keys = state.keys.list_for_user(&uid).await;
    let resp: Vec<ListKeyResponse> = keys
        .into_iter()
        .map(|k| ListKeyResponse {
            key_id: k.key_id,
            label: k.label,
            created_at: k.created_at,
            expires_at: k.expires_at,
            public_key_pem: k.public_key_pem,
        })
        .collect();
    Json(resp)
}

/// Create a new API key
#[utoipa::path(
    post,
    path = "/dashboard/api/keys",
    request_body = CreateKeyRequest,
    responses((status = 200, description = "Created key with secret", body = ApiKeyResponse)),
    tag = "keys"
)]
async fn create_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateKeyRequest>,
) -> impl IntoResponse {
    let uid = get_user_id(&headers, &state);
    let (key_id, secret) = state
        .keys
        .create_key(
            &uid,
            &body.label,
            body.expires_in,
            body.public_key_pem,
            body.workspace_id,
        )
        .await;
    let key = state.keys.get_key(&key_id).await;
    let created_at = key
        .as_ref()
        .map_or_else(|| "0".to_string(), |k| k.created_at.clone());
    let expires_at = key.as_ref().and_then(|k| k.expires_at.clone());
    let public_key_pem = key.as_ref().and_then(|k| k.public_key_pem.clone());
    Json(ApiKeyResponse {
        key_id,
        secret,
        label: body.label,
        created_at,
        expires_at,
        public_key_pem,
    })
}

/// Revoke an API key
#[utoipa::path(
    delete,
    path = "/dashboard/api/keys",
    request_body = DeleteKeyRequest,
    responses((status = 204, description = "Key revoked"), (status = 404, description = "Key not found")),
    tag = "keys"
)]
async fn delete_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<DeleteKeyRequest>,
) -> impl IntoResponse {
    let uid = get_user_id(&headers, &state);
    if state.keys.delete_key(&body.key_id, &uid).await {
        StatusCode::NO_CONTENT.into_response()
    } else {
        (StatusCode::NOT_FOUND, "key not found").into_response()
    }
}

#[derive(Deserialize, Default)]
struct BackendQuery {
    workspace_id: Option<String>,
}

async fn get_backend(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<BackendQuery>,
) -> impl IntoResponse {
    let uid = get_user_id(&headers, &state);
    let key = params.workspace_id.as_deref().unwrap_or(&uid);
    let config = state.backends.get(key).unwrap_or(BackendConfig {
        backend_type: String::new(),
        role_arn: String::new(),
        external_id: state.backends.generate_external_id(&uid),
        endpoint: String::new(),
        access_key: String::new(),
        secret_key: String::new(),
        region: String::new(),
    });
    Json(config)
}

async fn put_backend(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<BackendQuery>,
    Json(config): Json<BackendConfig>,
) -> impl IntoResponse {
    let uid = get_user_id(&headers, &state);
    let key = params.workspace_id.as_deref().unwrap_or(&uid);
    let mut config = config;
    if config.external_id.is_empty() {
        config.external_id = state.backends.generate_external_id(&uid);
    }
    state.backends.set(key, config);
    StatusCode::OK.into_response()
}

async fn get_plugins(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(state.plugins.list())
}

#[derive(Deserialize)]
struct SetPublicKeyRequest {
    key_id: String,
    public_key_pem: String,
}

async fn set_public_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<SetPublicKeyRequest>,
) -> impl IntoResponse {
    let uid = get_user_id(&headers, &state);
    if state
        .keys
        .set_public_key(&body.key_id, &uid, &body.public_key_pem)
        .await
    {
        StatusCode::OK.into_response()
    } else {
        (StatusCode::NOT_FOUND, "key not found or not owned by user").into_response()
    }
}

async fn create_plugin(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let name = headers
        .get("x-s4-plugin-name")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("imported")
        .to_string();
    match state.plugins.import(&name, &body) {
        Ok(info) => (StatusCode::CREATED, Json(info)).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct PluginUpdate {
    enabled: Option<bool>,
    name: Option<String>,
}

#[derive(Deserialize)]
struct PluginReorder {
    order: Vec<String>,
}

async fn reorder_plugins(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PluginReorder>,
) -> impl IntoResponse {
    state.plugins.reorder(body.order);
    StatusCode::OK.into_response()
}

async fn update_plugin(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(update): Json<PluginUpdate>,
) -> impl IntoResponse {
    let found = update
        .enabled
        .is_some_and(|enabled| state.plugins.set_enabled(&id, enabled).is_some())
        || update
            .name
            .is_some_and(|name| state.plugins.set_name(&id, &name).is_some());
    if let Some(info) = state.plugins.get_info(&id) {
        Json(info).into_response()
    } else if found {
        StatusCode::OK.into_response()
    } else {
        (StatusCode::NOT_FOUND, "plugin not found").into_response()
    }
}

async fn delete_plugin(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if state.plugins.remove(&id) {
        StatusCode::NO_CONTENT.into_response()
    } else {
        (StatusCode::NOT_FOUND, "plugin not found").into_response()
    }
}

/// List all objects in the store
#[utoipa::path(
    get,
    path = "/dashboard/api/objects",
    responses((status = 200, description = "Objects", body = Vec<ObjectResponse>)),
    tag = "objects"
)]
async fn list_objects(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let objects: Vec<ObjectResponse> = state
        .store
        .list_keys()
        .into_iter()
        .map(|k| {
            let parts: Vec<&str> = k.splitn(2, '/').collect();
            let bucket = parts[0];
            let obj_key = parts.get(1).unwrap_or(&"");
            let size = state
                .store
                .get(bucket, obj_key)
                .map(|o| o.data.len())
                .unwrap_or(0);
            ObjectResponse { key: k, size }
        })
        .collect();
    Json(objects)
}

fn component_path() -> PathBuf {
    std::env::var("S4_FILTER_COMPONENT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            p.push("..");
            p.push("..");
            p.push("target");
            p.push("components");
            p.push("pii-default.component.wasm");
            p
        })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let s3_endpoint = std::env::var("S3_ENDPOINT").ok();
    let listen_addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());

    let component_bytes = std::fs::read(component_path())?;
    let pipeline_fuel = std::env::var("S4_WASM_FUEL")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(s4_gateway::plugin_registry::DEFAULT_PIPELINE_FUEL);
    let engine = s4_wasm_runtime::FilterEngine::with_fuel(&component_bytes, pipeline_fuel)?;
    let plugins = Arc::new(PluginRegistry::with_fuel(pipeline_fuel));

    // Load default filter plugin
    plugins.import("pii-default", &component_bytes)?;

    // Auto-load plugins from S4_PLUGINS_DIR if set
    if let Ok(plugin_dir) = std::env::var("S4_PLUGINS_DIR") {
        let dir = std::path::Path::new(&plugin_dir);
        if dir.exists() {
            plugins.load_from_dir(dir)?;
        }
    }

    let gateway = Gateway::with_registry(engine, plugins.clone());

    let s3_client = match &s3_endpoint {
        Some(endpoint) => {
            let creds = Credentials::new("minioadmin", "minioadmin", None, None, "static");
            let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
                .region(Region::new("us-east-1"))
                .endpoint_url(endpoint)
                .credentials_provider(creds)
                .load()
                .await;
            Some(Client::new(&config))
        }
        None => None,
    };

    let supabase_url =
        std::env::var("SUPABASE_URL").unwrap_or_else(|_| "http://127.0.0.1:54321".to_string());
    let supabase_jwt_secret = std::env::var("SUPABASE_JWT_SECRET").ok();

    let jwt_decoder = supabase_jwt_secret
        .map(|secret| Arc::new(jsonwebtoken::DecodingKey::from_secret(secret.as_bytes())));

    // Local mode: skip all auth UI and allow unauthenticated S3 access.
    let auth_disabled = std::env::var("AUTH_DISABLED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let service_backends = std::env::var("S4_SERVICE_BUCKETS")
        .ok()
        .map(|v| parse_service_backends(&v))
        .unwrap_or_default();
    let service_storage = Arc::new(ServiceStorage::new(service_backends));

    // API key persistence: Postgres (Supabase) when DATABASE_URL is set,
    // a JSON file when S4_KEYS_FILE is set, a default JSON file in local
    // mode (AUTH_DISABLED=true), and otherwise the in-memory KeyStore.
    let (keys, db_pool): (Arc<dyn KeyRepository>, Option<sqlx::PgPool>) =
        if let Ok(database_url) = std::env::var("DATABASE_URL") {
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(5)
                .connect(&database_url)
                .await
                .expect("failed to connect to DATABASE_URL");
            sqlx::migrate!("../../migrations")
                .run(&pool)
                .await
                .expect("failed to run migrations");
            info!("Key store: Postgres (migrations applied)");
            (Arc::new(PostgresKeyStore::new(pool.clone())), Some(pool))
        } else if let Ok(keys_file) = std::env::var("S4_KEYS_FILE") {
            info!("Key store: file ({keys_file})");
            (Arc::new(FileKeyStore::new(PathBuf::from(keys_file))), None)
        } else if auth_disabled {
            let path = FileKeyStore::default_path();
            info!("Key store: file ({}) (local mode)", path.display());
            (Arc::new(FileKeyStore::new(path)), None)
        } else {
            info!("Key store: in-memory (set DATABASE_URL or S4_KEYS_FILE for persistence)");
            (Arc::new(KeyStore::new()), None)
        };

    let state = Arc::new(AppState {
        gateway: Arc::new(gateway),
        store: Arc::new(MemoryStore::new()),
        keys,
        backends: Arc::new(BackendRegistry::new()),
        plugins,
        service_storage,
        s3_client,
        supabase_url,
        jwt_decoder,
        auth_disabled,
        pool: db_pool.clone(),
        meter: WorkspaceMeter::new(),
    });

    info!("S4 gateway listening on {listen_addr}");
    if let Some(ref ep) = s3_endpoint {
        info!("S3 backend: {ep}");
    } else {
        info!("Storage mode: in-memory");
        info!("Dashboard: http://localhost:8080");
    }

    // Periodic aggregation: flush in-memory usage counters to usage_records.
    if let Some(pool) = state.pool.clone() {
        let meter = state.meter.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                let drained = meter.drain();
                for (dim, (w, r, b)) in &drained {
                    let gb = *b as f64 / 1_000_000_000.0;
                    // dim is workspace_id (UUID) for scoped keys, user_id for unscoped.
                    // Parse as UUID for workspace-scoped; fall back to NULL.
                    let ws_id: Option<uuid::Uuid> = uuid::Uuid::parse_str(dim).ok();
                    let result = sqlx::query(
                        "INSERT INTO usage_records (workspace_id, period_start, period_end, write_count, read_count, gb_processed) \
                         VALUES ($1::uuid, date_trunc('hour', now()), date_trunc('hour', now()) + interval '1 hour', $2, $3, $4)"
                    )
                    .bind(ws_id)
                    .bind(*w as i64)
                    .bind(*r as i64)
                    .bind(gb)
                    .execute(&pool)
                    .await;
                    match result {
                        Ok(_) => info!(
                            "flushed usage [{}]: {} writes, {} reads, {:.4} GB",
                            dim, w, r, gb
                        ),
                        Err(e) => warn!("failed to flush usage [{}]: {e}", dim),
                    }
                }
            }
        });
    }

    let app = Router::new()
        .route("/health", get(health))
        .route("/", get(|| async { Html(dashboard_html()) }))
        .route("/dashboard/api/keys", get(get_keys))
        .route("/dashboard/api/keys", post(create_key))
        .route("/dashboard/api/keys", delete(delete_key))
        .route("/dashboard/api/keys/public-key", put(set_public_key))
        .route("/dashboard/api/me", get(get_me))
        .route("/dashboard/api/workspaces", get(list_workspaces))
        .route("/dashboard/api/workspaces", post(create_workspace))
        .route("/dashboard/api/workspaces/{id}", delete(delete_workspace))
        .route("/dashboard/api/usage", get(get_usage))
        .route("/dashboard/api/backend", get(get_backend))
        .route("/dashboard/api/backend", put(put_backend))
        .route("/dashboard/api/plugins", get(get_plugins))
        .route("/dashboard/api/plugins", post(create_plugin))
        .route("/dashboard/api/plugins/reorder", put(reorder_plugins))
        .route("/dashboard/api/plugins/{id}", put(update_plugin))
        .route("/dashboard/api/plugins/{id}", delete(delete_plugin))
        .route("/dashboard/api/objects", get(list_objects))
        .route("/{bucket}/{*key}", put(s3_put))
        .route("/{bucket}/{*key}", get(s3_get))
        .route("/{bucket}/{*key}", head(s3_head))
        .route("/{bucket}/{*key}", delete(s3_delete))
        .route("/{bucket}/{*key}", post(s3_post))
        .layer(CorsLayer::permissive())
        .with_state(state)
        .merge(SwaggerUi::new("/docs").url("/openapi.json", ApiDoc::openapi()));

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
